#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  config_parser.cc  —  nginx-inspired config parser
// ─────────────────────────────────────────────────────────────────────────────
#include "../../include/np_config.hh"
#include <fstream>
#include <stdexcept>
#include <algorithm>

struct Token { enum Type{Word,LBrace,RBrace,Semi,Eof} type; std::string val; };

static std::vector<Token> tokenize(const std::string& src){
    std::vector<Token> t; size_t i=0;
    while(i<src.size()){
        char c=src[i];
        if(c=='#'){while(i<src.size()&&src[i]!='\n')i++;continue;}
        if(std::isspace((unsigned char)c)){i++;continue;}
        if(c=='{'){t.push_back({Token::LBrace,"{"});i++;continue;}
        if(c=='}'){t.push_back({Token::RBrace,"}"});i++;continue;}
        if(c==';'){t.push_back({Token::Semi,";"});i++;continue;}
        if(c=='"'||c=='\''){
            char q=c; i++; std::string w;
            while(i<src.size()&&src[i]!=q) w+=src[i++];
            if(i<src.size())i++;
            t.push_back({Token::Word,w}); continue;
        }
        std::string w;
        while(i<src.size()&&!std::isspace((unsigned char)src[i])&&
              src[i]!='{'&&src[i]!='}'&&src[i]!=';'&&src[i]!='#') w+=src[i++];
        if(!w.empty()) t.push_back({Token::Word,w});
    }
    t.push_back({Token::Eof,""});
    return t;
}

struct P {
    std::vector<Token> t; size_t i{0};
    Token& peek(){return t[i];}
    Token  eat(){return t[i++];}
    bool at(Token::Type tp){return peek().type==tp;}
    std::string word(){
        if(!at(Token::Word)) throw std::runtime_error("expected word, got '"+peek().val+"'");
        return eat().val;
    }
    void expect(Token::Type tp){ if(peek().type!=tp) throw std::runtime_error("unexpected '"+peek().val+"'"); eat(); }
};

static int pi(const std::string& s,int d=0){try{return std::stoi(s);}catch(...){return d;}}
static bool pb(const std::string& s){return s=="on"||s=="true"||s=="yes"||s=="1";}

static MiddlewareScript parse_middleware(P& p){
    MiddlewareScript mw;
    std::string engine_str=p.word();
    if(engine_str=="js"||engine_str=="javascript") mw.engine=ScriptEngine::JS;
    else if(engine_str=="lua")                     mw.engine=ScriptEngine::Lua;
    // next token: file path or inline{ ... }
    if(p.at(Token::LBrace)){
        p.eat();
        std::string code;
        int depth=1;
        while(!p.at(Token::Eof)&&depth>0){
            if(p.at(Token::LBrace)){depth++;code+="{";p.eat();}
            else if(p.at(Token::RBrace)){depth--;if(depth>0)code+="}";p.eat();}
            else code+=p.eat().val+" ";
        }
        mw.inline_code=code;
    } else {
        mw.path=p.word();
    }
    return mw;
}

static LocationConfig parse_location(P& p){
    LocationConfig loc;
    if(p.peek().val=="="){p.eat();loc.exact=true;}
    loc.prefix=p.word();
    p.expect(Token::LBrace);
    while(!p.at(Token::RBrace)&&!p.at(Token::Eof)){
        auto key=p.word();
        if(key=="proxy_pass"){loc.type=LocationType::Proxy;loc.upstream=p.word();}
        else if(key=="root"){loc.type=LocationType::Static;loc.root=p.word();}
        else if(key=="websocket"){loc.websocket=pb(p.word());}
        else if(key=="proxy_timeout"){loc.proxy_timeout=pi(p.word(),30);}
        else if(key=="gzip"){loc.gzip=pb(p.word());}
        else if(key=="etag"){loc.etag=pb(p.word());}
        else if(key=="autoindex"){loc.autoindex=pb(p.word());}
        else if(key=="spa_fallback"){/* handled in static */p.word();}
        else if(key=="cache"){
            auto v=p.word();
            if(v=="off") loc.cache_max_age=-1;
            else if(v=="on") loc.cache_max_age=60;
            else {
                // "max_age=31536000" or just a number
                auto eq=v.find('=');
                if(eq!=std::string::npos) loc.cache_max_age=pi(v.substr(eq+1));
                else loc.cache_max_age=pi(v,60);
            }
        }
        else if(key=="rate_limit"){
            // rate_limit 200/min burst=50
            loc.rate_limit.enabled=true;
            auto rval=p.word();
            auto slash=rval.find('/');
            int maxreq=pi(slash!=std::string::npos?rval.substr(0,slash):rval,200);
            int window=60;
            if(slash!=std::string::npos){
                auto unit=rval.substr(slash+1);
                if(unit=="sec"||unit=="second") window=1;
            }
            loc.rate_limit.rate=(double)maxreq/window;
            loc.rate_limit.burst=50.0;
            while(p.at(Token::Word)){
                auto opt=p.eat().val;
                if(opt.substr(0,6)=="burst=") loc.rate_limit.burst=pi(opt.substr(6),50);
            }
        }
        else if(key=="js_middleware"){
            MiddlewareScript mw; mw.engine=ScriptEngine::JS; mw.path=p.word();
            loc.middlewares.push_back(mw);
        }
        else if(key=="lua_middleware"){
            MiddlewareScript mw; mw.engine=ScriptEngine::Lua; mw.path=p.word();
            loc.middlewares.push_back(mw);
        }
        else if(key=="middleware"){
            loc.middlewares.push_back(parse_middleware(p));
            if(p.at(Token::Semi)) p.eat();
            continue;
        }
        else if(key=="add_header"){auto k=p.word(),v=p.word();loc.add_headers.emplace_back(k,v);}
        else if(key=="hide_header"){loc.hide_headers.push_back(p.word());}
        else if(key=="return"){loc.type=LocationType::Return;loc.return_code=pi(p.word(),200);if(p.at(Token::Word))loc.return_body=p.word();}
        else if(key=="redirect"){loc.type=LocationType::Redirect;loc.redirect_url=p.word();}
        else if(key=="try_files"){while(p.at(Token::Word))loc.try_files.push_back(p.eat().val);}
        else if(key=="health_check"){loc.health_check_path=p.word();if(p.at(Token::Word))loc.health_check_interval=pi(p.eat().val,30);}
        else if(key=="proxy_connect_timeout"){loc.proxy_connect_timeout=pi(p.word(),5);}
        else if(key=="named"){loc.named_location=p.word();}
        else {while(p.at(Token::Word))p.eat();}
        if(p.at(Token::Semi)) p.eat();
    }
    p.expect(Token::RBrace);
    return loc;
}

static ServerConfig parse_server(P& p){
    ServerConfig srv; p.expect(Token::LBrace);
    while(!p.at(Token::RBrace)&&!p.at(Token::Eof)){
        auto key=p.word();
        if(key=="listen"){
            ListenDirective ld;
            auto v=p.word();
            auto c=v.rfind(':');
            ld.port=(uint16_t)pi(c!=std::string::npos?v.substr(c+1):v,80);
            while(p.at(Token::Word)){
                auto f=p.eat().val;
                if(f=="ssl")  ld.ssl=true;
                if(f=="http2")ld.http2=true;
                if(f=="quic"||f=="http3") ld.http3=true;
                if(f=="default_server") ld.default_server=true;
            }
            srv.listens.push_back(ld);
        }
        else if(key=="server_name"){while(p.at(Token::Word))srv.server_names.push_back(p.eat().val);}
        else if(key=="ssl_cert"){srv.ssl_cert=p.word();}
        else if(key=="ssl_key"){srv.ssl_key=p.word();}
        else if(key=="ssl_protocols"){std::string pr;while(p.at(Token::Word))pr+=p.eat().val+" ";srv.ssl_protocols=pr;}
        else if(key=="keepalive_timeout"){srv.keepalive_timeout=pi(p.word(),65);}
        else if(key=="keepalive_requests"){srv.keepalive_requests=pi(p.word(),1000);}
        else if(key=="client_max_body_size"){srv.client_max_body=pi(p.word(),64*1024*1024);}
        else if(key=="access_log"){srv.access_log=p.word();}
        else if(key=="error_log"){srv.error_log=p.word();}
        else if(key=="location"){srv.locations.push_back(parse_location(p));continue;}
        else if(key=="error_page"){int code=pi(p.word(),404);std::string pg=p.word();srv.error_pages[code]=pg;}
        else if(key=="default_server"){for(auto& l:srv.listens)l.default_server=true;}
        else{while(p.at(Token::Word))p.eat();}
        if(p.at(Token::Semi)) p.eat();
    }
    p.expect(Token::RBrace);
    return srv;
}

std::shared_ptr<Config> parse_config(const std::string& path){
    std::ifstream f(path);
    if(!f) throw std::runtime_error("Cannot open config: "+path);
    std::string src((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());
    auto toks=tokenize(src);
    P p{std::move(toks),0};
    auto cfg=std::make_shared<Config>();
    while(!p.at(Token::Eof)){
        auto key=p.word();
        if(key=="worker_processes"){cfg->worker_processes=pi(p.word(),0);}
        else if(key=="worker_connections"){cfg->worker_connections=pi(p.word(),8192);}
        else if(key=="cache_size"){cfg->cache_size=pi(p.word(),4096);}
        else if(key=="cache_ttl"){cfg->cache_ttl=pi(p.word(),60);}
        else if(key=="log_level"){cfg->log_level=p.word();}
        else if(key=="pid_file"){cfg->pid_file=p.word();}
        else if(key=="admin_user"){cfg->admin_user=p.word();}
        else if(key=="admin_password"){cfg->admin_password=p.word();}
        else if(key=="admin_allow_ips"){while(p.at(Token::Word))cfg->admin_allow_ips.push_back(p.eat().val);}
        else if(key=="v8_heap_mb"){cfg->v8_heap_mb=pi(p.word(),64);}
        else if(key=="v8_timeout_ms"){cfg->v8_timeout_ms=pi(p.word(),50);}
        else if(key=="scripts_dir"){cfg->scripts_dir=p.word();}
        else if(key=="upstream"){
            UpstreamConfig up; up.name=p.word();
            p.expect(Token::LBrace);
            while(!p.at(Token::RBrace)&&!p.at(Token::Eof)){
                auto k=p.word();
                if(k=="server"){
                    UpstreamServer s; auto addr=p.word();
                    auto col=addr.rfind(':');
                    if(col!=std::string::npos){s.host=addr.substr(0,col);s.port=(uint16_t)pi(addr.substr(col+1),3000);}
                    else{s.host=addr;}
                    while(p.at(Token::Word)){
                        auto opt=p.eat().val;
                        auto eq=opt.find('=');
                        if(eq!=std::string::npos){
                            auto ok2=opt.substr(0,eq),ov=opt.substr(eq+1);
                            if(ok2=="weight") s.weight=pi(ov,1);
                            else if(ok2=="max_fails") s.max_fails=pi(ov,3);
                            else if(ok2=="fail_timeout") s.fail_timeout=pi(ov,30);
                        } else if(opt=="backup") s.backup=true;
                    }
                    up.servers.push_back(s);
                } else if(k=="keepalive"){up.keepalive=pi(p.word(),32);}
                  else if(k=="strategy"){
                    auto sv=p.word();
                    if(sv=="round_robin")   up.strategy=LBStrategy::RoundRobin;
                    else if(sv=="weighted") up.strategy=LBStrategy::WeightedRR;
                    else if(sv=="ip_hash")  up.strategy=LBStrategy::IPHash;
                    else                    up.strategy=LBStrategy::LeastConn;
                  }
                  else if(k=="sticky"){up.sticky_sessions=pb(p.word());}
                  else if(k=="health_check"){
                    up.hc_enabled=true;
                    while(p.at(Token::Word)){
                        auto tok=p.eat().val;
                        if(tok=="off"){up.hc_enabled=false;}
                        else if(tok[0]=='/') up.hc_path=tok;
                        else if(tok.substr(0,9)=="interval=") up.hc_interval=pi(tok.substr(9),5);
                        else if(tok.substr(0,7)=="expect=")  up.hc_expected_status=pi(tok.substr(7),200);
                    }
                  }
                  else{while(p.at(Token::Word))p.eat();}
                if(p.at(Token::Semi)) p.eat();
            }
            p.expect(Token::RBrace);
            cfg->upstreams.push_back(up);
            continue;
        }
        else if(key=="server"){cfg->servers.push_back(parse_server(p));continue;}
        // Feature flags
        else if(key=="module_cache")     {cfg->module_cache          =pb(p.word());}
        else if(key=="module_ratelimit") {cfg->module_ratelimit       =pb(p.word());}
        else if(key=="module_lua")       {cfg->module_lua             =pb(p.word());}
        else if(key=="module_js")        {cfg->module_js              =pb(p.word());}
        else if(key=="module_acme")      {cfg->module_acme            =pb(p.word());cfg->acme.enabled=cfg->module_acme;}
        else if(key=="module_gzip")      {cfg->module_gzip            =pb(p.word());}
        else if(key=="module_healthcheck"){cfg->module_lb_healthcheck =pb(p.word());}
        // ModSecurity WAF
        else if(key=="modsec_enabled")   {cfg->modsec_enabled  =pb(p.word());}
        else if(key=="modsec_block")     {cfg->modsec_block    =pb(p.word());}
        else if(key=="modsec_rules_dir") {cfg->modsec_rules_dir=p.word();}
        else if(key=="modsec_conf")      {cfg->modsec_conf     =p.word();}
        else if(key=="waf_regex_enabled")    {cfg->waf_regex_enabled    =pb(p.word());}
        else if(key=="waf_regex_block")      {cfg->waf_regex_block      =pb(p.word());}
        else if(key=="blacklist_file")      {cfg->blacklist_file=p.word();}
        else if(key=="waf_regex_check_body") {cfg->waf_regex_check_body =pb(p.word());}
        else if(key == "admin_tls_only") { cfg.admin_tls_only = (val == "true" || val == "1" || val == "yes"); }
        // ACME config block
        else if(key=="acme"){
            p.expect(Token::LBrace);
            while(!p.at(Token::RBrace)&&!p.at(Token::Eof)){
                auto k=p.word();
                if(k=="enabled")    {cfg->acme.enabled=pb(p.word());cfg->module_acme=cfg->acme.enabled;}
                else if(k=="email") {cfg->acme.email=p.word();}
                else if(k=="domain"||k=="domains"){while(p.at(Token::Word))cfg->acme.domains.push_back(p.eat().val);}
                else if(k=="cert_dir")    {cfg->acme.cert_dir=p.word();}
                else if(k=="staging")     {cfg->acme.staging=pb(p.word());}
                else if(k=="renew_days")  {cfg->acme.renew_days=pi(p.word(),30);}
                else if(k=="auto_renew")  {cfg->acme.auto_renew=pb(p.word());}
                else if(k=="challenge")   {cfg->acme.challenge_type=p.word();}
                else if(k=="dns_provider"){cfg->acme.dns_provider=p.word();}
                else if(k=="dns_cf_token"){cfg->acme.dns_cf_token=p.word();}
                else if(k=="dns_cf_zone") {cfg->acme.dns_cf_zone_id=p.word();}
                else if(k=="dns_exec")    {cfg->acme.dns_exec_path=p.word();}
                else{while(p.at(Token::Word))p.eat();}
                if(p.at(Token::Semi))p.eat();
            }
            p.expect(Token::RBrace); continue;
        }
        else{while(p.at(Token::Word))p.eat();}
        if(p.at(Token::Semi)) p.eat();
    }
    return cfg;
}

std::shared_ptr<Config> default_config(){
    static constexpr int DEFAULT_PORT         = 8080;
    static constexpr int DEFAULT_BACKEND_PORT = 3000;
    static constexpr int DEFAULT_WEIGHT       = 1;
    static constexpr int DEFAULT_MAX_FAILS    = 3;
    static constexpr int DEFAULT_FAIL_TIMEOUT = 30;

    auto cfg=std::make_shared<Config>();
    UpstreamConfig up; up.name="node_app";
    up.servers.push_back({"127.0.0.1", DEFAULT_BACKEND_PORT,
                          DEFAULT_WEIGHT, DEFAULT_MAX_FAILS, DEFAULT_FAIL_TIMEOUT});
    cfg->upstreams.push_back(up);
    ServerConfig srv; srv.listens.push_back({DEFAULT_PORT,false,false,false,true});
    LocationConfig loc; loc.prefix="/"; loc.type=LocationType::Proxy;
    loc.upstream="node_app"; loc.websocket=true;
    srv.locations.push_back(loc);
    cfg->servers.push_back(srv);
    return cfg;
}
