#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  acme.cc  —  ACME v2 / Let's Encrypt client (HTTP-01 challenge)
//  Implements: account creation, order, challenge, CSR, finalize, download
//  Requires: OpenSSL (already linked)
// ─────────────────────────────────────────────────────────────────────────────
#include "../../include/np_types.hh"
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/stat.h>
#include <atomic>
#include <thread>
#include <mutex>
#include <functional>
#include <map>

// ── Base64url (RFC 4648 §5, no padding) ──────────────────────────────────────
static std::string b64url(const unsigned char* d, size_t n){
    static const char* t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string o; o.reserve((n+2)/3*4);
    for(size_t i=0;i<n;i+=3){
        uint32_t v=(uint32_t)d[i]<<16|(i+1<n?(uint32_t)d[i+1]<<8:0)|(i+2<n?(uint32_t)d[i+2]:0);
        o+=t[(v>>18)&63];o+=t[(v>>12)&63];
        if(i+1<n)o+=t[(v>>6)&63];
        if(i+2<n)o+=t[v&63];
    }
    return o;
}
static std::string b64url_s(const std::string& s){return b64url((const unsigned char*)s.data(),s.size());}
static std::string b64url_bn(const BIGNUM* bn){
    std::vector<unsigned char> buf(BN_num_bytes(bn));
    BN_bn2bin(bn,buf.data());
    return b64url(buf.data(),buf.size());
}

// ── Minimal HTTPS client for ACME calls ──────────────────────────────────────
struct AcmeHttpResp { int status{0}; std::string body; std::map<std::string,std::string> headers; };

static AcmeHttpResp acme_http(const std::string& method, const std::string& url,
                               const std::string& body, const std::string& ct, SSL_CTX* ctx,
                               const std::string& extra_header=""){
    AcmeHttpResp res;
    std::string host, path="/"; int port=443;
    size_t start = url.find("://"); start = (start==std::string::npos)?0:start+3;
    auto slash = url.find('/',start);
    host = url.substr(start, slash==std::string::npos?std::string::npos:slash-start);
    if(slash!=std::string::npos) path=url.substr(slash);
    auto colon = host.rfind(':');
    if(colon!=std::string::npos){port=std::stoi(host.substr(colon+1));host=host.substr(0,colon);}

    struct addrinfo hints{},*ai=nullptr; hints.ai_socktype=SOCK_STREAM;
    char ps[8]; snprintf(ps,sizeof(ps),"%d",port);
    if(getaddrinfo(host.c_str(),ps,&hints,&ai)!=0) return res;
    int fd=socket(ai->ai_family,SOCK_STREAM,0);
    struct timeval tv{15,0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
    if(connect(fd,ai->ai_addr,ai->ai_addrlen)<0){freeaddrinfo(ai);close(fd);return res;}
    freeaddrinfo(ai);

    SSL* ssl=nullptr;
    if(ctx){
        ssl=SSL_new(ctx);
        SSL_set_tlsext_host_name(ssl,host.c_str());
        SSL_set_fd(ssl,fd);
        if(SSL_connect(ssl)!=1){SSL_free(ssl);close(fd);return res;}
    }

    std::string req=method+" "+path+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n";
    if(!extra_header.empty()) req+=extra_header+"\r\n";
    if(!body.empty()){
        if(!ct.empty()) req+="Content-Type: "+ct+"\r\n";
        req+="Content-Length: "+std::to_string(body.size())+"\r\n";
    }
    req+="\r\n"+body;

    const char* p=req.c_str(); size_t rem=req.size();
    while(rem>0){int r=ssl?SSL_write(ssl,p,rem):(int)send(fd,p,rem,0);if(r<=0)break;p+=r;rem-=r;}

    std::string raw; raw.reserve(16384);
    char buf[4096];
    while(true){
        int n=ssl?SSL_read(ssl,buf,sizeof(buf)):(int)recv(fd,buf,sizeof(buf),0);
        if(n<=0) break;
        raw.append(buf,n);
        if(raw.size()>1024*1024) break;
    }
    if(ssl){SSL_shutdown(ssl);SSL_free(ssl);}
    close(fd);

    if(raw.size()<12) return res;
    sscanf(raw.c_str(),"HTTP/%*s %d",&res.status);
    auto hend=raw.find("\r\n\r\n");
    if(hend==std::string::npos) return res;
    std::string hp=raw.substr(0,hend);
    size_t pos=hp.find("\r\n");
    while(pos!=std::string::npos){
        size_t nl=hp.find("\r\n",pos+2);
        std::string line=hp.substr(pos+2,nl==std::string::npos?std::string::npos:nl-pos-2);
        auto c2=line.find(':');
        if(c2!=std::string::npos){
            std::string k=line.substr(0,c2),v=line.substr(c2+1);
            while(!v.empty()&&v[0]==' ')v.erase(0,1);
            for(auto& ch:k)ch=(char)tolower((unsigned char)ch);
            res.headers[k]=v;
        }
        pos=nl;
    }
    res.body=raw.substr(hend+4);
    return res;
}

// ── JSON helpers (no external deps) ──────────────────────────────────────────
static std::string jstr(const std::string& j,const std::string& key){
    auto kq="\""+key+"\"";auto p=j.find(kq);if(p==std::string::npos)return"";
    auto c=j.find(':',p+kq.size());if(c==std::string::npos)return"";
    auto q1=j.find('"',c);if(q1==std::string::npos)return"";
    auto q2=j.find('"',q1+1);if(q2==std::string::npos)return"";
    return j.substr(q1+1,q2-q1-1);
}
static std::string jarr_first(const std::string& j,const std::string& key){
    auto kq="\""+key+"\"";auto p=j.find(kq);if(p==std::string::npos)return"";
    auto b=j.find('[',p);if(b==std::string::npos)return"";
    auto q=j.find('"',b);if(q==std::string::npos)return"";
    auto q2=j.find('"',q+1);if(q2==std::string::npos)return"";
    return j.substr(q+1,q2-q-1);
}
static std::vector<std::string> jarr_all(const std::string& j,const std::string& key){
    std::vector<std::string> out;
    auto kq="\""+key+"\"";auto p=j.find(kq);if(p==std::string::npos)return out;
    auto b=j.find('[',p);if(b==std::string::npos)return out;
    auto e=j.find(']',b);if(e==std::string::npos)return out;
    size_t pos=b;
    while(pos<e){
        auto q=j.find('"',pos);if(q==std::string::npos||q>e)break;
        auto q2=j.find('"',q+1);if(q2==std::string::npos||q2>e)break;
        out.push_back(j.substr(q+1,q2-q-1));
        pos=q2+1;
    }
    return out;
}

// ── ACME Client ───────────────────────────────────────────────────────────────
class AcmeClient {
public:
    static constexpr const char* LE_PROD    = "https://acme-v02.api.letsencrypt.org/directory";
    static constexpr const char* LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory";

    struct Config {
        std::string directory_url{LE_STAGING};
        std::string email;
        std::string cert_dir{"/etc/nas-web"};
        std::vector<std::string> domains;
        int  renew_days_before{30};
        bool auto_renew{true};
        bool enabled{false};
        bool staging{true};
        // DNS-01 challenge support
        std::string challenge_type{"http-01"};  // "http-01" or "dns-01"
        std::string dns_provider;               // "cloudflare", "exec"
        std::string dns_cf_token;               // Cloudflare API token
        std::string dns_cf_zone_id;             // Cloudflare Zone ID (or auto-detect)
        std::string dns_exec_path;              // script for add/remove TXT records
    };

    explicit AcmeClient(const Config& cfg):cfg_(cfg){
        ssl_ctx_=SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_default_verify_paths(ssl_ctx_);
    }
    ~AcmeClient(){
        running_=false;
        if(renew_thread_.joinable())renew_thread_.join();
        if(acct_key_)EVP_PKEY_free(acct_key_);
        if(ssl_ctx_)SSL_CTX_free(ssl_ctx_);
    }

    void set_challenge_handler(
        std::function<void(const std::string&,const std::string&)> add,
        std::function<void(const std::string&)> remove){
        on_add_=add; on_rm_=remove;
    }
    void set_cert_ready(std::function<void(const std::string&,const std::string&)> cb){
        on_ready_=cb;
    }

    void start(){
        if(cfg_.auto_renew && cfg_.enabled){
            running_=true;
            renew_thread_=std::thread(&AcmeClient::renew_loop,this);
        }
    }

    // ── DNS-01 helpers ───────────────────────────────────────────────────────

    // Extract base domain for _acme-challenge TXT record
    // e.g. "sub.example.com" → "_acme-challenge.sub.example.com"
    static std::string dns_record_name(const std::string& domain){
        return "_acme-challenge." + domain;
    }

    // Cloudflare: add TXT record, returns record_id or "" on error
    std::string cf_add_txt(const std::string& domain, const std::string& value){
        // First find zone_id if not configured
        std::string zone_id = cfg_.dns_cf_zone_id;
        if(zone_id.empty()){
            // Extract root domain (last two parts)
            auto parts = domain; size_t dots=0;
            for(char c:domain) if(c=='.') dots++;
            std::string root = domain;
            if(dots >= 2){
                auto p1=domain.rfind('.'); auto p2=domain.rfind('.',p1-1);
                root = domain.substr(p2+1);
            }
            std::string auth = "Bearer " + cfg_.dns_cf_token;
            auto r = acme_http("GET","https://api.cloudflare.com/client/v4/zones?name="+root,
                               "","",ssl_ctx_, "Authorization: "+auth);
            if(r.status!=200){ NW_ERROR("acme","CF zones lookup failed: %d",r.status); return ""; }
            zone_id = jstr(r.body,"id");
            if(zone_id.empty()){ NW_ERROR("acme","CF zone not found for: %s",root.c_str()); return ""; }
        }
        std::string auth = "Bearer " + cfg_.dns_cf_token;
        std::string payload = std::string("{\"type\":\"TXT\",\"name\":\"") + dns_record_name(domain)
                            + std::string("\",\"content\":\"") + value + std::string("\",\"ttl\":60}");
        auto r = acme_http("POST",
            "https://api.cloudflare.com/client/v4/zones/"+zone_id+"/dns_records",
            payload, "application/json", ssl_ctx_, "Authorization: "+auth);
        if(r.status!=200&&r.status!=201){
            NW_ERROR("acme","CF add TXT failed: %d %s",r.status,r.body.substr(0,200).c_str());
            return "";
        }
        auto rid = jstr(r.body,"id");
        NW_INFO("acme","CF TXT added: %s = %s (record_id=%s)",
                dns_record_name(domain).c_str(), value.c_str(), rid.c_str());
        return rid;
    }

    void cf_del_txt(const std::string& domain, const std::string& record_id){
        if(record_id.empty()) return;
        std::string zone_id = cfg_.dns_cf_zone_id;
        if(zone_id.empty()) return; // already cleaned up above
        std::string auth = "Bearer " + cfg_.dns_cf_token;
        auto r = acme_http("DELETE",
            "https://api.cloudflare.com/client/v4/zones/"+zone_id+"/dns_records/"+record_id,
            "","",ssl_ctx_, "Authorization: Bearer "+cfg_.dns_cf_token);
        NW_INFO("acme","CF TXT deleted: record_id=%s HTTP=%d",record_id.c_str(),r.status);
    }

    // exec provider: calls script with args: add|remove domain value
    std::string exec_dns(const std::string& op, const std::string& domain,
                         const std::string& value=""){
        if(cfg_.dns_exec_path.empty()) return "dns_exec not configured";
        std::string cmd = cfg_.dns_exec_path+" "+op+" "+domain+" \""+value+"\" 2>&1";
        NW_INFO("acme","DNS exec: %s",cmd.c_str());
        FILE* p = popen(cmd.c_str(),"r");
        if(!p) return "popen failed";
        char buf[512]=""; size_t nr=fread(buf,1,511,p); buf[nr]='\0';
        int rc = pclose(p);
        if(rc!=0) return std::string("DNS exec failed (rc=")+std::to_string(rc)+"): "+buf;
        return "";
    }

    // Returns "" on success, error string on failure
    std::string obtain_cert(){
        if(cfg_.domains.empty()) return "No domains configured";
        NW_INFO("acme","=== Starting ACME for: %s ===",cfg_.domains[0].c_str());
        set_progress("Pobieranie directory ACME...", 5);

        // ── Step 1: Directory ────────────────────────────────────────────────
        auto dir=acme_http("GET",cfg_.directory_url,"","",ssl_ctx_);
        if(dir.status!=200) return "Directory fetch failed: "+std::to_string(dir.status);
        std::string nn_url=jstr(dir.body,"newNonce");
        nn_url_=nn_url;  // save for badNonce retry in post_jws
        std::string na_url=jstr(dir.body,"newAccount");
        std::string no_url=jstr(dir.body,"newOrder");
        if(nn_url.empty()||na_url.empty()||no_url.empty())
            return "Directory missing URLs: "+dir.body.substr(0,200);

        // ── Step 2: Account key + nonce ──────────────────────────────────────
        set_progress("Generowanie / ładowanie klucza konta...", 10);
        if(!acct_key_) acct_key_=load_or_gen(cfg_.cert_dir+"/acme_account.key");
        if(!acct_key_) return "Cannot generate account key";

        std::string nonce=fresh_nonce(nn_url);
        if(nonce.empty()) return "Cannot get nonce";

        // ── Step 3: Register / find account ─────────────────────────────────
        set_progress("Rejestracja konta ACME...", 15);
        std::string kid;
        {
            std::string pl=
                "{\"termsOfServiceAgreed\":true,"
                "\"contact\":[\"mailto:"+cfg_.email+"\"]}";
            auto r=post_jws(make_jwk(),"",nonce,na_url,pl);
            nonce=r.headers["replay-nonce"]; kid=r.headers["location"];
            if(r.status!=200&&r.status!=201)
                return "Account failed: "+std::to_string(r.status)+" "+r.body.substr(0,300);
            NW_INFO("acme","Account KID: %s",kid.c_str());
            set_progress("Konto ACME gotowe", 20);
        }

        // ── Step 4: New order ────────────────────────────────────────────────
        set_progress("Tworzenie order ACME...", 25);
        std::string order_url,finalize_url,auth_url;
        {
            std::string ids="[";
            for(size_t i=0;i<cfg_.domains.size();i++){
                if(i)ids+=",";
                ids+="{\"type\":\"dns\",\"value\":\""+cfg_.domains[i]+"\"}";
            }
            ids+="]";
            auto r=post_jws("",kid,nonce,no_url,"{\"identifiers\":"+ids+"}");
            nonce=r.headers["replay-nonce"];
            order_url=r.headers["location"];
            finalize_url=jstr(r.body,"finalize");
            auth_url=jarr_first(r.body,"authorizations"); // first authz (main loop uses this)
            { auto all=jarr_all(r.body,"authorizations");
              NW_INFO("acme","Order has %zu authz(s)",(size_t)all.size()); }
            if(r.status!=201&&r.status!=200)
                return "Order failed: "+std::to_string(r.status)+" "+r.body.substr(0,300);
            NW_INFO("acme","Order: %s  finalize: %s",order_url.c_str(),finalize_url.c_str());
            NW_INFO("acme","Order authz URL: %s", auth_url.c_str());
            NW_INFO("acme","Full order body: %s", r.body.substr(0,500).c_str());
            // Check if order is already ready/valid (cached auth)
            auto order_status_init = jstr(r.body, "status");
            NW_INFO("acme","Order initial status: %s", order_status_init.c_str());
            if(order_status_init == "ready" || order_status_init == "valid"){
                // Skip challenge — go straight to finalize
                set_progress("Order gotowy od razu (cached auth) — finalizacja...", 80);
                NW_INFO("acme","Order already ready — skipping challenge phase");
                // Set auth_url empty so challenge step is skipped
                auth_url = "__order_ready__";
            } else {
                set_progress("Order stworzony, pobieranie challenge...", 30);
            }
        }

        // ── Step 5: Authorization + challenge for ALL authz in order ───────────
        // Order may have multiple authz (e.g. nasserver.pl + www.nasserver.pl)
        // ALL must be valid before order transitions pending→ready
        std::string ch_url, token;
        bool use_dns01 = (cfg_.challenge_type == "dns-01");
        bool auth_valid = false;

        // Collect ALL authz URLs from order (we stored body above)
        // Re-fetch order to get authz list (or use cached order body)
        std::vector<std::string> all_authz_urls;
        {
            auto ro=post_jws("",kid,nonce,order_url,"");
            nonce=ro.headers["replay-nonce"];
            all_authz_urls=jarr_all(ro.body,"authorizations");
            if(all_authz_urls.empty() && !auth_url.empty())
                all_authz_urls.push_back(auth_url);
            NW_INFO("acme","Processing %zu authz(s)",(size_t)all_authz_urls.size());
        }

        if(auth_url == "__order_ready__"){
            token = "__already_valid__";
            auth_valid = true;
            NW_INFO("acme","Skipping challenge — order was ready on creation");
        } else {
        set_progress("Pobieranie danych autoryzacji...", 35);
        // Process each authz — serve token and trigger challenge for each pending one
        for(size_t authz_idx=0; authz_idx<all_authz_urls.size() && running_; authz_idx++){
            const std::string& cur_auth_url = all_authz_urls[authz_idx];
            NW_INFO("acme","Authz [%zu/%zu]: %s",authz_idx+1,all_authz_urls.size(),cur_auth_url.c_str());
        {
            auto r=post_jws("",kid,nonce,cur_auth_url,"");  // POST-as-GET
            nonce=r.headers["replay-nonce"];
            if(r.status!=200&&r.status!=201)
                return "Auth fetch failed: "+std::to_string(r.status)+" "+r.body.substr(0,200);

            // Check cached auth status FIRST — LE caches auths 30 days
            auto auth_status = jstr(r.body, "status");
            NW_INFO("acme","Auth status on fetch: %s (challenge: %s)",
                    auth_status.c_str(), cfg_.challenge_type.c_str());

            if(auth_status == "valid"){
                // Auth shows valid (cached from previous order) but the NEW order's
                // authz is still pending internally. We must do the full challenge flow
                // (serve token + POST challenge) so LE verifies and transitions order→ready.
                NW_INFO("acme","Auth cached-valid — doing full challenge flow for new order authz");
                // auth_valid stays FALSE — we go through normal HTTP-01 path
                // Extract ch_url for challenge POST
                auto& body2 = r.body;
                std::string find_type2 = use_dns01 ? "dns-01" : "http-01";
                size_t p2=0;
                while(true){
                    p2=body2.find(find_type2,p2);
                    if(p2==std::string::npos) break;
                    size_t tb2=body2.rfind('{',p2);
                    if(tb2==std::string::npos){p2++;continue;}
                    size_t depth2=0,te2=tb2;
                    for(size_t j2=tb2;j2<body2.size();j2++){
                        if(body2[j2]=='{')depth2++;
                        else if(body2[j2]=='}'){if(--depth2==0){te2=j2;break;}}
                    }
                    if(te2>tb2){
                        auto chunk2=body2.substr(tb2,te2-tb2+1);
                        auto cu2=jstr(chunk2,"url");
                        auto to2=jstr(chunk2,"token");
                        if(!cu2.empty()){ ch_url=cu2; }
                        if(!to2.empty()){ token=to2; }
                        if(!cu2.empty()&&!to2.empty()) break;
                    }
                    p2++;
                }
                NW_INFO("acme","ch_url=%s token=%s",
                    ch_url.empty()?"(not found)":ch_url.c_str(),
                    token.empty()?"(not found)":token.substr(0,16).c_str());
            } else if(auth_status == "invalid" || auth_status == "revoked"){
                std::string why;
                auto ep=r.body.find("\"error\"");
                if(ep!=std::string::npos){
                    auto eb=r.body.find('{',ep),ee=r.body.find('}',ep);
                    if(eb!=std::string::npos&&ee!=std::string::npos) why=r.body.substr(eb,ee-eb+1);
                }
                return "Auth "+auth_status+" (LE cached 30-day auth). Sprawdz:\n"
                       "1. Port 80 otwarty na zewnatrz (lub uzyj dns-01 dla wildcard)\n"
                       "2. DNS wskazuje na ten serwer\n"
                       "3. Sprobuj za godzine (rate limit LE: 5 fail/h)\n"
                       "Szczegol: "+why.substr(0,300);
            } else {
                // Find challenge object matching our type
                auto& body = r.body;
                std::string find_type = use_dns01 ? "dns-01" : "http-01";
                size_t p=0;
                while(true){
                    p=body.find(find_type,p);
                    if(p==std::string::npos) break;
                    size_t tb=body.rfind('{',p);
                    if(tb==std::string::npos){p++;continue;}
                    size_t depth=0,te=tb;
                    for(size_t j=tb;j<body.size();j++){
                        if(body[j]=='{')depth++;
                        else if(body[j]=='}'){if(--depth==0){te=j;break;}}
                    }
                    if(te>tb){
                        auto chunk=body.substr(tb,te-tb+1);
                        auto cu=jstr(chunk,"url"),to=jstr(chunk,"token");
                        if(!cu.empty()&&!to.empty()){ ch_url=cu; token=to; break; }
                    }
                    p++;
                }
                if(token.empty())
                    return "No "+find_type+" challenge found in auth response: "+r.body.substr(0,400);
                NW_INFO("acme","Challenge: type=%s token=%s url=%s",
                        find_type.c_str(), token.c_str(), ch_url.c_str());
            }
        }

        // ── Step 6+7+8: Challenge — HTTP-01 or DNS-01 ─────────────────────────
        // auth_valid already set above
        std::string dns_record_id; // for cleanup after DNS-01

        if(!auth_valid){
            std::string key_auth = token + "." + thumbprint();

            if(use_dns01){
                // DNS-01: create _acme-challenge.<domain> TXT record = base64url(sha256(key_auth))
                unsigned char digest[32];
                SHA256((const unsigned char*)key_auth.data(), key_auth.size(), digest);
                std::string txt_value = b64url(digest, 32);
                set_progress("DNS-01: tworzenie rekordu TXT _acme-challenge...", 42);
                NW_INFO("acme","DNS-01 TXT value: %s", txt_value.c_str());

                if(cfg_.dns_provider == "cloudflare"){
                    dns_record_id = cf_add_txt(cfg_.domains[0], txt_value);
                    if(dns_record_id.empty())
                        return "DNS-01: Cloudflare TXT record creation failed";
                } else if(cfg_.dns_provider == "exec"){
                    auto err = exec_dns("add", cfg_.domains[0], txt_value);
                    if(!err.empty()) return "DNS-01 exec add failed: "+err;
                    dns_record_id = "__exec__";
                } else {
                    return "DNS-01: dns_provider not configured (use 'cloudflare' or 'exec')";
                }

                // Wait for DNS propagation (60s min recommended by LE)
                set_progress("DNS-01: czekam na propagację DNS (60s)...", 50);
                NW_INFO("acme","DNS-01: waiting 65s for propagation...");
                for(int i=0; i<65 && running_; i++){
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    if(i%10==9) set_progress("DNS propagacja: "+std::to_string(i+1)+"s / 65s", 50+i/13);
                }
            } else {
                // HTTP-01: serve token file
                if(on_add_) on_add_(token, key_auth);
                set_progress("HTTP-01: challenge gotowy — czekam na weryfikację LE...", 40);
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }

            // Respond to challenge (trigger LE verification)
            {
                auto r=post_jws("",kid,nonce,ch_url,"{}");
                nonce=r.headers["replay-nonce"];
                NW_INFO("acme","Challenge triggered: HTTP %d",r.status);
            }
        } else {
            // Auth is cached-valid but order is pending.
            // POST to challenge URL to trigger pending→ready transition.
            if(!ch_url.empty()){
                set_progress("Auth ważna — aktywacja order (POST challenge)...", 68);
                auto r2=post_jws("",kid,nonce,ch_url,"{}");
                nonce=r2.headers["replay-nonce"];
                NW_INFO("acme","Challenge POST for cached auth: HTTP %d body=%s",
                    r2.status, r2.body.substr(0,80).c_str());
                // Poll authz until valid (should be near-instant for cached auth)
                for(int i=0;i<10&&running_;i++){
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                    auto ra=post_jws("",kid,nonce,auth_url,"");
                    nonce=ra.headers["replay-nonce"];
                    auto ast=jstr(ra.body,"status");
                    NW_INFO("acme","Auth poll [%d/10]: status=%s",i+1,ast.c_str());
                    set_progress("Auth poll ["+std::to_string(i+1)+"/10]: "+ast, 70+i);
                    if(ast=="valid"){ auth_valid=true; break; }
                    if(ast=="invalid"||ast=="revoked")
                        return "Auth "+ast+" after POST: "+ra.body.substr(0,200);
                }
            } else {
                set_progress("Auth ważna (cache LE) — czekam na order ready...", 72);
                NW_INFO("acme","ch_url empty for cached auth — relying on LE auto-transition");
                auth_valid = true;
            }
        }

        // ── Step 8: Poll this authz until valid ──────────────────────────────
        bool this_authz_valid = false;
        for(int i=0;i<30&&!this_authz_valid&&running_;i++){
            std::this_thread::sleep_for(std::chrono::seconds(3));
            auto r=post_jws("",kid,nonce,cur_auth_url,"");  // POST-as-GET
            nonce=r.headers["replay-nonce"];
            auto st=jstr(r.body,"status");
            set_progress("Authz "+std::to_string(authz_idx+1)+"/"+std::to_string(all_authz_urls.size())
                +" ["+std::to_string(i+1)+"/30]: "+st, 55+i);
            NW_INFO("acme","Authz %zu poll [%d/30]: %s",authz_idx+1,i+1,st.c_str());
            if(st=="valid"){ this_authz_valid=true; }
            else if(st=="invalid"||st=="revoked"){
                if(!use_dns01 && on_rm_) on_rm_(token);
                if(use_dns01){
                    if(cfg_.dns_provider=="cloudflare") cf_del_txt(cfg_.domains[0], dns_record_id);
                    else if(cfg_.dns_provider=="exec") exec_dns("remove",cfg_.domains[0]);
                }
                return "Challenge "+st+": "+r.body.substr(0,400);
            }
        }
        // Cleanup token for this authz
        if(!use_dns01 && on_rm_) on_rm_(token);
        if(use_dns01){
            if(cfg_.dns_provider=="cloudflare" && !dns_record_id.empty())
                cf_del_txt(cfg_.domains[0], dns_record_id);
            else if(cfg_.dns_provider=="exec" && !dns_record_id.empty())
                exec_dns("remove", cfg_.domains[0]);
        }
        if(!this_authz_valid){
            return "Authz "+std::to_string(authz_idx+1)+" timed out";
        }
        // Reset per-authz state for next authz
        ch_url=""; token=""; dns_record_id="";
        } // end authz body block
        } // end authz loop

        auth_valid = true; // all authz processed successfully

        // ── Step 9: Poll order until ready ───────────────────────────────────
        // RFC 8555 §7.4 — order MUST be "ready" before finalize.
        // When auth is already cached-valid, LE still needs a moment to flip
        // order pending→ready. Give it a head start before polling.
        if(auth_valid && token == "__already_valid__"){
            NW_INFO("acme","Auth was cached-valid — waiting 5s for order to become ready...");
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
        if(!order_url.empty() && !finalize_url.empty()){
            // Poll order for ready status, but don't wait forever.
            // acme.sh approach: if authz is valid, attempt finalize regardless of order status.
            bool order_ready = false;
            for(int i=0;i<6&&running_;i++){
                auto r=post_jws("",kid,nonce,order_url,"");
                nonce=r.headers["replay-nonce"];
                auto st=jstr(r.body,"status");
                NW_INFO("acme","Order poll [%d/6]: status=%s",i+1,st.c_str());
                set_progress("Order poll ["+std::to_string(i+1)+"/6]: "+st, 74+i*2);
                if(st=="ready"||st=="valid"){ order_ready=true; break; }
                if(st=="invalid") return "Order invalid: "+r.body.substr(0,200);
                std::this_thread::sleep_for(std::chrono::seconds(3));
            }
            if(!order_ready){
                // authz is valid but order didn't flip to ready — proceed anyway
                // LE sometimes accepts finalize when authz valid even if order shows pending
                NW_INFO("acme","Order not ready after poll — proceeding to finalize (authz is valid)");
                set_progress("Próba finalizacji mimo order=pending (authz valid)...", 82);
            }
        }

        // ── Step 10: Generate domain key + CSR ───────────────────────────────
        set_progress("Generowanie klucza domeny i CSR...", 83);
        auto* dk=gen_rsa(2048); if(!dk) return "Domain key gen failed";
        save_key(dk,cfg_.cert_dir+"/privkey.pem");
        auto csr_der=make_csr(dk,cfg_.domains);
        EVP_PKEY_free(dk);
        if(csr_der.empty()) return "CSR generation failed";
        NW_INFO("acme","CSR ready (%zu bytes DER)",csr_der.size());

        // ── Step 11: Finalize (retry on orderNotReady) ───────────────────────
        set_progress("Finalizacja — wysyłam CSR...", 88);
        std::string cert_url;
        {
            std::string csr_b64=b64url((const unsigned char*)csr_der.data(),csr_der.size());
            std::string fpayload="{\"csr\":\""+csr_b64+"\"}";
            AcmeHttpResp r;
            bool finalized=false;
            for(int fi=0; fi<15 && running_; fi++){
                r=post_jws("",kid,nonce,finalize_url,fpayload);
                nonce=r.headers["replay-nonce"];
                NW_INFO("acme","Finalize attempt %d: HTTP %d",fi+1,r.status);
                if(r.status==200||r.status==201){ finalized=true; break; }
                if(r.body.find("orderNotReady")!=std::string::npos){
                    set_progress("Order not ready — retry "+std::to_string(fi+1)+"/15...", 88);
                    NW_INFO("acme","orderNotReady — waiting 5s");
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    continue;
                }
                return "Finalize failed: "+std::to_string(r.status)+" "+r.body.substr(0,400);
            }
            if(!finalized)
                return "Finalize failed after retries: "+r.body.substr(0,200);

            // ── Step 12: Poll order for cert URL ─────────────────────────────
            for(int i=0;i<20&&cert_url.empty()&&running_;i++){
                cert_url=jstr(r.body,"certificate");
                if(!cert_url.empty()) break;
                auto st=jstr(r.body,"status");
                set_progress("Czekam na certyfikat: "+st+" ["+std::to_string(i+1)+"/20]", 90+i/2);
                NW_INFO("acme","Waiting cert URL, order status=%s [%d/20]",st.c_str(),i+1);
                if(st=="invalid") return "Order invalidated: "+r.body.substr(0,200);
                std::this_thread::sleep_for(std::chrono::seconds(3));
                if(order_url.empty()) break;
                r=post_jws("",kid,nonce,order_url,"");  // POST-as-GET
                nonce=r.headers["replay-nonce"];
            }
            if(cert_url.empty()) return "No certificate URL after finalize";
        }

        // ── Step 13: Download certificate ────────────────────────────────────
        set_progress("Pobieranie certyfikatu...", 97);
        {
            auto r=post_jws("",kid,nonce,cert_url,"");  // POST-as-GET
            if(r.status!=200) return "Cert download: HTTP "+std::to_string(r.status)+" "+r.body.substr(0,200);
            if(r.body.find("-----BEGIN CERTIFICATE-----")==std::string::npos)
                return "Response is not PEM: "+r.body.substr(0,200);
            // Save fullchain.pem
            std::string cp=cfg_.cert_dir+"/fullchain.pem";
            FILE* f=fopen(cp.c_str(),"w");
            if(!f) return "Cannot write "+cp+": "+strerror(errno);
            fwrite(r.body.c_str(),1,r.body.size(),f); fclose(f);
            chmod(cp.c_str(),0644);
            NW_INFO("acme","=== Certificate saved: %s (%zu bytes) ===",cp.c_str(),r.body.size());
            set_progress("Certyfikat zapisany!", 100);
            if(on_ready_) on_ready_(cp,cfg_.cert_dir+"/privkey.pem");
        }
        return "";
    }

    bool needs_renewal() const {
        FILE* f=fopen((cfg_.cert_dir+"/fullchain.pem").c_str(),"r");
        if(!f) return true;
        X509* x=PEM_read_X509(f,nullptr,nullptr,nullptr); fclose(f);
        if(!x) return true;
        auto* nb=X509_get0_notAfter(x);
        int y,mo,d,h,mi,s;
        sscanf((const char*)nb->data,"%2d%2d%2d%2d%2d%2dZ",&y,&mo,&d,&h,&mi,&s);
        struct tm t{}; t.tm_year=(y<70?y+100:y);t.tm_mon=mo-1;t.tm_mday=d;
        t.tm_hour=h;t.tm_min=mi;t.tm_sec=s;
        time_t exp=timegm(&t); X509_free(x);
        int days=(int)((exp-time(nullptr))/86400);
        NW_INFO("acme","Cert expires in %d days",days);
        return days<cfg_.renew_days_before;
    }

    const Config& config() const { return cfg_; }

private:
    Config cfg_;
    SSL_CTX* ssl_ctx_{nullptr};
    std::string nn_url_;   // newNonce URL — for badNonce retry
    EVP_PKEY* acct_key_{nullptr};
    std::thread renew_thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> obtaining_{false};   // prevent concurrent obtain_cert() calls
    std::mutex obtain_mu_;                  // serialize manual + auto renew
    std::function<void(const std::string&,const std::string&)> on_add_,on_ready_;
    std::function<void(const std::string&)> on_rm_;
    // Progress reporting — updated during obtain_cert(), read by /np_acme GET
    mutable std::mutex progress_mu_;
    std::string progress_step_;   // current step name
    int progress_pct_{0};         // 0-100
    std::string last_error_;
    std::string last_ok_time_;
public:
    struct Progress { std::string step; int pct; std::string last_error; std::string last_ok; bool running; };
    Progress get_progress() const {
        std::lock_guard lk(progress_mu_);
        return {progress_step_, progress_pct_, last_error_, last_ok_time_, obtaining_.load()};
    }
private:
    void set_progress(const std::string& step, int pct){
        std::lock_guard lk(progress_mu_);
        progress_step_=step; progress_pct_=pct;
        NW_INFO("acme","[%d%%] %s",pct,step.c_str());
    }

    void renew_loop(){
        // Wait 5min before first check so server is fully started
        for(int i=0;i<300&&running_;i++)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        while(running_){
            if(needs_renewal()){
                NW_INFO("acme","Auto-renew triggered");
                auto err=safe_obtain();
                if(!err.empty()) NW_ERROR("acme","Renewal failed: %s",err.c_str());
                else NW_INFO("acme","Auto-renewed OK");
            }
            // Check every 12h
            for(int i=0;i<43200&&running_;i++)
                std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

public:
    // Thread-safe wrapper — prevents concurrent obtain calls
    std::string safe_obtain(){
        if(obtaining_.exchange(true)){
            NW_WARN("acme","obtain_cert already in progress, skipping");
            return "Already in progress";
        }
        std::string err;
        try { err=obtain_cert(); } catch(...){ err="Exception in obtain_cert"; }
        {
            std::lock_guard lk(progress_mu_);
            if(err.empty()){ last_ok_time_=[](){
                time_t t=time(nullptr); char buf[32]; strftime(buf,sizeof(buf),"%Y-%m-%d %H:%M:%S",localtime(&t)); return std::string(buf);
            }(); last_error_=""; }
            else { last_error_=err; }
        }
        obtaining_.store(false);
        return err;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    // Fetch a fresh nonce (HEAD first, then GET)
    std::string fresh_nonce(const std::string& nn_url){
        auto r=acme_http("HEAD",nn_url,"","",ssl_ctx_);
        if(!r.headers["replay-nonce"].empty()) return r.headers["replay-nonce"];
        auto r2=acme_http("GET",nn_url,"","",ssl_ctx_);
        return r2.headers["replay-nonce"];
    }

    // Sign + POST in one call, updates nonce automatically
    // Retries once on badNonce (LE returns fresh nonce in error response)
    AcmeHttpResp post_jws(const std::string& jwk,const std::string& kid,
                          std::string& nonce, const std::string& url,
                          const std::string& payload){
        for(int attempt=0; attempt<3; attempt++){
            auto jws=sign_jws(jwk,kid,nonce,url,payload);
            auto r=acme_http("POST",url,jws,"application/jose+json",ssl_ctx_);
            // Always update nonce from response (even on error LE sends new nonce)
            if(!r.headers["replay-nonce"].empty()) nonce=r.headers["replay-nonce"];
            // Retry on badNonce — use the fresh nonce LE just gave us
            if(r.status==400 && r.body.find("badNonce")!=std::string::npos){
                NW_INFO("acme","badNonce on attempt %d — retrying with fresh nonce",attempt+1);
                if(nonce.empty() && !nn_url_.empty())
                    nonce=fresh_nonce(nn_url_);
                continue;
            }
            return r;
        }
        // Fallback after 3 attempts
        auto jws=sign_jws(jwk,kid,nonce,url,payload);
        auto r=acme_http("POST",url,jws,"application/jose+json",ssl_ctx_);
        if(!r.headers["replay-nonce"].empty()) nonce=r.headers["replay-nonce"];
        return r;
    }

    static EVP_PKEY* gen_rsa(int bits){
        auto* ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,nullptr);
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx,bits);
        EVP_PKEY* k=nullptr; EVP_PKEY_keygen(ctx,&k);
        EVP_PKEY_CTX_free(ctx); return k;
    }
    static void save_key(EVP_PKEY* k,const std::string& p){
        FILE* f=fopen(p.c_str(),"w");if(!f)return;
        PEM_write_PrivateKey(f,k,nullptr,nullptr,0,nullptr,nullptr);
        fclose(f); chmod(p.c_str(),0600);
    }
    static EVP_PKEY* load_or_gen(const std::string& p){
        FILE* f=fopen(p.c_str(),"r");
        if(f){auto* k=PEM_read_PrivateKey(f,nullptr,nullptr,nullptr);fclose(f);if(k)return k;}
        auto* k=gen_rsa(2048); if(k)save_key(k,p); return k;
    }

    std::string make_jwk(){
        // OpenSSL 3.0 API — extract RSA n/e directly from EVP_PKEY
        BIGNUM *n=nullptr, *e=nullptr;
        EVP_PKEY_get_bn_param(acct_key_, "n", &n);
        EVP_PKEY_get_bn_param(acct_key_, "e", &e);
        auto j="{\"e\":\""+b64url_bn(e)+"\",\"kty\":\"RSA\",\"n\":\""+b64url_bn(n)+"\"}";
        BN_free(n); BN_free(e);
        return j;
    }
    std::string thumbprint(){
        auto jwk=make_jwk();
        unsigned char h[SHA256_DIGEST_LENGTH];
        SHA256((const unsigned char*)jwk.data(),jwk.size(),h);
        return b64url(h,SHA256_DIGEST_LENGTH);
    }

    std::string sign_jws(const std::string& jwk,const std::string& kid,
                         const std::string& nonce,const std::string& url,
                         const std::string& payload){
        std::string hdr;
        if(!kid.empty()) hdr="{\"alg\":\"RS256\",\"kid\":\""+kid+"\",\"nonce\":\""+nonce+"\",\"url\":\""+url+"\"}";
        else             hdr="{\"alg\":\"RS256\",\"jwk\":"+jwk+",\"nonce\":\""+nonce+"\",\"url\":\""+url+"\"}";
        auto hp=b64url_s(hdr), pp=payload.empty()?"":b64url_s(payload);
        std::string si=hp+"."+pp;
        auto* mdctx=EVP_MD_CTX_new();
        EVP_DigestSignInit(mdctx,nullptr,EVP_sha256(),nullptr,acct_key_);
        EVP_DigestSignUpdate(mdctx,si.data(),si.size());
        size_t sl=0; EVP_DigestSignFinal(mdctx,nullptr,&sl);
        std::vector<unsigned char> sig(sl);
        EVP_DigestSignFinal(mdctx,sig.data(),&sl);
        EVP_MD_CTX_free(mdctx);
        return "{\"protected\":\""+hp+"\",\"payload\":\""+pp+"\",\"signature\":\""+b64url(sig.data(),sl)+"\"}";
    }

    static std::string make_csr(EVP_PKEY* key,const std::vector<std::string>& domains){
        auto* req=X509_REQ_new(); X509_REQ_set_version(req,0);
        X509_REQ_set_pubkey(req,key);
        auto* name=X509_REQ_get_subject_name(req);
        if(!domains.empty())
            X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(const unsigned char*)domains[0].c_str(),-1,-1,0);
        if(!domains.empty()){
            auto* exts=sk_X509_EXTENSION_new_null();
            std::string san; for(size_t i=0;i<domains.size();i++){if(i)san+=",";san+="DNS:"+domains[i];}
            auto* ext=X509V3_EXT_conf_nid(nullptr,nullptr,NID_subject_alt_name,san.c_str());
            if(ext){sk_X509_EXTENSION_push(exts,ext);X509_REQ_add_extensions(req,exts);sk_X509_EXTENSION_pop_free(exts,X509_EXTENSION_free);}
        }
        X509_REQ_sign(req,key,EVP_sha256());
        int len=i2d_X509_REQ(req,nullptr);
        std::string der(len,'\0'); auto* p=(unsigned char*)der.data();
        i2d_X509_REQ(req,&p); X509_REQ_free(req);
        return der;
    }
};

// ── Globals ───────────────────────────────────────────────────────────────────
static std::unique_ptr<AcmeClient>       g_acme;
static std::mutex                         g_acme_mu;
static std::map<std::string,std::string>  g_acme_tokens; // token → key_auth

static void acme_init(const AcmeClient::Config& cfg,
                      std::function<void(const std::string&,const std::string&)> on_ready){
    g_acme=std::make_unique<AcmeClient>(cfg);
    g_acme->set_challenge_handler(
        [](const std::string& t,const std::string& ka){
            std::lock_guard lk(g_acme_mu); g_acme_tokens[t]=ka;
            NW_INFO("acme","Challenge ready: %s",t.c_str());
        },
        [](const std::string& t){ std::lock_guard lk(g_acme_mu); g_acme_tokens.erase(t); }
    );
    g_acme->set_cert_ready(on_ready);
    g_acme->start();
}

// Serve /.well-known/acme-challenge/<token> from dispatch()
static bool acme_try_serve(const std::string& path, std::string& out_body){
    static const std::string pfx="/.well-known/acme-challenge/";
    if(path.size()<=pfx.size()||path.substr(0,pfx.size())!=pfx) return false;
    auto tok=path.substr(pfx.size());
    std::lock_guard lk(g_acme_mu);
    auto it=g_acme_tokens.find(tok);
    if(it==g_acme_tokens.end()) return false;
    out_body=it->second; return true;
}
