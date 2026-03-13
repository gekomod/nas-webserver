#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  parser.cc  —  HTTP/1.1 request + response parser
// ─────────────────────────────────────────────────────────────────────────────
#include "../../include/np_types.hh"
#include <cctype>
#include <cstdlib>

enum class ParseResult { Complete, Incomplete, Error, TooLarge };

static std::string url_decode(std::string_view sv){
    std::string out; out.reserve(sv.size());
    for(size_t i=0;i<sv.size();){
        if(sv[i]=='%'&&i+2<sv.size()&&isxdigit((unsigned char)sv[i+1])&&isxdigit((unsigned char)sv[i+2])){
            auto h=[](char c)->int{return isdigit((unsigned char)c)?c-'0':tolower((unsigned char)c)-'a'+10;};
            out+=(char)((h(sv[i+1])<<4)|h(sv[i+2])); i+=3;
        } else if(sv[i]=='+'){out+=' ';i++;}
        else out+=sv[i++];
    }
    return out;
}

std::pair<ParseResult,size_t> parse_request(const char* buf,size_t len,Request& req){
    if(len==0) return {ParseResult::Incomplete,0};
    if(len>NP_MAX_BODY+NP_BUF) return {ParseResult::TooLarge,0};
    std::string_view sv{buf,len};
    auto hend=sv.find("\r\n\r\n");
    if(hend==std::string_view::npos) return {ParseResult::Incomplete,0};
    auto fnl=sv.find("\r\n");
    auto rl =sv.substr(0,fnl);
    auto s1 =rl.find(' '), s2=rl.rfind(' ');
    if(s1==std::string_view::npos||s1==s2) return {ParseResult::Error,0};
    req.method=method_parse(rl.substr(0,s1));
    if(req.method==Method::Unknown) return {ParseResult::Error,0};
    auto raw_path=rl.substr(s1+1,s2-s1-1);
    auto proto=rl.substr(s2+1);
    auto q=raw_path.find('?');
    if(q!=std::string_view::npos){req.path=url_decode(raw_path.substr(0,q));req.query=std::string(raw_path.substr(q+1));}
    else req.path=url_decode(raw_path);
    req.version=(proto.find("1.0")!=std::string_view::npos)?HttpVersion::HTTP10:HttpVersion::HTTP11;
    req.keep_alive=(req.version==HttpVersion::HTTP11);

    size_t pos=fnl+2;
    std::string_view hpart=sv.substr(0,hend);
    while(pos<hpart.size()){
        auto nl=hpart.find("\r\n",pos);
        auto line=hpart.substr(pos,nl==std::string_view::npos?std::string_view::npos:nl-pos);
        pos=(nl==std::string_view::npos?hpart.size():nl+2);
        if(line.empty()) break;
        auto colon=line.find(':');
        if(colon==std::string_view::npos) continue;
        std::string k{line.substr(0,colon)};
        auto val=line.substr(colon+1);
        while(!val.empty()&&(val[0]==' '||val[0]=='\t')) val.remove_prefix(1);
        std::string v{val};
        if(ci_eq(k,"Host")) req.host=v;
        else if(ci_eq(k,"Content-Length")) req.content_length=(size_t)std::stoul(v);
        else if(ci_eq(k,"Connection")){
            if(ci_eq(v,"close")) req.keep_alive=false;
            else if(ci_eq(v,"keep-alive")) req.keep_alive=true;
        }
        req.headers.set(std::move(k),std::move(v));
    }
    auto conn=req.headers.get("Connection");
    auto upg=req.headers.get("Upgrade");
    req.is_websocket=(!conn.empty()&&conn.find("Upgrade")!=std::string_view::npos
                     &&ci_eq(upg,"websocket"));
    size_t hdr_end=hend+4;
    if(req.content_length>0){
        if(len-hdr_end<req.content_length) return {ParseResult::Incomplete,0};
        req.body.assign(buf+hdr_end,req.content_length);
        return {ParseResult::Complete,hdr_end+req.content_length};
    }
    return {ParseResult::Complete,hdr_end};
}

std::pair<ParseResult,size_t> parse_response(const char* buf,size_t len,Response& resp){
    if(len<12) return {ParseResult::Incomplete,0};
    std::string_view sv{buf,len};
    auto hend=sv.find("\r\n\r\n");
    if(hend==std::string_view::npos) return {ParseResult::Incomplete,0};
    auto fnl=sv.find("\r\n");
    auto rl=sv.substr(0,fnl);
    auto s1=rl.find(' '),s2=rl.find(' ',s1+1);
    if(s1==std::string_view::npos) return {ParseResult::Error,0};
    resp.status=std::stoi(std::string(rl.substr(s1+1,s2-s1-1)));
    size_t pos=fnl+2;
    std::string_view hpart=sv.substr(0,hend);
    bool chunked=false; size_t clen=0;
    while(pos<hpart.size()){
        auto nl=hpart.find("\r\n",pos);
        auto line=hpart.substr(pos,nl==std::string_view::npos?std::string_view::npos:nl-pos);
        pos=(nl==std::string_view::npos?hpart.size():nl+2);
        if(line.empty()) break;
        auto colon=line.find(':');
        if(colon==std::string_view::npos) continue;
        std::string k{line.substr(0,colon)};
        auto val=line.substr(colon+1);
        while(!val.empty()&&(val[0]==' '||val[0]=='\t')) val.remove_prefix(1);
        if(ci_eq(k,"Content-Length")) clen=std::stoul(std::string(val));
        if(ci_eq(k,"Transfer-Encoding")&&val.find("chunked")!=std::string_view::npos) chunked=true;
        resp.headers.set(std::move(k),std::string(val));
    }
    size_t body_start=hend+4;
    if(!chunked&&clen>0){
        if(len-body_start<clen) return {ParseResult::Incomplete,0};
        resp.body.assign(buf+body_start,clen);
        return {ParseResult::Complete,body_start+clen};
    }
    resp.body.assign(buf+body_start,len-body_start);
    return {ParseResult::Complete,len};
}

namespace http { using ::parse_request; using ::parse_response; using ::ParseResult; }
