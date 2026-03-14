#include "../include/np_types.hh"
#include "../src/http/parser.cc"
// Stub for g_log — required by NW_WARN/NW_LOG macros in parser.cc.
// The real definition lives in server.cc, not linked in unit tests.
LogBuffer g_log;

#include "../src/cache/cache.cc"
#include <cassert>
#include <cstdio>
static int ok=0,fail=0;
#define CHK(c,m) do{if(c){ok++;printf("  ✓ %s\n",m);}else{fail++;printf("  ✗ FAIL: %s\n",m);}}while(0)

Response make_resp(int status,const std::string& body,const std::string& cc="max-age=60"){
    Response r; r.status=status;
    r.headers.set("Content-Type","application/json");
    r.headers.set("Cache-Control",cc);
    r.headers.set("ETag","\"test-etag-123\"");
    r.body=body;
    r.headers.set("Content-Length",std::to_string(body.size()));
    return r;
}
Request make_req(const std::string& path="/api/data"){
    Request r; r.method=Method::GET; r.path=path; r.host="x.com"; return r;
}

void test_store_and_hit(){
    ResponseCache c(100,60);
    auto req=make_req(); auto resp=make_resp(200,R"({"data":"value"})");
    auto key=ResponseCache::make_key(req);
    CHK(c.put(key,resp,req),         "put returns true for cacheable");
    CHK(c.get(key)!=nullptr,          "HIT after store");
    CHK(c.get(key)->status==200,      "cached status");
    auto s=c.stats(); CHK(s.hits==2,"hit count (2 gets)");
}
void test_no_store(){
    ResponseCache c(100,60);
    auto req=make_req("/secret");
    auto resp=make_resp(200,"secret","no-store");
    auto key=ResponseCache::make_key(req);
    CHK(!c.put(key,resp,req),    "no-store not cached");
    CHK(c.get(key)==nullptr,      "no-store not retrievable");
}
void test_post_skip(){
    ResponseCache c(100,60);
    Request req=make_req(); req.method=Method::POST;
    auto resp=make_resp(200,"ok");
    auto key=ResponseCache::make_key(req);
    CHK(!c.put(key,resp,req),"POST not cached");
}
void test_lru_eviction(){
    ResponseCache c(3,60);
    for(int i=0;i<6;i++){
        auto req=make_req("/item/"+std::to_string(i));
        auto resp=make_resp(200,"body"+std::to_string(i));
        c.put(ResponseCache::make_key(req),resp,req);
    }
    CHK(c.stats().evictions==3,"evicted 3 (over capacity 3)");
}
void test_etag_304(){
    ResponseCache c(100,60);
    auto req=make_req("/page");
    auto resp=make_resp(200,"<html>hello</html>");
    auto key=ResponseCache::make_key(req);
    c.put(key,resp,req);
    auto* e=c.get(key);
    Request cond_req=make_req("/page");
    cond_req.headers.set("If-None-Match","\"test-etag-123\"");
    CHK(c.check_conditional(*e,cond_req),"ETag match → 304");
    Request diff_req=make_req("/page");
    diff_req.headers.set("If-None-Match","\"different\"");
    CHK(!c.check_conditional(*e,diff_req),"ETag mismatch → 200");
}
void test_non_200_cacheable(){
    ResponseCache c(100,60);
    auto req=make_req("/gone"); auto resp=make_resp(410,"","max-age=3600");
    auto key=ResponseCache::make_key(req);
    CHK(c.put(key,resp,req),"410 Gone is cacheable");
}
int main(){
    printf("=== Cache ===\n\n");
    test_store_and_hit(); test_no_store(); test_post_skip();
    test_lru_eviction(); test_etag_304(); test_non_200_cacheable();
    printf("\n%d passed, %d failed\n",ok,fail);
    return fail>0?1:0;
}
