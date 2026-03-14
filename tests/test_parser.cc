#include "../include/np_types.hh"
#include "../src/http/parser.cc"
// Stub for g_log — required by NW_WARN/NW_LOG macros in parser.cc.
// The real definition lives in server.cc, not linked in unit tests.
LogBuffer g_log;

#include <cassert>
#include <cstring>
#include <cstdio>
static int ok=0,fail=0;
#define CHK(c,m) do{if(c){ok++;printf("  ✓ %s\n",m);}else{fail++;printf("  ✗ FAIL: %s\n",m);}}while(0)

void test_get(){
    const char* r="GET /api/v2/users?page=2&limit=10 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer eyJhb\r\nAccept: application/json\r\nConnection: keep-alive\r\n\r\n";
    Request req; auto[res,n]=parse_request(r,strlen(r),req);
    CHK(res==ParseResult::Complete,  "GET complete");
    CHK(req.method==Method::GET,     "method GET");
    CHK(req.path=="/api/v2/users",   "path");
    CHK(req.query=="page=2&limit=10","query");
    CHK(req.host=="api.example.com", "host");
    CHK(req.keep_alive,              "keep-alive");
    CHK(req.headers.has("Authorization"),"auth header preserved");
}
void test_post_json(){
    std::string body=R"({"name":"alice","role":"admin"})";
    std::string r="POST /api/users HTTP/1.1\r\nHost: x.com\r\nContent-Type: application/json\r\nContent-Length: "+std::to_string(body.size())+"\r\n\r\n"+body;
    Request req; auto[res,n]=parse_request(r.c_str(),r.size(),req);
    CHK(res==ParseResult::Complete,    "POST complete");
    CHK(req.method==Method::POST,       "method POST");
    CHK(req.content_length==body.size(),"content-length");
    CHK(req.body==body,                 "body matches");
}
void test_websocket(){
    const char* r="GET /ws/chat HTTP/1.1\r\nHost: x.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    Request req; auto[res,n]=parse_request(r,strlen(r),req);
    CHK(res==ParseResult::Complete, "WS complete");
    CHK(req.is_websocket,            "WS detected");
    CHK(req.path=="/ws/chat",        "WS path");
}
void test_incomplete(){
    const char* r="GET /path HTTP/1.1\r\nHost: x";
    Request req; auto[res,n]=parse_request(r,strlen(r),req);
    CHK(res==ParseResult::Incomplete,"incomplete detected");
}
void test_url_encoding(){
    const char* r="GET /path%20with%20spaces?q=hello+world&tag=C%2B%2B HTTP/1.1\r\nHost: x.com\r\n\r\n";
    Request req; auto[res,n]=parse_request(r,strlen(r),req);
    CHK(res==ParseResult::Complete,          "url-encoded complete");
    CHK(req.path=="/path with spaces",        "path decoded");
    CHK(req.query=="q=hello+world&tag=C%2B%2B","query preserved");
}
void test_response(){
    const char* r="HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 19\r\nX-Request-Id: abc\r\n\r\n{\"id\":42,\"ok\":true}";
    Response resp; auto[res,n]=parse_response(r,strlen(r),resp);
    CHK(res==ParseResult::Complete,           "response complete");
    CHK(resp.status==201,                      "status 201");
    CHK(resp.body=="{\"id\":42,\"ok\":true}","body");
    CHK(resp.headers.get("X-Request-Id")=="abc","custom header");
}
int main(){
    printf("=== HTTP Parser ===\n\n");
    test_get(); test_post_json(); test_websocket();
    test_incomplete(); test_url_encoding(); test_response();
    printf("\n%d passed, %d failed\n",ok,fail);
    return fail>0?1:0;
}
