// ─────────────────────────────────────────────────────────────────────────────
//  np_types.hh  —  core types shared across all modules
// ─────────────────────────────────────────────────────────────────────────────
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <ctime>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <optional>
#include <unordered_map>
#include <functional>
#include <chrono>
#include <atomic>
#include <variant>
#include <algorithm>
#include <sstream>

#ifdef NAS_WEB_VERSION
inline constexpr std::string_view NP_VERSION = NAS_WEB_VERSION;
#else
inline constexpr std::string_view NP_VERSION = "2.2.84";
#endif
inline constexpr std::string_view NP_NAME    = "nas-web";

// ── Buffer sizes ──────────────────────────────────────────────────────────────
inline constexpr size_t NP_BUF          = 65536;       // 64 KB recv/send
inline constexpr size_t NP_MAX_HEADERS  = 96;
inline constexpr size_t NP_MAX_PATH     = 4096;
inline constexpr size_t NP_MAX_BODY     = 64*1024*1024; // 64 MB

// ── HTTP method ───────────────────────────────────────────────────────────────
enum class Method { Unknown,GET,POST,PUT,DELETE,PATCH,HEAD,OPTIONS,CONNECT };

inline std::string_view method_str(Method m) {
    switch(m){
    case Method::GET:     return "GET";
    case Method::POST:    return "POST";
    case Method::PUT:     return "PUT";
    case Method::DELETE:  return "DELETE";
    case Method::PATCH:   return "PATCH";
    case Method::HEAD:    return "HEAD";
    case Method::OPTIONS: return "OPTIONS";
    case Method::CONNECT: return "CONNECT";
    default:              return "UNKNOWN";
    }
}
inline Method method_parse(std::string_view s) {
    if(s=="GET")     return Method::GET;
    if(s=="POST")    return Method::POST;
    if(s=="PUT")     return Method::PUT;
    if(s=="DELETE")  return Method::DELETE;
    if(s=="PATCH")   return Method::PATCH;
    if(s=="HEAD")    return Method::HEAD;
    if(s=="OPTIONS") return Method::OPTIONS;
    if(s=="CONNECT") return Method::CONNECT;
    return Method::Unknown;
}

// ── HTTP version ──────────────────────────────────────────────────────────────
enum class HttpVersion { HTTP10=10, HTTP11=11, HTTP20=20, HTTP30=30 };

// ── Header map (insertion-ordered, case-insensitive lookup) ──────────────────
struct Headers {
    std::vector<std::pair<std::string,std::string>> items;

    void set(std::string k, std::string v) {
        for(auto&[ek,ev]:items)
            if(strcasecmp(ek.c_str(),k.c_str())==0){ev=std::move(v);return;}
        items.emplace_back(std::move(k),std::move(v));
    }
    std::string_view get(std::string_view k) const {
        for(auto&[ek,ev]:items)
            if(strcasecmp(ek.c_str(),k.data())==0) return ev;
        return {};
    }
    bool has(std::string_view k) const { return !get(k).empty(); }
    void remove(std::string_view k){
        items.erase(std::remove_if(items.begin(),items.end(),
            [&](auto&kv){return strcasecmp(kv.first.c_str(),k.data())==0;}),
            items.end());
    }
    // merge: add headers not already present
    void merge(const Headers& other){
        for(auto&[k,v]:other.items) if(!has(k)) set(k,v);
    }
};

// ── HTTP Request ──────────────────────────────────────────────────────────────
struct Request {
    Method      method{Method::Unknown};
    HttpVersion version{HttpVersion::HTTP11};
    std::string path;
    std::string query;
    std::string host;
    std::string scheme{"http"};
    std::string client_ip;
    uint16_t    client_port{};
    bool        keep_alive{true};
    bool        is_websocket{false};
    bool        is_h2{false};
    Headers     headers;
    std::string body;
    size_t      content_length{};
    int32_t     h2_stream_id{-1};   // HTTP/2 stream
};

// ── HTTP Response ─────────────────────────────────────────────────────────────
struct Response {
    int         status{200};
    HttpVersion version{HttpVersion::HTTP11};
    Headers     headers;
    std::string body;

    static std::string_view status_text(int s) {
        switch(s){
        case 100:return"Continue"; case 101:return"Switching Protocols";
        case 200:return"OK"; case 201:return"Created";
        case 204:return"No Content"; case 206:return"Partial Content";
        case 301:return"Moved Permanently"; case 302:return"Found";
        case 304:return"Not Modified"; case 307:return"Temporary Redirect";
        case 308:return"Permanent Redirect";
        case 400:return"Bad Request"; case 401:return"Unauthorized";
        case 403:return"Forbidden"; case 404:return"Not Found";
        case 405:return"Method Not Allowed"; case 408:return"Request Timeout";
        case 413:return"Payload Too Large"; case 422:return"Unprocessable Entity";
        case 429:return"Too Many Requests"; case 451:return"Unavailable For Legal Reasons";
        case 500:return"Internal Server Error"; case 502:return"Bad Gateway";
        case 503:return"Service Unavailable"; case 504:return"Gateway Timeout";
        default: return"Unknown";
        }
    }

    static Response make_error(int code, std::string_view detail={}) {
        Response r;
        r.status = code;
        const char* icon =
            code==404?"&#x2205;":
            code==403?"&#x26D4;":
            code==429?"&#x1F6A7;":
            code==500?"&#x1F525;":
            code==502?"&#x1F517;":
            code==503?"&#x23F3;":"&#x26A0;";
        const char* hint =
            code==404?"The page you are looking for does not exist or has been moved.":
            code==403?"You don't have permission to access this resource.":
            code==429?"Too many requests. Please slow down and try again shortly.":
            code==500?"An internal server error occurred. Check the server logs.":
            code==502?"The upstream server is unreachable or returned an invalid response.":
            code==503?"The server is temporarily unavailable. Try again in a moment.":
                      "An unexpected error occurred.";
        std::string det = detail.empty() ? "" :
            "<div class='detail'>" + std::string(detail) + "</div>";
        char buf[4096];
        snprintf(buf, sizeof(buf), R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%d &mdash; %s</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0b0d;color:#c8d0e0;font-family:'JetBrains Mono',monospace,sans-serif;
  min-height:100vh;display:flex;align-items:center;justify-content:center;
  background-image:linear-gradient(rgba(30,35,48,.4) 1px,transparent 1px),
  linear-gradient(90deg,rgba(30,35,48,.4) 1px,transparent 1px);
  background-size:40px 40px;}
.card{text-align:center;padding:60px 48px;max-width:520px}
.icon{font-size:64px;margin-bottom:24px;display:block;
  filter:drop-shadow(0 0 24px rgba(0,212,170,.3))}
.code{font-size:96px;font-weight:300;color:#eef2ff;line-height:1;
  letter-spacing:-4px;margin-bottom:8px}
.msg{font-size:18px;color:#00d4aa;margin-bottom:20px;font-weight:500}
.hint{font-size:13px;color:#3a4055;line-height:1.6;margin-bottom:24px}
.detail{font-size:11px;color:#1e2330;background:#0f1114;border:1px solid #1e2330;
  padding:10px 14px;border-radius:4px;margin-bottom:24px;text-align:left}
.back{display:inline-flex;align-items:center;gap:8px;padding:10px 20px;
  background:rgba(0,212,170,.08);border:1px solid rgba(0,212,170,.2);
  border-radius:4px;color:#00d4aa;text-decoration:none;font-size:12px;
  transition:all .15s}
.back:hover{background:rgba(0,212,170,.15)}
.server{margin-top:32px;font-size:10px;color:#1e2330}
</style>
</head>
<body>
<div class="card">
  <span class="icon">%s</span>
  <div class="code">%d</div>
  <div class="msg">%s</div>
  <div class="hint">%s</div>
  %s
  <a class="back" href="/">&#8592; Go back home</a>
  <div class="server">nas-web/2.2.84</div>
</div>
</body>
</html>)HTML",
            code, std::string(status_text(code)).c_str(),
            icon, code, std::string(status_text(code)).c_str(),
            hint, det.c_str());
        r.body = buf;
        r.headers.set("Content-Type","text/html; charset=utf-8");
        r.headers.set("Content-Length",std::to_string(r.body.size()));
        r.headers.set("Connection","close");
        r.headers.set("X-Error-Code", std::to_string(code));
        return r;
    }

    // JSON error — for API paths
    static Response make_json_error(int code, std::string_view detail={}) {
        Response r;
        r.status = code;
        r.body   = std::string("{\"error\":") + std::to_string(code)
                 + ",\"message\":\"" + std::string(status_text(code))
                 + (detail.empty()?"":std::string(", ")+std::string(detail))
                 + "\"}";
        r.headers.set("Content-Type","application/json; charset=utf-8");
        r.headers.set("Content-Length",std::to_string(r.body.size()));
        r.headers.set("Connection","close");
        return r;
    }

    std::string serialize_h1() const {
        std::string out;
        out.reserve(256+body.size());
        out += "HTTP/1.1 "; out += std::to_string(status);
        out += ' '; out += status_text(status); out += "\r\n";
        for(auto&[k,v]:headers.items) { out+=k; out+=": "; out+=v; out+="\r\n"; }
        if(!headers.has("Content-Length"))
            out+="Content-Length: "+std::to_string(body.size())+"\r\n";
        out+="\r\n"; out+=body;
        return out;
    }

    // Headers only — no Content-Length, no body (for SSE / chunked streaming)
    std::string serialize_h1_headers_only() const {
        std::string out;
        out.reserve(256);
        out += "HTTP/1.1 "; out += std::to_string(status);
        out += ' '; out += status_text(status); out += "\r\n";
        for(auto&[k,v]:headers.items) { out+=k; out+=": "; out+=v; out+="\r\n"; }
        out += "\r\n";
        return out;
    }
};

// ── Monotonic clock ───────────────────────────────────────────────────────────
inline int64_t now_ms(){
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
inline uint32_t fnv1a(std::string_view s){
    uint32_t h=2166136261u;
    for(unsigned char c:s){h^=c;h*=16777619u;}
    return h;
}
inline bool ci_eq(std::string_view a,std::string_view b){
    if(a.size()!=b.size())return false;
    for(size_t i=0;i<a.size();i++)
        if(tolower((unsigned char)a[i])!=tolower((unsigned char)b[i]))return false;
    return true;
}

// ── Log ring buffer ───────────────────────────────────────────────────────────
#include <mutex>
#include <deque>
#include <cstdio>
#include <cstdarg>

enum class LogLevel { DEBUG=0, INFO=1, WARN=2, ERR=3 };

struct LogEntry {
    int64_t     ts;       // unix timestamp seconds
    LogLevel    level;
    std::string module;   // e.g. "proxy", "cache", "config"
    std::string msg;
};

struct LogBuffer {
    static constexpr size_t MAX = 500;
    std::deque<LogEntry>    entries;
    std::mutex              mu;
    std::atomic<int>        min_level{1}; // INFO by default

    // Optional SSE broadcast callback — set by server.cc after startup
    std::function<void(const LogEntry&)> sse_broadcast;

    void push(LogLevel lv, std::string_view mod, std::string_view msg) {
        if((int)lv < min_level.load()) return;
        LogEntry e;
        e.ts     = (int64_t)time(nullptr);
        e.level  = lv;
        e.module = std::string(mod);
        e.msg    = std::string(msg);
        {
            std::lock_guard<std::mutex> lg(mu);
            entries.push_back(e);
            while(entries.size() > MAX) entries.pop_front();
        }
        // Push to SSE clients (non-blocking — callback must be thread-safe)
        if(sse_broadcast) sse_broadcast(e);
    }

    // Serialize to JSON array, optionally filter by level & since timestamp
    std::string to_json(int min_lv=0, int64_t since=0, size_t limit=200) {
        static const char* lvnames[]={"debug","info","warn","error"};
        std::string out="[";
        std::lock_guard<std::mutex> lg(mu);
        size_t count=0;
        for(auto it=entries.rbegin(); it!=entries.rend() && count<limit; ++it) {
            if((int)it->level < min_lv) continue;
            if(it->ts < since) break;
            if(count) out+=',';
            char buf[64];
            // format timestamp
            struct tm* tm_info = localtime(&it->ts);
            strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
            // escape msg
            std::string emsg;
            for(char c : it->msg) {
                if(c=='"') emsg+="\\\"";
                else if(c=='\\') emsg+="\\\\";
                else if(c=='\n') emsg+="\\n";
                else emsg+=c;
            }
            out+="{\"ts\":\"";out+=buf;out+="\",\"level\":\"";
            out+=lvnames[(int)it->level];out+="\",\"module\":\"";
            out+=it->module;out+="\",\"msg\":\"";out+=emsg;out+="\"}";
            count++;
        }
        out+="]";
        return out;
    }
};

// Global log buffer — defined in server.cc
extern LogBuffer g_log;

// Logging macros
#define NW_LOG(level, mod, fmt, ...) do { \
    char _buf[512]; \
    snprintf(_buf, sizeof(_buf), fmt, ##__VA_ARGS__); \
    fprintf(stderr, "[%s][%s] %s\n", \
        level==LogLevel::ERR?"ERROR":level==LogLevel::WARN?"WARN":level==LogLevel::INFO?"INFO":"DEBUG", \
        mod, _buf); \
    g_log.push(level, mod, _buf); \
} while(0)

#define NW_INFO(mod,  fmt, ...) NW_LOG(LogLevel::INFO,  mod, fmt, ##__VA_ARGS__)
#define NW_WARN(mod,  fmt, ...) NW_LOG(LogLevel::WARN,  mod, fmt, ##__VA_ARGS__)
#define NW_ERROR(mod, fmt, ...) NW_LOG(LogLevel::ERR,   mod, fmt, ##__VA_ARGS__)
#define NW_DEBUG(mod, fmt, ...) NW_LOG(LogLevel::DEBUG, mod, fmt, ##__VA_ARGS__)
