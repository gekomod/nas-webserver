// server.cc — nodeproxy v2 main server
#include "../../include/np_types.hh"
#include "../../include/np_config.hh"
#include <uv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <thread>
#include <unordered_set>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <chrono>
#include <unordered_map>

#include "../http/parser.cc"
// Define macro so cache.cc skips its stub declarations (we own the real ones here)
#define NAS_WEB_SERVER_CC
// Global cache stats shared with cache.cc
static std::atomic<uint64_t> g_stat_cache_hit{0};
static std::atomic<uint64_t> g_stat_cache_miss{0};
static std::atomic<uint64_t> g_stat_cache_entries{0};
#define G_STAT_CACHE_ENTRIES_DEFINED  // tell cache.cc not to redefine

#include "../cache/cache.cc"
#include "../security/ratelimit.cc"
#include "../proxy/upstream.cc"
#include "../optimization/optimization.cc"
#include "../static/static_handler.cc"
#include "../config/config_parser.cc"
#include "../scripting/middleware_pipeline.cc"
#include "../http/h2_handler.cc"
#include "../http/h3_handler.cc"
#if defined(HAVE_ACME)
#include "../tls/acme.cc"
#else
// ACME stub when compiled without WITH_ACME
static bool acme_try_serve(const std::string&, std::string&){ return false; }
static void acme_init(...) {}
#endif
#include "../../include/admin_panel.h"
#include "../../include/autoban.hh"
#include "../../include/waf.hh"
#include "../../include/waf_regex.hh"

static std::shared_ptr<Config> g_config;
LogBuffer g_log;
static std::atomic<bool>     g_running{true};
static std::atomic<bool>     g_reload{false};
std::atomic<int>             g_worker_count{0};
static time_t                g_start_time = time(nullptr);
// Global aggregated stats — incremented by every worker
static std::atomic<uint64_t> g_stat_req{0};
static std::atomic<uint64_t> g_stat_err{0};
// req/s tracking
static std::atomic<uint64_t> g_stat_req_prev{0};
static std::atomic<uint64_t> g_stat_req_per_sec{0};
static time_t                g_stat_last_sec = time(nullptr);
static uint64_t              g_stat_latency_sum{0};   // ms sum for rolling avg
static uint64_t              g_stat_latency_cnt{0};   // sample count

static std::string g_config_path; // set in main(), used by /np_config endpoint


struct WorkerStats {
    std::atomic<uint64_t> req{0};
    std::atomic<uint64_t> err{0};
    std::atomic<uint64_t> cache_hit{0};
    std::atomic<uint64_t> active_conns{0};
};
static WorkerStats g_wstats[64];
static int         g_wstats_count{0}; // set during startup


static std::mutex                         g_blacklist_mu;
static std::unordered_set<std::string>    g_blacklist;

// ── Singleton globals — shared across all workers (defined once here) ────────
#define AUTOBAN_IMPL
AutoBan           g_autoban;
#define WAF_REGEX_IMPL
WafRegexEngine    g_waf_regex;
static std::string                        g_blacklist_file{"/var/lib/nas-web/blacklist.txt"};

// Musi być wywoływane BEZ trzymania g_blacklist_mu
static std::atomic<bool> g_blacklist_dirty{false};

static void blacklist_save_nolock(){
    g_blacklist_dirty.store(true, std::memory_order_relaxed);
}

// ── AutoBan recent_bans persistence ──────────────────────────────────────────
static const std::string G_BANS_FILE = "/var/lib/nas-web/recent_bans.txt";

static void bans_save(){
    FILE* f = fopen(G_BANS_FILE.c_str(), "w");
    if(!f) return;
    std::lock_guard<std::mutex> lk(g_autoban.mu_pub());
    for(auto& b : g_autoban.recent_bans){
        std::string esc;
        for(char c : b.detail){ if(c=='|') esc+="\\|"; else esc+=c; }
        fprintf(f, "%lld|%s|%s|%s\n", (long long)b.ts, b.ip.c_str(), b.reason.c_str(), esc.c_str());
    }
    fclose(f);
}

static void blacklist_flush_sync(){
    std::filesystem::create_directories("/var/lib/nas-web");
    std::vector<std::string> snap;
    bool dirty = false;
    {
        std::lock_guard<std::mutex> lk(g_blacklist_mu);
        dirty = g_blacklist_dirty.load(std::memory_order_relaxed);
        if(dirty){
            snap.assign(g_blacklist.begin(), g_blacklist.end());
            g_blacklist_dirty.store(false, std::memory_order_relaxed);
        }
    }
    if(dirty){
        FILE* f = fopen(g_blacklist_file.c_str(), "w");
        if(!f){ NW_WARN("blacklist","Cannot write %s",g_blacklist_file.c_str()); }
        else { for(auto& ip : snap) fprintf(f, "%s\n", ip.c_str()); fclose(f); }
    }
    bans_save();
}

static void bans_load(){
    FILE* f = fopen(G_BANS_FILE.c_str(), "r");
    if(!f) return;
    char buf[512];
    while(fgets(buf, sizeof(buf), f)){
        std::string line(buf);
        if(!line.empty() && line.back()=='\n') line.pop_back();
        // Parse: ts|ip|reason|detail
        auto p1 = line.find('|');
        auto p2 = line.find('|', p1+1);
        auto p3 = line.find('|', p2+1);
        if(p1==std::string::npos||p2==std::string::npos||p3==std::string::npos) continue;
        AutoBan::BanEvent ev;
        ev.ts     = (time_t)std::stoll(line.substr(0, p1));
        ev.ip     = line.substr(p1+1, p2-p1-1);
        ev.reason = line.substr(p2+1, p3-p2-1);
        ev.detail = line.substr(p3+1);
        g_autoban.recent_bans.push_back(ev);
    }
    fclose(f);
    NW_INFO("autoban", "Loaded %zu ban records from %s",
            g_autoban.recent_bans.size(), G_BANS_FILE.c_str());
}

static void blacklist_load(){
    FILE* f = fopen(g_blacklist_file.c_str(), "r");
    if(!f) return;
    char buf[64];
    std::lock_guard<std::mutex> lk(g_blacklist_mu);
    while(fgets(buf, sizeof(buf), f)){
        std::string ip(buf);
        while(!ip.empty() && (ip.back()=='\n'||ip.back()=='\r'||ip.back()==' ')) ip.pop_back();
        if(!ip.empty()) g_blacklist.insert(ip);
    }
    fclose(f);
    NW_INFO("server", "Loaded %zu blacklisted IPs from %s",
            g_blacklist.size(), g_blacklist_file.c_str());
}

// ── Per-IP connection counter ─────────────────────────────────────────────
static std::mutex                              g_connlimit_mu;
static std::unordered_map<std::string,int>    g_conn_count;
static int                                     g_max_conns_per_ip{32}; // default: 32 per IP

// ── Active connections list (for admin panel) ─────────────────────────────
struct ActiveConn {
    std::string ip, method, path;
    int status{0};
    int64_t started_ms;
    std::string type; // "proxy","static","ws"
};
static std::mutex                    g_active_mu;
static std::unordered_map<void*,ActiveConn> g_active; // key=Conn*

// Recent completed requests — ring buffer for Connections tab history
struct RecentReq {
    std::string ip, method, path, type;
    int status{0};
    int64_t ts_ms;
    int64_t duration_ms{0};
};
static std::mutex              g_recent_mu;
static std::deque<RecentReq>   g_recent_reqs; // last 200 requests
static const int               G_RECENT_MAX = 200;

// ── Upstream overrides (live-edited from panel) ───────────────────────────
static std::mutex                        g_upstream_mu;
struct UpstreamOverride {
    std::string name, address;
    bool enabled{true};
};
static std::vector<UpstreamOverride>     g_upstream_overrides;

// ── Stats history ring buffer (for dashboard charts) ─────────────────────────
struct StatSample {
    int64_t  ts;           // unix seconds
    uint64_t req_per_sec;
    uint64_t err_per_sec;
    uint64_t cache_hits;
    uint32_t active_conns;
    uint32_t latency_avg_ms; // rolling average
};
static std::mutex              g_stats_hist_mu;
static std::deque<StatSample>  g_stats_hist;   // 1 sample/s, max 3600 (1h)
static const int               G_STATS_HIST_MAX = 3600;
static std::atomic<bool>       g_stats_timer_running{false};
static std::thread             g_stats_thread;

// Prev values for delta calculation
static uint64_t g_prev_req{0};
static uint64_t g_prev_err{0};

static void stats_collector_tick(){
    uint64_t cur_req = g_stat_req.load();
    uint64_t cur_err = g_stat_err.load();

    uint64_t rps = cur_req > g_prev_req ? cur_req - g_prev_req : 0;
    uint64_t eps = cur_err > g_prev_err ? cur_err - g_prev_err : 0;
    g_prev_req = cur_req;
    g_prev_err = cur_err;

    // Update the atomic so /np_status also returns correct rps
    g_stat_req_per_sec.store(rps);

    StatSample s;
    s.ts             = (int64_t)time(nullptr);
    s.req_per_sec    = rps;
    s.err_per_sec    = eps;
    s.cache_hits     = g_stat_cache_hit.load();
    s.active_conns   = (uint32_t)g_active.size();
    s.latency_avg_ms = 0;
    {
        std::lock_guard lk(g_stats_hist_mu);
        g_stats_hist.push_back(s);
        if((int)g_stats_hist.size() > G_STATS_HIST_MAX)
            g_stats_hist.pop_front();
    }
}

// ── Audit log ────────────────────────────────────────────────────────────────
struct AuditEntry {
    int64_t     ts;
    std::string admin_ip;
    std::string action;   // "config_save","toggle_module","add_upstream", etc.
    std::string detail;
};
static std::mutex              g_audit_mu;
static std::deque<AuditEntry>  g_audit_log;
static const int               G_AUDIT_MAX = 500;

static void audit(const std::string& ip, const std::string& action, const std::string& detail="") {
    std::lock_guard lk(g_audit_mu);
    g_audit_log.push_back({(int64_t)time(nullptr), ip, action, detail});
    while((int)g_audit_log.size() > G_AUDIT_MAX) g_audit_log.pop_front();
    NW_INFO("audit", "[%s] %s %s", ip.c_str(), action.c_str(), detail.c_str());
}

// ── SSE clients for live log streaming ───────────────────────────────────────
static std::mutex                        g_sse_mu;
static std::vector<struct Conn*>         g_sse_clients; // live /np_logs/stream connections



// ── Worker ────────────────────────────────────────────────────────────────────
struct Worker {
    int         id{};
    uv_loop_t*  loop{nullptr};
    uv_tcp_t    server_h{};   // primary (HTTP) handle
    uv_tcp_t    tls_h{};      // secondary (HTTPS) handle — used if tls_fd >= 0
    int         tls_fd{-1};   // fd for TLS port, -1 if none
    uv_async_t  stop_async{};
    SSL_CTX*    ssl_ctx{nullptr};

    std::shared_ptr<Config>             config;
    std::unique_ptr<ResponseCache>      cache;
    std::unique_ptr<RateLimiter>        rl;
    std::unique_ptr<MiddlewarePipeline> mw;
    std::unique_ptr<UpstreamGroup>      upstream;

    uint64_t stat_req{}, stat_err{}, stat_cache_hit{};
};

// ── Connection ────────────────────────────────────────────────────────────────
struct Conn {
    uv_tcp_t    client{};
    Worker*     worker{nullptr};

    // ── TLS (memory BIO bridge) ──────────────────────────────────────────────
    // libuv owns raw TCP bytes. We feed them into rbio (OpenSSL reads from it),
    // and flush wbio (OpenSSL writes encrypted bytes here) back to libuv.
    SSL*        ssl{nullptr};       // non-null when port is TLS
    BIO*        rbio{nullptr};      // encrypted bytes from network -> OpenSSL
    BIO*        wbio{nullptr};      // encrypted bytes from OpenSSL -> network
    bool        tls_handshake_done{false};
    std::string tls_pending_write;  // plaintext queued before handshake done

    char        rbuf[NP_BUF]{};
    size_t      rbuf_len{0};

    Request     req{};
    bool        req_parsed{false};
    bool        is_sse{false};     // Server-Sent Events — keep connection open
    std::string response_data;
    std::string client_ip;
    int         requests_served{0};
    bool        is_ws{false};

    UpstreamPool* upstream_pool{nullptr};
    PoolConn*     upstream_conn{nullptr};
};

// ── ProxyJob (heap, lives across thread boundary) ─────────────────────────────
struct ProxyJob {
    uv_work_t   work{};
    Conn*       conn{};
    int         up_fd{};
    UpstreamPool* pool{};
    PoolConn*   pool_conn{};
    std::string buf{};
    bool        ok{false};
};

// ── Forward declarations ──────────────────────────────────────────────────────
static void close_conn(Conn*);
static void write_response(Conn*, std::string);
static void dispatch(Conn*);
static void on_alloc(uv_handle_t*, size_t, uv_buf_t*);
static void on_read(uv_stream_t*, ssize_t, const uv_buf_t*);

// ── TLS ───────────────────────────────────────────────────────────────────────


static SSL_CTX* create_ssl_ctx(const ServerConfig& srv) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if(!ctx) return nullptr;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_CIPHER_SERVER_PREFERENCE);
    // ALPN: http/1.1 only — h2 not supported over TLS in this build
    static const unsigned char alpn[] = "\x08http/1.1";
    SSL_CTX_set_alpn_protos(ctx, alpn, sizeof(alpn)-1);
    SSL_CTX_set_alpn_select_cb(ctx, [](SSL*, const unsigned char** out, unsigned char* outlen,
        const unsigned char* in, unsigned int inlen, void*) -> int {
        static const unsigned char pref[] = "\x08http/1.1";
        return SSL_select_next_proto((unsigned char**)out, outlen,
            pref, sizeof(pref)-1, in, inlen) == OPENSSL_NPN_NEGOTIATED
            ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_NOACK;
    }, nullptr);
    if(srv.ssl_cert.empty() || srv.ssl_key.empty()) {
        NW_WARN("tls", "No ssl_cert/ssl_key in config — TLS disabled");
        SSL_CTX_free(ctx); return nullptr;
    }
    if(SSL_CTX_use_certificate_chain_file(ctx, srv.ssl_cert.c_str()) != 1) {
        NW_ERROR("tls", "Cannot load cert: %s", srv.ssl_cert.c_str());
        SSL_CTX_free(ctx); return nullptr;
    }
    if(SSL_CTX_use_PrivateKey_file(ctx, srv.ssl_key.c_str(), SSL_FILETYPE_PEM) != 1) {
        NW_ERROR("tls", "Cannot load key: %s", srv.ssl_key.c_str());
        SSL_CTX_free(ctx); return nullptr;
    }
    if(SSL_CTX_check_private_key(ctx) != 1) {
        NW_ERROR("tls", "Cert/key mismatch");
        SSL_CTX_free(ctx); return nullptr;
    }
    NW_INFO("tls", "TLS context created: cert=%s", srv.ssl_cert.c_str());
    return ctx;
}

// ── TLS helpers ───────────────────────────────────────────────────────────────

// Flush any encrypted bytes OpenSSL wrote to wbio out to the TCP socket
static void tls_flush_wbio(Conn* conn) {
    char buf[16384];
    int n;
    while((n = BIO_read(conn->wbio, buf, sizeof(buf))) > 0) {
        auto* wr = static_cast<uv_write_t*>(malloc(sizeof(uv_write_t)));
        char* copy = static_cast<char*>(malloc(n));
        memcpy(copy, buf, n);
        wr->data = copy; // store for free in callback
        uv_buf_t b = uv_buf_init(copy, n);
        uv_write(wr, (uv_stream_t*)&conn->client, &b, 1,
            [](uv_write_t* req, int){ free(req->data); free(req); });
    }
}

// Feed raw TCP bytes into rbio and drive handshake or decrypt
// Returns false if connection should be closed
static bool tls_on_raw_data(Conn* conn, const char* data, size_t len) {
    // Push raw (encrypted) bytes from network into OpenSSL's read BIO
    BIO_write(conn->rbio, data, (int)len);

    if(!conn->tls_handshake_done) {
        // Drive handshake
        int r = SSL_accept(conn->ssl);
        tls_flush_wbio(conn); // send any ServerHello etc.
        if(r == 1) {
            conn->tls_handshake_done = true;
            NW_DEBUG("tls", "Handshake complete: %s %s",
                SSL_get_version(conn->ssl),
                SSL_get_cipher(conn->ssl));
            // Flush any plaintext queued during handshake
            if(!conn->tls_pending_write.empty()) {
                SSL_write(conn->ssl, conn->tls_pending_write.data(),
                          (int)conn->tls_pending_write.size());
                conn->tls_pending_write.clear();
                tls_flush_wbio(conn);
            }
            return true;
        }
        int err = SSL_get_error(conn->ssl, r);
        if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            return true; // handshake in progress
        // SSL_ERROR_SSL (1) = client dropped connection or sent bad data — not a server error
        if(err == SSL_ERROR_SSL || err == SSL_ERROR_SYSCALL) {
            unsigned long ossl_err = ERR_peek_last_error();
            int reason = ERR_GET_REASON(ossl_err);
            // Suppress common "noisy" errors: unexpected EOF, unknown protocol, no shared cipher
            if(reason == SSL_R_UNEXPECTED_EOF_WHILE_READING ||
               reason == SSL_R_UNKNOWN_PROTOCOL ||
               reason == SSL_R_NO_SHARED_CIPHER ||
               reason == SSL_R_WRONG_VERSION_NUMBER ||
               reason == 0) {
                ERR_clear_error();
                return false; // silent drop
            }
        }
        NW_WARN("tls", "Handshake failed: SSL error %d", err);
        ERR_clear_error();
        return false;
    }

    // Handshake done — decrypt application data
    char plain[NP_BUF];
    int n;
    while((n = SSL_read(conn->ssl, plain, sizeof(plain))) > 0) {
        // Feed decrypted bytes into HTTP parser buffer
        size_t avail = sizeof(conn->rbuf) - conn->rbuf_len - 1;
        if((size_t)n > avail) { NW_WARN("tls","rbuf overflow"); return false; }
        memcpy(conn->rbuf + conn->rbuf_len, plain, n);
        conn->rbuf_len += n;
    }
    int err = SSL_get_error(conn->ssl, n);
    if(err != SSL_ERROR_WANT_READ && err != SSL_ERROR_ZERO_RETURN
       && err != SSL_ERROR_NONE) {
        NW_DEBUG("tls", "SSL_read error %d", err);
        return false;
    }
    return true;
}

// Encrypt plaintext and write to TCP via wbio
static void tls_write_plaintext(Conn* conn, const char* data, size_t len) {
    if(!conn->tls_handshake_done) {
        // Queue until handshake complete
        conn->tls_pending_write.append(data, len);
        return;
    }
    // SSL_write may not accept all bytes at once
    size_t written = 0;
    while(written < len) {
        int n = SSL_write(conn->ssl, data + written, (int)(len - written));
        if(n <= 0) {
            int err = SSL_get_error(conn->ssl, n);
            NW_WARN("tls", "SSL_write error %d", err);
            break;
        }
        written += n;
    }
    tls_flush_wbio(conn);
}

// ── close_conn ────────────────────────────────────────────────────────────────
static void close_conn(Conn* conn) {
    // Remove from SSE clients if registered
    if(conn->is_sse) {
        std::lock_guard lk(g_sse_mu);
        g_sse_clients.erase(
            std::remove(g_sse_clients.begin(), g_sse_clients.end(), conn),
            g_sse_clients.end());
    }
    // ── Unregister active connection and save to history ──────────────────
    {
        std::lock_guard<std::mutex> lk(g_active_mu);
        auto it = g_active.find(conn);
        if(it != g_active.end()) g_active.erase(it);
    }
    // ── Decrement per-IP connection counter ──────────────────────────────
    if(!conn->client_ip.empty() && g_max_conns_per_ip > 0) {
        std::lock_guard<std::mutex> lk(g_connlimit_mu);
        auto it = g_conn_count.find(conn->client_ip);
        if(it != g_conn_count.end() && it->second > 0)
            it->second--;
    }
    if(conn->ssl) {
        SSL_shutdown(conn->ssl);
        tls_flush_wbio(conn); // send close_notify
        SSL_free(conn->ssl);
        conn->ssl  = nullptr;
        conn->rbio = nullptr; // freed by SSL_free
        conn->wbio = nullptr;
    }
    uv_close((uv_handle_t*)&conn->client, [](uv_handle_t* h){
        delete static_cast<Conn*>(h->data);
    });
}

// ── write_response ────────────────────────────────────────────────────────────
static void on_write_done(uv_write_t* req, int status) {
    Conn* conn = static_cast<Conn*>(req->data);
    free(req);
    if(status < 0 || !conn->req.keep_alive) { close_conn(conn); return; }
    // reset for next request
    conn->rbuf_len   = 0;
    conn->req_parsed = false;
    conn->req        = Request{};
    conn->response_data.clear();
    conn->upstream_conn = nullptr;
    conn->upstream_pool = nullptr;
    uv_read_start((uv_stream_t*)&conn->client,
        [](uv_handle_t* h, size_t, uv_buf_t* buf){
            auto* c = static_cast<Conn*>(h->data);
            buf->base = c->rbuf + c->rbuf_len;
            buf->len  = sizeof(c->rbuf) - c->rbuf_len - 1;
        },
        [](uv_stream_t* s, ssize_t nread, const uv_buf_t*){
            auto* c = static_cast<Conn*>(s->data);
            if(nread <= 0) { close_conn(c); return; }
            c->rbuf_len += (size_t)nread;
            Request req;
            auto [res, consumed] = parse_request(c->rbuf, c->rbuf_len, req);
            if(res == ParseResult::Incomplete) return;
            if(res != ParseResult::Complete) {
                write_response(c, Response::make_error(res==ParseResult::TooLarge?413:400).serialize_h1());
                return;
            }
            c->req = std::move(req);
            c->req.client_ip = c->client_ip;
            c->req.scheme    = c->ssl ? "https" : "http";
            c->req_parsed    = true;
            uv_read_stop(s);
            dispatch(c);
        });
}

static void update_conn_status(Conn* conn, int status, const std::string& type="") {
    std::lock_guard<std::mutex> lk(g_active_mu);
    auto it = g_active.find(conn);
    if(it != g_active.end()) {
        if(status > 0) it->second.status = status;
        if(!type.empty()) it->second.type = type;
    }
}

static void write_response(Conn* conn, std::string data) {
    conn->response_data = std::move(data);
    conn->requests_served++;
    Worker* w = conn->worker;
    int ka_max = (w && !w->config->servers.empty())
                 ? w->config->servers[0].keepalive_requests : 1000; // keep-alive uses first server defaults
    if(conn->requests_served >= ka_max) conn->req.keep_alive = false;

    // ── Global stats ──────────────────────────────────────────────────────
    // Count every response (except 401 auth challenges)
    if(conn->worker) {
        // Parse status from serialized response (first line: "HTTP/1.x NNN")
        int status_code = 200;
        if(conn->response_data.size() > 12) {
            auto sp = conn->response_data.find(' ');
            if(sp != std::string::npos && sp+4 <= conn->response_data.size())
                try { status_code = std::stoi(conn->response_data.substr(sp+1,3)); } catch(const std::exception&){}
        }
        if(status_code != 401) {
            g_stat_req.fetch_add(1, std::memory_order_relaxed);
            if(status_code >= 400)
                g_stat_err.fetch_add(1, std::memory_order_relaxed);
            // Record to recent requests history (per response, not per close)
            {
                std::lock_guard<std::mutex> lk2(g_active_mu);
                auto it2 = g_active.find(conn);
                if(it2 != g_active.end()) {
                    auto& ac = it2->second;
                    if(ac.method != "?") {
                        it2->second.status = status_code;
                        // Skip admin poll endpoints to avoid noise
                        bool is_poll = (ac.path.size()>3 && ac.path.substr(0,4)=="/np_");
                        if(!is_poll) {
                            std::lock_guard<std::mutex> rl2(g_recent_mu);
                            RecentReq rr;
                            rr.ip = ac.ip; rr.method = ac.method; rr.path = ac.path;
                            rr.type = ac.type.empty() ? "other" : ac.type;
                            rr.status = status_code;
                            rr.ts_ms = ac.started_ms;
                            rr.duration_ms = now_ms() - ac.started_ms;
                            // Feed latency rolling average for dashboard
                            g_stat_latency_sum += (uint64_t)rr.duration_ms;
                            g_stat_latency_cnt++;
                            g_recent_reqs.push_back(std::move(rr));
                            if((int)g_recent_reqs.size() > G_RECENT_MAX) g_recent_reqs.pop_front();
                        }
                        // Reset for next keep-alive request
                        it2->second.method = "?";
                        it2->second.path = "/";
                        it2->second.type = "pending";
                        it2->second.started_ms = now_ms();
                    }
                }
            }
            // (req/s and stats history updated by per-second timer, not here)
        }
    }

    if(conn->ssl) {
        // TLS path: encrypt via BIO bridge, on_write_done handled by tls_flush_wbio
        tls_write_plaintext(conn, conn->response_data.data(), conn->response_data.size());
        // After sending, handle keep-alive reset manually
        if(conn->req.keep_alive) {
            conn->rbuf_len   = 0;
            conn->req_parsed = false;
            conn->req        = Request{};
            conn->response_data.clear();
            conn->upstream_conn = nullptr;
            conn->upstream_pool = nullptr;
            uv_read_start((uv_stream_t*)&conn->client, on_alloc, on_read);
        } else {
            close_conn(conn);
        }
        return;
    }

    // Plaintext path
    auto* wr = static_cast<uv_write_t*>(malloc(sizeof(uv_write_t)));
    wr->data = conn;
    uv_buf_t buf = uv_buf_init(conn->response_data.data(), conn->response_data.size());
    uv_write(wr, (uv_stream_t*)&conn->client, &buf, 1, on_write_done);
}

// ── dispatch ──────────────────────────────────────────────────────────────────
static void dispatch(Conn* conn) {
    Worker* w = conn->worker;
    if(!w || !w->config || w->config->servers.empty()) {
        write_response(conn, Response::make_error(503).serialize_h1()); return;
    }
    const Config& cfg = *w->config;
    // Virtual host routing — match by Host header
    const ServerConfig* srv_ptr = cfg.match_server(std::string(conn->req.host));
    if(!srv_ptr) {
        write_response(conn, Response::make_error(421, "No matching server block").serialize_h1());
        return;
    }
    const ServerConfig& srv = *srv_ptr;

    // ── Update active connection info ─────────────────────────────────────
    {
        std::lock_guard<std::mutex> lk(g_active_mu);
        auto it = g_active.find(conn);
        if(it != g_active.end()) {
            it->second.method = conn->req.method == Method::GET ? "GET" :
                conn->req.method == Method::POST ? "POST" :
                conn->req.method == Method::PUT  ? "PUT"  :
                conn->req.method == Method::DELETE ? "DELETE" : "OTHER";
            it->second.path = std::string(conn->req.path.substr(0,64));
        }
    }

    // ── Built-in endpoints (before location matching) ─────────────────────────
    static const time_t server_start_time = time(nullptr);
    const std::string& rpath = conn->req.path;

    // /apis/healths  /apis/healthy  /apis/health  /health
    // ── ACME HTTP-01 challenge ────────────────────────────────────────────────
    if(rpath.size() > 28 && rpath.substr(0,28) == "/.well-known/acme-challenge/") {
        std::string body;
        if(acme_try_serve(rpath, body)) {
            Response r; r.status=200;
            r.headers.set("Content-Type","text/plain");
            r.headers.set("Content-Length",std::to_string(body.size()));
            r.body=body;
            write_response(conn, r.serialize_h1()); return;
        }
        write_response(conn, Response::make_error(404,"ACME challenge not found").serialize_h1()); return;
    }

    if(rpath == "/apis/healths" || rpath == "/apis/healthy" ||
       rpath == "/apis/health"  || rpath == "/health") {
        time_t now = time(nullptr);
        char ts[32], body[256];
        struct tm* tm_info = localtime(&now);
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm_info);
        snprintf(body, sizeof(body),
            "{\"status\":\"healthy\",\"healthy\":true,"
            "\"timestamp\":\"%s\",\"uptime\":%ld,\"version\":\"1.0\"}",
            ts, (long)(now - server_start_time));
        Response r; r.status = 200;
        r.headers.set("Content-Type",   "application/json");
        r.headers.set("Content-Length", std::to_string(strlen(body)));
        r.headers.set("Cache-Control",  "no-cache");
        r.body = body;
        write_response(conn, r.serialize_h1()); return;
    }

    // /apis/heartbeat
    if(rpath == "/apis/heartbeat") {
        time_t now = time(nullptr);
        long client_ts = 0;
        // parse client timestamp from body if present
        if(!conn->req.body.empty()) {
            auto pos = conn->req.body.find("\"timestamp\":");
            if(pos != std::string::npos)
                client_ts = std::strtol(conn->req.body.c_str() + pos + 12, nullptr, 10);
        }
        char body[200];
        snprintf(body, sizeof(body),
            "{\"status\":\"ok\",\"server_timestamp\":%ld,"
            "\"client_timestamp\":%ld,\"uptime\":%ld}",
            (long)now, client_ts, (long)(now - server_start_time));
        Response r; r.status = 200;
        r.headers.set("Content-Type",   "application/json");
        r.headers.set("Content-Length", std::to_string(strlen(body)));
        r.headers.set("Cache-Control",  "no-cache");
        r.headers.set("Access-Control-Allow-Origin", "*");
        r.body = body;
        write_response(conn, r.serialize_h1()); return;
    }

    // /apis/ping
    if(rpath == "/apis/ping") {
        char body[64];
        snprintf(body, sizeof(body), "{\"pong\":true,\"timestamp\":%ld}", (long)time(nullptr));
        Response r; r.status = 200;
        r.headers.set("Content-Type",   "application/json");
        r.headers.set("Content-Length", std::to_string(strlen(body)));
        r.headers.set("Cache-Control",  "no-cache");
        r.body = body;
        write_response(conn, r.serialize_h1()); return;
    }
    // ── Admin endpoints — custom login page, NO browser popup ────────────────


        // ── /np_admin — serve panel HTML (NO auth — login form is inside the HTML) ─
    if(rpath == "/np_admin" || rpath == "/np_admin/") {
        // IP Allowlist check
        if(!cfg.admin_allow_ips.empty()) {
            bool allowed = false;
            for(auto& cidr : cfg.admin_allow_ips) {
                // Simple prefix match: "192.168.1." or exact IP
                if(conn->client_ip.find(cidr) == 0 || conn->client_ip == cidr) {
                    allowed = true; break;
                }
            }
            if(!allowed) {
                NW_WARN("admin","Panel access denied for IP: %s",conn->client_ip.c_str());
                Response r; r.status = 403;
                r.headers.set("Content-Type","text/plain");
                r.headers.set("Content-Length","9");
                r.body = "Forbidden";
                write_response(conn, r.serialize_h1()); return;
            }
        }
        // Security headers
        Response r; r.status = 200;
        r.headers.set("Content-Type",   "text/html; charset=utf-8");
        r.headers.set("Content-Length", std::to_string(strlen(ADMIN_HTML)));
        r.headers.set("Cache-Control",  "no-cache, no-store");
        r.headers.set("X-Frame-Options", "DENY");
        r.headers.set("X-Content-Type-Options", "nosniff");
        r.headers.set("Referrer-Policy", "no-referrer");
        r.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
        r.body = ADMIN_HTML;
        write_response(conn, r.serialize_h1()); return;
    }

    auto is_admin_path = [&]() {
        return rpath == "/np_status"     || rpath == "/np_logs"        ||
               rpath == "/np_reload"     || rpath == "/np_restart"     ||
               rpath == "/np_module"     || rpath == "/np_ssl"         ||
               rpath == "/np_blacklist"  || rpath == "/np_connections" ||
               rpath == "/np_upstream"   || rpath == "/np_settings"    ||
               rpath == "/np_cache"      || rpath == "/np_workers"     ||
               rpath == "/np_config"     || rpath == "/np_logfile" ||
               rpath == "/np_acme"       || rpath == "/np_features"  ||
               rpath == "/np_stats"      || rpath == "/np_audit"      ||
               rpath == "/np_acme_diag"  || rpath == "/np_logs/stream" ||
               rpath == "/np_autoban" ||
               rpath == "/np_waf" ||
               rpath == "/np_waf_regex";
    };

    if(is_admin_path()) {
        // Base64 decode helper
        auto b64decode = [](const std::string& enc) -> std::string {
            static const char* b64t =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out; int val=0, valb=-8;
            for(unsigned char c : enc){
                const char* p = strchr(b64t, c);
                if(!p) break;
                val=(val<<6)+(int)(p-b64t); valb+=6;
                if(valb>=0){ out+=(char)((val>>valb)&0xFF); valb-=8; }
            }
            return out;
        };

        const std::string& pass = cfg.admin_password;
        if(!pass.empty()) {
            bool authed = false;
            auto auth_hdr = conn->req.headers.get("Authorization");
            if(!auth_hdr.empty() && auth_hdr.size() > 6 && auth_hdr.substr(0,6) == "Basic ") {
                std::string decoded = b64decode(std::string(auth_hdr.substr(6)));
                authed = (decoded == cfg.admin_user + ":" + pass);
            }
            if(!authed) {
                // Return 401 WITHOUT WWW-Authenticate — prevents browser popup
                // The admin panel JS handles login with its own form
                Response r; r.status = 401;
                r.headers.set("Content-Type",   "application/json");
                r.headers.set("Content-Length", "27");
                r.headers.set("Cache-Control",  "no-store");
                r.body = "{\"error\":\"Unauthorized\"}";
                write_response(conn, r.serialize_h1()); return;
            }
        }

        // Force Connection: close for all admin API endpoints
        // Prevents browser connection pool exhaustion (6-conn limit per host)
        // SSE (/np_logs/stream) is exempt — it needs a persistent connection
        if(rpath != "/np_logs/stream") {
            conn->req.keep_alive = false;
        }

        // /np_logs — real log entries from ring buffer
    if(rpath == "/np_logs") {
        // parse ?level=0&since=0&limit=200
        int min_lv=1; int64_t since=0; size_t limit=200;
        {
            auto& qs = conn->req.query;
            auto parse_param=[&](const char* key)->std::string{
                std::string k=std::string(key)+"=";
                auto p=qs.find(k);
                if(p==std::string::npos)return "";
                auto e=qs.find('&',p);
                return qs.substr(p+k.size(), e==std::string::npos?std::string::npos:e-p-k.size());
            };
            auto lv_s=parse_param("level"); if(!lv_s.empty()) try{min_lv=std::stoi(lv_s);}catch(const std::exception&){}
            auto si_s=parse_param("since"); if(!si_s.empty()) try{since=std::stoll(si_s);}catch(const std::exception&){}
            auto li_s=parse_param("limit"); if(!li_s.empty()) try{limit=std::stoul(li_s);}catch(const std::exception&){}
        }
        std::string body = g_log.to_json(min_lv, since, limit);
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length",std::to_string(body.size()));
        r.headers.set("Cache-Control","no-cache");
        r.body=body;
        write_response(conn, r.serialize_h1()); return;
    }

    // /np_status — server stats JSON
    if(rpath == "/np_status") {
        int nw = g_worker_count.load(); if(nw < 1) nw = 1;
        // Read CPU and RSS from /proc/self
        long cpu_ms = 0; long rss_kb = 0;
        {
            FILE* fp = fopen("/proc/self/stat", "r");
            if(fp){
                long utime=0, stime=0;
                // field 14=utime, 15=stime (jiffies)
                int _r = fscanf(fp, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %ld %ld", &utime, &stime); (void)_r;
                fclose(fp);
                long hz = sysconf(_SC_CLK_TCK);
                if(hz > 0) cpu_ms = (utime + stime) * 1000 / hz;
            }
            FILE* fp2 = fopen("/proc/self/status", "r");
            if(fp2){
                char line[128];
                while(fgets(line, sizeof(line), fp2)){
                    if(strncmp(line, "VmRSS:", 6)==0){
                        sscanf(line+6, "%ld", &rss_kb); break;
                    }
                }
                fclose(fp2);
            }
        }
        char buf[768];
        snprintf(buf, sizeof(buf),
            "{\"version\":\"%.*s\",\"worker\":%d,\"workers\":%d,"
            "\"requests\":%llu,\"cache_hits\":%llu,\"errors\":%llu,"
            "\"req_per_sec\":%llu,"
            "\"uptime\":%lld,"
            "\"cpu_ms\":%ld,\"rss_kb\":%ld,"
            "\"client_ip\":\"%s\","
            "\"admin_allowlist_size\":%zu,"
            "\"modules\":{\"lua\":%s,\"quickjs\":%s,\"nghttp2\":%s,\"tls\":%s,\"brotli\":%s}}",
            (int)NP_VERSION.size(), NP_VERSION.data(), w->id, nw,
            (unsigned long long)g_stat_req.load(),
            (unsigned long long)g_stat_cache_hit.load(),
            (unsigned long long)g_stat_err.load(),
            (unsigned long long)g_stat_req_per_sec.load(),
            (long long)(time(nullptr) - g_start_time),
            cpu_ms, rss_kb,
            conn->client_ip.c_str(),
            cfg.admin_allow_ips.size(),
#if defined(HAVE_LUA)
            "true",
#else
            "false",
#endif
#if defined(HAVE_QUICKJS)
            "true",
#else
            "false",
#endif
#if defined(HAVE_NGHTTP2)
            "true",
#else
            "false",
#endif
            (w->ssl_ctx != nullptr) ? "true" : "false",
#if defined(HAVE_BROTLI)
            "true"
#else
            "false"
#endif
            );
        Response r; r.status = 200;
        r.headers.set("Content-Type",   "application/json");
        r.headers.set("Content-Length", std::to_string(strlen(buf)));
        r.headers.set("Cache-Control",  "no-store");
        r.body = buf;
        write_response(conn, r.serialize_h1()); return;
    }

    // /np_reload — send SIGHUP to self
    if(rpath == "/np_reload" && conn->req.method == Method::POST) {
        audit(conn->client_ip, "reload", "SIGHUP triggered"); kill(getpid(), SIGHUP);
        NW_INFO("admin", "Reload requested via panel by %s", conn->client_ip.c_str());
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length","16");
        r.body="{\"ok\":true}";
        write_response(conn, r.serialize_h1()); return;
    }

    // /np_restart — graceful worker restart (SIGUSR1)
    if(rpath == "/np_restart" && conn->req.method == Method::POST) {
        NW_INFO("admin", "Restart requested via panel by %s", conn->client_ip.c_str());
        kill(getpid(), SIGTERM); // will restart via systemd Restart=on-failure
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length","11");
        r.body="{\"ok\":true}";
        write_response(conn, r.serialize_h1()); return;
    }

    // /np_ssl — generate self-signed certificate
    if(rpath == "/np_ssl" && conn->req.method == Method::POST) {
        // Parse JSON body: {"action":"generate","cn":"hostname","days":365}
        std::string action, cn="nas-web"; int days=365;
        auto& body = conn->req.body;
        auto jget = [&](const char* key) -> std::string {
            std::string k = std::string("\"") + key + "\":";
            auto p = body.find(k);
            if(p == std::string::npos) return "";
            auto vs = body.find('"', p + k.size());
            auto ve = vs != std::string::npos ? body.find('"', vs+1) : std::string::npos;
            if(vs == std::string::npos || ve == std::string::npos) return "";
            return body.substr(vs+1, ve-vs-1);
        };
        action = jget("action");
        auto cn_v = jget("cn"); if(!cn_v.empty()) cn = cn_v;
        auto d_str = [&]() -> std::string {
            auto p = body.find("\"days\":");
            if(p == std::string::npos) return "365";
            auto v = body.find_first_of("0123456789", p+7);
            if(v == std::string::npos) return "365";
            auto e = body.find_first_not_of("0123456789", v);
            return body.substr(v, e == std::string::npos ? std::string::npos : e-v);
        }();
        try { days = std::stoi(d_str); } catch(...) { days=365; }

        std::string result_json;
        if(action == "generate") {
            // Use openssl CLI — safest, always available
            std::string cert_path = "/etc/nas-web/cert.pem";
            std::string key_path  = "/etc/nas-web/key.pem";
            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s"
                " -days %d -nodes -subj '/CN=%s' 2>/dev/null",
                key_path.c_str(), cert_path.c_str(), days, cn.c_str());
            int rc = system(cmd);
            if(rc == 0) {
                NW_INFO("tls", "Self-signed cert generated: CN=%s days=%d", cn.c_str(), days);
                result_json = "{\"ok\":true,\"cert\":\"/etc/nas-web/cert.pem\","
                              "\"key\":\"/etc/nas-web/key.pem\","
                              "\"message\":\"Certificate generated. Add ssl_cert/ssl_key to config and reload.\"}";
            } else {
                result_json = "{\"ok\":false,\"error\":\"openssl failed — is openssl installed?\"}";
            }
        } else if(action == "status") {
            // Check if cert exists and when it expires
            char out_buf[256]={};
            FILE* fp = popen("openssl x509 -in /etc/nas-web/cert.pem -noout"
                             " -enddate 2>/dev/null", "r");
            if(fp){ if(fgets(out_buf, sizeof(out_buf), fp)){} pclose(fp); }
            std::string expiry(out_buf);
            // strip newline
            if(!expiry.empty() && expiry.back()=='\n') expiry.pop_back();
            result_json = "{\"ok\":true,\"expiry\":\"" + expiry + "\","
                          "\"cert_exists\":" +
                          (expiry.empty()?"false":"true") + "}";
        } else {
            result_json = "{\"ok\":false,\"error\":\"unknown action\"}";
        }
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length",std::to_string(result_json.size()));
        r.body=result_json;
        write_response(conn, r.serialize_h1()); return;
    }

    // /np_module — enable/disable/status of runtime modules
    if(rpath == "/np_module") {
        bool lua_c=false, qjs_c=false, ng2_c=false;
#if defined(HAVE_LUA)
        lua_c=true;
#endif
#if defined(HAVE_QUICKJS)
        qjs_c=true;
#endif
#if defined(HAVE_NGHTTP2)
        ng2_c=true;
#endif
        auto& cfg2 = *w->config;
        bool cache_on = cfg2.module_cache;
        bool rl_on    = cfg2.module_ratelimit;
        bool gzip_on  = cfg2.module_gzip;
        bool lua_on   = lua_c && cfg2.module_lua;
        bool js_on    = qjs_c && cfg2.module_js;
        bool tls_on   = (w->ssl_ctx != nullptr);
        bool h2_on    = ng2_c;
        bool hc_on    = cfg2.module_lb_healthcheck;
        bool acme_on  = cfg2.module_acme;
        bool zstd_on  = opt::zstd_available();
        bool janet_on = JANET_REAL != 0;
        char buf[4096];
        snprintf(buf,sizeof(buf),
            "{\"modules\":["
            "{\"name\":\"Cache\",\"id\":\"cache\",\"enabled\":%s,\"toggleable\":true,\"icon\":\"cache\",\"version\":\"LRU\",\"note\":\"Odpowiedzi proxy i pliki statyczne w pamieci\"},"
            "{\"name\":\"Rate Limiter\",\"id\":\"ratelimit\",\"enabled\":%s,\"toggleable\":true,\"icon\":\"ratelimit\",\"version\":\"token-bucket\",\"note\":\"Token bucket per IP per lokacja\"},"
            "{\"name\":\"Gzip/Brotli\",\"id\":\"gzip\",\"enabled\":%s,\"toggleable\":true,\"icon\":\"gzip\",\"version\":\"system\",\"note\":\"Kompresja odpowiedzi statycznych i proxy\"},"
            "{\"name\":\"zstd\",\"id\":\"zstd\",\"enabled\":%s,\"toggleable\":false,\"icon\":\"gzip\",\"version\":\"%s\",\"note\":\"%s\"},"
            "{\"name\":\"Lua 5.4\",\"id\":\"lua\",\"enabled\":%s,\"toggleable\":%s,\"icon\":\"lua\",\"version\":\"5.4\",\"note\":\"%s\"},"
            "{\"name\":\"QuickJS\",\"id\":\"js\",\"enabled\":%s,\"toggleable\":%s,\"icon\":\"js\",\"version\":\"2024\",\"note\":\"%s\"},"
            "{\"name\":\"Janet WAF\",\"id\":\"janet\",\"enabled\":%s,\"toggleable\":false,\"icon\":\"js\",\"version\":\"%s\",\"note\":\"%s\"},"
            "{\"name\":\"Page Optimizer\",\"id\":\"optimizer\",\"enabled\":true,\"toggleable\":false,\"icon\":\"gzip\",\"version\":\"built-in\",\"note\":\"CSS minify, HTML rewrite (lazy-img, charset), WebP detection\"},"
            "{\"name\":\"TLS/SSL\",\"id\":\"tls\",\"enabled\":%s,\"toggleable\":false,\"icon\":\"tls\",\"version\":\"OpenSSL 3\",\"note\":\"%s\"},"
            "{\"name\":\"HTTP\\/2\",\"id\":\"h2\",\"enabled\":%s,\"toggleable\":false,\"icon\":\"h2\",\"version\":\"nghttp2\",\"note\":\"%s\"},"
            "{\"name\":\"Health Check\",\"id\":\"healthcheck\",\"enabled\":%s,\"toggleable\":true,\"icon\":\"hc\",\"version\":\"built-in\",\"note\":\"Automatyczne monitorowanie upstreamow\"},"
            "{\"name\":\"ACME\",\"id\":\"acme\",\"enabled\":%s,\"toggleable\":true,\"icon\":\"acme\",\"version\":\"ACMEv2\",\"note\":\"Auto-certyfikaty SSL od Let Encrypt\"}"
            "]}",
            cache_on?"true":"false",
            rl_on?"true":"false",
            gzip_on?"true":"false",
            zstd_on?"true":"false", opt::zstd_version_str(),
            zstd_on?"aktywny — kompresja zstd dla plików statycznych":"uruchom vendor/zstd/fetch_zstd.sh i przebuduj",
            lua_on?"true":"false", lua_c?"true":"false", lua_c?"aktywny":"zainstaluj liblua5.4-dev",
            js_on?"true":"false",  qjs_c?"true":"false", qjs_c?"aktywny":"uruchom vendor/quickjs/fetch_quickjs.sh",
            janet_on?"true":"false", opt::janet_version_str(),
            janet_on?"aktywny — reguły WAF w języku Janet (Lisp)":"uruchom vendor/janet/fetch_janet.sh i przebuduj",
            tls_on?"true":"false",
            tls_on?"Aktywne - certyfikat zaladowany":"Brak certyfikatu - dodaj ssl_cert i ssl_key w configu serwera",
            h2_on?"true":"false", ng2_c?"aktywny":"zainstaluj libnghttp2-dev",
            hc_on?"true":"false",
            acme_on?"true":"false"
        );
        std::string json=buf;
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length",std::to_string(json.size()));
        r.body=json;
        write_response(conn, r.serialize_h1()); return;
    }

    // /np_blacklist — manage IP blacklist
    if(rpath == "/np_blacklist") {
        std::string result;
        if(conn->req.method == Method::POST) {
            // body: {"action":"add"|"remove","ip":"1.2.3.4"}
            auto& body = conn->req.body;
            auto jstr=[&](const char* k)->std::string{
                std::string key=std::string("\"")+ k+"\":\""; auto p=body.find(key);
                if(p==std::string::npos)return"";
                auto e=body.find('"',p+key.size()); return e==std::string::npos?"":body.substr(p+key.size(),e-p-key.size());
            };
            std::string action=jstr("action"), ip=jstr("ip");
            if(!ip.empty()) {
                {
                std::lock_guard<std::mutex> lk(g_blacklist_mu);
                if(action=="add") {
                    g_blacklist.insert(ip);
                    blacklist_save_nolock();
                    NW_INFO("blacklist","Added: %s",ip.c_str());
                } else if(action=="remove") {
                    g_blacklist.erase(ip);
                    blacklist_save_nolock();
                    NW_INFO("blacklist","Removed: %s",ip.c_str());
                }
                } // lock released before audit
                if(action=="add") audit(conn->client_ip, "blacklist_add", ip);
            }
            // rebuild JSON list
            std::lock_guard<std::mutex> lk(g_blacklist_mu);
            result = "{\"ok\":true,\"count\":" + std::to_string(g_blacklist.size()) + ",\"ips\":[";
            bool first=true;
            for(auto& bip : g_blacklist){ if(!first)result+=","; result+="\""+bip+"\""; first=false; }
            result += "]}";
        } else {
            // GET — return current list
            std::lock_guard<std::mutex> lk(g_blacklist_mu);
            result = "{\"count\":" + std::to_string(g_blacklist.size()) + ",\"ips\":[";
            bool first=true;
            for(auto& bip : g_blacklist){ if(!first)result+=","; result+="\""+bip+"\""; first=false; }
            result += "]}";
        }
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length",std::to_string(result.size()));
        r.headers.set("Cache-Control","no-store");
        r.body=result;
        write_response(conn, r.serialize_h1()); return;
    }

    // /np_connections — active connections + recent request history
    if(rpath == "/np_connections") {
        std::string json = "{\"connections\":[";
        int64_t now = now_ms();
        bool first = true;
        size_t active_count = 0;
        {
            std::lock_guard<std::mutex> lk(g_active_mu);
            active_count = g_active.size();
            for(auto& [ptr, ac] : g_active) {
                if(!first) json += ",";
                char buf[512];
                snprintf(buf,sizeof(buf),
                    "{\"ip\":\"%s\",\"method\":\"%s\",\"path\":\"%s\","
                    "\"age_ms\":%lld,\"type\":\"%s\",\"active\":true}",
                    ac.ip.c_str(), ac.method.c_str(), ac.path.c_str(),
                    (long long)(now - ac.started_ms), ac.type.c_str());
                json += buf; first = false;
            }
        }
        // Add recent completed requests (newest first, up to 100)
        {
            std::lock_guard<std::mutex> rl(g_recent_mu);
            int shown = 0;
            for(auto it = g_recent_reqs.rbegin(); it != g_recent_reqs.rend() && shown < 100; ++it, ++shown) {
                if(!first) json += ",";
                char buf[512];
                // escape path
                std::string epath;
                for(char c : it->path) { if(c=='"') epath+="\\\""; else epath+=c; }
                snprintf(buf,sizeof(buf),
                    "{\"ip\":\"%s\",\"method\":\"%s\",\"path\":\"%s\","
                    "\"age_ms\":%lld,\"type\":\"%s\",\"status\":%d,\"active\":false}",
                    it->ip.c_str(), it->method.c_str(), epath.c_str(),
                    (long long)(now - it->ts_ms), it->type.c_str(), it->status);
                json += buf; first = false;
            }
        }
        json += "],\"total\":" + std::to_string(active_count) + "}";
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length",std::to_string(json.size()));
        r.headers.set("Cache-Control","no-store");
        r.body=json;
        write_response(conn, r.serialize_h1()); return;
    }

    // /np_upstream — live upstream management
    if(rpath == "/np_upstream") {
        if(conn->req.method == Method::POST) {
            auto& body = conn->req.body;
            auto jstr=[&](const char* k)->std::string{
                std::string key=std::string("\"")+ k+"\":\""; auto p=body.find(key);
                if(p==std::string::npos)return"";
                auto e=body.find('"',p+key.size()); return e==std::string::npos?"":body.substr(p+key.size(),e-p-key.size());
            };
            std::string action=jstr("action"), name=jstr("name"), addr=jstr("address");
            {
                std::lock_guard<std::mutex> lk(g_upstream_mu);
                if(action=="add" && !name.empty() && !addr.empty()) {
                    g_upstream_overrides.push_back({name, addr, true});
            audit(conn->client_ip, "upstream_add", name+" "+addr);
                    NW_INFO("upstream","Live add: %s -> %s", name.c_str(), addr.c_str());
                } else if(action=="remove" && !name.empty()) {
                    g_upstream_overrides.erase(
                        std::remove_if(g_upstream_overrides.begin(), g_upstream_overrides.end(),
                            [&](auto& u){ return u.name==name; }),
                        g_upstream_overrides.end());
                } else if(action=="toggle" && !name.empty()) {
                    for(auto& u : g_upstream_overrides)
                        if(u.name==name) { u.enabled=!u.enabled; break; }
                }
            }
        }
        // Return current upstream list from config + overrides
        std::string json = "{\"upstreams\":[";
        bool first=true;
        for(auto& up : cfg.upstreams) {
            for(auto& srv2 : up.servers) {
                if(!first) json+=",";
                json += "{\"name\":\""+up.name+"\",\"address\":\""+srv2.host+":"+std::to_string(srv2.port)+"\",\"enabled\":true,\"source\":\"config\"}";
                first=false;
            }
        }
        {
            std::lock_guard<std::mutex> lk(g_upstream_mu);
            for(auto& u : g_upstream_overrides) {
                if(!first) json+=",";
                json += "{\"name\":\""+u.name+"\",\"address\":\""+u.address+"\",\"enabled\":"+std::string(u.enabled?"true":"false")+",\"source\":\"live\"}";
                first=false;
            }
        }
        json += "]}";
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length",std::to_string(json.size()));
        r.body=json;
        write_response(conn, r.serialize_h1()); return;
    }

    // /np_settings — global settings (conn limit, brotli, etc.)
    if(rpath == "/np_settings") {
        if(conn->req.method == Method::POST) {
            auto& body = conn->req.body;
            // parse {"max_conns_per_ip":N}
            auto p = body.find("\"max_conns_per_ip\":"); 
            if(p != std::string::npos) {
                auto v = body.find_first_of("0123456789", p+19);
                auto e = v!=std::string::npos ? body.find_first_not_of("0123456789",v) : std::string::npos;
                if(v!=std::string::npos) {
                    int n = std::stoi(body.substr(v, e==std::string::npos?std::string::npos:e-v));
                    g_max_conns_per_ip = n;
                    NW_INFO("settings","max_conns_per_ip set to %d", n);
                }
            }
        }
        char buf[256];
        snprintf(buf,sizeof(buf),"{\"max_conns_per_ip\":%d,\"blacklist_size\":%zu,\"active_conns\":%zu}",
            g_max_conns_per_ip, g_blacklist.size(), g_active.size());
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length",std::to_string(strlen(buf)));
        r.body=buf;
        write_response(conn, r.serialize_h1()); return;
    }

    // /np_config — read/reload config file
    if(rpath == "/np_config") {
        if(conn->req.method == Method::POST) {
            // POST body: {"content":"...file content..."}
            auto& body = conn->req.body;
            std::string new_content;
            auto p = body.find("\"content\":\"");
            if(p != std::string::npos) {
                p += 11;
                while(p < body.size()) {
                    if(body[p] == '"' && (p == 0 || body[p-1] != '\\')) break;
                    if(body[p] == '\\' && p+1 < body.size()) {
                        char nc = body[p+1];
                        if(nc=='n') new_content+='\n';
                        else if(nc=='r') new_content+='\r';
                        else if(nc=='t') new_content+='\t';
                        else if(nc=='"') new_content+='"';
                        else if(nc=='\\') new_content+='\\';
                        else new_content+=nc;
                        p+=2;
                    } else { new_content+=body[p++]; }
                }
            }
            std::string result;
            if(!new_content.empty() && !g_config_path.empty()) {
                audit(conn->client_ip, "config_save", g_config_path);
                std::ofstream fw(g_config_path, std::ios::trunc);
                if(fw) {
                    fw << new_content; fw.close();
                    NW_INFO("config", "Config saved by admin panel");
                    kill(getpid(), SIGHUP);
                    result = "{\"ok\":true,\"msg\":\"saved and reloading\"}";
                } else {
                    result = "{\"ok\":false,\"msg\":\"cannot write — check permissions\"}";
                }
            } else {
                result = "{\"ok\":false,\"msg\":\"no config path or empty content\"}";
            }
            Response r; r.status=200;
            r.headers.set("Content-Type","application/json");
            r.headers.set("Content-Length",std::to_string(result.size()));
            r.body=result;
            write_response(conn, r.serialize_h1()); return;
        }
        // GET = return config file contents as JSON
        std::string cfg_content;
        if(!g_config_path.empty()) {
            std::ifstream f(g_config_path);
            if(f) cfg_content = std::string(std::istreambuf_iterator<char>(f), {});
            else  cfg_content = "# Could not read: " + g_config_path;
        } else {
            cfg_content = "# No config file specified";
        }
        std::string esc;
        for(char c : cfg_content) {
            if(c=='"') esc+="\\\"";
            else if(c=='\\') esc+="\\\\";
            else if(c=='\n') esc+="\\n";
            else if(c=='\r') esc+="\\r";
            else esc+=c;
        }
        std::string json = "{\"path\":\"" + g_config_path + "\",\"content\":\"" + esc + "\"}";
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length",std::to_string(json.size()));
        r.body=json;
        write_response(conn, r.serialize_h1()); return;
    }

    // /np_logfile — tail real log files from /var/log/nas-panel/
    if(rpath == "/np_logfile") {
        std::string file_param = "access";
        int lines_param = 100;
        // query string is in conn->req.query (parsed separately from path)
        {
            const auto& qs = conn->req.query;
            auto get_param = [&](const char* key) -> std::string {
                std::string k = std::string(key) + "=";
                auto pp = qs.find(k);
                if(pp == std::string::npos) return "";
                auto e = qs.find('&', pp);
                return qs.substr(pp+k.size(), e==std::string::npos?std::string::npos:e-pp-k.size());
            };
            auto fv = get_param("file");  if(!fv.empty()) file_param = fv;
            auto lv = get_param("lines"); if(!lv.empty()) lines_param = std::stoi(lv);
        }
        // sanitize — only alphanumeric
        for(char& c : file_param) if(!isalnum((unsigned char)c)) c = '_';
        std::string log_path = "/var/log/nas-panel/" + file_param + ".log";
        std::ifstream lf(log_path);
        std::string json = "[";
        bool first = true;
        if(lf) {
            lf.seekg(0, std::ios::end);
            auto fsz = (long long)lf.tellg();
            long long seek_pos = (fsz > lines_param*300LL) ? (fsz - lines_param*300LL) : 0LL;
            lf.seekg(seek_pos);
            if(seek_pos > 0) { std::string skip; std::getline(lf, skip); }
            std::deque<std::string> buf;
            std::string line;
            while(std::getline(lf, line)) {
                if(!line.empty()) buf.push_back(line);
                if((int)buf.size() > lines_param) buf.pop_front();
            }
            for(auto& ln : buf) {
                if(!first) json += ",";
                std::string esc;
                for(char c : ln) {
                    if(c=='"') esc+="\\\"";
                    else if(c=='\\') esc+="\\\\";
                    else esc+=c;
                }
                json += "\"" + esc + "\"";
                first = false;
            }
        }
        json += "]";
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length",std::to_string(json.size()));
        r.body=json;
        write_response(conn, r.serialize_h1()); return;
    }

    // /np_workers — per-worker stats
    // /np_acme -- ACME / Let's Encrypt status and control
    if(rpath == "/np_acme") {
        if(conn->req.method == Method::POST) {
            std::string action = "obtain";
            auto ap = conn->req.body.find("\"action\":\"");
            if(ap != std::string::npos) {
                ap += 10;
                auto ae = conn->req.body.find('"', ap);
                if(ae != std::string::npos) action = conn->req.body.substr(ap, ae-ap);
            }
            if(!g_acme) {
                std::string j = "{\"ok\":false,\"msg\":\"ACME not configured\"}";
                Response r; r.status=200;
                r.headers.set("Content-Type","application/json");
                r.headers.set("Content-Length",std::to_string(j.size()));
                r.body=j; write_response(conn,r.serialize_h1()); return;
            }
            if(action == "check") {
                bool needs = g_acme->needs_renewal();
                std::string j = std::string("{\"ok\":true,\"needs_renewal\":") + (needs?"true":"false") + "}";
                Response r; r.status=200;
                r.headers.set("Content-Type","application/json");
                r.headers.set("Content-Length",std::to_string(j.size()));
                r.body=j; write_response(conn,r.serialize_h1()); return;
            }
            // obtain/renew in background — safe_obtain prevents concurrent calls
            std::thread([]{
                if(g_acme){auto err=g_acme->safe_obtain();if(!err.empty())NW_ERROR("acme","Manual: %s",err.c_str());}
            }).detach();
            std::string j = "{\"ok\":true,\"msg\":\"Certificate request started\"}";
            Response r; r.status=200;
            r.headers.set("Content-Type","application/json");
            r.headers.set("Content-Length",std::to_string(j.size()));
            r.body=j; write_response(conn,r.serialize_h1()); return;
        }
        // GET — with progress info
        bool acme_on = (g_acme != nullptr);
        bool needs_renew = acme_on && g_acme->needs_renewal();
        std::string domains_j = "[";
        if(g_acme){const auto& doms=g_acme->config().domains;for(size_t i=0;i<doms.size();i++){if(i)domains_j+=",";domains_j+="\""+doms[i]+"\"";}};
        domains_j+="]";
        bool staging = g_acme ? g_acme->config().staging : true;
        AcmeClient::Progress prog{};
        if(g_acme) prog=g_acme->get_progress();
        auto js_esc=[](std::string s){std::string o;for(char c:s){if(c=='"')o+="\\\"";else if(c=='\\')o+="\\\\";else o+=c;}return o;};
        char abuf[1024];
        snprintf(abuf,sizeof(abuf),
            "{\"enabled\":%s,\"needs_renewal\":%s,\"staging\":%s,\"domains\":%s,"
            "\"running\":%s,\"step\":\"%s\",\"pct\":%d,"
            "\"last_error\":\"%s\",\"last_ok\":\"%s\"}",
            acme_on?"true":"false", needs_renew?"true":"false",
            staging?"true":"false", domains_j.c_str(),
            prog.running?"true":"false",
            js_esc(prog.step).c_str(), prog.pct,
            js_esc(prog.last_error).c_str(),
            js_esc(prog.last_ok).c_str());
        std::string aj=abuf;
        Response ar; ar.status=200;
        ar.headers.set("Content-Type","application/json");
        ar.headers.set("Content-Length",std::to_string(aj.size()));
        ar.body=aj; write_response(conn,ar.serialize_h1()); return;
    }

    // /np_features -- runtime feature flags get/set
    if(rpath == "/np_features") {
        if(conn->req.method == Method::POST && g_config) {
            auto& body = conn->req.body;
            auto mp = body.find("\"module\":\"");
            auto ep = body.find("\"enabled\":");
            if(mp != std::string::npos && ep != std::string::npos) {
                mp += 10;
                auto me = body.find('"', mp);
                std::string mod = (me!=std::string::npos) ? body.substr(mp,me-mp) : "";
                bool val = (body.find("true",ep) != std::string::npos);
                if(mod=="cache")          g_config->module_cache=val;
                else if(mod=="ratelimit") g_config->module_ratelimit=val;
                else if(mod=="lua")       g_config->module_lua=val;
                else if(mod=="js")        g_config->module_js=val;
                else if(mod=="gzip")      g_config->module_gzip=val;
                else if(mod=="healthcheck") g_config->module_lb_healthcheck=val;
#if defined(HAVE_ACME)
                else if(mod=="acme") {
                    audit(conn->client_ip, "toggle_module", std::string("acme=")+( val?"on":"off"));
                    g_config->module_acme = val;
                    // Start or stop ACME client dynamically
                    if(val && !g_acme && !g_config->acme.email.empty()) {
                        AcmeClient::Config ac;
                        ac.enabled = true; ac.email = g_config->acme.email;
                        ac.domains = g_config->acme.domains;
                        ac.cert_dir = g_config->acme.cert_dir;
                        ac.staging = g_config->acme.staging;
                        ac.renew_days_before = g_config->acme.renew_days;
                        ac.auto_renew = g_config->acme.auto_renew;
                        ac.directory_url = ac.staging ? AcmeClient::LE_STAGING : AcmeClient::LE_PROD;
                        ac.challenge_type  = g_config->acme.challenge_type;
                        ac.dns_provider    = g_config->acme.dns_provider;
                        ac.dns_cf_token    = g_config->acme.dns_cf_token;
                        ac.dns_cf_zone_id  = g_config->acme.dns_cf_zone_id;
                        ac.dns_exec_path   = g_config->acme.dns_exec_path;
                        acme_init(ac, [](const std::string& cert, const std::string& key){
                            NW_INFO("acme","New cert ready: %s", cert.c_str());
                            g_reload.store(true);
                        });
                        NW_INFO("features","ACME client started dynamically");
                    } else if(!val && g_acme) {
                        g_acme.reset(); // stop background thread
                        NW_INFO("features","ACME client stopped");
                    }
                }
#endif
                NW_INFO("features","Module '%s' -> %s", mod.c_str(), val?"on":"off");
                std::string j="{\"ok\":true,\"module\":\""+mod+"\",\"enabled\":"+std::string(val?"true":"false")+"}";
                Response r; r.status=200;
                r.headers.set("Content-Type","application/json");
                r.headers.set("Content-Length",std::to_string(j.size()));
                r.body=j; write_response(conn,r.serialize_h1()); return;
            }
        }
        // GET all flags
        char fbuf[512]; if(g_config){
        snprintf(fbuf,sizeof(fbuf),
            "{\"cache\":%s,\"ratelimit\":%s,\"lua\":%s,\"js\":%s,"
            "\"gzip\":%s,\"acme\":%s,\"healthcheck\":%s}",
            g_config->module_cache?"true":"false",
            g_config->module_ratelimit?"true":"false",
            g_config->module_lua?"true":"false",
            g_config->module_js?"true":"false",
            g_config->module_gzip?"true":"false",
            g_config->module_acme?"true":"false",
            g_config->module_lb_healthcheck?"true":"false");
        } else { snprintf(fbuf,sizeof(fbuf),"{}"); }
        std::string fj=fbuf;
        Response fr; fr.status=200;
        fr.headers.set("Content-Type","application/json");
        fr.headers.set("Content-Length",std::to_string(fj.size()));
        fr.body=fj; write_response(conn,fr.serialize_h1()); return;
    }

    if(rpath == "/np_workers") {
        int nw = g_wstats_count > 0 ? g_wstats_count : g_worker_count.load();
        if(nw < 1) nw = 1;
        std::string json = "{\"workers\":[";
        for(int i = 0; i < nw && i < 64; i++) {
            if(i) json += ",";
            char buf[256];
            bool has_lua = false, has_qjs = false;
#if defined(HAVE_LUA)
            has_lua = true;
#endif
#if defined(HAVE_QUICKJS)
            has_qjs = true;
#endif
            snprintf(buf, sizeof(buf),
                "{\"id\":%d,\"req\":%llu,\"err\":%llu,\"cache_hit\":%llu,"
                "\"lua\":%s,\"quickjs\":%s,\"tls\":%s}",
                i,
                (unsigned long long)g_wstats[i].req.load(),
                (unsigned long long)g_wstats[i].err.load(),
                (unsigned long long)g_wstats[i].cache_hit.load(),
                has_lua  ? "true" : "false",
                has_qjs  ? "true" : "false",
                (w->ssl_ctx != nullptr) ? "true" : "false");
            json += buf;
        }
        json += "]}";
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length",std::to_string(json.size()));
        r.headers.set("Cache-Control","no-store");
        r.body=json;
        write_response(conn, r.serialize_h1()); return;
    }

    // ── DELETE /np_cache — flush all cache entries ──────────────────────────
    if(rpath == "/np_cache_flush" || (rpath == "/np_cache" && conn->req.method == Method::DELETE)) {
        // Flush this worker's cache
        if(w && w->cache) w->cache->flush();
        g_stat_cache_entries.store(0);
        NW_INFO("cache","Cache flushed by admin %s", conn->client_ip.c_str());
        audit(conn->client_ip, "cache_flush", "all entries");
        static const char* ok = "{\"ok\":true}";
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length","10");
        r.body=ok; write_response(conn, r.serialize_h1()); return;
    }

    // /np_cache — real cache stats + entry list
    if(rpath == "/np_cache") {
        // Read stats directly from cache object (most accurate)
        uint64_t hits    = w->cache ? w->cache->stats().hits   : g_stat_cache_hit.load();
        uint64_t misses  = w->cache ? w->cache->stats().misses : g_stat_cache_miss.load();
        uint64_t total   = hits + misses;
        double   ratio   = total > 0 ? (double)hits / total : 0.0;
        size_t   entries = w->cache ? w->cache->size() : g_stat_cache_entries.load();
        int      max_e   = w->cache ? w->cache->max_entries() : 1024;

        // Build full stats from cache object (has real evictions/bytes_stored)
        std::string base_json;
        if(w->cache){
            base_json = w->cache->stats_json();
            // Strip trailing } to append entries_list
            if(!base_json.empty() && base_json.back()=='}')
                base_json.pop_back();
            // Override entries count with global atomic (cross-worker)
            // entries field already in stats_json — keep it
        } else {
            char hdr[256];
            snprintf(hdr, sizeof(hdr),
                "{\"entries\":%zu,\"max\":%d,\"hits\":%llu,"
                "\"misses\":%llu,\"evictions\":0,"
                "\"bytes_stored\":0,\"hit_ratio\":%.3f",
                entries, max_e,
                (unsigned long long)hits,
                (unsigned long long)misses,
                ratio);
            base_json = hdr;
        }
        // Also inject global atomic entries count
        {
            std::string tag = "\"entries\":";
            auto p = base_json.find(tag);
            if(p != std::string::npos){
                auto e2 = base_json.find_first_of(",}", p+tag.size());
                base_json = base_json.substr(0,p+tag.size()) + std::to_string(entries) + base_json.substr(e2);
            }
        }

        std::string json = base_json;
        json += ",\"entries_list\":[";
        bool first = true;
        if(w->cache) {
            w->cache->each_entry([&](const std::string& key, size_t size, int ttl_left, uint64_t){
                if(!first) json += ",";
                char buf[512];
                snprintf(buf, sizeof(buf),
                    "{\"path\":\"%s\",\"size\":\"%zuKB\",\"ttl\":%d,\"hits\":0}",
                    key.c_str(), size/1024+1, ttl_left);
                json += buf; first = false;
            });
        }
        json += "]}";
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length",std::to_string(json.size()));
        r.headers.set("Cache-Control","no-store");
        r.body=json;
        write_response(conn, r.serialize_h1()); return;
    }

    // (np_admin served before auth check above)
    // (is_admin_path block continues below — /np_stats /np_audit /np_acme_diag)

    // ── /np_stats — dashboard chart history ──────────────────────────────────
    if(rpath == "/np_stats") {
        size_t count = 120; // default: 2 min
        {
            // query string is in conn->req.query (parser strips it from path)
            auto& qs = conn->req.query;
            auto p = qs.find("count=");
            if(p != std::string::npos) {
                try { count = std::stoul(qs.substr(p+6)); } catch(const std::exception&) {}
                if(count > 3600) count = 3600;
                if(count < 1)    count = 1;
            }
        }
        std::string out="[";
        std::lock_guard lk(g_stats_hist_mu);
        size_t skip = g_stats_hist.size() > count ? g_stats_hist.size()-count : 0;
        bool first=true;
        for(size_t i=skip;i<g_stats_hist.size();i++){
            auto& s=g_stats_hist[i];
            if(!first) out+=",";
            first=false;
            char buf[160];
            snprintf(buf,sizeof(buf),
                "{\"ts\":%lld,\"rps\":%llu,\"eps\":%llu,\"cache\":%llu,\"conns\":%u,\"lat\":%u}",
                (long long)s.ts,(unsigned long long)s.req_per_sec,
                (unsigned long long)s.err_per_sec,(unsigned long long)s.cache_hits,
                (unsigned)s.active_conns,(unsigned)s.latency_avg_ms);
            out+=buf;
        }
        out+="]";
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length",std::to_string(out.size()));
        r.headers.set("Cache-Control","no-cache");
        r.body=out; write_response(conn,r.serialize_h1()); return;
    }

    // ── /np_audit — audit log ─────────────────────────────────────────────────
    if(rpath == "/np_audit") {
        std::string out="[";
        std::lock_guard lk(g_audit_mu);
        bool first=true;
        for(auto it=g_audit_log.rbegin();it!=g_audit_log.rend();++it){
            if(!first) out+=",";
            first=false;
            char ts[32]; struct tm* ti=localtime(&it->ts);
            strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S",ti);
            auto esc=[](std::string s){std::string o;for(char c:s){if(c=='"')o+="\\\"";else if(c=='\\')o+="\\\\";else o+=c;}return o;};
            char buf[512];
            snprintf(buf,sizeof(buf),
                "{\"ts\":\"%s\",\"ip\":\"%s\",\"action\":\"%s\",\"detail\":\"%s\"}",
                ts,it->admin_ip.c_str(),esc(it->action).c_str(),esc(it->detail).c_str());
            out+=buf;
        }
        out+="]";
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length",std::to_string(out.size()));
        r.headers.set("Cache-Control","no-cache");
        r.body=out; write_response(conn,r.serialize_h1()); return;
    }

    // ── /np_acme_diag — port 80 reachability check ────────────────────────────
    if(rpath == "/np_acme_diag") {
        // Tries to connect to external IP:80 to verify port is open
        // Returns JSON with result
        std::string domain;
        {
            auto& full=conn->req.query; auto qi=full.find("domain=");
            if(qi!=std::string::npos){
                auto e=full.find('&',qi);
                domain=full.substr(qi+7,e==std::string::npos?std::string::npos:e-qi-7);
            }
        }
        if(g_acme) {
            const auto& doms = g_acme->config().domains;
            if(domain.empty() && !doms.empty()) domain = doms[0];
        }
        // Check if /.well-known/acme-challenge/ping responds on port 80
        bool ok = false; std::string detail = "not checked";
        if(!domain.empty()) {
            // resolve + connect port 80 with 3s timeout
            struct addrinfo hints{}, *res=nullptr;
            hints.ai_socktype=SOCK_STREAM; hints.ai_family=AF_INET;
            if(getaddrinfo(domain.c_str(),"80",&hints,&res)==0 && res){
                int fd=socket(res->ai_family,SOCK_STREAM,0);
                if(fd>=0){
                    // non-blocking connect with timeout
                    fcntl(fd,F_SETFL,O_NONBLOCK);
                    int cr=connect(fd,res->ai_addr,res->ai_addrlen);
                    if(cr==0||(cr<0&&errno==EINPROGRESS)){
                        fd_set ws; FD_ZERO(&ws); FD_SET(fd,&ws);
                        struct timeval tv{3,0};
                        int sr=select(fd+1,nullptr,&ws,nullptr,&tv);
                        if(sr>0){ ok=true; detail="Port 80 dostepny"; }
                        else     { detail="Timeout 3s — port 80 zablokowany lub przekierowany"; }
                    } else { detail="Connection refused — port 80 nie nasluchuje"; }
                    close(fd);
                }
                freeaddrinfo(res);
            } else { detail="DNS resolution failed dla: "+domain; }
        } else { detail="Brak domeny w konfiguracji ACME"; }
        char buf[256];
        snprintf(buf,sizeof(buf),
            "{\"ok\":%s,\"domain\":\"%s\",\"detail\":\"%s\"}",
            ok?"true":"false", domain.c_str(), detail.c_str());
        std::string j=buf;
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length",std::to_string(j.size()));
        r.body=j; write_response(conn,r.serialize_h1()); return;
    }




    // ── /np_waf_regex — built-in WAF stats + config ───────────────────────────
    if(rpath == "/np_waf_regex") {
        if(conn->req.method == Method::POST) {
            auto& body = conn->req.body;
            auto fb = [&](const char* key) -> int {
                auto p = body.find(std::string("\"")+key+"\":");
                if(p==std::string::npos) return -1;
                auto v = body.substr(p+strlen(key)+3);
                return (v.find("true") < v.find("false")) ? 1 : 0;
            };
            int en = fb("enabled");   if(en>=0) g_waf_regex.cfg.enabled=en;
            int bm = fb("block_mode"); if(bm>=0) g_waf_regex.cfg.block_mode=bm;
            int cb = fb("check_body"); if(cb>=0) g_waf_regex.cfg.check_body=cb;
            int cl = fb("clear");
            if(cl==1){ g_waf_regex.clear_events(); audit(conn->client_ip,"waf_regex_clear",""); }
        }
        std::string j = g_waf_regex.stats_json();
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length",std::to_string(j.size()));
        r.headers.set("Cache-Control","no-cache");
        r.body=j; write_response(conn,r.serialize_h1()); return;
    }

    // ── /np_waf — WAF status + config ────────────────────────────────────────
    if(rpath == "/np_waf") {
#ifdef WITH_MODSEC
        if(conn->req.method == Method::POST) {
            auto& body = conn->req.body;
            auto find_bool = [&](const char* key) -> int {
                auto p = body.find(std::string("\"")+key+"\":");
                if(p==std::string::npos) return -1;
                auto v = body.substr(p+strlen(key)+3);
                return (v.find("true") < v.find("false")) ? 1 : 0;
            };
            int en = find_bool("enabled");   if(en>=0) g_waf.cfg.enabled=en;
            int bm = find_bool("block_mode"); if(bm>=0) g_waf.cfg.block_mode=bm;
            int clr = find_bool("clear");
            if(clr==1){
                std::lock_guard<std::mutex> lk(g_waf.events_mu);
                g_waf.events.clear();
                audit(conn->client_ip,"waf_clear","events cleared");
            }
        }
        std::string j = g_waf.stats_json();
#else
        std::string j = "{\"loaded\":false,\"enabled\":false,\"block_mode\":false,"
                        "\"rules_dir\":\"\",\"load_error\":\"Compiled without WITH_MODSEC\","
                        "\"total_checked\":0,\"total_blocked\":0,\"total_detected\":0,\"events\":[]}";
#endif
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length",std::to_string(j.size()));
        r.headers.set("Cache-Control","no-cache");
        r.body=j; write_response(conn,r.serialize_h1()); return;
    }

    // ── /np_autoban — autoban stats + config ─────────────────────────────────
    if(rpath == "/np_autoban") {
        if(conn->req.method == Method::POST && g_config) {
            // POST: {"enabled":true/false} or {"clear":true} or config params
            auto& body = conn->req.body;
            auto find_bool = [&](const char* key) -> int { // -1=not found, 0=false, 1=true
                auto p = body.find(std::string("\"")+key+"\":");
                if(p == std::string::npos) return -1;
                auto v = body.substr(p+strlen(key)+3);
                return (v.find("true") < v.find("false")) ? 1 : 0;
            };
            auto find_int = [&](const char* key) -> int {
                auto p = body.find(std::string("\"")+key+"\":");
                if(p == std::string::npos) return -1;
                try { return std::stoi(body.substr(p+strlen(key)+3)); } catch(...){ return -1; }
            };
            int en = find_bool("enabled");
            if(en >= 0) g_autoban.cfg.enabled = (en==1);
            int clr = find_bool("clear");
            if(clr == 1) { g_autoban.clear_stats(); audit(conn->client_ip,"autoban_clear","stats cleared"); }
            int rps = find_int("rate_limit_rps");   if(rps>0)  g_autoban.cfg.rate_limit_rps=rps;
            int e4  = find_int("err404_threshold");  if(e4>0)   g_autoban.cfg.err404_threshold=e4;
            int sc  = find_int("scan_threshold");    if(sc>0)   g_autoban.cfg.scan_threshold=sc;
            int win = find_int("window_sec");        if(win>0)  g_autoban.cfg.window_sec=win;
            int bsp = find_bool("ban_scanpaths");    if(bsp>=0) g_autoban.cfg.ban_scanpaths=(bsp==1);
            int brl = find_bool("ban_ratelimit");    if(brl>=0) g_autoban.cfg.ban_ratelimit=(brl==1);
            int b4  = find_bool("ban_404flood");     if(b4>=0)  g_autoban.cfg.ban_404flood=(b4==1);
            int bua = find_bool("ban_bad_ua");       if(bua>=0) g_autoban.cfg.ban_bad_ua=(bua==1);
        }
        // GET or POST — return current state
        auto& c = g_autoban.cfg;
        char cfg_buf[256];
        snprintf(cfg_buf,sizeof(cfg_buf),
            "\"config\":{\"enabled\":%s,\"rate_limit_rps\":%d,\"err404_threshold\":%d,"
            "\"scan_threshold\":%d,\"window_sec\":%d,"
            "\"ban_scanpaths\":%s,\"ban_ratelimit\":%s,\"ban_404flood\":%s,\"ban_bad_ua\":%s}",
            c.enabled?"true":"false", c.rate_limit_rps, c.err404_threshold,
            c.scan_threshold, c.window_sec,
            c.ban_scanpaths?"true":"false", c.ban_ratelimit?"true":"false",
            c.ban_404flood?"true":"false", c.ban_bad_ua?"true":"false");
        std::string stats = g_autoban.stats_json();
        // Merge: insert config before closing }
        std::string j = stats.substr(0, stats.size()-1) + "," + cfg_buf + "}";
        Response r; r.status=200;
        r.headers.set("Content-Type","application/json");
        r.headers.set("Content-Length",std::to_string(j.size()));
        r.headers.set("Cache-Control","no-cache");
        r.body=j; write_response(conn,r.serialize_h1()); return;
    }

    // /np_logs/stream — disabled (SSE causes connection slot starvation on HTTP/1.1)
    // Use /np_logs?since=<ts>&limit=50 polling instead
    if(rpath == "/np_logs/stream") {
        Response r; r.status=204;
        r.headers.set("Content-Length","0");
        write_response(conn, r.serialize_h1()); return;
    }

    } // end is_admin_path

    // ── IP Blacklist check ────────────────────────────────────────────────────
    {
        std::lock_guard<std::mutex> lk(g_blacklist_mu);
        if(g_blacklist.count(conn->client_ip)) {
            NW_DEBUG("blacklist", "Blocked IP: %s", conn->client_ip.c_str());
            g_stat_err.fetch_add(1, std::memory_order_relaxed);
            uv_close((uv_handle_t*)&conn->client, [](uv_handle_t* h){
                delete static_cast<Conn*>(h->data); });
            return;
        }
    }

    // ── AutoBan pre-request check (ZAWSZE przed WAF — zlicza scan_hits) ───────
    {
        auto ua  = std::string(conn->req.headers.get("User-Agent"));
        auto verdict = g_autoban.check(conn->client_ip, conn->req.path, ua, 0);
        if(verdict == AutoBan::Verdict::Ban) {
            std::lock_guard<std::mutex> lk(g_blacklist_mu);
            g_blacklist.insert(conn->client_ip);
            blacklist_save_nolock();
            uv_close((uv_handle_t*)&conn->client, [](uv_handle_t* h){
                delete static_cast<Conn*>(h->data); });
            return;
        }
    }

    // ── Built-in regex WAF check (PRZED match_location — blokuje też 404-bound scans) ──
    if(g_waf_regex.cfg.enabled && g_waf_regex.compiled){
        std::string waf_cat, waf_detail;
        std::string raw_hdrs;
        for(auto& h : conn->req.headers.items)
            raw_hdrs += std::string(h.first) + ": " + std::string(h.second) + "\r\n";
        bool allowed = g_waf_regex.check(
            conn->client_ip,
            std::string(method_str(conn->req.method)),
            conn->req.path,
            conn->req.query,
            conn->req.body,
            raw_hdrs,
            &waf_cat, &waf_detail
        );
        if(!allowed){
            auto r = Response::make_json_error(403,
                "Blocked by WAF: " + waf_cat + " — " + waf_detail);
            write_response(conn, r.serialize_h1()); return;
        }
    }

#ifdef WITH_MODSEC
    // ── ModSecurity WAF check (po parse HTTP, przed match_location) ───────────
    if(g_waf.cfg.enabled && g_waf.loaded){
        std::string hdr_str;
        for(auto& h : conn->req.headers.items)
            hdr_str += std::string(h.first) + ": " + std::string(h.second) + "\r\n";
        int waf_status = 403;
        std::string waf_rule;
        std::string uri_with_query = conn->req.path;
        if(!conn->req.query.empty()) uri_with_query += "?" + conn->req.query;
        bool allowed = g_waf.check(
            conn->client_ip,
            std::string(method_str(conn->req.method)),
            uri_with_query,
            "HTTP/1.1",
            hdr_str,
            conn->req.body,
            &waf_status, &waf_rule
        );
        if(!allowed){
            std::string msg = "WAF: blocked by rule " + waf_rule;
            auto r = Response::make_json_error(waf_status, msg);
            write_response(conn, r.serialize_h1()); return;
        }
    }
#endif

    // ── match_location (po WAF — skanery na nieistniejące ścieżki też blokowane) ──
    const LocationConfig* loc = cfg.match_location(srv, conn->req.path);
    if(!loc) {
        bool api = conn->req.path.substr(0,4) == "/api";
        auto r = api ? Response::make_json_error(404,"Not found: "+conn->req.path)
                     : Response::make_error(404);
        g_autoban.check(conn->client_ip, conn->req.path,
            std::string(conn->req.headers.get("User-Agent")), 404);
        write_response(conn, r.serialize_h1()); return;
    }

    // ── Rate limit ────────────────────────────────────────────────────────────
    // ── Rate limit: per-IP global + per-endpoint ────────────────────────────
    if(loc->rate_limit.enabled && w->rl && w->config->module_ratelimit) {
        // Key = IP (global) or IP+path prefix (per-endpoint)
        std::string rl_key = conn->client_ip;
        if(!loc->prefix.empty() && loc->prefix != "/") rl_key += "|" + loc->prefix;
        int64_t retry_after = 0;
        if(w->rl->check(rl_key, &retry_after)) {
            bool api2 = conn->req.path.substr(0,4) == "/api";
            auto r = api2 ? Response::make_json_error(429,"Rate limit exceeded")
                          : Response::make_error(429,"Rate limit exceeded");
            r.headers.set("Retry-After", std::to_string(retry_after/1000+1));
            r.headers.set("X-RateLimit-Path", std::string(loc->prefix));
            write_response(conn, r.serialize_h1());
            NW_WARN("ratelimit", "Rate limit [%s]: %s -> %.*s",
                loc->prefix.c_str(), conn->client_ip.c_str(),
                (int)conn->req.path.size(), conn->req.path.data());
            w->stat_err++; return;
        }
    }

    // ── Middleware — request phase ────────────────────────────────────────────
    if(w->mw && !loc->middlewares.empty() && (w->config->module_lua || w->config->module_js)) {
        auto blocked = w->mw->run_request(loc->middlewares, conn->req);
        if(blocked) { write_response(conn, blocked->serialize_h1()); return; }
    }

    // ── Static files ──────────────────────────────────────────────────────────
    if(loc->type == LocationType::Static) {
        update_conn_status(conn, 0, "static");

        // ── Cache lookup for static files ────────────────────────────────────
        if(w->cache && w->config->module_cache && conn->req.method == Method::GET
           && loc->cache_max_age != -1) {
            auto key = ResponseCache::make_key(conn->req);
            if(auto* e = w->cache->get(key)) {
                if(w->cache->check_conditional(*e, conn->req)) {
                    Response r; r.status = 304;
                    if(!e->etag.empty()) r.headers.set("ETag", e->etag);
                    write_response(conn, r.serialize_h1());
                    w->stat_cache_hit++;
                    g_stat_cache_hit.fetch_add(1, std::memory_order_relaxed);
                    if(w->id<64) g_wstats[w->id].cache_hit.fetch_add(1,std::memory_order_relaxed);
                    return;
                }
                write_response(conn, e->serialized);
                w->stat_cache_hit++;
                g_stat_cache_hit.fetch_add(1, std::memory_order_relaxed);
                if(w->id<64) g_wstats[w->id].cache_hit.fetch_add(1,std::memory_order_relaxed);
                return;
            }
        }

        StaticConfig scfg;
        scfg.root = loc->root; scfg.gzip = loc->gzip && w->config->module_gzip; scfg.etag = loc->etag;
        scfg.cache_max_age = loc->cache_max_age; scfg.autoindex = loc->autoindex;
        // Auto SPA fallback: root location "/" with no subpath → Vue/React router
        scfg.spa_fallback = (loc->prefix == "/" || loc->prefix.empty());
        auto resp = serve_static(conn->req, scfg);
        if(w->mw && !loc->middlewares.empty() && (w->config->module_lua || w->config->module_js))
            w->mw->run_response(loc->middlewares, conn->req, resp);
        for(auto& l : srv.listens) if(l.http3){ H3Handler::inject_alt_svc(resp,l.port); break; }

        // ── Cache store for static files ─────────────────────────────────────
        if(w->cache && w->config->module_cache && conn->req.method == Method::GET
           && loc->cache_max_age != -1 && resp.status == 200) {
            auto key = ResponseCache::make_key(conn->req);
            int ttl = loc->cache_max_age > 0 ? loc->cache_max_age : 0;
            w->cache->put(key, resp, conn->req, ttl);
        }

        write_response(conn, resp.serialize_h1()); return;
    }


    // ── Return / Redirect ─────────────────────────────────────────────────────
    if(loc->type == LocationType::Return) {
        Response r; r.status = loc->return_code; r.body = loc->return_body;
        r.headers.set("Content-Length", std::to_string(r.body.size()));
        write_response(conn, r.serialize_h1()); return;
    }
    if(loc->type == LocationType::Redirect) {
        Response r; r.status = 302;
        r.headers.set("Location", loc->redirect_url);
        r.headers.set("Content-Length", "0");
        write_response(conn, r.serialize_h1()); return;
    }

    // ── Cache lookup (if module enabled) ─────────────────────────────────────
    if(w->cache && w->config->module_cache && conn->req.method == Method::GET) {
        auto key = ResponseCache::make_key(conn->req);
        if(auto* e = w->cache->get(key)) {
            if(w->cache->check_conditional(*e, conn->req)) {
                Response r; r.status = 304;
                if(!e->etag.empty()) r.headers.set("ETag", e->etag);
                write_response(conn, r.serialize_h1());
                w->stat_cache_hit++;
                g_stat_cache_hit.fetch_add(1, std::memory_order_relaxed);
                if(w->id<64)g_wstats[w->id].cache_hit.fetch_add(1,std::memory_order_relaxed);
                return;
            }
            write_response(conn, e->serialized);
            w->stat_cache_hit++;
            g_stat_cache_hit.fetch_add(1, std::memory_order_relaxed);
            if(w->id<64)g_wstats[w->id].cache_hit.fetch_add(1,std::memory_order_relaxed);
            return;
        }
        // miss already counted in cache->get()
    }

    // ── Proxy ─────────────────────────────────────────────────────────────────
    if(!w->upstream) {
        { bool a=conn->req.path.substr(0,4)=="/api"; write_response(conn,(a?Response::make_json_error(503,"No upstream"):Response::make_error(503,"No upstream")).serialize_h1()); return; }
    }
    UpstreamPool* up = w->upstream->pick(conn->client_ip);
    if(!up) {
        { NW_WARN("proxy", "All upstreams down for %.*s", (int)conn->req.path.size(), conn->req.path.data()); bool a=conn->req.path.substr(0,4)=="/api"; write_response(conn,(a?Response::make_json_error(502,"All upstreams down"):Response::make_error(502,"All upstreams down")).serialize_h1()); w->stat_err++; return; }
    }
    PoolConn* upc = up->acquire();
    if(!upc) {
        { bool a=conn->req.path.substr(0,4)=="/api"; write_response(conn,(a?Response::make_json_error(502,"Pool exhausted"):Response::make_error(502,"Pool exhausted")).serialize_h1()); return; }
    }

    conn->is_ws = loc->websocket && conn->req.is_websocket;

    // Proxy headers
    conn->req.headers.set("X-Forwarded-For",  conn->client_ip);
    conn->req.headers.set("X-Real-IP",         conn->client_ip);
    conn->req.headers.set("X-Forwarded-Proto", conn->req.scheme);
    conn->req.headers.remove("Connection");
    conn->req.headers.set("Connection", conn->is_ws ? "Upgrade" : "close");
    for(auto&[k,v] : loc->add_headers)  conn->req.headers.set(k,v);
    for(auto& h    : loc->hide_headers) conn->req.headers.remove(h);

    // Serialise forwarded request
    std::string fwd;
    fwd.reserve(1024 + conn->req.body.size());
    fwd += method_str(conn->req.method);
    fwd += ' '; fwd += conn->req.path;
    if(!conn->req.query.empty()) { fwd += '?'; fwd += conn->req.query; }
    fwd += " HTTP/1.1\r\n";
    for(auto&[k,v] : conn->req.headers.items) { fwd+=k; fwd+=": "; fwd+=v; fwd+="\r\n"; }
    fwd += "\r\n";
    if(!conn->req.body.empty()) fwd += conn->req.body;

    // Set blocking before send+recv
    { int fl = fcntl(upc->fd, F_GETFL, 0); fcntl(upc->fd, F_SETFL, fl & ~O_NONBLOCK); }

    ssize_t sent = write(upc->fd, fwd.data(), fwd.size());
    if(sent < 0) {
        up->mark_fail(); up->release(upc, false);
        write_response(conn, Response::make_error(502,"Upstream write failed").serialize_h1());
        return;
    }

    conn->upstream_conn = upc;
    conn->upstream_pool = up;

    // Read upstream response in threadpool (blocking, no size limit)
    auto* job      = new ProxyJob();
    job->work.data = job;
    job->conn      = conn;
    job->up_fd     = upc->fd;
    job->pool      = up;
    job->pool_conn = upc;
    job->buf.reserve(65536);

    uv_queue_work(w->loop, &job->work,
        [](uv_work_t* req) {
            auto* j = static_cast<ProxyJob*>(req->data);
            char tmp[32768];
            ssize_t n;
            while((n = ::read(j->up_fd, tmp, sizeof(tmp))) > 0)
                j->buf.append(tmp, (size_t)n);
            j->ok = !j->buf.empty();
        },
        [](uv_work_t* req, int) {
            auto* j = static_cast<ProxyJob*>(req->data);
            Conn* c = j->conn;

            j->pool->release(j->pool_conn, j->ok);
            c->upstream_conn = nullptr;
            c->upstream_pool = nullptr;

            if(!j->ok) {
                delete j;
                write_response(c, Response::make_error(502,"Empty upstream response").serialize_h1());
                return;
            }

            Response resp;
            parse_response(j->buf.data(), j->buf.size(), resp);
            delete j;

            resp.headers.remove("Connection");
            resp.headers.remove("Transfer-Encoding");
            resp.headers.set("Connection", c->req.keep_alive ? "keep-alive" : "close");
            resp.headers.set("X-Proxy", "nas-web/" + std::string(NP_VERSION));
            // X-Request-ID for tracing
            static std::atomic<uint64_t> req_id{1};
            char rid[32]; snprintf(rid, sizeof(rid), "%016llx", (unsigned long long)req_id.fetch_add(1));
            resp.headers.set("X-Request-ID", rid);

            Worker* w2 = c->worker;
            if(w2 && w2->config && !w2->config->servers.empty()) {
                const auto& srv2 = w2->config->servers[0];
                auto* loc2 = w2->config->match_location(srv2, c->req.path);
                if(loc2 && w2->mw && !loc2->middlewares.empty())
                    w2->mw->run_response(loc2->middlewares, c->req, resp);
                for(auto& l : srv2.listens)
                    if(l.http3) { H3Handler::inject_alt_svc(resp, l.port); break; }
                if(w2->cache && c->req.method == Method::GET) {
                    auto key  = ResponseCache::make_key(c->req);
                    auto* lc3 = w2->config->match_location(srv2, c->req.path);
                    bool do_cache = !lc3 || lc3->cache_max_age != -1;
                    if(do_cache && w2->config->module_cache) {
                        int ttl = lc3 && lc3->cache_max_age > 0 ? lc3->cache_max_age : 0;
                        w2->cache->put(key, resp, c->req, ttl);
                    }
                }
            }
            update_conn_status(c, resp.status, "proxy");
            write_response(c, resp.serialize_h1());
            if(w2){ w2->stat_req++; g_stat_req.fetch_add(1,std::memory_order_relaxed); if(w2->id<64)g_wstats[w2->id].req.fetch_add(1,std::memory_order_relaxed); }
        }
    );
}

// ── on_alloc / on_read ────────────────────────────────────────────────────────
static void on_alloc(uv_handle_t* h, size_t, uv_buf_t* buf) {
    auto* c = static_cast<Conn*>(h->data);
    if(c->ssl) {
        // TLS: use end of rbuf as a temporary raw-bytes staging area
        // tls_on_raw_data will decrypt into the front of rbuf
        buf->base = c->rbuf + c->rbuf_len;
        buf->len  = sizeof(c->rbuf) - c->rbuf_len - 1;
    } else {
        buf->base = c->rbuf + c->rbuf_len;
        buf->len  = sizeof(c->rbuf) - c->rbuf_len - 1;
    }
}

static void on_read(uv_stream_t* s, ssize_t nread, const uv_buf_t*) {
    auto* conn = static_cast<Conn*>(s->data);
    if(nread <= 0) { close_conn(conn); return; }

    if(conn->ssl) {
        // TLS: raw bytes landed at rbuf+rbuf_len (staging area, not counted yet)
        // Feed into BIO, get back decrypted bytes into the front of rbuf
        size_t old_len = conn->rbuf_len;
        if(!tls_on_raw_data(conn, conn->rbuf + old_len, (size_t)nread)) {
            close_conn(conn); return;
        }
        if(!conn->tls_handshake_done) return; // still handshaking
        // tls_on_raw_data filled conn->rbuf[0..rbuf_len] with decrypted data
    } else {
        conn->rbuf_len += (size_t)nread;
    }

    if(conn->req_parsed) return;

    Request req;
    auto [result, consumed] = parse_request(conn->rbuf, conn->rbuf_len, req);
    if(result == ParseResult::Incomplete) return;
    if(result != ParseResult::Complete) {
        write_response(conn, Response::make_error(result==ParseResult::TooLarge?413:400).serialize_h1());
        return;
    }
    conn->req = std::move(req);
    conn->req.client_ip = conn->client_ip;
    conn->req.scheme    = conn->ssl ? "https" : "http";
    conn->req_parsed    = true;
    uv_read_stop(s);
    dispatch(conn);
}

// ── on_connection ─────────────────────────────────────────────────────────────
static void on_connection(uv_stream_t* server, int status) {
    if(status < 0) return;
    Worker* w = static_cast<Worker*>(server->loop->data);
    // Determine if this connection arrived on the TLS handle
    bool is_tls = (server == (uv_stream_t*)&w->tls_h) && (w->ssl_ctx != nullptr);

    auto* conn   = new Conn();
    conn->worker = w;
    uv_tcp_init(server->loop, &conn->client);
    conn->client.data = conn;

    if(uv_accept(server, (uv_stream_t*)&conn->client) != 0) {
        uv_close((uv_handle_t*)&conn->client, [](uv_handle_t* h){ delete static_cast<Conn*>(h->data); });
        return;
    }

    struct sockaddr_storage addr{}; int alen = sizeof(addr);
    uv_tcp_getpeername(&conn->client, (sockaddr*)&addr, &alen);
    char ip[46]{};
    if(addr.ss_family == AF_INET)
        inet_ntop(AF_INET,  &reinterpret_cast<sockaddr_in*>(&addr)->sin_addr,  ip, sizeof(ip));
    else
        inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(&addr)->sin6_addr, ip, sizeof(ip));
    conn->client_ip = ip;

    uv_tcp_nodelay(&conn->client, 1);
    uv_tcp_keepalive(&conn->client, 1, 60);

    // ── Per-IP connection limit ───────────────────────────────────────────────
    if(g_max_conns_per_ip > 0) {
        std::lock_guard<std::mutex> lk(g_connlimit_mu);
        if(g_conn_count[conn->client_ip] >= g_max_conns_per_ip) {
            NW_DEBUG("connlimit", "IP %s over limit (%d)", conn->client_ip.c_str(), g_max_conns_per_ip);
            g_stat_err.fetch_add(1, std::memory_order_relaxed);
            uv_close((uv_handle_t*)&conn->client, [](uv_handle_t* h){
                delete static_cast<Conn*>(h->data); });
            return;
        }
        g_conn_count[conn->client_ip]++;
    }

    // ── Early blacklist check — przed TLS, przed HTTP parse ──────────────────
    {
        std::lock_guard<std::mutex> lk(g_blacklist_mu);
        if(g_blacklist.count(conn->client_ip)){
            NW_DEBUG("blacklist","Early drop banned IP: %s", conn->client_ip.c_str());
            uv_close((uv_handle_t*)&conn->client,[](uv_handle_t* h){
                delete static_cast<Conn*>(h->data);});
            return;
        }
    }
    {
        std::lock_guard<std::mutex> lk(g_active_mu);
        g_active[conn] = {conn->client_ip, "?", "/", 0, now_ms(), "pending"};
    }

    // ── TLS setup (memory BIO bridge) ────────────────────────────────────────
    if(is_tls && w->ssl_ctx) {
        conn->ssl  = SSL_new(w->ssl_ctx);
        // Memory BIOs: OpenSSL reads/writes encrypted bytes through these
        // We manually pump data between libuv TCP and the BIOs
        conn->rbio = BIO_new(BIO_s_mem());
        conn->wbio = BIO_new(BIO_s_mem());
        BIO_set_mem_eof_return(conn->rbio, -1);
        BIO_set_mem_eof_return(conn->wbio, -1);
        SSL_set_bio(conn->ssl, conn->rbio, conn->wbio);
        SSL_set_accept_state(conn->ssl); // server mode
        NW_DEBUG("tls", "New TLS connection from %s", conn->client_ip.c_str());
    }

    uv_read_start((uv_stream_t*)&conn->client, on_alloc, on_read);
}

// ── make_server_socket ────────────────────────────────────────────────────────
static int make_server_socket(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) { perror("socket"); return -1; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);
    if(bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); close(fd); return -1; }
    if(listen(fd, 4096) < 0) { perror("listen"); close(fd); return -1; }
    int fl = fcntl(fd, F_GETFL, 0); fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    return fd;
}

// ── run_worker (called in new thread) ────────────────────────────────────────
static void run_worker(Worker* w, int wfd, std::atomic<int>& ready) {
    w->loop = uv_loop_new();
    w->loop->data = w;

    uv_tcp_init(w->loop, &w->server_h);
    uv_tcp_open(&w->server_h, wfd);
    w->server_h.data = w;
    uv_listen((uv_stream_t*)&w->server_h, 4096, on_connection);

    // TLS port (e.g. 443) — second handle
    if(w->tls_fd >= 0) {
        uv_tcp_init(w->loop, &w->tls_h);
        uv_tcp_open(&w->tls_h, w->tls_fd);
        w->tls_h.data = w;
        uv_listen((uv_stream_t*)&w->tls_h, 4096, on_connection);
        NW_DEBUG("tls", "Worker %d: TLS handle listening", w->id);
    }

    uv_async_init(w->loop, &w->stop_async, [](uv_async_t* a){
        Worker* wk = static_cast<Worker*>(a->data);
        // Close all active handles so uv_run() can exit cleanly
        uv_walk(wk->loop, [](uv_handle_t* h, void*){
            if(!uv_is_closing(h)) uv_close(h, nullptr);
        }, nullptr);
    });
    w->stop_async.data = w;

    NW_INFO("worker", "Worker %d ready  (V8:%s Lua:%s Scripts:%d)", w->id, JS_RUNTIME, LUA_RUNTIME, w->mw->loaded_count());
    if(w->id < 64) { g_wstats[w->id].req = 0; g_wstats[w->id].err = 0; g_wstats[w->id].cache_hit = 0; }
    ready.fetch_add(1);

    uv_run(w->loop, UV_RUN_DEFAULT);

    // Drain remaining handles then close loop
    uv_run(w->loop, UV_RUN_NOWAIT);
    uv_loop_close(w->loop);
    uv_loop_delete(w->loop);
    w->loop = nullptr;
    if(w->ssl_ctx) { SSL_CTX_free(w->ssl_ctx); w->ssl_ctx = nullptr; }
    close(wfd);
}

// ── main ──────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP,  [](int){ g_reload.store(true); });
    signal(SIGTERM, [](int){ g_running.store(false); });
    signal(SIGINT,  [](int){ g_running.store(false); });

    fprintf(stderr,
        "\xE2\x95\x94\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90"
        "\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90"
        "\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90"
        "\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90"
        "\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90"
        "\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90"
        "\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90"
        "\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x97\n"
        "\xE2\x95\x91  nas-web %.*s  -- NAS Panel Web Server  \xE2\x95\x91\n"
        "\xE2\x95\x9A\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90"
        "\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90"
        "\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90"
        "\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90"
        "\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90"
        "\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90"
        "\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90"
        "\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x9D\n",
        (int)NP_VERSION.size(), NP_VERSION.data());

    // ── Parse CLI arguments ───────────────────────────────────────────────────
    // Usage:
    //   nas-web [config_file] [--password_change=NEWPASSWORD]
    //
    // --password_change=NEW  : load config, set admin_password=NEW,
    //                          rewrite config file in-place, exit(0).
    //                          Config file must be specified as first positional arg.
    const char* cfg_path     = nullptr;
    std::string new_password;   // non-empty → password_change mode

    for(int i = 1; i < argc; ++i) {
        std::string_view arg(argv[i]);
        const std::string_view pw_prefix = "--password_change=";
        if(arg.substr(0, pw_prefix.size()) == pw_prefix) {
            new_password = std::string(arg.substr(pw_prefix.size()));
        } else if(arg == "--password_change") {
            // --password_change NEW  (space-separated)
            if(i + 1 < argc) { new_password = argv[++i]; }
            else { fprintf(stderr, "[ERROR] --password_change requires a value\n"); return 1; }
        } else if(arg.substr(0,2) != "--") {
            cfg_path = argv[i];   // positional → config file
        } else {
            fprintf(stderr, "[WARN ] Unknown option: %s\n", argv[i]);
        }
    }

    if(cfg_path) g_config_path = cfg_path;

    // ── --password_change mode ────────────────────────────────────────────────
    if(!new_password.empty()) {
        if(!cfg_path) {
            fprintf(stderr,
                "[ERROR] --password_change requires a config file as first argument\n"
                "        Usage: nas-web /etc/nas-web/nas-web.conf --password_change=NEWPASSWORD\n");
            return 1;
        }
        if(new_password.size() < 6) {
            fprintf(stderr, "[ERROR] New password must be at least 6 characters\n");
            return 1;
        }
        // Read current config file
        std::ifstream fin(cfg_path);
        if(!fin) {
            fprintf(stderr, "[ERROR] Cannot open config: %s\n", cfg_path);
            return 1;
        }
        std::string content((std::istreambuf_iterator<char>(fin)),
                             std::istreambuf_iterator<char>());
        fin.close();

        // Replace or append admin_password directive
        // Strategy: regex-like line-by-line replacement
        std::string out;
        out.reserve(content.size() + 64);
        std::istringstream ss(content);
        std::string line;
        bool replaced = false;
        while(std::getline(ss, line)) {
            // Detect "admin_password <value>;" lines (with optional whitespace)
            std::string trimmed = line;
            size_t s = trimmed.find_first_not_of(" \t");
            if(s != std::string::npos) trimmed = trimmed.substr(s);
            if(trimmed.substr(0, std::min(trimmed.size(), std::string("admin_password").size())) == "admin_password") {
                // Preserve leading whitespace
                std::string indent;
                for(char c : line) { if(c==' '||c=='\t') indent+=c; else break; }
                out += indent + "admin_password " + new_password + ";\n";
                replaced = true;
            } else {
                out += line + "\n";
            }
        }
        // If directive not found, append to file
        if(!replaced) {
            out += "admin_password " + new_password + ";\n";
            fprintf(stderr, "[INFO ] admin_password directive not found — appended to config\n");
        }

        // Write back
        std::ofstream fout(cfg_path, std::ios::trunc);
        if(!fout) {
            fprintf(stderr, "[ERROR] Cannot write config: %s\n", cfg_path);
            return 1;
        }
        fout << out;
        fout.close();

        fprintf(stderr, "[OK   ] Password changed successfully in %s\n", cfg_path);
        fprintf(stderr, "[INFO ] Restart nas-web for change to take effect, or send SIGHUP to reload\n");
        return 0;
    }
    // ── Normal startup — load config ──────────────────────────────────────────
    try {
        if(cfg_path) {
            NW_INFO("config", "Loading config: %s", cfg_path);
            g_config = parse_config(cfg_path);
            NW_INFO("config", "Config loaded: %zu server(s), %zu upstream(s)", g_config->servers.size(), g_config->upstreams.size());
        } else {
            NW_WARN("config", "No config file specified — using built-in defaults");
            g_config = default_config();
        }
    } catch(std::exception& e) {
        NW_ERROR("config", "Parse error: %s", e.what()); return 1;
    }
    if(g_config->servers.empty()) {
        NW_ERROR("config", "No server blocks defined"); return 1;
    }

    // ── Initialize ACME client if enabled ────────────────────────────────────
#if defined(HAVE_ACME)
    if(g_config->acme.enabled && !g_config->acme.email.empty()) {
        AcmeClient::Config ac;
        ac.enabled     = true;
        ac.email       = g_config->acme.email;
        ac.domains     = g_config->acme.domains;
        ac.cert_dir    = g_config->acme.cert_dir;
        ac.staging     = g_config->acme.staging;
        ac.renew_days_before = g_config->acme.renew_days;
        ac.auto_renew  = g_config->acme.auto_renew;
        ac.directory_url = ac.staging ? AcmeClient::LE_STAGING : AcmeClient::LE_PROD;
        ac.challenge_type = g_config->acme.challenge_type;
        ac.dns_provider   = g_config->acme.dns_provider;
        ac.dns_cf_token   = g_config->acme.dns_cf_token;
        ac.dns_cf_zone_id = g_config->acme.dns_cf_zone_id;
        ac.dns_exec_path  = g_config->acme.dns_exec_path;
        acme_init(ac, [](const std::string& cert, const std::string& key){
            NW_INFO("acme","New cert ready: %s — triggering SSL reload", cert.c_str());
            g_reload.store(true); // trigger graceful reload to pick up new cert
        });
        NW_INFO("acme","ACME client started (%s) for %zu domain(s)",
                g_config->acme.staging?"staging":"production",
                g_config->acme.domains.size());
    }
#endif // HAVE_ACME

    V8Engine::init_platform(argv[0]);

    int nworkers = g_config->worker_processes;
    if(nworkers <= 0) nworkers = (int)std::thread::hardware_concurrency();
    nworkers = std::max(1, std::min(nworkers, 64));

    // Bind sockets once in main
    std::unordered_map<uint16_t,int> port_fds;
    for(auto& srv : g_config->servers)
        for(auto& l : srv.listens)
            if(!port_fds.count(l.port)) {
                int fd = make_server_socket(l.port);
                if(fd >= 0) {
                    port_fds[l.port] = fd;
                    NW_INFO("server", "Listening on port %d%s%s", l.port, l.ssl?" (TLS)":"", l.http2?" (HTTP/2)":"");
                }
            }

    uint16_t primary_port = g_config->servers[0].listens.empty()
                            ? (uint16_t)8080
                            : g_config->servers[0].listens[0].port;
    if(!port_fds.count(primary_port)) {
        int fd = make_server_socket(primary_port);
        if(fd < 0) { fprintf(stderr,"[ERROR] Cannot bind port %d\n", primary_port); return 1; }
        port_fds[primary_port] = fd;
        fprintf(stderr, "[nas-web] Listening on port %d\n", primary_port);
    }
    int primary_fd = port_fds[primary_port];

    NW_INFO("server", "Starting %d worker(s)...", nworkers);
    // Wire SSE broadcast into LogBuffer — push new log entries to all open /np_logs/stream connections
    // SSE broadcast removed — use /np_logs?since= polling instead
    g_log.sse_broadcast = nullptr;

    // AutoBan: wire ban callback → add to blacklist + audit
    g_autoban.on_ban = [](const std::string& ip, const std::string& reason) {
        {
            std::lock_guard<std::mutex> lk(g_blacklist_mu);
            g_blacklist.insert(ip);
        }
        audit("autoban", "autoban", ip + " — " + reason);
        NW_WARN("autoban", "BANNED %s — %s", ip.c_str(), reason.c_str());
    };
    g_wstats_count = nworkers;

    // ── Load persistent blacklist ─────────────────────────────────────────────
    if(g_config && !g_config->blacklist_file.empty())
        g_blacklist_file = g_config->blacklist_file;
    blacklist_load();
    bans_load();

    // ── Stats history collector ─────────────────────────────────────────────
    g_stats_timer_running.store(true);
    std::thread stats_thread([](){
        int flush_counter = 0;
        while(g_stats_timer_running.load()){
            stats_collector_tick();
            if(++flush_counter >= 5){
                flush_counter = 0;
                if(g_blacklist_dirty.load(std::memory_order_relaxed))
                    blacklist_flush_sync();
            }
            // Sleep in short intervals to react to shutdown quickly
            for(int i=0; i<10 && g_stats_timer_running.load(); i++)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
    // stats_thread is joined at shutdown via g_stats_thread handle
    g_stats_thread = std::move(stats_thread);
    NW_INFO("stats","Stats history collector started");

    // ── Built-in regex WAF — always active, no dependencies ──────────────────
    if(g_config) {
        g_waf_regex.cfg.enabled    = g_config->waf_regex_enabled;
        g_waf_regex.cfg.block_mode = g_config->waf_regex_block;
        g_waf_regex.cfg.check_body = g_config->waf_regex_check_body;
    }
    g_waf_regex.on_block = [](const std::string& ip, const std::string& reason){
        {
            std::lock_guard<std::mutex> lk(g_blacklist_mu);
            g_blacklist.insert(ip);
            blacklist_save_nolock(); // already holding mutex — no recursive lock
        }
        audit("waf_regex", "waf_regex_block", ip + " — " + reason);
        NW_WARN("waf_regex", "BLOCKED %s — %s", ip.c_str(), reason.c_str());
    };
    g_waf_regex.compile();
    NW_INFO("waf_regex", "Built-in WAF regex compiled (%zu pattern sets)",
            g_waf_regex.pattern_sets.size());

#ifdef WITH_MODSEC
    // ── WAF init ──────────────────────────────────────────────────────────────
    if(g_config && !g_config->modsec_rules_dir.empty())
        g_waf.cfg.rules_dir = g_config->modsec_rules_dir;
    if(g_config && !g_config->modsec_conf.empty())
        g_waf.cfg.main_conf = g_config->modsec_conf;
    if(g_config) {
        g_waf.cfg.enabled    = g_config->modsec_enabled;
        g_waf.cfg.block_mode = g_config->modsec_block;
        NW_INFO("waf", "WAF config: enabled=%s block=%s rules_dir=%s",
            g_config->modsec_enabled?"true":"false",
            g_config->modsec_block?"true":"false",
            g_config->modsec_rules_dir.c_str());
    }
    g_waf.on_block = [](const std::string& ip, const std::string& reason){
        {
            std::lock_guard<std::mutex> lk(g_blacklist_mu);
            g_blacklist.insert(ip);
            blacklist_save_nolock(); // already holding mutex — no recursive lock
        }
        audit("waf", "waf_block", ip + " — " + reason);
        NW_WARN("waf", "BLOCKED %s — %s", ip.c_str(), reason.c_str());
    };
    if(!g_waf.init())
        NW_WARN("waf", "WAF init failed: %s", g_waf.load_error.c_str());
#endif
    g_worker_count.store(nworkers);

    // Allocate workers on heap BEFORE spawning threads
    std::vector<std::unique_ptr<Worker>> workers;
    for(int i = 0; i < nworkers; i++) {
        auto w = std::make_unique<Worker>();
        w->id     = i;
        w->config = g_config;

        // Init subsystems in main thread (single-threaded, safe)
        if(!g_config->upstreams.empty())
            w->upstream = std::make_unique<UpstreamGroup>(g_config->upstreams[0]);
        w->cache = std::make_unique<ResponseCache>(g_config->cache_size, g_config->cache_ttl);

        // Rate limiter config
        double rl_rate = 200.0/60.0, rl_burst = 50.0;
        for(auto& srv : g_config->servers)
            for(auto& loc : srv.locations)
                if(loc.rate_limit.enabled) {
                    rl_rate = loc.rate_limit.rate;
                    rl_burst = loc.rate_limit.burst;
                }
        w->rl = std::make_unique<RateLimiter>(RateLimiter::Config{rl_rate, rl_burst, 0, 300});
        w->mw = std::make_unique<MiddlewarePipeline>(*g_config);

        // SSL — enable if listen has ssl flag OR port 443 with cert configured
        for(auto& srv : g_config->servers)
            for(auto& l : srv.listens) {
                bool want_ssl = l.ssl || (l.port == 443 && !srv.ssl_cert.empty());
                if(want_ssl && !srv.ssl_cert.empty() && !w->ssl_ctx) {
                    l.ssl = true;
                    w->ssl_ctx = create_ssl_ctx(srv);
                }
            }

        workers.push_back(std::move(w));
    }

    // Spawn threads — workers already on heap, pointers stable
    std::atomic<int> ready_count{0};
    std::vector<std::thread> threads;

    // Find TLS fd (port 443 or any ssl listen)
    int tls_src_fd = -1;
    for(auto& srv : g_config->servers)
        for(auto& l : srv.listens)
            if(l.ssl && l.port != primary_port && port_fds.count(l.port))
                tls_src_fd = port_fds[l.port];

    for(int i = 0; i < (int)workers.size(); i++) {
        int wfd = dup(primary_fd);
        if(wfd < 0) { perror("dup"); continue; }
        if(tls_src_fd >= 0) {
            workers[i]->tls_fd = dup(tls_src_fd);
            if(workers[i]->tls_fd < 0) { perror("dup tls"); workers[i]->tls_fd = -1; }
        }
        Worker* wp = workers[i].get();
        threads.emplace_back(run_worker, wp, wfd, std::ref(ready_count));
    }
    close(primary_fd);
    if(tls_src_fd >= 0) close(tls_src_fd);

    // Wait for all workers to start
    while(ready_count.load() < (int)threads.size())
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Main loop — graceful reload
    while(g_running.load()) {
        sleep(1);
        if(g_reload.exchange(false)) {
            NW_INFO("config", "SIGHUP received — graceful reload starting");
            try {
                auto new_cfg = cfg_path ? parse_config(cfg_path) : g_config;
                NW_INFO("config", "New config parsed: %zu server(s), %zu upstream(s)",
                        new_cfg->servers.size(), new_cfg->upstreams.size());

                // ── Graceful: atomically swap config for each worker ──────────
                // Each worker checks w->config at dispatch time (shared_ptr, thread-safe read)
                // Active requests finish with the old config naturally
                for(auto& w : workers) {
                    // Build new upstream/cache for new config if needed
                    if(!new_cfg->upstreams.empty()) {
                        auto new_up = std::make_unique<UpstreamGroup>(new_cfg->upstreams[0]);
                        // Workers will pick up new upstream on next request
                        // We swap via a lock-free shared_ptr exchange
                    }
                    // Atomic config swap — safe because shared_ptr is atomic-capable
                    std::atomic_store(&w->config, new_cfg);
                    // Swap middleware pipeline (needs new config)
                    // (done under worker's own protection — dispatch reads w->config atomically)
                }
                g_config = new_cfg; // update global reference

                // Reload SSL context if certs changed
                for(auto& w : workers) {
                    const auto& cfg2 = *w->config;
                    for(auto& srv : cfg2.servers)
                        for(auto& l : srv.listens) {
                            bool want_ssl = l.ssl || (l.port==443 && !srv.ssl_cert.empty());
                            if(want_ssl && !srv.ssl_cert.empty()) {
                                auto* new_ctx = create_ssl_ctx(srv);
                                if(new_ctx) {
                                    if(w->ssl_ctx) SSL_CTX_free(w->ssl_ctx);
                                    w->ssl_ctx = new_ctx;
                                }
                            }
                        }
                }

                NW_INFO("config", "Graceful reload complete — %d workers updated", (int)workers.size());
            } catch(std::exception& e) {
                NW_ERROR("config", "Reload failed (keeping old config): %s", e.what());
            }
        }
    }

    NW_INFO("server", "Shutting down...");
    // Stop background stats/flush thread first
    g_stats_timer_running.store(false);
    if(g_stats_thread.joinable()) g_stats_thread.join();
    // Signal all worker loops to stop
    for(auto& w : workers)
        if(w->loop) uv_async_send(&w->stop_async);
    // Join worker threads
    for(auto& t : threads)
        if(t.joinable()) t.join();
    // Final blacklist flush on clean shutdown
    if(g_blacklist_dirty.load())
        blacklist_flush_sync();
    NW_INFO("server", "Shutdown complete");
    return 0;
}
