// ─────────────────────────────────────────────────────────────────────────────
//  np_config.hh  —  configuration structures
//
//  Składnia (nginx-inspired + rozszerzenia):
//
//    upstream node_app {
//        server 127.0.0.1:3000;
//        health_check /health interval=5;
//        keepalive 32;
//    }
//
//    server {
//        listen 80;
//        listen 443 ssl http2;
//        listen 443 quic;          # HTTP/3
//        ssl_cert  /etc/ssl/cert.pem;
//        ssl_key   /etc/ssl/key.pem;
//
//        location /api {
//            proxy_pass node_app;
//            rate_limit 200/min burst=50;
//            js_middleware /etc/nodeproxy/scripts/auth.js;
//        }
//        location /static {
//            root /var/www;
//            gzip on;
//            cache max_age=3600;
//        }
//        location /admin {
//            proxy_pass node_app;
//            lua_middleware /etc/nodeproxy/scripts/acl.lua;
//        }
//    }
// ─────────────────────────────────────────────────────────────────────────────
#pragma once
#include <unordered_map>
#include "np_types.hh"

// ── Upstream ──────────────────────────────────────────────────────────────────
struct UpstreamServer {
    std::string host{"127.0.0.1"};
    uint16_t    port{3000};
    int         weight{1};
    int         max_fails{3};
    int         fail_timeout{30};
    bool        backup{false};     // only used when all primaries are down
};

enum class LBStrategy { LeastConn, RoundRobin, WeightedRR, IPHash };

struct UpstreamConfig {
    std::string                  name;
    std::vector<UpstreamServer>  servers;
    int   keepalive{32};
    bool  hc_enabled{true};
    int   hc_interval{5};
    std::string hc_path{"/health"};
    int   hc_expected_status{200};  // 200-399 = ok by default
    LBStrategy strategy{LBStrategy::LeastConn};
    bool  sticky_sessions{false};   // hash client IP → same backend
};

// ── Rate limit ────────────────────────────────────────────────────────────────
struct RateLimitConfig {
    bool   enabled{false};
    double rate{200.0};     // requests per second (converted from /min)
    double burst{50.0};
    int    block_sec{300};
    int    max_conns{0};    // concurrent connections per IP
};

// ── Scripting middleware ──────────────────────────────────────────────────────
enum class ScriptEngine { None, JS, Lua };

struct MiddlewareScript {
    ScriptEngine engine{ScriptEngine::None};
    std::string  path;          // file path to script
    std::string  inline_code;   // or inline code
    int          timeout_ms{50}; // max execution time
};

// ── Location ──────────────────────────────────────────────────────────────────
enum class LocationType { Proxy, Static, Redirect, Return };

struct LocationConfig {
    std::string   prefix;
    bool          exact{false};
    LocationType  type{LocationType::Proxy};

    // proxy
    std::string   upstream;
    int           proxy_timeout{30};
    int           proxy_connect_timeout{5};
    bool          websocket{true};   // auto-detect + pass through

    // static
    std::string   root;
    bool          gzip{true};
    bool          etag{true};
    int           cache_max_age{0};
    bool          autoindex{false};

    // rate limit
    RateLimitConfig rate_limit;

    // scripting
    std::vector<MiddlewareScript> middlewares;  // executed in order

    // header manipulation
    std::vector<std::pair<std::string,std::string>> add_headers;
    std::vector<std::string>                        hide_headers;

    // health check (for proxy locations)
    std::string health_check_path;      // e.g. "/health"
    int         health_check_interval{30}; // seconds

    // special
    int         return_code{200};
    std::string return_body;
    std::string redirect_url;
    std::vector<std::string> try_files;  // e.g. ["$uri", "$uri/", "@fallback"]
    std::string named_location;          // @name for named locations
};

// ── Server (vhost) ────────────────────────────────────────────────────────────
struct ListenDirective {
    uint16_t port{80};
    bool     ssl{false};
    bool     http2{false};
    bool     http3{false};   // QUIC
    bool     default_server{false};
};

struct ServerConfig {
    std::vector<ListenDirective> listens;
    std::vector<std::string>     server_names;  // SNI matching
    std::string                  ssl_cert;
    std::string                  ssl_key;
    std::string                  ssl_protocols{"TLSv1.2 TLSv1.3"};
    std::string                  ssl_ciphers;

    std::vector<LocationConfig>  locations;

    int   keepalive_timeout{65};
    int   keepalive_requests{1000};
    int   client_max_body{64*1024*1024};
    int   send_timeout{60};
    int   read_timeout{30};

    std::string access_log{"/var/log/nodeproxy/access.log"};
    std::string error_log{"/var/log/nodeproxy/error.log"};
    std::unordered_map<int,std::string> error_pages;  // status → file/url
};

// ── Global config ─────────────────────────────────────────────────────────────
struct Config {
    int    worker_processes{0};     // 0 = #CPUs
    int    worker_connections{8192};
    int    cache_size{4096};        // max entries per worker
    int    cache_ttl{60};
    std::string log_level{"info"};
    std::string pid_file{"/var/run/nodeproxy.pid"};
    std::string blacklist_file{"/var/lib/nas-web/blacklist.txt"};

    // V8 scripting
    int    v8_heap_mb{64};          // per-worker V8 heap limit
    int    v8_timeout_ms{50};       // default script timeout
    std::string scripts_dir;        // preload all .js from this dir

    // Lua scripting
    bool   lua_enabled{true};
    std::string lua_package_path;

    // Admin panel auth (Basic Auth)
    std::string admin_user{"admin"};
    std::string admin_password{""};  // empty = no auth required
    std::vector<std::string> admin_allow_ips; // empty=allow all; prefix match e.g. "192.168.1."
    // Require TLS for /np_admin and admin API endpoints.
    // Plain HTTP requests receive 301 redirect to https://.
    bool admin_tls_only = true;

    // ── Feature flags ────────────────────────────────────────────────────────
    bool  module_cache{true};
    bool  module_ratelimit{true};
    bool  module_lua{true};
    bool  module_js{true};
    bool  module_acme{false};
    bool  module_lb_healthcheck{true};
    bool  module_gzip{true};

    // ── ACME / Let's Encrypt ─────────────────────────────────────────────────
    struct AcmeCfg {
        bool        enabled{false};
        std::string email;
        std::vector<std::string> domains;
        std::string cert_dir{"/etc/nas-web"};
        bool        staging{true};
        int         renew_days{30};
        bool        auto_renew{true};
        // DNS-01 challenge (for wildcard certs / no port 80 needed)
        std::string challenge_type{"http-01"}; // "http-01" or "dns-01"
        std::string dns_provider;              // "cloudflare","route53","digitalocean","exec"
        std::string dns_cf_token;              // Cloudflare API token
        std::string dns_cf_zone_id;            // Cloudflare Zone ID
        std::string dns_exec_path;             // path to custom DNS hook script
    } acme;

    // ── ModSecurity WAF ───────────────────────────────────────────────────────
#ifdef WITH_MODSEC
    bool        modsec_enabled{true};   // auto-enabled when compiled with WITH_MODSEC=ON
#else
    bool        modsec_enabled{false};
#endif
    bool        modsec_block{true};     // false = detect-only
    std::string modsec_rules_dir{"/etc/modsecurity/crs"};
    std::string modsec_conf{"/etc/modsecurity/modsecurity.conf"};

    // ── Built-in regex WAF (SQLi/XSS/path traversal/cmdinject/SSRF/XXE) ──────
    bool        waf_regex_enabled{true};   // active by default, no dependencies
    bool        waf_regex_block{true};     // false = detect-only
    bool        waf_regex_check_body{true};

    std::vector<UpstreamConfig>  upstreams;
    std::vector<ServerConfig>    servers;

    const UpstreamConfig* find_upstream(std::string_view name) const {
        for(auto&u:upstreams) if(u.name==name) return &u;
        return nullptr;
    }

    // Match server block by Host header (virtual hosting)
    const ServerConfig* match_server(const std::string& host) const {
        // Strip port from host header
        std::string h = host;
        auto cp = h.rfind(':');
        if(cp != std::string::npos) h = h.substr(0, cp);
        // Exact match first
        for(auto& s : servers)
            for(auto& n : s.server_names)
                if(n == h) return &s;
        // Wildcard *.example.com
        for(auto& s : servers)
            for(auto& n : s.server_names)
                if(!n.empty() && n[0]=='*') {
                    auto suffix = n.substr(1); // ".example.com"
                    if(h.size() > suffix.size() &&
                       h.substr(h.size()-suffix.size()) == suffix) return &s;
                }
        // default_server or first
        for(auto& s : servers)
            for(auto& l : s.listens)
                if(l.default_server) return &s;
        return servers.empty() ? nullptr : &servers[0];
    }

    const LocationConfig* match_location(const ServerConfig& srv,
                                          std::string_view path) const {
        const LocationConfig* best=nullptr;
        size_t best_len=0;
        for(auto&loc:srv.locations){
            if(loc.exact){
                if(path==loc.prefix) return &loc;
                continue;
            }
            if(path.size()>=loc.prefix.size() &&
               path.substr(0,loc.prefix.size())==loc.prefix){
                if(loc.prefix.size()>best_len){
                    best_len=loc.prefix.size(); best=&loc;
                }
            }
        }
        return best;
    }
};

// ── Global config extensions ───────────────────────────────────────────────────
struct GlobalOptions {
    // Error pages (status → file path)
    std::unordered_map<int,std::string> error_pages;
    // ACL
    std::vector<std::string> allow_from;
    std::vector<std::string> deny_from;
};


std::shared_ptr<Config> parse_config(const std::string& path);
std::shared_ptr<Config> default_config();
