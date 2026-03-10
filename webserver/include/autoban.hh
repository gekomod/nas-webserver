#pragma once
// ── AutoBan — automatic threat detection and IP blacklisting ─────────────────
// Detects: path scanning, 404 flood, rate abuse, malicious User-Agents
// Thread-safe. Call autoban_check() from dispatch() after parsing request.

#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <mutex>
#include <atomic>
#include <ctime>
#include <cstring>
#include <algorithm>
#include <functional>

// ── Suspicious path patterns ─────────────────────────────────────────────────
static constexpr const char* SCAN_PATHS[] = {
    // Credentials / secrets
    ".env", ".env.", "/.aws/", "/.git/", ".git/config", ".gitconfig",
    "config/.env", "docker-compose", ".htpasswd", "web.config",
    // CMS exploits
    "wp-login.php", "wp-admin", "wp-includes", "wp-content",
    "xmlrpc.php", "wlwmanifest.xml", "wp-config.php",
    "wp-content/uploads", "administrator/", "joomla", "drupal",
    // Shell / backdoors
    ".php?", "cmd=", "exec=", "shell.php", "c99.php", "r57.php",
    "webshell", "eval(", "base64_decode",
    // Common scanners
    "/phpmyadmin", "/pma/", "/myadmin/", "phpinfo.php",
    "adminer.php", "/manager/html",
    // Path traversal
    "../", "..\\", "%2e%2e", "%252e",
    // Config leaks
    "/.env.prod", "/.env.local", "/.env.staging", "/.env.backup",
    "/.env.bak", "/.env.dev", "/.env.test", "/.env.ci",
    "/configuration/.env", "/config/.git", "/app/.git",
    // Cloud metadata
    "169.254.169.254", "metadata.google",
    nullptr
};

// ── Suspicious User-Agent substrings ─────────────────────────────────────────
static constexpr const char* BAD_UA[] = {
    "nikto", "nmap", "masscan", "zgrab", "nuclei", "sqlmap",
    "dirbuster", "gobuster", "wfuzz", "ffuf", "feroxbuster",
    "hydra", "medusa", "burpsuite", "acunetix", "nessus",
    "openvas", "w3af", "havij", "libwww-perl", "python-requests/2.",
    "go-http-client/1.", "scanbot", "semrush", "ahrefsbot",
    nullptr
};

// ── Per-IP tracking ───────────────────────────────────────────────────────────
struct IpStats {
    // sliding window counters (last 60s)
    std::deque<time_t> req_times;    // all requests
    std::deque<time_t> err404_times; // 404 responses
    std::deque<time_t> scan_times;   // scan path hits (windowed)
    std::deque<time_t> ua_times;     // bad UA hits (windowed)
    time_t first_seen = 0;
    time_t last_seen  = 0;
};

// ── AutoBan engine ────────────────────────────────────────────────────────────
struct AutoBan {
    struct Config {
        bool     enabled          = true;
        int      rate_limit_rps   = 30;   // req/s per IP → ban
        int      err404_threshold = 12;   // 404s in window → ban
        int      scan_threshold   = 3;    // scan paths → ban
        int      window_sec       = 30;   // sliding window seconds
        bool     ban_scanpaths    = true;
        bool     ban_ratelimit    = false;  // disabled by default
        bool     ban_404flood     = false;  // disabled by default
        bool     ban_bad_ua       = true;
    } cfg;

    // callback: called when IP should be banned, returns reason string
    std::function<void(const std::string& ip, const std::string& reason)> on_ban;

    enum class Verdict { Allow, Ban };
    enum class BanReason { ScanPath, RateLimit, Err404Flood, BadUA };

    struct BanEvent {
        std::string ip;
        std::string reason;
        std::string detail;
        time_t      ts;
    };

    std::deque<BanEvent>  recent_bans;   // last 200 ban events
    std::atomic<uint64_t> total_banned{0};
    std::atomic<uint64_t> total_blocked{0};

    // ── check() — call BEFORE processing request ─────────────────────────────
    // Returns Ban if IP should be blocked.
    // path, ua, status: status=0 means pre-response check
    Verdict check(const std::string& ip,
                  const std::string& path,
                  const std::string& ua,
                  int status_code = 0)
    {
        if(!cfg.enabled || ip.empty()) return Verdict::Allow;
        // Never ban private/loopback IPs
        if(ip == "127.0.0.1" || ip == "::1" ||
           ip.substr(0,8) == "192.168." ||
           ip.substr(0,3) == "10." ||
           ip.substr(0,7) == "172.16." ||
           ip.substr(0,7) == "172.17." ||
           ip.substr(0,7) == "172.18." ||
           ip.substr(0,7) == "172.19." ||
           ip.substr(0,7) == "172.20." ||
           ip.substr(0,7) == "172.21." ||
           ip.substr(0,7) == "172.22." ||
           ip.substr(0,7) == "172.23." ||
           ip.substr(0,7) == "172.24." ||
           ip.substr(0,7) == "172.25." ||
           ip.substr(0,7) == "172.26." ||
           ip.substr(0,7) == "172.27." ||
           ip.substr(0,7) == "172.28." ||
           ip.substr(0,7) == "172.29." ||
           ip.substr(0,7) == "172.30." ||
           ip.substr(0,7) == "172.31.")
            return Verdict::Allow;

        std::lock_guard<std::mutex> lk(mu_);
        auto& st = stats_[ip];
        time_t now = time(nullptr);
        if(!st.first_seen) st.first_seen = now;
        st.last_seen = now;

        // Slide windows
        slide(st.req_times,  now, cfg.window_sec);
        slide(st.err404_times, now, cfg.window_sec);
        st.req_times.push_back(now);
        if(status_code == 404) st.err404_times.push_back(now);

        // ── 1. Bad User-Agent ─────────────────────────────────────────────────
        if(cfg.ban_bad_ua && !ua.empty()) {
            std::string ua_lower = ua;
            std::transform(ua_lower.begin(), ua_lower.end(), ua_lower.begin(), ::tolower);
            for(int i = 0; BAD_UA[i]; i++) {
                if(ua_lower.find(BAD_UA[i]) != std::string::npos) {
                    slide(st.ua_times, now, cfg.window_sec);
                    st.ua_times.push_back(now);
                    // Bad UA: ban immediately on first hit
                    return do_ban(ip, "bad_ua", std::string(BAD_UA[i]));
                }
            }
        }

        // ── 2. Scan path detection ────────────────────────────────────────────
        if(cfg.ban_scanpaths && !path.empty()) {
            std::string path_lower = path;
            std::transform(path_lower.begin(), path_lower.end(),
                           path_lower.begin(), ::tolower);
            for(int i = 0; SCAN_PATHS[i]; i++) {
                if(path_lower.find(SCAN_PATHS[i]) != std::string::npos) {
                    slide(st.scan_times, now, cfg.window_sec);
                    st.scan_times.push_back(now);
                    if((int)st.scan_times.size() >= cfg.scan_threshold)
                        return do_ban(ip, "scan", path.substr(0, 80));
                    break;
                }
            }
        }

        // ── 3. 404 flood ──────────────────────────────────────────────────────
        if(cfg.ban_404flood &&
           (int)st.err404_times.size() >= cfg.err404_threshold)
            return do_ban(ip, "404_flood",
                         std::to_string(st.err404_times.size()) + " 404s/" +
                         std::to_string(cfg.window_sec) + "s");

        // ── 4. Rate limit ─────────────────────────────────────────────────────
        if(cfg.ban_ratelimit &&
           (int)st.req_times.size() >= cfg.rate_limit_rps)
            return do_ban(ip, "rate_limit",
                         std::to_string(st.req_times.size()) + " req/" +
                         std::to_string(cfg.window_sec) + "s");

        return Verdict::Allow;
    }

    // ── Stats for admin panel ─────────────────────────────────────────────────
    std::string stats_json() {
        std::lock_guard<std::mutex> lk(mu_);
        std::string j = "{\"total_banned\":" + std::to_string(total_banned.load()) +
                        ",\"total_blocked\":" + std::to_string(total_blocked.load()) +
                        ",\"tracked_ips\":" + std::to_string(stats_.size()) +
                        ",\"recent_bans\":[";
        bool first = true;
        // newest first, max 50
        int start = (int)recent_bans.size() > 50 ? (int)recent_bans.size()-50 : 0;
        for(int i = (int)recent_bans.size()-1; i >= start; i--) {
            auto& b = recent_bans[i];
            char ts[32]; struct tm* tm=localtime(&b.ts);
            strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S",tm);
            auto esc=[](std::string s){
                std::string o;
                for(char c:s){if(c=='"')o+="\\\"";else if(c=='\\')o+="\\\\";else o+=c;}
                return o;
            };
            if(!first) j+=",";
            first=false;
            j+="{\"ts\":\""+std::string(ts)+"\",\"ip\":\""+b.ip+
               "\",\"reason\":\""+b.reason+"\",\"detail\":\""+esc(b.detail)+"\"}";
        }
        j += "]}";
        return j;
    }

    void clear_stats() {
        std::lock_guard<std::mutex> lk(mu_);
        stats_.clear();
    }

    // Public mutex accessor for persistence helpers in server.cc
    std::mutex& mu_pub() { return mu_; }

private:
    std::mutex mu_;
    std::unordered_map<std::string, IpStats> stats_;

    void slide(std::deque<time_t>& dq, time_t now, int window) {
        while(!dq.empty() && dq.front() < now - window)
            dq.pop_front();
    }

    Verdict do_ban(const std::string& ip,
                   const std::string& reason,
                   const std::string& detail) {
        total_banned.fetch_add(1, std::memory_order_relaxed);
        BanEvent ev{ip, reason, detail, time(nullptr)};
        recent_bans.push_back(ev);
        if((int)recent_bans.size() > 200) recent_bans.pop_front();
        if(on_ban) on_ban(ip, reason + ": " + detail);
        return Verdict::Ban;
    }
};

// g_autoban defined once in server.cc — use extern to reference it
#ifndef AUTOBAN_IMPL
extern AutoBan g_autoban;
#endif
