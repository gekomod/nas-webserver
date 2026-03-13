#pragma once
// ── WafRegex — lightweight built-in WAF layer ────────────────────────────────
// No external dependencies. Uses <regex> (C++11) for SQLi, XSS, path
// traversal, command injection, SSRF, and common web exploit patterns.
// Complements ModSecurity — always active, zero install overhead.
//
// Design: patterns compiled once at startup, checked per-request on
// path + query + body (combined). Ban on first match → immediate 403.

#include <string>
#include <vector>
#include <regex>
#include <deque>
#include <mutex>
#include <atomic>
#include <ctime>
#include <functional>
#include <algorithm>
#include <cctype>

struct WafRegexEvent {
    time_t      ts;
    std::string ip;
    std::string method;
    std::string uri;
    std::string category;
    std::string matched;    // which pattern matched (truncated)
    std::string detail;     // matched substring
};

struct WafRegexEngine {

    struct Config {
        bool enabled       = true;
        bool block_mode    = true;   // false = detect only
        bool check_path    = true;
        bool check_query   = true;
        bool check_body    = true;
        bool check_headers = false;  // expensive, off by default
        size_t max_body_check = 32768; // only check first 32KB of body
    } cfg;

    std::function<void(const std::string& ip, const std::string& reason)> on_block;

    std::atomic<uint64_t> total_checked{0};
    std::atomic<uint64_t> total_blocked{0};
    std::atomic<uint64_t> total_detected{0};

    std::deque<WafRegexEvent> events;
    std::mutex                events_mu;

    // ── Pattern categories ───────────────────────────────────────────────────
    struct PatternSet {
        std::string category;
        std::vector<std::regex> patterns;
        std::vector<std::string> raw;  // for display in panel
    };

    std::vector<PatternSet> pattern_sets;
    bool compiled = false;

    // ── Pattern definitions ──────────────────────────────────────────────────
    void compile() {
        auto flag = std::regex::icase | std::regex::optimize;

        // ── SQL Injection ─────────────────────────────────────────────────────
        PatternSet sqli; sqli.category = "SQLi";
        std::vector<std::string> sqli_raw = {
            // Classic tautologies
            R"(\b(or|and)\s+[\w'"\s]+=[\w'"\s]+)",
            R"(\b(or|and)\s+\d+\s*=\s*\d+)",
            R"(\b(or|and)\s+'[^']*'\s*=\s*'[^']*')",
            // UNION attacks
            R"(\bunion\s+(all\s+)?select\b)",
            // Comment terminators
            R"(--\s*$|;--|\*/\s*$|#\s*$)",
            // SQL keywords in suspicious context
            R"(\b(select|insert|update|delete|drop|truncate|alter|create|exec|execute)\s+\w)",
            // Stacked queries
            R"(;\s*(select|insert|update|delete|drop|exec))",
            // Blind injection timing
            R"(\b(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\()",
            // Out-of-band / info disclosure
            R"(\b(load_file|into\s+outfile|into\s+dumpfile)\b)",
            R"(\b(information_schema|sys\.databases|sysobjects|syscolumns)\b)",
            // Hex/char encoding evasion
            R"(\b(char|nchar|varchar)\s*\(\s*\d+)",
            R"(0x[0-9a-f]{6,})",
            // Subqueries in params
            R"(\(\s*select\s+\w+\s+from\s+\w+)",
        };
        for(auto& r : sqli_raw) {
            try { sqli.patterns.emplace_back(r, flag); sqli.raw.push_back(r); }
            catch(...) {}
        }
        pattern_sets.push_back(std::move(sqli));

        // ── Cross-Site Scripting (XSS) ────────────────────────────────────────
        PatternSet xss; xss.category = "XSS";
        std::vector<std::string> xss_raw = {
            // Script tags
            R"(<\s*script[\s>])",
            R"(<\s*/\s*script\s*>)",
            // Event handlers
            R"(\bon\w+\s*=\s*[\"']?\s*(javascript|alert|eval|document|window))",
            R"(\b(onerror|onload|onclick|onmouseover|onfocus|onblur)\s*=)",
            // JS protocol
            R"(javascript\s*:)",
            R"(vbscript\s*:)",
            R"(data\s*:\s*text/html)",
            // eval / expression
            R"(\beval\s*\()",
            R"(\bexpression\s*\()",
            R"(\bsetTimeout\s*\(|setInterval\s*\()",
            // document/window access
            R"(\bdocument\s*\.\s*(cookie|write|location|domain))",
            R"(\bwindow\s*\.\s*(location|open|top))",
            // iframe / object injection
            R"(<\s*(iframe|object|embed|applet|form)[\s>])",
            // CSS injection
            R"(url\s*\(\s*javascript)",
            R"(-moz-binding\s*:)",
            // HTML entities bypass
            R"(&\#(x[0-9a-f]+|[0-9]+);.*<\s*script)",
            // Encoded script
            R"(%3c\s*script|%3cscript)",
        };
        for(auto& r : xss_raw) {
            try { xss.patterns.emplace_back(r, flag); xss.raw.push_back(r); }
            catch(...) {}
        }
        pattern_sets.push_back(std::move(xss));

        // ── Path Traversal ────────────────────────────────────────────────────
        PatternSet pt; pt.category = "PathTraversal";
        std::vector<std::string> pt_raw = {
            R"(\.\./|\.\.\\)",                       // ../
            R"(%2e%2e[%2f%5c]|%2e%2e/)",             // URL encoded
            R"(%252e%252e)",                          // double encoded
            R"(\.\.[/\\]{1,3}(etc|proc|sys|var|home|root|windows|win))",
            R"(/etc/(passwd|shadow|hosts|crontab|sudoers))",
            R"(/proc/(self|environ|cmdline|maps|mem))",
            R"(c:[/\\]windows[/\\])",
            R"(\\\\.\\(pipe|mailslot|physical))",     // Windows UNC
        };
        for(auto& r : pt_raw) {
            try { pt.patterns.emplace_back(r, flag); pt.raw.push_back(r); }
            catch(...) {}
        }
        pattern_sets.push_back(std::move(pt));

        // ── Command Injection ─────────────────────────────────────────────────
        PatternSet ci; ci.category = "CmdInjection";
        std::vector<std::string> ci_raw = {
            R"([;&|`]\s*(ls|cat|id|whoami|uname|curl|wget|nc|bash|sh|python|perl|ruby|php)\b)",
            R"(\$\([^)]+\)|\$\{[^}]+\})",             // $(cmd) ${var}
            R"(`[^`]+`)",                              // backtick exec
            R"(\|\s*(bash|sh|cmd|powershell))",
            R"(;(wget|curl)\s+https?://)",
            R"(\b(chmod|chown|passwd|useradd|sudo)\b)",
            R"(/bin/(bash|sh|dash|zsh|ksh|csh|tcsh))",
            // PHP-specific
            R"(\b(system|passthru|proc_open|popen|shell_exec)\s*\()",
            R"(\b(base64_decode|gzinflate|str_rot13)\s*\([^)]*base64)",
        };
        for(auto& r : ci_raw) {
            try { ci.patterns.emplace_back(r, flag); ci.raw.push_back(r); }
            catch(...) {}
        }
        pattern_sets.push_back(std::move(ci));

        // ── SSRF / Request Forgery ────────────────────────────────────────────
        PatternSet ssrf; ssrf.category = "SSRF";
        std::vector<std::string> ssrf_raw = {
            R"(https?://(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1))",
            R"(https?://169\.254\.169\.254)",          // AWS/GCP metadata
            R"(https?://metadata\.google\.internal)",
            R"(https?://[^/]*@)",                      // URL with credentials
            R"(file:///)",                              // file:// protocol
            R"(gopher://|dict://|ldap://|tftp://)",    // dangerous protocols
            R"(https?://10\.\d+\.\d+\.\d+)",           // private ranges as URL
            R"(https?://192\.168\.\d+\.\d+)",
            R"(https?://172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)",
        };
        for(auto& r : ssrf_raw) {
            try { ssrf.patterns.emplace_back(r, flag); ssrf.raw.push_back(r); }
            catch(...) {}
        }
        pattern_sets.push_back(std::move(ssrf));

        // ── XXE / XML injection ───────────────────────────────────────────────
        PatternSet xxe; xxe.category = "XXE";
        std::vector<std::string> xxe_raw = {
            R"(<!ENTITY\s+\w+\s+(SYSTEM|PUBLIC))",
            R"(<!DOCTYPE[^>]*\[)",
            R"(SYSTEM\s+[\"']file://)",
            R"(\bxpath\b.*(//|@\w))",
        };
        for(auto& r : xxe_raw) {
            try { xxe.patterns.emplace_back(r, flag); xxe.raw.push_back(r); }
            catch(...) {}
        }
        pattern_sets.push_back(std::move(xxe));

        // ── Scanner / Probe Detection ─────────────────────────────────────────
        // Typowe ścieżki skanerów WordPress, Joomla, phpMyAdmin, CVE scannerów
        PatternSet scan; scan.category = "ScanProbe";
        std::vector<std::string> scan_raw = {
            // WordPress fingerprinting (match with or without leading slash)
            R"([/\\]wp-(includes|content|admin|login|cron|json|config|signup|trackback|comments)[/\\])",
            R"([/\\]wp-(includes|content|admin|login)\.php)",
            R"([/\\]xmlrpc\.php)",
            R"([/\\]wlwmanifest\.xml)",
            R"([/\\]wp-config(\.php|\.bak|\.old|\.txt|~))",
            R"(wp-login\.php)",
            // Joomla / Drupal / other CMS
            R"(/administrator/(index|login)\.php)",
            R"(/joomla/(administrator|index))",
            R"(/sites/default/files)",
            R"(/core/install\.php)",
            // phpMyAdmin / database tools
            R"(/(phpmyadmin|pma|myadmin|mysql|sqladmin|dbadmin)[^a-zA-Z])",
            R"(/phpmyadmin)",
            // Shell/backdoor probing
            R"(/((c99|r57|shell|cmd|webshell|b374k|bypass|exploit)\.(php|asp|jsp|cfm)))",
            R"(/\.(git|svn|env|htpasswd|htaccess|DS_Store|idea|vscode)/)",
            R"(/\.git/(HEAD|config|objects))",
            R"(/\.env($|\?))",
            // Common vuln scanners
            R"(/(config|setup|install|upgrade|update)\.(php|asp|jsp)$)",
            R"(/etc/(passwd|shadow|hosts))",
            R"(/(invoker|jmx-console|web-console|status|manager)($|/))",
            // CVE / RCE probes
            R"(/cgi-bin/(\w+\.(cgi|pl|sh|py)|admin\.cgi))",
            R"(/actuator/(env|heapdump|shutdown|beans|mappings))",
            R"(/(api/|v[0-9]+/)?(health|metrics|info|debug|trace|swagger|openapi)\.json)",
            // Additional WordPress/CMS aggressive probing
            R"([/\\](wp-login|wp-signup|wp-register)\.php)",
            R"([/\\]wp-json/wp/v[0-9])",
            R"([/\\]wp-content/uploads/[0-9]{4}/)",
            R"([/\\](license|readme|license\.(txt|html|md))$)",
            R"([/\\]\.well-known/security\.txt)",
            // Common backdoor/webshell names
            R"([/\\](alfa|alfa1|alfa2|r57|c99|b374k|wso|priv8|indoxploit)\.(php|txt))",
            R"([/\\](shell|cmd|websh|backdoor|hack|hacked)\.(php|asp|jsp))",
        };
        for(auto& r : scan_raw) {
            try { scan.patterns.emplace_back(r, flag); scan.raw.push_back(r); }
            catch(const std::exception& ex) {
                NW_WARN("waf_regex", "ScanProbe pattern compile error: %s", ex.what());
            }
        }
        pattern_sets.push_back(std::move(scan));

        // ── Bad User-Agent ────────────────────────────────────────────────────
        PatternSet ua; ua.category = "BadUA";
        std::vector<std::string> ua_raw = {
            R"(\b(sqlmap|nikto|nmap|masscan|zap|burpsuite|acunetix|nessus)\b)",
            R"(\b(zgrab|gobuster|dirbuster|dirb|wfuzz|ffuf|feroxbuster)\b)",
            R"(\b(nuclei|httpx|subfinder|amass|shodan|censys)\b)",
            R"(\b(python-requests|go-http-client|curl/[0-9]|wget/[0-9])\b)",
            R"(\b(scrapy|mechanize|libwww-perl|lwp-trivial)\b)",
            R"((wordpress|wp-) (scanner|attack|probe|hack))",
            R"(\b(bot|crawler|spider|scraper)\b.{0,30}\b(attack|scan|probe|hack)\b)",
        };
        for(auto& r : ua_raw) {
            try { ua.patterns.emplace_back(r, std::regex_constants::icase | std::regex_constants::optimize); ua.raw.push_back(r); }
            catch(const std::exception& ex) {
                NW_WARN("waf_regex", "BadUA pattern compile error: %s", ex.what());
            }
        }
        pattern_sets.push_back(std::move(ua));

        compiled = true;
    }

    // ── Check a request ───────────────────────────────────────────────────────
    // Returns true = allow, false = block (or detect if !cfg.block_mode)
    bool check(const std::string& ip,
               const std::string& method,
               const std::string& path,
               const std::string& query,
               const std::string& body,
               const std::string& raw_headers = "",
               std::string* out_category = nullptr,
               std::string* out_detail   = nullptr)
    {
        if(!cfg.enabled || !compiled) return true;
        total_checked.fetch_add(1, std::memory_order_relaxed);

        // Build combined target string from enabled parts
        std::string target;
        target.reserve(path.size() + query.size() + 512);
        if(cfg.check_path)  target += path + " ";
        if(cfg.check_query) target += query + " ";
        if(cfg.check_body && !body.empty())
            target += body.substr(0, cfg.max_body_check) + " ";

        // Extract User-Agent from raw_headers for BadUA matching (always)
        std::string ua_str;
        if(!raw_headers.empty()) {
            auto uap = raw_headers.find("User-Agent:");
            if(uap == std::string::npos) uap = raw_headers.find("user-agent:");
            if(uap != std::string::npos) {
                auto end = raw_headers.find('\n', uap);
                ua_str = raw_headers.substr(uap, end == std::string::npos ? 256 : end - uap);
            }
        }

        // URL-decode target once for better pattern coverage
        std::string decoded = url_decode(target);

        for(auto& ps : pattern_sets) {
            // BadUA uses User-Agent header only; others use path/query/body
            const std::string& check_str = (ps.category == "BadUA")
                ? ua_str
                : decoded;
            if(check_str.empty()) continue;
            for(size_t i = 0; i < ps.patterns.size(); i++) {
                std::smatch m;
                if(std::regex_search(check_str, m, ps.patterns[i])) {
                    total_detected.fetch_add(1, std::memory_order_relaxed);
                    if(cfg.block_mode)
                        total_blocked.fetch_add(1, std::memory_order_relaxed);

                    std::string matched_str = m.str().substr(0, 60);
                    std::string cat = ps.category;

                    if(out_category) *out_category = cat;
                    if(out_detail)   *out_detail   = matched_str;

                    // Record event
                    {
                        std::lock_guard<std::mutex> lk(events_mu);
                        WafRegexEvent ev;
                        ev.ts       = time(nullptr);
                        ev.ip       = ip;
                        ev.method   = method;
                        ev.uri      = path.substr(0, 150);
                        if(!query.empty()) ev.uri += "?" + query.substr(0,50);
                        ev.category = cat;
                        ev.matched  = ps.raw.size() > i ? ps.raw[i].substr(0,60) : "?";
                        ev.detail   = matched_str;
                        events.push_back(ev);
                        if((int)events.size() > 200) events.pop_front();
                    }

                    if(cfg.block_mode && on_block)
                        on_block(ip, cat + ": " + matched_str);

                    return !cfg.block_mode;  // false=block, true=detect-only
                }
            }
        }
        return true;  // allow
    }

    // ── Stats JSON ────────────────────────────────────────────────────────────
    std::string stats_json() {
        std::lock_guard<std::mutex> lk(events_mu);
        // count per category
        std::unordered_map<std::string,int> cat_counts;
        for(auto& e : events) cat_counts[e.category]++;

        std::string cats = "[";
        bool first = true;
        for(auto& [k,v] : cat_counts) {
            if(!first) cats += ",";
            first = false;
            cats += "{\"cat\":\""+k+"\",\"count\":"+std::to_string(v)+"}";
        }
        cats += "]";

        std::string j = "{\"enabled\":" + std::string(cfg.enabled?"true":"false") +
            ",\"block_mode\":" + (cfg.block_mode?"true":"false") +
            ",\"compiled\":"   + (compiled?"true":"false") +
            ",\"total_checked\":"  + std::to_string(total_checked.load()) +
            ",\"total_blocked\":"  + std::to_string(total_blocked.load()) +
            ",\"total_detected\":" + std::to_string(total_detected.load()) +
            ",\"categories\":" + cats +
            ",\"events\":[";

        first = true;
        int start = (int)events.size() > 50 ? (int)events.size()-50 : 0;
        for(int i = (int)events.size()-1; i >= start; i--){
            auto& e = events[i];
            char ts[32]; struct tm* tm = localtime(&e.ts);
            strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
            auto esc=[](std::string s){
                std::string o; for(char c:s){
                    if(c=='"') o+="\\\""; else if(c=='\\') o+="\\\\";
                    else if(c<32) o+=" "; else o+=c;
                } return o;
            };
            if(!first) j += ",";
            first = false;
            j += "{\"ts\":\"" + std::string(ts) +
                 "\",\"ip\":\""      + e.ip +
                 "\",\"method\":\""  + e.method +
                 "\",\"uri\":\""     + esc(e.uri) +
                 "\",\"cat\":\""     + e.category +
                 "\",\"detail\":\""  + esc(e.detail) + "\"}";
        }
        j += "]}";
        return j;
    }

    void clear_events() {
        std::lock_guard<std::mutex> lk(events_mu);
        events.clear();
    }

private:
    // ── Simple URL decoder ────────────────────────────────────────────────────
    static std::string url_decode(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for(size_t i = 0; i < s.size(); i++) {
            if(s[i]=='%' && i+2 < s.size() &&
               isxdigit((unsigned char)s[i+1]) &&
               isxdigit((unsigned char)s[i+2])) {
                char hex[3] = {s[i+1], s[i+2], 0};
                out += (char)strtol(hex, nullptr, 16);
                i += 2;
            } else if(s[i]=='+') {
                out += ' ';
            } else {
                out += s[i];
            }
        }
        return out;
    }
};

// g_waf_regex defined once in server.cc
#ifndef WAF_REGEX_IMPL
extern WafRegexEngine g_waf_regex;
#endif
