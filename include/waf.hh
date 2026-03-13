#pragma once
#ifdef WITH_MODSEC
// ── WAF wrapper — libmodsecurity3 (ModSecurity v3) ──────────────────────────
// Requires: libmodsecurity-dev, libmodsecurity3
// OWASP CRS rules: /etc/modsecurity/crs/ or modsec_rules_dir in config
//
// API used:
//   modsecurity/modsecurity.h  — ModSecurity core
//   modsecurity/rules_set.h    — rules loading
//   modsecurity/transaction.h  — per-request transaction

#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>

#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <ctime>
#include <functional>
#include <filesystem>

namespace fs = std::filesystem;

struct WafEvent {
    time_t      ts;
    std::string ip;
    std::string method;
    std::string uri;
    std::string rule_id;
    std::string message;
    std::string severity;
    int         status;  // suggested HTTP status (403)
};

struct WafEngine {
    // ── Config ────────────────────────────────────────────────────────────────
    struct Config {
        bool        enabled     = true;
        bool        block_mode  = true;   // false = detect-only (log but allow)
        std::string rules_dir   = "/etc/modsecurity/crs";
        std::string main_conf   = "/etc/modsecurity/modsecurity.conf";
        std::string connector   = "nas-web";
    } cfg;

    // ── State ─────────────────────────────────────────────────────────────────
    modsecurity::ModSecurity* modsec  = nullptr;
    modsecurity::RulesSet*    rules   = nullptr;
    bool                      loaded  = false;
    int                       rules_count = 0;
    std::string               load_error;

    std::atomic<uint64_t>     total_checked{0};
    std::atomic<uint64_t>     total_blocked{0};
    std::atomic<uint64_t>     total_detected{0};

    std::deque<WafEvent>      events;   // last 200
    std::mutex                events_mu;

    // ── Callback: called when IP should be banned (optional) ─────────────────
    std::function<void(const std::string& ip, const std::string& reason)> on_block;

    // ── Init ──────────────────────────────────────────────────────────────────
    bool init() {
        modsec = modsecurity::msc_init();
        if(!modsec){ load_error = "msc_init() failed"; return false; }

        modsecurity::msc_set_connector_info(modsec, cfg.connector.c_str());
        modsecurity::msc_set_log_cb(modsec, [](void*, const void*) {
            // ModSecurity internal logs — suppressed
        });

        rules = modsecurity::msc_create_rules_set();
        if(!rules){ load_error = "msc_create_rules_set() failed"; return false; }

        const char* err = nullptr;
        int loaded_count = 0;

        // ── Helper: load single file ─────────────────────────────────────────
        auto load_file = [&](const std::string& path) -> bool {
            if(!fs::exists(path)) return true;  // skip missing, non-fatal
            int r = modsecurity::msc_rules_add_file(rules, path.c_str(), &err);
            if(r < 0){
                NW_WARN("waf", "Rule load error %s: %s", path.c_str(), err?err:"unknown");
                // Non-fatal — continue loading other files
                return true;
            }
            loaded_count += r;
            return true;
        };

        // ── Auto-discover rules_dir if not set or default is empty ────────────
        // Candidate paths in priority order
        static const char* CANDIDATES[] = {
            "/etc/modsecurity/crs",
            "/usr/share/modsecurity-crs",
            "/usr/share/modsecurity-crs/owasp-crs",
            "/etc/modsecurity",
            "/usr/local/modsecurity",
            nullptr
        };
        if(cfg.rules_dir.empty() || cfg.rules_dir == "/etc/modsecurity/crs"){
            for(int i = 0; CANDIDATES[i]; i++){
                // Check if this dir has actual .conf files (setup or rules)
                std::string candidate = CANDIDATES[i];
                bool has_rules = fs::exists(candidate + "/crs-setup.conf") ||
                                 fs::exists(candidate + "/rules") ||
                                 [&](){
                                     if(!fs::is_directory(candidate)) return false;
                                     for(auto& e : fs::directory_iterator(candidate))
                                         if(e.path().extension() == ".conf") return true;
                                     return false;
                                 }();
                if(has_rules){
                    cfg.rules_dir = candidate;
                    NW_INFO("waf", "Auto-detected CRS rules dir: %s", candidate.c_str());
                    break;
                }
            }
        }

        // ── Load modsecurity.conf ─────────────────────────────────────────────
        // Look in rules_dir and /etc/modsecurity
        for(auto& mc : {cfg.main_conf,
                         cfg.rules_dir + "/modsecurity.conf",
                         std::string("/etc/modsecurity/modsecurity.conf")}){
            if(fs::exists(mc)){
                int r = modsecurity::msc_rules_add_file(rules, mc.c_str(), &err);
                if(r >= 0) loaded_count += r;
                break;
            }
        }

        // ── Load crs-setup.conf ───────────────────────────────────────────────
        for(auto& setup : {cfg.rules_dir + "/crs-setup.conf",
                            cfg.rules_dir + "/owasp-crs/crs-setup.conf"}){
            if(fs::exists(setup)){ load_file(setup); break; }
        }

        // ── Load rules/*.conf (sorted) ────────────────────────────────────────
        // Try several subdirectory layouts used by different distros
        std::vector<std::string> rule_dirs = {
            cfg.rules_dir + "/rules",        // Debian/Ubuntu: /usr/share/modsecurity-crs/rules/
            cfg.rules_dir,                   // flat layout
            cfg.rules_dir + "/owasp-crs/rules",
        };
        for(auto& rdir : rule_dirs){
            if(!fs::is_directory(rdir)) continue;
            std::vector<fs::path> rule_files;
            for(auto& ent : fs::directory_iterator(rdir))
                if(ent.path().extension() == ".conf")
                    rule_files.push_back(ent.path());
            if(rule_files.empty()) continue;
            std::sort(rule_files.begin(), rule_files.end());
            int before = loaded_count;
            for(auto& f : rule_files) load_file(f.string());
            if(loaded_count > before) break;  // found rules, stop searching
        }

        if(loaded_count == 0){
            load_error = "No rules loaded — tried: " + cfg.rules_dir +
                " and standard paths. Run: apt install modsecurity-crs";
            NW_WARN("waf", "%s", load_error.c_str());
        }

        rules_count = loaded_count;
        loaded = true;
        NW_INFO("waf", "ModSecurity %s ready — %d rules loaded from %s (mode: %s)",
                "(v3)",
                loaded_count, cfg.rules_dir.c_str(),
                cfg.block_mode ? "BLOCK" : "DETECT");
        return true;
    }

    // ── Check a request ───────────────────────────────────────────────────────
    // Returns true = allow, false = block
    bool check(const std::string& client_ip,
               const std::string& method,
               const std::string& uri,
               const std::string& http_version,
               const std::string& request_headers,  // raw "Name: Value\r\n" pairs
               const std::string& body,
               int* out_status = nullptr,
               std::string* out_rule_id = nullptr)
    {
        if(!cfg.enabled || !loaded || !modsec || !rules) return true;

        total_checked.fetch_add(1, std::memory_order_relaxed);

        modsecurity::Transaction* tx =
            modsecurity::msc_new_transaction(modsec, rules, nullptr);
        if(!tx) return true;  // fail-open

        // ── Feed request data ─────────────────────────────────────────────────
        modsecurity::msc_process_connection(tx,
            client_ip.c_str(), 0,
            "0.0.0.0", 80);  // server IP/port not critical for WAF

        modsecurity::msc_process_uri(tx,
            uri.c_str(),
            method.c_str(),
            http_version.c_str());

        // Parse and add headers
        size_t pos = 0;
        while(pos < request_headers.size()){
            size_t colon = request_headers.find(':', pos);
            size_t eol   = request_headers.find("\r\n", pos);
            if(eol == std::string::npos) eol = request_headers.find('\n', pos);
            if(colon == std::string::npos || (eol != std::string::npos && colon > eol)){
                if(eol == std::string::npos) break;
                pos = eol + (request_headers[eol]=='\r' ? 2 : 1);
                continue;
            }
            std::string hname = request_headers.substr(pos, colon-pos);
            size_t vstart = colon+1;
            while(vstart < request_headers.size() && request_headers[vstart]==' ') vstart++;
            size_t vend = (eol != std::string::npos) ? eol : request_headers.size();
            std::string hval = request_headers.substr(vstart, vend-vstart);
            modsecurity::msc_add_request_header(tx,
                (const unsigned char*)hname.c_str(),
                (const unsigned char*)hval.c_str());
            pos = (eol != std::string::npos)
                ? eol + (request_headers[eol]=='\r' ? 2 : 1)
                : request_headers.size();
        }
        modsecurity::msc_process_request_headers(tx);

        if(!body.empty()){
            modsecurity::msc_append_request_body(tx,
                (const unsigned char*)body.data(), body.size());
            modsecurity::msc_process_request_body(tx);
        }

        // ── // Check intervention after each phase
        // ModSec v3: msc_intervention() checked after URI/headers/body phases.
        // One call at end misses phase-1/2 detections.
        // Events recorded in both BLOCK and DETECT mode.

        auto extract_tag = [](const std::string& log, const std::string& tag) -> std::string {
            std::string needle = "[" + tag + " \"";
            auto p = log.find(needle);
            if(p == std::string::npos) return "";
            p += needle.size();
            auto e = log.find("\"", p);
            return e != std::string::npos ? log.substr(p, e-p) : "";
        };

        auto check_itv = [&](modsecurity::Transaction* tx_) -> bool {
            modsecurity::ModSecurityIntervention itv;
            memset(&itv, 0, sizeof(itv));
            itv.status = 200;
            if(!modsecurity::msc_intervention(tx_, &itv)) return false;
            if(itv.status < 400) {
                if(itv.log) free(itv.log);
                if(itv.url) free(itv.url);
                return false;
            }

            total_detected.fetch_add(1, std::memory_order_relaxed);
            bool do_block = cfg.block_mode;
            if(do_block) total_blocked.fetch_add(1, std::memory_order_relaxed);

            std::string rule_id, message, severity;
            if(itv.log) {
                std::string log_str(itv.log);
                rule_id  = extract_tag(log_str, "id");
                message  = extract_tag(log_str, "msg");
                severity = extract_tag(log_str, "severity");
                if(message.empty()) {
                    // Fallback: use first part of raw log
                    message = log_str.substr(0, 150);
                    auto nl = message.find('\n');
                    if(nl != std::string::npos) message = message.substr(0, nl);
                }
                free(itv.log);
            }
            if(itv.url) free(itv.url);

            if(out_status)  *out_status  = itv.status;
            if(out_rule_id) *out_rule_id = rule_id;

            // Record event in both BLOCK and DETECT mode
            WafEvent ev;
            ev.ts       = time(nullptr);
            ev.ip       = client_ip;
            ev.method   = method;
            ev.uri      = uri.substr(0, 200);
            ev.rule_id  = rule_id.empty()  ? "?" : rule_id;
            ev.message  = message.empty()  ? "WAF detection" : message;
            ev.severity = severity.empty() ? "WARNING" : severity;
            ev.status   = itv.status;
            {
                std::lock_guard<std::mutex> lk(events_mu);
                events.push_back(ev);
                if((int)events.size() > 200) events.pop_front();
            }

            if(do_block && on_block)
                on_block(client_ip, "WAF rule " + ev.rule_id + ": " + ev.message);

            return do_block;
        };

        bool blocked = false;
        if(check_itv(tx)) blocked = true;

        modsecurity::msc_transaction_cleanup(tx);
        return !blocked;
    }

    // ── Stats JSON ────────────────────────────────────────────────────────────
    std::string stats_json(){
        std::lock_guard<std::mutex> lk(events_mu);
        std::string j = "{\"loaded\":" + std::string(loaded?"true":"false") +
            ",\"block_mode\":"  + (cfg.block_mode?"true":"false") +
            ",\"enabled\":"     + (cfg.enabled?"true":"false") +
            ",\"rules_dir\":\""  + cfg.rules_dir + "\"" +
            ",\"rules_count\":" + std::to_string(rules_count) +
            ",\"total_checked\":"  + std::to_string(total_checked.load()) +
            ",\"total_blocked\":"  + std::to_string(total_blocked.load()) +
            ",\"total_detected\":" + std::to_string(total_detected.load()) +
            ",\"events\":[";
        bool first = true;
        int start = (int)events.size() > 50 ? (int)events.size()-50 : 0;
        for(int i = (int)events.size()-1; i >= start; i--){
            auto& e = events[i];
            char ts[32]; struct tm* tm=localtime(&e.ts);
            strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S",tm);
            auto esc=[](std::string s){
                std::string o; for(char c:s){
                    if(c=='"') o+="\\\"";
                    else if(c=='\\') o+="\\\\";
                    else if(c=='\n'||c=='\r') o+=" ";
                    else o+=c;
                } return o;
            };
            if(!first) j+=",";
            first = false;
            j+="{\"ts\":\""+std::string(ts)+"\",\"ip\":\""+e.ip+
               "\",\"method\":\""+e.method+"\",\"uri\":\""+esc(e.uri)+
               "\",\"rule\":\""+e.rule_id+"\",\"msg\":\""+esc(e.message)+
               "\",\"sev\":\""+e.severity+"\",\"status\":"+std::to_string(e.status)+"}";
        }
        j += "]}";
        return j;
    }

    ~WafEngine(){
        if(rules)  modsecurity::msc_rules_cleanup(rules);
        if(modsec) modsecurity::msc_cleanup(modsec);
    }
};

static WafEngine g_waf;

#endif // WITH_MODSEC
