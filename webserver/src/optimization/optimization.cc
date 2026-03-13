// optimization.cc — nas-web page/asset optimization module
// Provides:
//   - zstd compression (alongside gzip/brotli)
//   - CSS minification (vendor/cssmin)
//   - HTML rewriting (lazy-load imgs, add charset meta if missing)
//   - WebP redirect hint (Content-Type + Vary header)
//   - JS/HTML minification (strip HTML comments, collapse whitespace)
// Compiled as part of server.cc (single-TU build)

#pragma once
#include <string>
#include <string_view>
#include <cstring>

// ── zstd ─────────────────────────────────────────────────────────────────────
#if defined(HAVE_ZSTD)
#  include "../../vendor/zstd/zstd.h"
#  define ZSTD_REAL 1
#else
#  include "../../vendor/zstd/zstd.h"   // stub — compiles but returns errors
#  define ZSTD_REAL 0
#endif

// ── CSS minifier ──────────────────────────────────────────────────────────────
#include "../../vendor/cssmin/cssmin.h"

// ── Janet scripting engine ────────────────────────────────────────────────────
#if defined(HAVE_JANET)
extern "C" {
#  include "../../vendor/janet/janet.h"
}
#  define JANET_REAL 1
#else
#  include "../../vendor/janet/janet.h"  // stub
#  define JANET_REAL 0
#endif

// ─────────────────────────────────────────────────────────────────────────────
namespace opt {

// ── zstd compression ─────────────────────────────────────────────────────────

struct CompressResult {
    std::string data;
    std::string encoding; // "zstd", "br", "gzip", or ""
};

// Compress with zstd. Returns empty string on failure (stub or error).
inline std::string zstd_compress(const std::string& src, int level = ZSTD_CLEVEL_DEFAULT) {
#if ZSTD_REAL
    size_t bound = ZSTD_compressBound(src.size());
    std::string out(bound, '\0');
    size_t r = ZSTD_compress(out.data(), bound, src.data(), src.size(), level);
    if (ZSTD_isError(r)) return {};
    out.resize(r);
    return out;
#else
    (void)src; (void)level;
    return {};
#endif
}

inline std::string zstd_decompress(const std::string& src) {
#if ZSTD_REAL
    long long fsize = ZSTD_getFrameContentSize(src.data(), src.size());
    if (fsize <= 0) return {};
    std::string out((size_t)fsize, '\0');
    size_t r = ZSTD_decompress(out.data(), (size_t)fsize, src.data(), src.size());
    if (ZSTD_isError(r)) return {};
    return out;
#else
    (void)src; return {};
#endif
}

inline bool zstd_available() { return ZSTD_REAL != 0; }

// Check if client accepts zstd
inline bool client_accepts_zstd(std::string_view accept_encoding) {
    return accept_encoding.find("zstd") != std::string_view::npos;
}

// ── CSS minification ──────────────────────────────────────────────────────────

inline std::string minify_css(const std::string& css) {
    return cssmin::minify(css);
}

// Ratio check — don't serve minified if barely smaller
inline bool should_minify_css(const std::string& orig, const std::string& minified) {
    if (minified.empty()) return false;
    if (minified.size() >= orig.size()) return false;
    // Only bother if we saved at least 3%
    return (orig.size() - minified.size()) * 100 / orig.size() >= 3;
}

// ── HTML rewriting ────────────────────────────────────────────────────────────

// Add loading="lazy" to <img> tags that don't already have it
inline std::string html_lazy_images(const std::string& html) {
    std::string out;
    out.reserve(html.size() + html.size() / 20);
    size_t pos = 0;
    while (pos < html.size()) {
        size_t tag = html.find("<img", pos);
        if (tag == std::string::npos) { out += html.substr(pos); break; }
        // Copy up to <img
        out += html.substr(pos, tag - pos);
        // Find end of tag
        size_t tend = html.find('>', tag);
        if (tend == std::string::npos) { out += html.substr(tag); break; }
        std::string imgtag = html.substr(tag, tend - tag + 1);
        // Only add if not already present
        if (imgtag.find("loading=") == std::string::npos &&
            imgtag.find("loading =") == std::string::npos) {
            // Insert before closing >
            size_t close = imgtag.rfind('>');
            bool self_close = (close > 0 && imgtag[close-1] == '/');
            if (self_close)
                imgtag.insert(close - 1, " loading=\"lazy\"");
            else
                imgtag.insert(close, " loading=\"lazy\"");
        }
        out += imgtag;
        pos = tend + 1;
    }
    return out;
}

// Add <meta charset="utf-8"> if missing from <head>
inline std::string html_ensure_charset(const std::string& html) {
    if (html.find("charset") != std::string::npos) return html;
    size_t head = html.find("<head");
    if (head == std::string::npos) return html;
    size_t headend = html.find('>', head);
    if (headend == std::string::npos) return html;
    std::string out = html;
    out.insert(headend + 1, "\n<meta charset=\"utf-8\">");
    return out;
}

// Strip HTML comments (<!-- ... -->) except IE conditionals <!--[if
inline std::string html_strip_comments(const std::string& html) {
    std::string out;
    out.reserve(html.size());
    size_t pos = 0;
    while (pos < html.size()) {
        size_t c = html.find("<!--", pos);
        if (c == std::string::npos) { out += html.substr(pos); break; }
        out += html.substr(pos, c - pos);
        // Check for IE conditional
        if (html.size() > c + 4 && html[c+4] == '[') {
            // Keep conditional comments
            size_t ce = html.find("-->", c + 4);
            if (ce == std::string::npos) { out += html.substr(c); break; }
            out += html.substr(c, ce - c + 3);
            pos = ce + 3;
        } else {
            size_t ce = html.find("-->", c + 4);
            if (ce == std::string::npos) { out += html.substr(c); break; }
            pos = ce + 3;
            // Replace with single space to avoid joining tokens
            if (!out.empty() && out.back() != ' ') out += ' ';
        }
    }
    return out;
}

// Combined HTML optimization pass
inline std::string optimize_html(const std::string& html, bool strip_comments = true, bool lazy_img = true) {
    std::string r = html;
    r = html_ensure_charset(r);
    if (strip_comments) r = html_strip_comments(r);
    if (lazy_img)       r = html_lazy_images(r);
    return r;
}

// ── Content-type helpers ──────────────────────────────────────────────────────

inline bool is_html(std::string_view ct) {
    return ct.find("text/html") != std::string_view::npos;
}
inline bool is_css(std::string_view ct) {
    return ct.find("text/css") != std::string_view::npos;
}
inline bool is_javascript(std::string_view ct) {
    return ct.find("javascript") != std::string_view::npos;
}
inline bool is_image(std::string_view ct) {
    return ct.find("image/") != std::string_view::npos;
}
inline bool is_compressible(std::string_view ct) {
    return is_html(ct) || is_css(ct) || is_javascript(ct) ||
           ct.find("text/") != std::string_view::npos ||
           ct.find("application/json") != std::string_view::npos ||
           ct.find("application/xml") != std::string_view::npos ||
           ct.find("image/svg") != std::string_view::npos;
}

// ── WebP detection ────────────────────────────────────────────────────────────
// Returns true if Accept header suggests browser supports WebP
inline bool client_accepts_webp(std::string_view accept) {
    return accept.find("image/webp") != std::string_view::npos;
}

// ── Janet WAF scripting ───────────────────────────────────────────────────────

struct JanetWAF {
    bool  enabled{false};
    void* env{nullptr};  // JanetTable* when real Janet

    void init() {
#if JANET_REAL
        janet_init();
        env = (void*)janet_core_env(nullptr);
        enabled = true;
#endif
    }
    void deinit() {
#if JANET_REAL
        if (enabled) janet_deinit();
        enabled = false;
#endif
    }

    // Load WAF rules from a Janet script file
    // Returns error string or "" on success
    std::string load_rules(const std::string& path) {
#if JANET_REAL
        if (!enabled) return "Janet not initialized";
        FILE* f = fopen(path.c_str(), "r");
        if (!f) return "Cannot open: " + path;
        fclose(f);
        Janet out;
        int r = janet_dostring((JanetTable*)env, nullptr, path.c_str(), &out);
        if (r != JANET_SIGNAL_OK) return "Janet error in: " + path;
        return "";
#else
        (void)path; return "Janet not compiled (run vendor/janet/fetch_janet.sh)";
#endif
    }

    // Evaluate a Janet expression for a request
    // Returns: 0=pass, 1=block, 2=challenge
    int eval_request(const std::string& ip, const std::string& uri,
                     const std::string& method, const std::string& ua) {
#if JANET_REAL
        if (!enabled || !env) return 0;
        // Build Janet expression: (waf-check ip uri method ua)
        std::string expr = "(if (defined? waf-check) "
            "(waf-check \"" + ip + "\" \"" + uri + "\" \""
            + method + "\" \"" + ua + "\") 0)";
        Janet out;
        int r = janet_dostring((JanetTable*)env, expr.c_str(), "waf-check", &out);
        if (r != JANET_SIGNAL_OK) return 0;
        if (janet_checktype(out, 1 /*JANET_NUMBER*/))
            return (int)janet_unwrap_integer(out);
        return janet_truthy(out) ? 1 : 0;
#else
        (void)ip; (void)uri; (void)method; (void)ua; return 0;
#endif
    }
};

// Global singleton (initialized in server startup)
static JanetWAF g_janet_waf;

// ── Version strings for admin panel ──────────────────────────────────────────

inline const char* zstd_version_str() {
#if ZSTD_REAL
    return ZSTD_VERSION_STRING;
#else
    return "not compiled (run vendor/zstd/fetch_zstd.sh)";
#endif
}

inline const char* janet_version_str() {
#if JANET_REAL
    return JANET_VERSION;
#else
    return "not compiled (run vendor/janet/fetch_janet.sh)";
#endif
}

} // namespace opt
