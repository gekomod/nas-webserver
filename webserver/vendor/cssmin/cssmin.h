/*
 * cssmin.h — single-header CSS minifier for nas-web
 * Based on the algorithm by Barnabus Nnaemeka (public domain)
 * Removes comments, excess whitespace, redundant semicolons.
 * No external dependencies.
 */
#pragma once
#ifndef CSSMIN_H_NAS_WEB
#define CSSMIN_H_NAS_WEB

#include <string>
#include <cstring>

namespace cssmin {

inline std::string minify(const std::string& css) {
    std::string out;
    out.reserve(css.size());
    const char* p = css.c_str();
    const char* end = p + css.size();

    while (p < end) {
        // Skip /* ... */ comments
        if (p+1 < end && p[0]=='/' && p[1]=='*') {
            p += 2;
            while (p+1 < end && !(p[0]=='*' && p[1]=='/')) ++p;
            p += 2;
            continue;
        }
        // Preserve strings (don't mangle content inside quotes)
        if (*p == '"' || *p == '\'') {
            char q = *p++;
            out += q;
            while (p < end && *p != q) {
                if (*p == '\\' && p+1 < end) { out += *p++; }
                out += *p++;
            }
            if (p < end) { out += *p++; }  // closing quote
            continue;
        }
        // Collapse whitespace
        if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
            // Emit single space only if last char wasn't delimiter
            if (!out.empty()) {
                char last = out.back();
                char nxt = ' ';
                // Find next non-ws
                const char* tmp = p;
                while (tmp < end && (*tmp==' '||*tmp=='\t'||*tmp=='\r'||*tmp=='\n')) ++tmp;
                if (tmp < end) nxt = *tmp;
                bool last_del = (last=='{'||last=='}'||last==';'||last==':'||last==','||last=='>'||last=='~'||last=='+'||last=='('||last==')');
                bool next_del = (nxt=='{'||nxt=='}'||nxt==';'||nxt==':'||nxt==','||nxt=='>'||nxt=='~'||nxt=='+'||nxt=='('||nxt==')'||nxt==0);
                if (!last_del && !next_del) out += ' ';
            }
            // Skip all whitespace
            while (p < end && (*p==' '||*p=='\t'||*p=='\r'||*p=='\n')) ++p;
            continue;
        }
        // Remove redundant semicolons before }
        if (*p == ';') {
            const char* tmp = p+1;
            while (tmp < end && (*tmp==' '||*tmp=='\t'||*tmp=='\r'||*tmp=='\n')) ++tmp;
            if (tmp < end && *tmp == '}') { ++p; continue; }
        }
        // Remove space around : inside rule blocks (not in selectors)
        // Keep as-is, emit character
        out += *p++;
    }

    // Trim leading/trailing whitespace
    size_t s = out.find_first_not_of(" \t\r\n");
    size_t e2 = out.find_last_not_of(" \t\r\n");
    if (s == std::string::npos) return "";
    return out.substr(s, e2-s+1);
}

// Returns true if content-type suggests CSS
inline bool is_css_type(const std::string& ct) {
    return ct.find("text/css") != std::string::npos;
}

} // namespace cssmin

#endif /* CSSMIN_H_NAS_WEB */
