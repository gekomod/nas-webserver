#pragma once
// ── admin_tls_guard.hh ────────────────────────────────────────────────────────
// Middleware: enforce HTTPS for /np_admin and configurable admin endpoints.
//
// Usage in request pipeline (before routing):
//
//   if (!admin_tls_guard(req, is_tls, cfg, response_out)) return;  // 301 sent
//
// Config knob in nas-web.conf:
//   admin_tls_only   true;   # default: true — plain HTTP returns 301
//
// To add new protected prefixes, extend AdminTlsGuard::PROTECTED_PREFIXES.
// ─────────────────────────────────────────────────────────────────────────────

#include <string>
#include <string_view>
#include <array>

// Forward declarations (defined in server / np_types)
struct Request;
struct Response;
struct NpConfig;

namespace AdminTlsGuard {

// Paths that must only be reachable over TLS when admin_tls_only=true.
constexpr std::array<std::string_view, 4> PROTECTED_PREFIXES = {
    "/np_admin",
    "/apis/admin",
    "/apis/healths",   // exposes internal health details
    "/apis/metrics",
};

// Returns true  → request is allowed (either TLS, or guard disabled, or not an admin path).
// Returns false → plain-HTTP request to protected path; *resp is populated with 301.
inline bool check(const std::string& path,
                  bool               is_tls,
                  bool               admin_tls_only_enabled,
                  const std::string& host,
                  Response*          resp)
{
    if (!admin_tls_only_enabled) return true;  // feature disabled in config
    if (is_tls)                  return true;  // already on HTTPS

    bool protected_path = false;
    for (auto& prefix : PROTECTED_PREFIXES) {
        if (path.size() >= prefix.size() &&
            path.compare(0, prefix.size(), prefix) == 0)
        {
            protected_path = true;
            break;
        }
    }
    if (!protected_path) return true;

    // Build 301 redirect to HTTPS.
    // Strip any explicit :80 from Host header so the redirect URL is clean.
    std::string clean_host = host;
    auto colon = clean_host.rfind(':');
    if (colon != std::string::npos) {
        std::string_view port_sv(clean_host.data() + colon + 1,
                                  clean_host.size() - colon - 1);
        if (port_sv == "80") clean_host.erase(colon);
    }

    resp->status = 301;
    resp->headers.set("Location", "https://" + clean_host + path);
    resp->headers.set("Content-Type", "text/plain");
    resp->headers.set("Content-Length", "0");
    // Prevent caching of the redirect so it doesn't get stuck if TLS is toggled.
    resp->headers.set("Cache-Control", "no-store");
    return false;
}

} // namespace AdminTlsGuard
