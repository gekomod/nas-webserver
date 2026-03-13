/**
 * security_headers.js — inject security headers + log slow requests
 *
 * Security headers added to every response:
 *   - Strict-Transport-Security (HSTS)
 *   - X-Content-Type-Options
 *   - X-Frame-Options
 *   - Content-Security-Policy (basic)
 *   - Referrer-Policy
 *   - Permissions-Policy
 */

const SECURITY_HEADERS = {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'X-Content-Type-Options':    'nosniff',
    'X-Frame-Options':           'DENY',
    'Referrer-Policy':           'strict-origin-when-cross-origin',
    'Permissions-Policy':        'camera=(), microphone=(), geolocation=()',
};

// Strict CSP — adjust per app
const CSP = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",  // remove unsafe-inline in production
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "connect-src 'self' wss:",
    "font-src 'self'",
    "frame-ancestors 'none'",
].join('; ');

module.exports.default = {

    onRequest(req) {
        // Block obviously malicious paths
        const blocked_patterns = [
            '/.env', '/.git', '/wp-admin', '/phpmyadmin',
            '/etc/passwd', '/proc/', '/../'
        ];
        for (const p of blocked_patterns) {
            if (req.path.includes(p)) {
                log.warn(`Blocked malicious path: ${req.path} from ${req.clientIp}`);
                return { status: 403, body: '{"error":"Forbidden"}',
                         headers: { 'Content-Type': 'application/json' } };
            }
        }
        return null;
    },

    onResponse(req, resp) {
        // Apply security headers
        for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
            resp.headers[k] = v;
        }
        // Only add CSP for HTML responses
        const ct = resp.headers['content-type'] || resp.headers['Content-Type'] || '';
        if (ct.includes('text/html')) {
            resp.headers['Content-Security-Policy'] = CSP;
        }
        // Remove fingerprinting headers
        delete resp.headers['Server'];
        delete resp.headers['X-Powered-By'];
        delete resp.headers['X-AspNet-Version'];
        return resp;
    }
};
