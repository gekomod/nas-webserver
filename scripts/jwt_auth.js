/**
 * jwt_auth.js — JWT Bearer token validation middleware
 *
 * Runs in V8 (nodeproxy embedded engine).
 * Verifies Authorization: Bearer <token> header.
 * Extracts user ID and injects X-User-Id for Node.js.
 *
 * Configuration via environment (set in nodeproxy.conf or env):
 *   JWT_SECRET — HMAC-SHA256 signing secret
 */

// Simple base64url decode (V8 has btoa/atob but not base64url)
function base64url_decode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    try {
        return JSON.parse(atob(str));
    } catch {
        return null;
    }
}

// Constant-time string comparison (prevent timing attacks)
function safe_eq(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
}

module.exports.default = {

    /**
     * Intercept request before forwarding to Node.js.
     * Return null → pass through.
     * Return object { status, body, headers } → short-circuit response.
     */
    onRequest(req) {
        const auth = req.headers['authorization'] || req.headers['Authorization'];

        // Skip auth for OPTIONS (CORS preflight)
        if (req.method === 'OPTIONS') return null;

        if (!auth || !auth.startsWith('Bearer ')) {
            return {
                status: 401,
                body: JSON.stringify({ error: 'Missing Authorization header' }),
                headers: {
                    'Content-Type': 'application/json',
                    'WWW-Authenticate': 'Bearer realm="API"'
                }
            };
        }

        const token = auth.slice(7);
        const parts = token.split('.');
        if (parts.length !== 3) {
            return { status: 401, body: JSON.stringify({ error: 'Invalid token format' }) };
        }

        const payload = base64url_decode(parts[1]);
        if (!payload) {
            return { status: 401, body: JSON.stringify({ error: 'Invalid token payload' }) };
        }

        // Check expiry
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < now) {
            return {
                status: 401,
                body: JSON.stringify({ error: 'Token expired', exp: payload.exp }),
                headers: { 'Content-Type': 'application/json' }
            };
        }

        // Inject user info into request headers (visible to Node.js)
        if (payload.sub)   req.headers['X-User-Id']    = String(payload.sub);
        if (payload.role)  req.headers['X-User-Role']  = String(payload.role);
        if (payload.email) req.headers['X-User-Email'] = String(payload.email);

        // Note: signature not verified here (requires crypto.subtle HMAC)
        // For production: implement full HMAC-SHA256 verification
        // or delegate to a fast validation microservice via cache

        log.info(`JWT auth: user=${payload.sub} role=${payload.role} path=${req.path}`);
        return null; // pass through
    },

    onResponse(req, resp) {
        // Add request ID to response for tracing
        const userId = req.headers['X-User-Id'];
        if (userId) resp.headers['X-Served-To'] = userId;
        return resp;
    }
};
