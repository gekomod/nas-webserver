-- admin_acl.lua — IP-based access control for /admin
-- Lua is lighter than V8 for simple rule evaluation

local ALLOWED_IPS = {
    ["127.0.0.1"]    = true,
    ["10.0.0.1"]     = true,
    ["10.0.0.2"]     = true,
    ["192.168.1.0"]  = true,
}

local ALLOWED_CIDRS = {
    { prefix = "10.0.", len = 5 },
    { prefix = "172.16.", len = 7 },
    { prefix = "192.168.", len = 8 },
}

local function ip_allowed(ip)
    if ALLOWED_IPS[ip] then return true end
    for _, cidr in ipairs(ALLOWED_CIDRS) do
        if ip:sub(1, cidr.len) == cidr.prefix then return true end
    end
    return false
end

function on_request(req)
    local ip = req.client_ip or ""

    if not ip_allowed(ip) then
        np.log("warn", "Admin access denied: " .. ip .. " -> " .. req.path)
        return {
            status = 403,
            body   = '{"error":"Forbidden","message":"Admin access restricted"}',
            headers = { ["Content-Type"] = "application/json" }
        }
    end

    -- Add admin marker for Node.js
    req.headers["X-Admin-Access"] = "true"
    req.headers["X-Client-Ip"]    = ip
    np.log("info", "Admin access granted: " .. ip)
    return nil -- pass through
end

function on_response(req, resp)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Robots-Tag"]  = "noindex"
    return resp
end
