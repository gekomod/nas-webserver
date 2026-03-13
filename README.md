# nas-web

> High-performance C++20 reverse proxy and static file server for NAS/homelab environments.

[![Build](https://github.com/gekomod/nas-webserver/actions/workflows/build.yml/badge.svg)](https://github.com/gekomod/nas-webserver/actions/workflows/build.yml)
[![CodeQL](https://github.com/gekomod/nas-webserver/actions/workflows/codeql.yml/badge.svg)](https://github.com/gekomod/nas-webserver/actions/workflows/codeql.yml)
![Version](https://img.shields.io/badge/version-2.2.84-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

| Category | What's included |
|---|---|
| **Protocol** | HTTP/1.1, HTTP/2 (nghttp2), TLS 1.2/1.3 (OpenSSL 3), WebSocket proxy |
| **Compression** | gzip, Brotli, zstd — negotiated by `Accept-Encoding`, pre-compressed file support (`.gz` `.br` `.zst`) |
| **WAF** | Built-in regex WAF (SQLi, XSS, path traversal, CmdInjection, SSRF, XXE, BadUA) + optional ModSecurity v3 with OWASP CRS |
| **Scripting** | Lua 5.4 middleware, QuickJS (ES2020), Janet (Lisp-like WAF rules) |
| **TLS automation** | Built-in ACME client — HTTP-01 and DNS-01 (Cloudflare), wildcard certs |
| **Proxy** | Upstream pools, keepalive, health checks, load balancing (round-robin, sticky IP), WebSocket |
| **Cache** | In-memory LRU, configurable TTL, per-location control |
| **Rate limiting** | Token bucket per IP, per-location |
| **Security** | IP blacklist (persistent), auto-ban on 404 scan patterns, admin allowlist |
| **Optimization** | CSS minification, HTML rewriting (lazy-load images, charset), WebP content negotiation |
| **Admin panel** | Dark-theme web UI at `/np_admin` — real-time stats, WAF logs, cache control, ACME, config editor |

---

## Quick start

### Requirements

```
Ubuntu 22.04+ / Debian 12+
cmake >= 3.18
libuv1-dev libssl-dev zlib1g-dev libbrotli-dev libnghttp2-dev liblua5.4-dev
```

### Build and install

```bash
git clone https://github.com/nas-panel/nas-web
cd nas-web
bash build-deb.sh
sudo dpkg -i nas-web_2.2.83-1_amd64.deb
sudo systemctl enable --now nas-web
```

Admin panel: `http://localhost/np_admin` (default: `admin` / `nas-web-admin`)

> **Change the password** in `/etc/nas-web/nas-web.conf` before exposing to a network.

### Build options

```bash
bash build-deb.sh [options]

  --with-modsec    ModSecurity WAF (requires: apt install libmodsecurity-dev modsecurity-crs)
  --with-zstd      zstd compression  (requires: bash vendor/zstd/fetch_zstd.sh first)
  --with-janet     Janet WAF scripting (requires: bash vendor/janet/fetch_janet.sh first)
  --no-rebuild     Skip CMake/make, only repackage .deb
```

Full build with all optional modules:

```bash
bash vendor/zstd/fetch_zstd.sh
bash vendor/janet/fetch_janet.sh
bash vendor/quickjs/fetch_quickjs.sh
bash build-deb.sh --with-modsec --with-zstd --with-janet
```

---

## Configuration

`/etc/nas-web/nas-web.conf` — annotated example:

```nginx
worker_processes    0;          # 0 = auto (one per CPU core)
worker_connections  4096;
cache_size          1024;       # max cached entries
cache_ttl           60;         # seconds
log_level           info;       # debug | info | warn | error

admin_user          admin;
admin_password      changeme;
# admin_allow_ips   192.168.1.  10.0.0.;   # restrict panel to LAN

upstream backend {
    server 127.0.0.1:3000;
    keepalive 32;
}

server {
    listen 80;
    listen 443 ssl;

    # Self-signed cert auto-generated at startup if no ssl_cert specified.
    # For real certs:
    #   ssl_cert /etc/nas-web/certs/fullchain.pem;
    #   ssl_key  /etc/nas-web/certs/privkey.pem;

    location /api {
        proxy_pass    backend;
        proxy_timeout 30;
        cache         off;
    }

    location /ws {
        proxy_pass    backend;
        websocket     on;
        proxy_timeout 3600;
        cache         off;
    }

    location /assets {
        root       /opt/app/dist;
        cache      max_age=31536000;
        gzip       on;
        etag       on;
    }

    location / {
        root       /opt/app/dist;
        gzip       on;
        etag       on;
    }
}

# ACME / Let's Encrypt (HTTP-01)
# acme {
#     email    admin@example.com;
#     domains  example.com www.example.com;
#     staging  false;
# }

# ACME DNS-01 wildcard (Cloudflare)
# acme {
#     email          admin@example.com;
#     domains        example.com *.example.com;
#     challenge      dns-01;
#     dns_provider   cloudflare;
#     dns_cf_token   CF_API_TOKEN;
# }
```

---

## Scripting

### Lua middleware

```lua
-- /etc/nas-web/scripts/admin_acl.lua
if request.path:match("^/admin") then
    local ip = request.remote_addr
    if not ip:match("^192%.168%.") then
        return response.forbidden("Admin access restricted to LAN")
    end
end
```

### QuickJS (ES2020)

```javascript
// /etc/nas-web/scripts/security_headers.js
export function onResponse(req, res) {
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
}
```

### Janet WAF rules

```janet
# /etc/nas-web/scripts/waf_custom.janet
(defn waf-check [ip uri method ua]
  (cond
    (string/find "curl/7." ua)  1   # block old curl scanners
    (string/find "/etc/passwd" uri) 1
    0))                             # 0=pass, 1=block
```

Activate Janet WAF rules by building with `--with-janet`.

---

## Admin panel endpoints

All endpoints require HTTP Basic auth (`admin_user` / `admin_password`).

| Endpoint | Description |
|---|---|
| `GET /np_admin` | Web admin panel |
| `GET /np_stats` | JSON: requests, connections, cache hit rate, uptime |
| `GET /np_status` | JSON: module status, version, workers |
| `GET /np_logs?since=&limit=` | Structured log query |
| `GET /np_logs/stream` | SSE live log stream |
| `GET /np_waf_regex` | Built-in WAF stats + events |
| `POST /np_waf_regex` | Toggle WAF, clear events |
| `GET /np_waf` | ModSecurity stats + events |
| `GET /np_cache` | Cache stats |
| `POST /np_cache_flush` | Flush cache |
| `GET /np_blacklist` | IP blacklist |
| `POST /np_blacklist` | Add / remove IP |
| `GET /np_upstream` | Upstream pool stats |
| `GET /np_acme` | ACME status |
| `POST /np_acme` | Trigger cert renewal |
| `GET /np_config` | Current config (sanitized) |
| `POST /np_reload` | Reload config (SIGHUP) |
| `GET /np_connections` | Active connections |
| `GET /np_workers` | Worker stats |
| `GET /np_autoban` | Auto-ban stats |
| `GET /np_audit` | Admin audit log |

---

## Vendor libraries

| Library | Path | Activate |
|---|---|---|
| [QuickJS](https://bellard.org/quickjs/) | `vendor/quickjs/` | `bash vendor/quickjs/fetch_quickjs.sh` |
| [zstd](https://github.com/facebook/zstd) v1.5.7 | `vendor/zstd/` | `bash vendor/zstd/fetch_zstd.sh` + `--with-zstd` |
| [Janet](https://janet-lang.org/) v1.41.2 | `vendor/janet/` | `bash vendor/janet/fetch_janet.sh` + `--with-janet` |
| cssmin | `vendor/cssmin/cssmin.h` | always active (header-only) |

All vendor libraries are optional. The project compiles and runs with stub headers when vendor sources are not downloaded.

---

## Project structure

```
nas-web/
├── src/
│   ├── core/server.cc          # single-TU entry point — includes all other .cc
│   ├── http/parser.cc          # HTTP/1.1 parser
│   ├── http/h2_handler.cc      # HTTP/2 (nghttp2)
│   ├── http/h3_handler.cc      # HTTP/3 stub (quiche)
│   ├── cache/cache.cc          # LRU response cache
│   ├── proxy/upstream.cc       # upstream pool, keepalive, health checks
│   ├── security/ratelimit.cc   # token bucket rate limiter
│   ├── static/static_handler.cc# static files, gzip/br/zstd, ETag, Range
│   ├── optimization/optimization.cc  # CSS minify, HTML rewrite, zstd, Janet
│   ├── scripting/middleware_pipeline.cc  # Lua + QuickJS middleware
│   ├── config/config_parser.cc # config file parser
│   └── tls/acme.cc             # ACME client (HTTP-01 + DNS-01)
├── include/
│   ├── np_types.hh             # shared types (Request, Response, Headers)
│   ├── np_config.hh            # config structs
│   ├── waf.hh                  # ModSecurity v3 wrapper
│   ├── waf_regex.hh            # built-in regex WAF engine
│   ├── autoban.hh              # auto-ban on scan patterns
│   └── admin_panel.h           # admin panel HTML (embedded)
├── vendor/
│   ├── quickjs/                # QuickJS JS engine (fetch_quickjs.sh)
│   ├── zstd/                   # facebook/zstd (fetch_zstd.sh)
│   ├── janet/                  # Janet language (fetch_janet.sh)
│   └── cssmin/cssmin.h         # CSS minifier (header-only)
├── conf/nas-web.conf           # example configuration
├── scripts/                    # example Lua/JS/Janet middleware
├── tests/                      # unit tests (parser, cache, ratelimit)
├── CMakeLists.txt
├── build-deb.sh                # build + package as .deb
└── nas-web.service             # systemd unit
```

---

## Building from source (without .deb)

```bash
sudo apt-get install cmake libuv1-dev libssl-dev zlib1g-dev \
    libbrotli-dev libnghttp2-dev liblua5.4-dev

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    -DWITH_LUA=ON -DWITH_NGHTTP2=ON -DWITH_BROTLI=ON -DWITH_ACME=ON
cmake --build build --parallel $(nproc)

sudo install -m755 build/nas-web /usr/local/bin/nas-web
sudo mkdir -p /var/log/nas-web /etc/nas-web
sudo cp conf/nas-web.conf /etc/nas-web/
sudo nas-web /etc/nas-web/nas-web.conf
```

---

## Security notes

- The admin panel (`/np_admin`) is protected by HTTP Basic auth. Restrict access to LAN with `admin_allow_ips` in config.
- Self-signed TLS certificate is auto-generated at startup. For production use ACME or provide your own cert.
- Built-in WAF regex runs on every request before routing — it cannot be bypassed by 404-bound scanners.
- ModSecurity requires `apt install libmodsecurity-dev modsecurity-crs` and `--with-modsec` at build time.
- `NoNewPrivileges=no` in the systemd unit — the process binds port 80/443 as root, then continues as root. For privilege drop, set `User=` in the service file and use `CAP_NET_BIND_SERVICE`.

---

## License

MIT — see [LICENSE](LICENSE).
