#!/usr/bin/env bash
# tests/integration/test_deb_package.sh
# ── Debian package integration tests ──────────────────────────────────────────
# Runs against a freshly installed .deb on a live Debian/Ubuntu system.
# Designed for CI (GitHub Actions, local Docker, autopkgtest).
#
# Requirements:
#   - Must be run as root (or via sudo) — dpkg and systemctl need it
#   - DEB_PATH env var must point to the built .deb, or pass it as $1
#   - Tested on: Debian 12, Ubuntu 22.04, Ubuntu 24.04
#
# Usage:
#   sudo DEB_PATH=./nas-web_2.3.0-1_amd64.deb bash tests/integration/test_deb_package.sh
#
# Exit code: 0 = all passed, 1 = one or more failures
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

DEB="${DEB_PATH:-${1:-}}"
PASS=0; FAIL=0
BINARY=/usr/local/bin/nas-web
SERVICE=nas-web
CONF=/etc/nas-web/nas-web.conf
LOG_DIR=/var/log/nas-web
TIMEOUT=10   # seconds to wait for service to come up

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓${NC} $*"; ((PASS++)); }
fail() { echo -e "${RED}  ✗ FAIL:${NC} $*"; ((FAIL++)); }
info() { echo -e "${YELLOW}  →${NC} $*"; }

require_root() {
    [[ $EUID -eq 0 ]] || { echo "ERROR: must run as root"; exit 1; }
}

# ── 1. Pre-flight ─────────────────────────────────────────────────────────────
section_preflight() {
    echo; echo "=== Pre-flight ==="
    require_root

    [[ -n "$DEB" ]] || { echo "ERROR: DEB_PATH not set"; exit 1; }
    [[ -f "$DEB" ]] || { echo "ERROR: .deb not found: $DEB"; exit 1; }
    ok "deb file exists: $DEB"

    command -v dpkg    >/dev/null && ok "dpkg available"    || fail "dpkg not found"
    command -v systemctl >/dev/null && ok "systemctl available" || fail "systemctl not found"
    command -v curl    >/dev/null && ok "curl available"    || fail "curl not found (needed for HTTP tests)"
}

# ── 2. Install ────────────────────────────────────────────────────────────────
section_install() {
    echo; echo "=== Install ==="

    info "Running: dpkg -i $DEB"
    dpkg -i "$DEB" && ok "dpkg -i exit 0" || { fail "dpkg -i failed"; exit 1; }

    # Satisfy any missing deps
    apt-get install -f -y -qq 2>/dev/null && ok "apt-get -f (deps satisfied)" || true

    # Verify binary
    [[ -x "$BINARY" ]] && ok "binary installed: $BINARY" || fail "binary missing: $BINARY"

    # Verify config
    [[ -f "$CONF" ]]   && ok "config installed: $CONF"   || fail "config missing: $CONF"

    # Verify log dir
    [[ -d "$LOG_DIR" ]] && ok "log dir exists: $LOG_DIR"  || fail "log dir missing: $LOG_DIR"

    # Verify systemd unit
    [[ -f "/lib/systemd/system/$SERVICE.service" || -f "/etc/systemd/system/$SERVICE.service" ]] \
        && ok "systemd unit installed" || fail "systemd unit missing"
}

# ── 3. Package metadata ───────────────────────────────────────────────────────
section_metadata() {
    echo; echo "=== Package metadata ==="

    local pkg_name
    pkg_name=$(dpkg-deb --field "$DEB" Package)
    [[ "$pkg_name" == "nas-web" ]] && ok "Package name: $pkg_name" || fail "Unexpected package name: $pkg_name"

    local version
    version=$(dpkg-deb --field "$DEB" Version)
    # Must match semver: MAJOR.MINOR.PATCH-DEBREV
    if echo "$version" | grep -qP '^\d+\.\d+\.\d+-\d+$'; then
        ok "Version is semver-compliant: $version"
    else
        fail "Version does not follow semver: $version (expected X.Y.Z-N)"
    fi

    local arch
    arch=$(dpkg-deb --field "$DEB" Architecture)
    [[ "$arch" == "amd64" || "$arch" == "arm64" || "$arch" == "any" ]] \
        && ok "Architecture: $arch" || fail "Unexpected architecture: $arch"

    dpkg-deb --field "$DEB" Depends | grep -q "libuv1\|libssl" \
        && ok "Runtime Depends present (libuv1, libssl)" \
        || fail "Runtime Depends missing expected libraries"
}

# ── 4. postinst — service user ────────────────────────────────────────────────
section_user() {
    echo; echo "=== System user (postinst) ==="
    id nas-web &>/dev/null \
        && ok "nas-web system user created by postinst" \
        || fail "nas-web user missing — postinst may not have run useradd"

    # Shell should be nologin
    local shell
    shell=$(getent passwd nas-web | cut -d: -f7)
    [[ "$shell" == */nologin || "$shell" == */false ]] \
        && ok "nas-web user has nologin shell: $shell" \
        || fail "nas-web user has unexpected shell: $shell"
}

# ── 5. File permissions ───────────────────────────────────────────────────────
section_permissions() {
    echo; echo "=== File permissions ==="

    local bin_perms
    bin_perms=$(stat -c '%a' "$BINARY")
    [[ "$bin_perms" == "755" || "$bin_perms" == "750" ]] \
        && ok "Binary permissions: $bin_perms" \
        || fail "Binary permissions unexpected: $bin_perms (expected 755 or 750)"

    # Config must not be world-readable (contains password)
    local conf_perms
    conf_perms=$(stat -c '%a' "$CONF")
    [[ "${conf_perms: -1}" == "0" ]] \
        && ok "Config not world-readable: $conf_perms" \
        || fail "Config is world-readable: $conf_perms — credential exposure risk"

    local log_owner
    log_owner=$(stat -c '%U' "$LOG_DIR")
    [[ "$log_owner" == "nas-web" || "$log_owner" == "root" ]] \
        && ok "Log dir owner: $log_owner" \
        || fail "Log dir owner unexpected: $log_owner"
}

# ── 6. systemd unit hardening ─────────────────────────────────────────────────
section_systemd() {
    echo; echo "=== systemd unit hardening ==="

    local unit_file
    unit_file=$(systemctl show -p FragmentPath "$SERVICE" 2>/dev/null | cut -d= -f2)
    [[ -f "$unit_file" ]] || { fail "Cannot find unit file"; return; }

    grep -q "NoNewPrivileges=yes"            "$unit_file" && ok "NoNewPrivileges=yes"           || fail "NoNewPrivileges not set to yes"
    grep -q "AmbientCapabilities=CAP_NET_BIND_SERVICE" "$unit_file" && ok "CAP_NET_BIND_SERVICE present" || fail "CAP_NET_BIND_SERVICE missing"
    grep -q "PrivateTmp=yes"                 "$unit_file" && ok "PrivateTmp=yes"                || fail "PrivateTmp not yes"
    grep -q "ProtectSystem=strict"           "$unit_file" && ok "ProtectSystem=strict"          || fail "ProtectSystem not strict"
    grep -qv "User=root"                     "$unit_file" && ok "Service not running as root"   || fail "Service still running as root"
}

# ── 7. Service lifecycle ──────────────────────────────────────────────────────
section_service() {
    echo; echo "=== Service lifecycle ==="

    systemctl daemon-reload
    systemctl enable "$SERVICE" 2>/dev/null && ok "systemctl enable" || fail "systemctl enable failed"
    systemctl start  "$SERVICE"             && ok "systemctl start"  || fail "systemctl start failed"

    # Wait for it to come up
    local i=0
    while ! systemctl is-active --quiet "$SERVICE" && (( i < TIMEOUT )); do
        sleep 1; ((i++))
    done
    systemctl is-active --quiet "$SERVICE" \
        && ok "Service active after ${i}s" \
        || fail "Service not active after ${TIMEOUT}s — $(journalctl -u $SERVICE -n 5 --no-pager)"

    # reload (HUP)
    systemctl reload "$SERVICE" 2>/dev/null && ok "systemctl reload (HUP)" || fail "systemctl reload failed"

    # stop / restart
    systemctl stop    "$SERVICE" && ok "systemctl stop"    || fail "systemctl stop failed"
    systemctl restart "$SERVICE" && ok "systemctl restart" || fail "systemctl restart failed"
    sleep 2
    systemctl is-active --quiet "$SERVICE" && ok "Service active after restart" || fail "Service not active after restart"
}

# ── 8. HTTP smoke tests ───────────────────────────────────────────────────────
section_http() {
    echo; echo "=== HTTP smoke tests ==="

    local base="http://localhost"

    http_ok() {
        local url="$1" expected="$2" label="$3"
        local code
        code=$(curl -sk -o /dev/null -w '%{http_code}' "$url")
        [[ "$code" == "$expected" ]] && ok "$label (HTTP $code)" || fail "$label expected $expected, got $code"
    }

    http_ok "$base/apis/ping"      "200" "GET /apis/ping"
    http_ok "$base/apis/heartbeat" "200" "GET /apis/heartbeat"

    # Admin should require auth
    http_ok "$base/np_admin"       "401" "GET /np_admin → 401 without auth"

    # Admin with wrong creds
    local code
    code=$(curl -sk -o /dev/null -w '%{http_code}' -u "wrong:creds" "$base/np_admin")
    [[ "$code" == "401" || "$code" == "403" ]] \
        && ok "Admin with wrong creds: $code" \
        || fail "Admin with wrong creds: expected 401/403, got $code"

    # WAF: basic SQLi attempt should be blocked
    local waf_code
    waf_code=$(curl -sk -o /dev/null -w '%{http_code}' "$base/?x=1+UNION+SELECT+1")
    [[ "$waf_code" == "403" ]] && ok "WAF blocks SQLi → 403" || fail "WAF did not block SQLi (got $waf_code)"

    # WAF: path traversal
    waf_code=$(curl -sk -o /dev/null -w '%{http_code}' "$base/../../../etc/passwd")
    [[ "$waf_code" == "403" || "$waf_code" == "400" ]] \
        && ok "WAF blocks path traversal → $waf_code" \
        || fail "WAF did not block path traversal (got $waf_code)"
}

# ── 9. Upgrade / reinstall idempotency ───────────────────────────────────────
section_upgrade() {
    echo; echo "=== Upgrade (reinstall same .deb) ==="
    dpkg -i "$DEB" && ok "Re-install (upgrade) exit 0" || fail "Re-install failed"
    sleep 2
    systemctl is-active --quiet "$SERVICE" \
        && ok "Service active after upgrade" \
        || fail "Service not active after upgrade"
}

# ── 10. Purge ─────────────────────────────────────────────────────────────────
section_purge() {
    echo; echo "=== Purge ==="
    dpkg --purge nas-web && ok "dpkg --purge exit 0" || fail "dpkg --purge failed"

    [[ ! -f "$BINARY" ]]  && ok "Binary removed after purge"  || fail "Binary still present after purge"
    [[ ! -f "$CONF" ]]    && ok "Config removed after purge"  || fail "Config still present after purge"
    ! systemctl is-active --quiet "$SERVICE" 2>/dev/null \
                          && ok "Service inactive after purge" || fail "Service still running after purge"
}

# ── Run all sections ──────────────────────────────────────────────────────────
section_preflight
section_install
section_metadata
section_user
section_permissions
section_systemd
section_service
section_http
section_upgrade
section_purge

echo
echo "============================================"
echo "  $PASS passed,  $FAIL failed"
echo "============================================"
[[ $FAIL -eq 0 ]]
