#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  build-deb.sh — buduje nas-web i pakuje jako .deb
#  Wersja pobierana automatycznie z debian/changelog
#  Użycie: bash build-deb.sh [--no-rebuild] [--with-modsec]
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Wersja z debian/changelog ─────────────────────────────────────────────────
CHANGELOG="${SCRIPT_DIR}/debian/changelog"
if [[ ! -f "${CHANGELOG}" ]]; then
    echo "ERROR: debian/changelog not found!"
    exit 1
fi
# Pierwsza linia: "nas-web (2.2.30-1) stable; urgency=..."
VERSION=$(head -1 "${CHANGELOG}" | grep -oP '\(\K[^)]+' | head -1)
# Usuń ewentualny sufiks -1
PKG_VERSION="${VERSION}"
DEB_REVISION=$(echo "${VERSION}" | grep -oP '(?<=-)\d+$' || echo "1")
UPSTREAM_VER=$(echo "${VERSION}" | sed 's/-[0-9]*$//')

ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
PKG="nas-web_${PKG_VERSION}_${ARCH}"
BUILD_DIR="${SCRIPT_DIR}/build"

# ── Flagi CMake ───────────────────────────────────────────────────────────────
WITH_MODSEC="OFF"
NO_REBUILD=0
for arg in "$@"; do
    case "$arg" in
        --with-modsec) WITH_MODSEC="ON" ;;
        --no-rebuild)  NO_REBUILD=1 ;;
    esac
done

printf "╔══════════════════════════════════════════╗\n"
printf "║   nas-web %-31s║\n" "${UPSTREAM_VER} — build .deb"
printf "║   ModSecurity: %-26s║\n" "${WITH_MODSEC}"
printf "╚══════════════════════════════════════════╝\n\n"

# ── 1. Build binary ───────────────────────────────────────────────────────────
if [[ "${NO_REBUILD}" -eq 0 ]]; then
    echo "[1/4] Building binary (version ${UPSTREAM_VER})..."
    rm -rf "${BUILD_DIR}"
    mkdir -p "${BUILD_DIR}"

    cmake -S "${SCRIPT_DIR}" -B "${BUILD_DIR}" \
        -DCMAKE_BUILD_TYPE=Release   \
        -DWITH_LUA=ON                \
        -DWITH_QUICKJS=ON            \
        -DWITH_NGHTTP2=ON            \
        -DWITH_BROTLI=ON             \
        -DWITH_ACME=ON               \
        -DWITH_MODSEC="${WITH_MODSEC}"\
        -DWITH_QUICHE=OFF

    cmake --build "${BUILD_DIR}" --parallel "$(nproc)"
else
    echo "[1/4] Skipping rebuild (--no-rebuild)"
fi

if [[ ! -f "${BUILD_DIR}/nas-web" ]]; then
    echo "ERROR: ${BUILD_DIR}/nas-web not found — build failed?"
    exit 1
fi

# ── 2. Prepare package tree ───────────────────────────────────────────────────
echo "[2/4] Preparing package tree..."
PKGDIR=$(mktemp -d)
trap "rm -rf '${PKGDIR}'" EXIT

mkdir -p "${PKGDIR}/DEBIAN"
mkdir -p "${PKGDIR}/usr/local/bin"
mkdir -p "${PKGDIR}/etc/nas-web/scripts"
mkdir -p "${PKGDIR}/var/log/nas-web"
mkdir -p "${PKGDIR}/var/lib/nas-web"
mkdir -p "${PKGDIR}/etc/systemd/system"

# Binary
cp "${BUILD_DIR}/nas-web"            "${PKGDIR}/usr/local/bin/nas-web"
chmod 755 "${PKGDIR}/usr/local/bin/nas-web"

# Config
cp "${SCRIPT_DIR}/conf/nas-web.conf" "${PKGDIR}/etc/nas-web/nas-web.conf"

# Scripts
if ls "${SCRIPT_DIR}/scripts/"* &>/dev/null 2>&1; then
    cp "${SCRIPT_DIR}/scripts/"* "${PKGDIR}/etc/nas-web/scripts/"
fi

# Systemd
cp "${SCRIPT_DIR}/nas-web.service"   "${PKGDIR}/etc/systemd/system/nas-web.service"

# Maintainer scripts
for f in postinst prerm postrm; do
    src="${SCRIPT_DIR}/debian/nas-web.${f}"
    if [[ -f "${src}" ]]; then
        cp "${src}" "${PKGDIR}/DEBIAN/${f}"
        chmod 755   "${PKGDIR}/DEBIAN/${f}"
    fi
done

# ── 3. Detect runtime deps ────────────────────────────────────────────────────
DEPS="libuv1 (>= 1.40), libssl3"
if ldd "${BUILD_DIR}/nas-web" 2>/dev/null | grep -q "liblua";       then DEPS="${DEPS}, liblua5.4-0";     fi
if ldd "${BUILD_DIR}/nas-web" 2>/dev/null | grep -q "libnghttp2";   then DEPS="${DEPS}, libnghttp2-14";   fi
if ldd "${BUILD_DIR}/nas-web" 2>/dev/null | grep -q "libbrotli"; then
    # libbrotlienc1 (Debian ≤11) vs libbrotli1 (Debian 12+ / Ubuntu 22+)
    if dpkg -l libbrotli1 2>/dev/null | grep -q '^ii'; then
        DEPS="${DEPS}, libbrotli1"
    elif dpkg -l libbrotlienc1 2>/dev/null | grep -q '^ii'; then
        DEPS="${DEPS}, libbrotlienc1"
    else
        DEPS="${DEPS}, libbrotli1 | libbrotlienc1"
    fi
fi
if ldd "${BUILD_DIR}/nas-web" 2>/dev/null | grep -q "libmodsecurity"; then DEPS="${DEPS}, libmodsecurity3"; fi

# ── 4. Control file z aktualną wersją ────────────────────────────────────────
INSTALLED_SIZE=$(du -sk "${PKGDIR}" | cut -f1)

# Wyciągnij opis z changelog (linie po pierwszej aż do pustej)
CHANGELOG_DESC=$(awk 'NR>1{if(/^$/){exit}print "  "$0}' "${CHANGELOG}" | head -10)

cat > "${PKGDIR}/DEBIAN/control" << CTRL
Package: nas-web
Version: ${PKG_VERSION}
Section: web
Priority: optional
Architecture: ${ARCH}
Installed-Size: ${INSTALLED_SIZE}
Depends: ${DEPS}
Recommends: curl, openssl, libmodsecurity3, modsecurity-crs
Maintainer: NAS Panel <admin@localhost>
Description: NAS Panel Web Server ${UPSTREAM_VER}
 High-performance C++20 reverse proxy and static file server.
 .
 Features: HTTP/1.1, HTTP/2, TLS, Lua scripting, QuickJS JS middleware,
 LRU cache, rate limiter, WebSocket proxy, ACME/Let's Encrypt, load balancer,
 virtual hosts, WAF (built-in regex + optional ModSecurity), admin panel.
 .
 ModSecurity: ${WITH_MODSEC}
CTRL

cat > "${PKGDIR}/DEBIAN/conffiles" << CONF
/etc/nas-web/nas-web.conf
CONF

# ── 5. Build .deb ─────────────────────────────────────────────────────────────
echo "[3/4] Building ${PKG}.deb..."
dpkg-deb --build --root-owner-group "${PKGDIR}" "${SCRIPT_DIR}/${PKG}.deb"

# ── 6. Done ───────────────────────────────────────────────────────────────────
SIZE=$(du -sh "${SCRIPT_DIR}/${PKG}.deb" | cut -f1)
echo ""
echo "[4/4] Done!"
echo ""
echo "  Package  : ${SCRIPT_DIR}/${PKG}.deb  (${SIZE})"
echo "  Version  : ${PKG_VERSION} (from debian/changelog)"
echo "  ModSec   : ${WITH_MODSEC}"
echo ""
echo "  Install  : sudo dpkg -i ${PKG}.deb"
echo "  Start    : sudo systemctl enable --now nas-web"
echo "  Admin    : http://localhost/np_admin"
echo ""
echo "  Tip: bash build-deb.sh --with-modsec   # build z ModSecurity"
echo ""
