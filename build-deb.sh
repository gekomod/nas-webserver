#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  build-deb.sh — buduje nas-web i pakuje jako .deb
#  Wersja pobierana automatycznie z debian/changelog
#
#  Użycie: bash build-deb.sh [opcje]
#
#  Opcje:
#    --with-modsec    ModSecurity WAF (wymaga: apt install libmodsecurity-dev)
#    --with-zstd      zstd kompresja  (wymaga: vendor/zstd/fetch_zstd.sh)
#    --with-janet     Janet WAF       (wymaga: vendor/janet/fetch_janet.sh)
#    --with-sqlite    SQLite3 persistence (vendored, domyślnie ON)
#    --no-sqlite      Wyłącz SQLite3
#    --with-lua-cjson lua-cjson JSON  (vendored, domyślnie ON)
#    --no-lua-cjson   Wyłącz lua-cjson
#    --no-rebuild     Pomiń cmake/make, tylko przepakuj .deb
#    --help           Pokaż tę pomoc
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

# ── Pomoc ──────────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n '2,20p' "$0" | sed 's/^#  \?//'
    exit 0
fi

# ── Wersja z debian/changelog ─────────────────────────────────────────────────
CHANGELOG="${SCRIPT_DIR}/debian/changelog"
if [[ ! -f "${CHANGELOG}" ]]; then
    echo "ERROR: debian/changelog not found!" >&2
    exit 1
fi
# Pierwsza linia: "nas-web (2.3.0-1) stable; urgency=..."
PKG_VERSION=$(head -1 "${CHANGELOG}" | grep -oP '\(\K[^)]+' | head -1)
if [[ -z "${PKG_VERSION}" ]]; then
    echo "ERROR: Cannot parse version from debian/changelog" >&2
    exit 1
fi
UPSTREAM_VER=$(echo "${PKG_VERSION}" | sed 's/-[0-9]*$//')

ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
PKG="nas-web_${PKG_VERSION}_${ARCH}"
BUILD_DIR="${SCRIPT_DIR}/build"

# ── Parsuj flagi ──────────────────────────────────────────────────────────────
WITH_MODSEC="OFF"
WITH_ZSTD="OFF"
WITH_JANET="OFF"
WITH_SQLITE="ON"
WITH_LUA_CJSON="ON"
NO_REBUILD=0

for arg in "$@"; do
    case "${arg}" in
        --with-modsec)   WITH_MODSEC="ON"    ;;
        --with-zstd)     WITH_ZSTD="ON"      ;;
        --with-janet)    WITH_JANET="ON"      ;;
        --with-sqlite)   WITH_SQLITE="ON"     ;;
        --no-sqlite)     WITH_SQLITE="OFF"    ;;
        --with-lua-cjson) WITH_LUA_CJSON="ON" ;;
        --no-lua-cjson)  WITH_LUA_CJSON="OFF" ;;
        --no-rebuild)    NO_REBUILD=1          ;;
        --help|-h)       ;;
        *) echo "WARN: unknown option: ${arg}" >&2 ;;
    esac
done

# ── Sprawdź root (potrzebny do apt-get install) ───────────────────────────────
SUDO=""
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    if command -v sudo &>/dev/null; then
        SUDO="sudo"
    else
        echo "WARN: Not root and sudo not available — skipping dependency install" >&2
    fi
fi

# ── Sprawdź i zainstaluj zależności budowania ─────────────────────────────────
BUILD_DEPS="liblua5.4-dev libuv1-dev libssl-dev libbrotli-dev libnghttp2-dev cmake build-essential pkg-config zlib1g-dev"
[[ "${WITH_MODSEC}" == "ON" ]] && BUILD_DEPS="${BUILD_DEPS} libmodsecurity-dev"

MISSING_DEPS=""
for pkg in ${BUILD_DEPS}; do
    dpkg -s "${pkg}" &>/dev/null || MISSING_DEPS="${MISSING_DEPS} ${pkg}"
done
if [[ -n "${MISSING_DEPS}" ]]; then
    echo ">>> Instaluję brakujące zależności budowania:${MISSING_DEPS}"
    ${SUDO} apt-get install -y ${MISSING_DEPS}
fi

# ── Pobierz vendory jeśli potrzebne ──────────────────────────────────────────
if [[ "${NO_REBUILD}" -eq 0 ]]; then
    if [[ "${WITH_SQLITE}" == "ON" && ! -f "${SCRIPT_DIR}/vendor/sqlite/sqlite3.c" ]]; then
        echo ">>> Pobieram SQLite3 amalgamation..."
        bash "${SCRIPT_DIR}/vendor/sqlite/fetch_sqlite.sh"
    fi
    if [[ "${WITH_LUA_CJSON}" == "ON" && ! -f "${SCRIPT_DIR}/vendor/lua-cjson/lua_cjson.c" ]]; then
        echo ">>> Pobieram lua-cjson..."
        bash "${SCRIPT_DIR}/vendor/lua-cjson/fetch_lua_cjson.sh"
    fi
    if [[ "${WITH_ZSTD}" == "ON" && ! -f "${SCRIPT_DIR}/vendor/zstd/lib/zstd.h" ]]; then
        echo ">>> Pobieram zstd..."
        bash "${SCRIPT_DIR}/vendor/zstd/fetch_zstd.sh"
    fi
    if [[ "${WITH_JANET}" == "ON" && ! -f "${SCRIPT_DIR}/vendor/janet/janet.c" ]]; then
        echo ">>> Pobieram janet..."
        bash "${SCRIPT_DIR}/vendor/janet/fetch_janet.sh"
    fi
fi

printf "\n╔══════════════════════════════════════════╗\n"
printf "║   nas-web %-31s║\n" "${UPSTREAM_VER} — build .deb"
printf "║   ModSecurity: %-26s║\n" "${WITH_MODSEC}"
printf "║   zstd:        %-26s║\n" "${WITH_ZSTD}"
printf "║   Janet WAF:   %-26s║\n" "${WITH_JANET}"
printf "║   SQLite3:     %-26s║\n" "${WITH_SQLITE}"
printf "║   lua-cjson:   %-26s║\n" "${WITH_LUA_CJSON}"
printf "╚══════════════════════════════════════════╝\n\n"

# ── 1. Build binary ───────────────────────────────────────────────────────────
STEP=1
TOTAL=4
if [[ "${NO_REBUILD}" -eq 0 ]]; then
    echo "[${STEP}/${TOTAL}] Building binary (version ${UPSTREAM_VER})..."
    rm -rf "${BUILD_DIR}"
    mkdir -p "${BUILD_DIR}"

    cmake -S "${SCRIPT_DIR}" -B "${BUILD_DIR}"    \
        -DCMAKE_BUILD_TYPE=Release                \
        -DWITH_LUA=ON                             \
        -DWITH_QUICKJS=ON                         \
        -DWITH_NGHTTP2=ON                         \
        -DWITH_BROTLI=ON                          \
        -DWITH_ACME=ON                            \
        -DWITH_SQLITE="${WITH_SQLITE}"            \
        -DWITH_LUA_CJSON="${WITH_LUA_CJSON}"      \
        -DWITH_ZSTD="${WITH_ZSTD}"                \
        -DWITH_JANET="${WITH_JANET}"              \
        -DWITH_MODSEC="${WITH_MODSEC}"            \
        -DWITH_QUICHE=OFF
    cmake --build "${BUILD_DIR}" --parallel "$(nproc)"
else
    echo "[${STEP}/${TOTAL}] Skipping rebuild (--no-rebuild)"
fi
((STEP++))

if [[ ! -f "${BUILD_DIR}/nas-web" ]]; then
    echo "ERROR: ${BUILD_DIR}/nas-web not found — build failed?" >&2
    exit 1
fi

# ── 2. Prepare package tree ───────────────────────────────────────────────────
echo "[${STEP}/${TOTAL}] Preparing package tree..."
((STEP++))

# Zdefiniuj PKGDIR przed trap żeby cleanup zawsze zadziałał
PKGDIR=$(mktemp -d)
trap "rm -rf '${PKGDIR}'" EXIT

mkdir -p "${PKGDIR}/DEBIAN"
mkdir -p "${PKGDIR}/usr/local/bin"
mkdir -p "${PKGDIR}/etc/nas-web/scripts"
mkdir -p "${PKGDIR}/var/log/nas-web"
mkdir -p "${PKGDIR}/var/lib/nas-web"
mkdir -p "${PKGDIR}/etc/systemd/system"

# Binary
install -m 755 "${BUILD_DIR}/nas-web" "${PKGDIR}/usr/local/bin/nas-web"

# Config — nie nadpisuj jeśli już istnieje (obsługiwane przez conffiles)
install -m 640 "${SCRIPT_DIR}/conf/nas-web.conf" "${PKGDIR}/etc/nas-web/nas-web.conf"

# Lua scripts
if ls "${SCRIPT_DIR}/scripts/"*.lua &>/dev/null 2>&1; then
    install -m 644 "${SCRIPT_DIR}/scripts/"*.lua "${PKGDIR}/etc/nas-web/scripts/"
fi

# Systemd unit
install -m 644 "${SCRIPT_DIR}/nas-web.service" "${PKGDIR}/etc/systemd/system/nas-web.service"

# Maintainer scripts
for f in postinst prerm postrm; do
    src="${SCRIPT_DIR}/debian/nas-web.${f}"
    if [[ -f "${src}" ]]; then
        install -m 755 "${src}" "${PKGDIR}/DEBIAN/${f}"
    fi
done

# ── 3. Detect runtime deps z ldd ─────────────────────────────────────────────
echo "[${STEP}/${TOTAL}] Detecting runtime dependencies..."
((STEP++))

# Zawsze linkowane
DEPS="libuv1 (>= 1.40), libssl3, zlib1g"

_ldd() { ldd "${BUILD_DIR}/nas-web" 2>/dev/null | grep -q "$1"; }

_ldd "liblua"        && DEPS="${DEPS}, liblua5.4-0"
_ldd "libnghttp2"    && DEPS="${DEPS}, libnghttp2-14"
if _ldd "libbrotli"; then
    if dpkg -l libbrotli1 2>/dev/null | grep -q '^ii'; then
        DEPS="${DEPS}, libbrotli1"
    else
        DEPS="${DEPS}, libbrotli1 | libbrotlienc1"
    fi
fi
_ldd "libmodsecurity" && DEPS="${DEPS}, libmodsecurity3"
# SQLite jest statycznie linkowane (vendor) — nie dodajemy do Depends

# ── 4. Control file ───────────────────────────────────────────────────────────
INSTALLED_SIZE=$(du -sk "${PKGDIR}" | cut -f1)

cat > "${PKGDIR}/DEBIAN/control" << CTRL
Package: nas-web
Version: ${PKG_VERSION}
Section: web
Priority: optional
Architecture: ${ARCH}
Installed-Size: ${INSTALLED_SIZE}
Depends: ${DEPS}
Recommends: curl, openssl
Suggests: certbot, libmodsecurity3, modsecurity-crs
Maintainer: NAS Panel Team <admin@localhost>
Description: NAS Panel Web Server ${UPSTREAM_VER}
 High-performance C++20 reverse proxy and static file server.
 .
 Features: HTTP/1.1, HTTP/2, TLS, Lua 5.4 scripting, QuickJS JS middleware,
 LRU response cache, rate limiter, WebSocket proxy, ACME/Let's Encrypt,
 load balancer, virtual hosts, WAF (built-in regex + optional ModSecurity),
 SQLite3 persistence, admin panel at /np_admin.
 .
 Build options: ModSec=${WITH_MODSEC} zstd=${WITH_ZSTD} janet=${WITH_JANET}
CTRL

cat > "${PKGDIR}/DEBIAN/conffiles" << CONF
/etc/nas-web/nas-web.conf
CONF

# ── 5. Build .deb ─────────────────────────────────────────────────────────────
echo "[${STEP}/${TOTAL}] Building ${PKG}.deb..."

DEB_OUT="${SCRIPT_DIR}/${PKG}.deb"

# --root-owner-group dostępne od dpkg 1.19.0 (Debian 10+)
DPKG_VER=$(dpkg-deb --version | grep -oP '\d+\.\d+' | head -1)
DPKG_MAJOR=$(echo "${DPKG_VER}" | cut -d. -f1)
DPKG_MINOR=$(echo "${DPKG_VER}" | cut -d. -f2)
if [[ "${DPKG_MAJOR}" -gt 1 ]] || [[ "${DPKG_MAJOR}" -eq 1 && "${DPKG_MINOR}" -ge 19 ]]; then
    dpkg-deb --build --root-owner-group "${PKGDIR}" "${DEB_OUT}"
else
    # Starsze dpkg: ustaw ownership ręcznie
    chown -R root:root "${PKGDIR}" 2>/dev/null || true
    dpkg-deb --build "${PKGDIR}" "${DEB_OUT}"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
SIZE=$(du -sh "${DEB_OUT}" | cut -f1)

printf "\n╔══════════════════════════════════════════╗\n"
printf "║   Build complete!                        ║\n"
printf "╚══════════════════════════════════════════╝\n\n"
echo "  Package  : ${DEB_OUT}  (${SIZE})"
echo "  Version  : ${PKG_VERSION}"
echo "  Arch     : ${ARCH}"
echo "  SQLite3  : ${WITH_SQLITE}"
echo "  lua-cjson: ${WITH_LUA_CJSON}"
echo "  ModSec   : ${WITH_MODSEC}"
echo "  zstd     : ${WITH_ZSTD}"
echo "  Janet    : ${WITH_JANET}"
echo ""
echo "  Install  : sudo dpkg -i ${PKG}.deb"
echo "  Start    : sudo systemctl enable --now nas-web"
echo "  Admin    : http://localhost/np_admin"
echo ""
