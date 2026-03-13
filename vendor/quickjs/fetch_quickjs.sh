#!/bin/bash
# Pobiera QuickJS ze źródeł i kopiuje WSZYSTKIE potrzebne pliki
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
QJS_VER="2024-01-13"
QJS_URL="https://bellard.org/quickjs/quickjs-${QJS_VER}.tar.xz"
TMP=$(mktemp -d)
trap "rm -rf '${TMP}'" EXIT

echo "[quickjs] Downloading QuickJS ${QJS_VER}..."
curl -L "${QJS_URL}" -o "${TMP}/qjs.tar.xz"
echo "[quickjs] Extracting..."
tar -xf "${TMP}/qjs.tar.xz" -C "${TMP}"
QJS_DIR="${TMP}/quickjs-${QJS_VER}"

echo "[quickjs] Copying source files..."
for f in quickjs.c libregexp.c libunicode.c libbf.c cutils.c; do
    [ -f "${QJS_DIR}/${f}" ] && cp "${QJS_DIR}/${f}" "${SCRIPT_DIR}/" && echo "  + ${f}"
done

echo "[quickjs] Copying ALL header files (including list.h, quickjs.h, cutils.h)..."
for f in "${QJS_DIR}"/*.h; do
    cp "${f}" "${SCRIPT_DIR}/" && echo "  + $(basename ${f})"
done

# Remove our shim — real quickjs.h from sources replaces it
if [ -f "${SCRIPT_DIR}/quickjs_stub.h" ]; then
    echo "[quickjs] Keeping quickjs_stub.h for no-QuickJS builds"
fi

echo ""
echo "[quickjs] Done! Rebuild:"
echo "  rm -rf build && mkdir build && cd build"
echo "  cmake .. -DWITH_QUICKJS=ON && make -j\$(nproc)"
