#!/bin/bash
# fetch_zstd.sh — pobiera zstd 1.5.7 źródła do vendor/zstd/lib/
# URL: https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
VER="1.5.7"
URL="https://github.com/facebook/zstd/releases/download/v${VER}/zstd-${VER}.tar.gz"
TMPDIR_=$(mktemp -d)
trap "rm -rf '${TMPDIR_}'" EXIT

echo ">>> Pobieranie zstd ${VER}..."
echo "    ${URL}"
curl -fsSL "${URL}" -o "${TMPDIR_}/zstd.tar.gz"

echo ">>> Rozpakowywanie..."
tar -xzf "${TMPDIR_}/zstd.tar.gz" -C "${TMPDIR_}"
SRC="${TMPDIR_}/zstd-${VER}/lib"

echo ">>> Kopiowanie do ${DIR}/lib/..."
rm -rf "${DIR}/lib"
mkdir -p "${DIR}/lib"
cp -r "${SRC}/common"     "${DIR}/lib/"
cp -r "${SRC}/compress"   "${DIR}/lib/"
cp -r "${SRC}/decompress" "${DIR}/lib/"
cp    "${SRC}/zstd.h"     "${DIR}/lib/"
cp    "${SRC}/zstd.h"     "${DIR}/zstd.h"    # nadpisz stub
cp    "${SRC}/zstd_errors.h" "${DIR}/lib/"   2>/dev/null || true
cp    "${SRC}/zdict.h"       "${DIR}/lib/"   2>/dev/null || true

echo ""
echo "OK: zstd ${VER} gotowy w ${DIR}/lib/"
echo "    Pliki .c: $(find "${DIR}/lib" -name '*.c' | wc -l)"
echo ""
echo "Teraz przebuduj:"
echo "  bash build-deb.sh --with-zstd"
