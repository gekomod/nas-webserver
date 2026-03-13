#!/bin/bash
# fetch_janet.sh — pobiera Janet 1.41.2 amalgamację bezpośrednio z release assets
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
VER="1.41.2"
BASE="https://github.com/janet-lang/janet/releases/download/v${VER}"

echo ">>> Pobieranie Janet ${VER}..."
curl -fsSL "${BASE}/janet.c" -o "${DIR}/janet.c"
curl -fsSL "${BASE}/janet.h" -o "${DIR}/janet.h"
curl -fsSL "${BASE}/shell.c" -o "${DIR}/shell.c"

echo ""
echo "OK: Janet ${VER} gotowy w ${DIR}/"
echo "    janet.c: $(wc -l < "${DIR}/janet.c") linii"
echo "    janet.h: $(wc -l < "${DIR}/janet.h") linii"
echo ""
echo "Teraz przebuduj:"
echo "  bash build-deb.sh --with-janet"
