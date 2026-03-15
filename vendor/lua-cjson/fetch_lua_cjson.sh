#!/usr/bin/env bash
# vendor/lua-cjson/fetch_lua_cjson.sh
# Downloads lua-cjson (OpenResty fork — actively maintained, Lua 5.4 compatible)
set -euo pipefail

VERSION="2.1.0.14"   # openresty/lua-cjson latest stable
DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ -f "$DIR/lua_cjson.c" && -f "$DIR/lua_cjson.h" ]]; then
    echo "lua-cjson already fetched — skipping."
    exit 0
fi

URL="https://github.com/openresty/lua-cjson/archive/refs/tags/${VERSION}.tar.gz"
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

echo "Downloading lua-cjson ${VERSION}..."
curl -fsSL "$URL" -o "$TMP/lua-cjson.tar.gz"
tar -xzf "$TMP/lua-cjson.tar.gz" -C "$TMP"

SRC="$TMP/lua-cjson-${VERSION}"
cp "$SRC/lua_cjson.c"   "$DIR/"
cp "$SRC/lua_cjson.h" "$DIR/" 2>/dev/null || true
cp "$SRC/strbuf.c"      "$DIR/"
cp "$SRC/strbuf.h"      "$DIR/"
cp "$SRC/fpconv.c"      "$DIR/"
cp "$SRC/fpconv.h"      "$DIR/"

echo "lua-cjson ${VERSION} fetched → vendor/lua-cjson/"
