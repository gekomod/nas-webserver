#!/usr/bin/env bash
# vendor/sqlite/fetch_sqlite.sh
# Downloads the SQLite3 amalgamation (single-file build) into this directory.
# Run once before cmake. No internet access needed after that.
set -euo pipefail

SQLITE_VERSION="3450200"   # 3.45.2 — update as needed
SQLITE_YEAR="2024"
DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ -f "$DIR/sqlite3.c" && -f "$DIR/sqlite3.h" ]]; then
    echo "SQLite3 already fetched — skipping."
    exit 0
fi

URL="https://www.sqlite.org/${SQLITE_YEAR}/sqlite-amalgamation-${SQLITE_VERSION}.zip"
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

echo "Downloading SQLite3 amalgamation ${SQLITE_VERSION}..."
curl -fsSL "$URL" -o "$TMP/sqlite.zip"
unzip -q "$TMP/sqlite.zip" -d "$TMP"

cp "$TMP/sqlite-amalgamation-${SQLITE_VERSION}/sqlite3.c" "$DIR/"
cp "$TMP/sqlite-amalgamation-${SQLITE_VERSION}/sqlite3.h" "$DIR/"
cp "$TMP/sqlite-amalgamation-${SQLITE_VERSION}/sqlite3ext.h" "$DIR/"

echo "SQLite3 ${SQLITE_VERSION} fetched → vendor/sqlite/"
