#!/usr/bin/env bash
# Build <cli>-<version>.tar.gz from next/ for IT's internal mirror, and print its SHA-256.
#   make-release.sh [OUTPUT_DIR]        (default: ./dist)
# Version comes from install/VERSION; the CLI name from product.json. Excludes install/, snapshots, state, .DS_Store.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "$HERE/../.." && pwd -P)"                 # next/
OUT="${1:-$PWD/dist}"
VERSION="$(tr -d '[:space:]' < "$ROOT/install/VERSION")"
CLI="$(plutil -extract cli raw -o - "$ROOT/product.json")"
[ -n "$VERSION" ] && [ -n "$CLI" ] || { echo "make-release: missing VERSION or product.json" >&2; exit 1; }
mkdir -p "$OUT"
TARBALL="$OUT/$CLI-$VERSION.tar.gz"
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
mkdir "$STAGE/$CLI-$VERSION"
# Copy everything except the installer itself, editor/OS junk, caches, and anything that looks like user state.
( cd "$ROOT" && tar -cf - \
    --exclude './install' \
    --exclude '.DS_Store' --exclude '*.pyc' --exclude '__pycache__' \
    --exclude '*.diff' --exclude '*.orig' --exclude '*.rej' --exclude '*.bak' \
    --exclude '*.har' --exclude '*.snapshot' --exclude '*-snapshot*' --exclude '*.pre-*' \
    --exclude 'web-token' --exclude 'current-project' --exclude 'rules.json' \
    --exclude './sessions' --exclude './collections' --exclude './mocks' \
    . ) | tar -xf - -C "$STAGE/$CLI-$VERSION"
# The installer needs VERSION + mirror.conf next to it in a checkout; the release carries only the tool.
echo "$VERSION" > "$STAGE/$CLI-$VERSION/VERSION"
rm -f "$TARBALL"
# Reproducible-ish: fixed owner, sorted names.
COPYFILE_DISABLE=1 tar --uid 0 --gid 0 --no-xattrs -czf "$TARBALL" -C "$STAGE" "$CLI-$VERSION"
SHA="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"
echo "$TARBALL"
echo "sha256  $SHA"
echo "Publish at: <MIRROR_BASE_URL>/$CLI/$CLI-$VERSION.tar.gz, then set TOOL_SHA256=$SHA in install/mirror.conf"
