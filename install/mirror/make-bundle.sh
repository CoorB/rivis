#!/usr/bin/env bash
# Build an offline installer bundle: one zip a user unzips and runs, no mirror needed.
#   make-bundle.sh MITMPROXY_ARCHIVE... [--out DIR]     (default DIR: ../dist beside next/)
# MITMPROXY_ARCHIVE = the official mitmproxy file(s) for the platforms to support, e.g.
#   mitmproxy-12.2.3-macos-arm64.tar.gz  mitmproxy-12.2.3-macos-x86_64.tar.gz
# Each one must match its pinned SHA-256 in install/mirror.conf, or the bundle is not built. The tool archive is made
# by make-release.sh and its hash is pinned into the bundle's own copy of mirror.conf (MIRROR_BASE_URL left empty).
# The installer prefers files sitting next to it over any mirror and verifies them exactly like a download.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "$HERE/../.." && pwd -P)"                 # next/
OUT="$ROOT/../dist"; ARCHIVES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift ;;
    -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0 ;;
    *) ARCHIVES+=("$1") ;;
  esac
  shift
done
[ ${#ARCHIVES[@]} -gt 0 ] || { echo "make-bundle: pass at least one official mitmproxy archive (see --help)" >&2; exit 2; }
CONF="$ROOT/install/mirror.conf"
conf() { sed -n "s/^$1=//p" "$CONF" | head -1; }
VERSION="$(tr -d '[:space:]' < "$ROOT/install/VERSION")"
CLI="$(plutil -extract cli raw -o - "$ROOT/product.json")"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd -P)"

STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
NAME="$CLI-installer-$VERSION"
B="$STAGE/$NAME"; mkdir "$B"

for a in "${ARCHIVES[@]}"; do              # only pinned official files, by their official names
  base="$(basename "$a")"
  key="$(sed -n "s/^MITMPROXY_FILE_\([A-Z0-9_]*\)=$base\$/\1/p" "$CONF" | head -1)"
  [ -n "$key" ] || { echo "make-bundle: $base is not a pinned MITMPROXY_FILE_* in mirror.conf" >&2; exit 1; }
  want="$(conf "MITMPROXY_SHA256_$key")"; got="$(shasum -a 256 "$a" | awk '{print $1}')"
  [ -n "$want" ] && [ "$want" = "$got" ] || { echo "make-bundle: $base SHA-256 does not match its pin — refusing" >&2; exit 1; }
  cp "$a" "$B/$base"
done

REL="$(bash "$HERE/make-release.sh" "$STAGE/release")"
TOOL_SHA="$(echo "$REL" | awk '/^sha256/{print $2}')"
cp "$STAGE/release/$CLI-$VERSION.tar.gz" "$B/"
cp "$ROOT/install/install.sh" "$ROOT/install/install.ps1" "$ROOT/install/VERSION" "$ROOT/install/product.json" "$B/"
sed -e "s|^MIRROR_BASE_URL=.*|MIRROR_BASE_URL=|" -e "s|^TOOL_SHA256=.*|TOOL_SHA256=$TOOL_SHA|" "$CONF" > "$B/mirror.conf"
chmod +x "$B/install.sh"

ZIP="$OUT/$NAME.zip"; rm -f "$ZIP"
( cd "$STAGE" && COPYFILE_DISABLE=1 zip -qrX "$ZIP" "$NAME" )
echo "$ZIP"
echo "sha256  $(shasum -a 256 "$ZIP" | awk '{print $1}')"
echo "contains: $(cd "$B" && ls | tr '\n' ' ')"
