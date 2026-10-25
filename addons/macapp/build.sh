#!/bin/bash
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd -P)"
dest="${1:-$here/build}"
if ! command -v swiftc >/dev/null 2>&1; then
  echo "Rivis: swiftc is required to build the native window" >&2
  exit 1
fi
mkdir -p "$dest/Rivis.app/Contents/MacOS"
app="$dest/Rivis.app"
cp "$here/Info.plist" "$app/Contents/Info.plist"
product="$here/../../product.json"
if [ -f "$product" ]; then
  version=$(/usr/bin/python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("version", "0"))' "$product")
  /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $version" "$app/Contents/Info.plist"
  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $version" "$app/Contents/Info.plist"
fi
swiftc -O "$here/RivisApp.swift" -o "$app/Contents/MacOS/Rivis" -framework AppKit -framework WebKit
codesign -s - --force --deep "$app" >/dev/null
printf '%s\n' "$app"
