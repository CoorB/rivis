#!/usr/bin/env bash
# Rename the placeholder product without editing implementation files.
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: ./rename.sh NEWNAME" >&2; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
PRODUCT="$SCRIPT_DIR/product.json"
eval "$(/usr/bin/python3 -I - "$PRODUCT" "$1" <<'PY'
import json, re, shlex, sys
with open(sys.argv[1]) as fh: old = json.load(fh)
name = sys.argv[2].strip()
if not re.match(r"^[A-Za-z]", name):
    raise SystemExit("NEWNAME must start with a letter")
cli = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
prefix = re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_")
if not re.fullmatch(r"[a-z][a-z0-9-]*", cli):
    raise SystemExit("derived CLI must start with a letter and contain only a-z, 0-9 and hyphens")
if not re.fullmatch(r"[A-Z][A-Z0-9_]*", prefix):
    raise SystemExit("derived environment prefix must start with a letter and contain only A-Z, 0-9 and underscores")
for key, value in (("OLD_CLI", old["cli"]), ("OLD_STATE", old["state_dir"]),
                   ("NEW_CLI", cli), ("NEW_NAME", name), ("NEW_PREFIX", prefix)):
    print("%s=%s" % (key, shlex.quote(value)))
PY
)"
[ "$OLD_CLI" = "$NEW_CLI" ] || {
  [ -f "$SCRIPT_DIR/$OLD_CLI" ] || { echo "$OLD_CLI is missing" >&2; exit 1; }
  [ -f "$SCRIPT_DIR/$OLD_CLI.ps1" ] || { echo "$OLD_CLI.ps1 is missing" >&2; exit 1; }
  [ ! -e "$SCRIPT_DIR/$NEW_CLI" ] || { echo "$NEW_CLI already exists" >&2; exit 1; }
  [ ! -e "$SCRIPT_DIR/$NEW_CLI.ps1" ] || { echo "$NEW_CLI.ps1 already exists" >&2; exit 1; }
}
OLD_STATE="${OLD_STATE/#\~/$HOME}"
NEW_STATE="$HOME/.$NEW_CLI"
if [ "$OLD_STATE" != "$NEW_STATE" ] && [ -d "$OLD_STATE" ] && [ ! -e "$NEW_STATE" ]; then
  STATE_PARENT="$(dirname "$NEW_STATE")"
  STATE_TMP="$STATE_PARENT/.$NEW_CLI.state.tmp.$$"
  [ ! -e "$STATE_TMP" ] || { echo "temporary state path already exists: $STATE_TMP" >&2; exit 1; }
  cp -R "$OLD_STATE" "$STATE_TMP" || { rm -rf "$STATE_TMP"; echo "could not copy state from $OLD_STATE" >&2; exit 1; }
  mv "$STATE_TMP" "$NEW_STATE" || { rm -rf "$STATE_TMP"; echo "could not install copied state at $NEW_STATE" >&2; exit 1; }
  echo "Copied state to $NEW_STATE (the original was left unchanged)."
fi
if [ "$OLD_CLI" != "$NEW_CLI" ]; then
  mv "$SCRIPT_DIR/$OLD_CLI" "$SCRIPT_DIR/$NEW_CLI"
  if ! mv "$SCRIPT_DIR/$OLD_CLI.ps1" "$SCRIPT_DIR/$NEW_CLI.ps1"; then
    mv "$SCRIPT_DIR/$NEW_CLI" "$SCRIPT_DIR/$OLD_CLI" 2>/dev/null || true
    echo "could not rename $OLD_CLI.ps1; restored the original CLI name" >&2
    exit 1
  fi
fi
if ! /usr/bin/python3 -I - "$PRODUCT" "$NEW_NAME" "$NEW_CLI" "$NEW_PREFIX" <<'PY'
import json, os, sys, tempfile
path, name, cli, prefix = sys.argv[1:]
doc = {"name": name, "cli": cli, "env_prefix": prefix, "state_dir": "~/." + cli}
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".product-", suffix=".json")
with os.fdopen(fd, "w") as fh: json.dump(doc, fh, indent=2); fh.write("\n")
os.replace(tmp, path)
PY
then
  if [ "$OLD_CLI" != "$NEW_CLI" ]; then
    mv "$SCRIPT_DIR/$NEW_CLI.ps1" "$SCRIPT_DIR/$OLD_CLI.ps1" 2>/dev/null || true
    mv "$SCRIPT_DIR/$NEW_CLI" "$SCRIPT_DIR/$OLD_CLI" 2>/dev/null || true
  fi
  echo "could not update product.json; restored the original CLI names" >&2
  exit 1
fi
echo "Renamed product to $NEW_NAME ($NEW_CLI)."
echo "Re-link the CLI: ln -sf \"$SCRIPT_DIR/$NEW_CLI\" ~/bin/$NEW_CLI"
echo "PowerShell entry point: $SCRIPT_DIR/$NEW_CLI.ps1"
