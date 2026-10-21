#!/bin/bash
# update_install.sh ZIP — install an update that updater.py already verified (signature + SHA-256), then restart the
# proxy exactly as it was last started (STATE_ROOT/last-start, written by `<cli> start`). Runs detached: it stops and
# restarts the very proxy that may have launched it. Order matters: install FIRST — if that fails, the running
# version is left alone; only then stop and start. A proxy that was not running is not started.
set -u
ZIP="${1:-}"
HERE="$(cd "$(dirname "$0")" && pwd -P)"
product() { /usr/bin/python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2]) or sys.argv[3])' "$HERE/../product.json" "$1" "$2"; }
CLI=$(product cli rivis)
STATE="$(product state_dir "~/.$CLI")"; STATE="${STATE/#\~/$HOME}"
LINK="$HOME/.local/bin/$CLI"
say() { echo "$(date '+%H:%M:%S') $*"; }

[ -f "$ZIP" ] || { say "no installer zip: $ZIP"; exit 1; }
say "installing $(basename "$ZIP")"
W=$(mktemp -d "${TMPDIR:-/tmp}/$CLI-update.XXXXXX") || exit 1
trap 'rm -rf "$W"' EXIT
ditto -x -k "$ZIP" "$W" || { say "could not unzip the update — nothing changed"; exit 1; }
D=$(find "$W" -maxdepth 1 -type d -name "$CLI-installer-*" | head -1)
[ -n "$D" ] && [ -f "$D/install.sh" ] || { say "the zip has no installer — nothing changed"; exit 1; }

running=0
"$LINK" status 2>/dev/null | grep -q "mitmweb pid" && running=1

# the iOS approval (if any) was handled at the first install; the shell setup is already in place
OUT="$W/install.out"
if ! /bin/bash "$D/install.sh" --yes --skip-local-capture > >(tee "$OUT") 2>&1; then
  say "the installer failed — the previous version is still installed and running"; exit 1
fi
say "installed: $("$LINK" --version 2>/dev/null)"

if [ "$running" = 0 ]; then say "it was not running — start it with: $CLI start --background"; exit 0; fi
# R4A-01: the installer restarts running instances itself; a second stop/start would only add another outage
if grep -q "restarted :" "$OUT" 2>/dev/null; then say "restarted on the new version"; exit 0; fi
START_PORT=""; START_WEB_PORT=""; START_PROJECT_SOURCE=""; START_PROJECT_EXPLICIT=0; START_ARGS=()
# shellcheck disable=SC1091 — written by `<cli> start` with printf %q into the owner-only state dir
# R4A-05: each web port saves its own start; this proxy's port arrives in the environment it was started with
P=$(product env_prefix RIVIS); WV="${P}_WEB_PORT"; WPORT="${!WV:-8083}"; SF="$STATE/last-start"; [ "$WPORT" = 8083 ] || SF="$STATE/last-start-$WPORT"
[ -f "$SF" ] && . "$SF"
[ ${#START_ARGS[@]} -gt 0 ] || START_ARGS=(start --background --no-open)
case " ${START_ARGS[*]} " in *" --background "*) ;; *) START_ARGS+=(--background); say "foreground instance continues in the background after this detached update" ;; esac
say "restarting"
P=$(product env_prefix RIVIS); envs=()
[ -n "$START_PORT" ] && envs+=("${P}_PORT=$START_PORT")
[ -n "$START_WEB_PORT" ] && envs+=("${P}_WEB_PORT=$START_WEB_PORT")
env ${envs[@]+"${envs[@]}"} "$LINK" stop
if env ${envs[@]+"${envs[@]}"} "RIVIS_START_PROJECT_SOURCE=${START_PROJECT_SOURCE:-legacy}" \
  "RIVIS_START_PROJECT_EXPLICIT=$START_PROJECT_EXPLICIT" "$LINK" "${START_ARGS[@]}"; then
  for _ in $(seq 1 20); do env ${envs[@]+"${envs[@]}"} "$LINK" health >/dev/null 2>&1 && break; sleep 0.5; done
  if env ${envs[@]+"${envs[@]}"} "$LINK" health; then say "restarted on the new version"
  else say "the new version is not healthy — go back with: $CLI rollback"; exit 1; fi
else say "could not restart — run: $CLI start --background"; exit 1; fi
