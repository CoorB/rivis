#!/bin/bash
# One command that runs the whole Rivis suite and prints a summary table.  bash 3.2 compatible.
#
#   tests/run.sh [--fast] [--ui] [--jobs N] [-k PATTERN]
#
#   (no flag)    everything: CLI, PowerShell, rules engine, profiles, breakpoints, collections, sessions, panel API,
#                scripts, viewers, TLS, installer, security, perf budgets and the browser UI smoke
#   --fast       skips the browser UI and the perf budgets/soak
#   --ui         ONLY the browser UI smoke (tests/ui) — needs Playwright + Chromium, otherwise it skips with the install command
#   --jobs N     test modules run in N parallel processes (default 4; each has its own fake HOME, CA, temp dir and random ports)
#   -k PATTERN   forwarded to pytest -k (select tests by name)
#
# Hermetic: random ports, fake HOME, private CA, shim directory first on PATH. It never touches ports 8080/8083/8090/8093/8094/
# 8095, ~/.mitmproxy, ~/.neo-mitm, ~/.rivis, devices or the VPN. After the run it checks that no process, port or temp dir is
# left, and that $HOME, the protected ports and the system proxy are unchanged. Exit status is non-zero on any failure,
# unexpected success (a known bug that got fixed — remove its expectedFailure marker) or leftover.
set -u
HERE="$(cd "$(dirname "$0")" && pwd -P)"
PY=/usr/bin/python3
FAST=0; UI_ONLY=0; JOBS=4; KEXPR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --fast) FAST=1 ;;
    --ui) UI_ONLY=1 ;;
    --jobs) JOBS="$2"; shift ;;
    -k) KEXPR="$2"; shift ;;
    -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0 ;;
    *) echo "run.sh: unknown option $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done
$PY -c 'import pytest' 2>/dev/null || { echo "run.sh: pytest is not importable by $PY (pip3 install --user pytest)" >&2; exit 2; }
command -v mitmweb >/dev/null || { echo "run.sh: mitmweb not found on PATH" >&2; exit 2; }

RES="$(mktemp -d "${TMPDIR:-/tmp}/rivis-results.XXXXXX")"     # deliberately not named rivis-t-*: it must outlive the leftover check
trap 'rm -rf "$RES"' EXIT
$PY "$HERE/hermetic.py" snapshot "$RES/before.snap" || exit 2

cd "$HERE" || exit 2
if [ "$UI_ONLY" = 1 ]; then
  MODULES="ui/test_ui.py"
else
  MODULES="$(ls test_*.py | sort)"
  [ "$FAST" = 1 ] || MODULES="$MODULES
$(ls perf/test_*.py ui/test_*.py 2>/dev/null)"
fi
echo "Rivis test suite — $(echo "$MODULES" | wc -l | tr -d ' ') modules, $JOBS parallel jobs$( [ "$FAST" = 1 ] && echo ', --fast')$( [ -n "$KEXPR" ] && echo ", -k $KEXPR")"
START=$(date +%s)
# longest modules first so the parallel run finishes sooner
ORDER="test_cli.py test_scripts.py test_rules_engine.py test_network.py test_collections_sessions.py test_panel.py test_tls_live.py"
SORTED=""
for m in $ORDER; do echo "$MODULES" | grep -qx "$m" && SORTED="$SORTED $m"; done
for m in $MODULES; do case " $ORDER " in *" $m "*) ;; *) SORTED="$SORTED $m" ;; esac; done
run_one() {
  m="$1"; name="$(echo "${m%.py}" | tr '/' '_')"
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$HERE" "$PY" -m pytest -q --no-header -p no:cacheprovider -p _summary \
      --json-out "$RES/$name.json" ${KEXPR:+-k "$KEXPR"} "$m" > "$RES/$name.log" 2>&1
  printf '  %-34s rc=%s\n' "$m" "$?"
}
for m in $SORTED; do                      # rolling pool (bash 3.2 has no `wait -n`)
  while [ "$(jobs -r | wc -l | tr -d ' ')" -ge "$JOBS" ]; do sleep 0.5; done
  run_one "$m" &
done
wait
echo "wall clock: $(( $(date +%s) - START )) s"
$PY "$HERE/hermetic.py" report "$RES" "$RES/before.snap"
RC=$?
mkdir -p "$HERE/.artifacts/last-run" && cp "$RES"/*.log "$RES"/*.json "$HERE/.artifacts/last-run/" 2>/dev/null
echo "per-module logs: tests/.artifacts/last-run/"
exit $RC
