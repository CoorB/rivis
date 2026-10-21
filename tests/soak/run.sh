#!/bin/bash
# Real-use soak gate: hermetic Rivis + a NEO-like upstream + streaming traffic + a Playwright-driven panel with real input
# + fault injection + health budgets. bash 3.2 compatible.
#
#   tests/soak/run.sh [--smoke] [--minutes N]
#
#   (no flag)     SOAK_MINUTES (default 25): the full gate
#   --smoke       3 minutes (SOAK_MINUTES=3): proves the harness and covers about two thirds of the scenarios
#   --minutes N   any length
#
# Environment (all optional): SOAK_MINUTES SOAK_SEED SOAK_RATE SOAK_PREFILL SOAK_PAUSE_SCALE SOAK_FAULTS=0 SOAK_TRACE=0
# SOAK_OUT and the budgets SOAK_PANEL_P95_MS SOAK_ADDED_P95_MS SOAK_RSS_GROWTH_MB SOAK_HEAP_GROWTH_MB SOAK_ACTION_DEADLINE (see README.md).
#
# Hermetic like tests/run.sh: random ports, fake HOME, private CA, shim directory first on PATH; never touches ports 8080/8083/
# 8090/8093/9090/9091, ~/.rivis, ~/.mitmproxy, the system proxy, devices or simulators. Afterwards it checks that no process,
# port or temp dir is left and that $HOME, the protected ports and the system proxy are unchanged.
# Output: tests/.artifacts/soak/<timestamp>/report.md (+ report.json, failures/*.png, failures/*-trace.zip).
# Exit status: 0 = PASS, 1 = a scenario or budget failed (or something was left behind), 2 = the harness could not run.
set -u
HERE="$(cd "$(dirname "$0")" && pwd -P)"
TESTS="$(cd "$HERE/.." && pwd -P)"
PY=/usr/bin/python3
while [ $# -gt 0 ]; do
  case "$1" in
    --smoke) SOAK_MINUTES=3; export SOAK_MINUTES ;;
    --minutes) SOAK_MINUTES="$2"; export SOAK_MINUTES; shift ;;
    -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0 ;;
    *) echo "soak/run.sh: unknown option $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done
$PY -c 'import playwright' 2>/dev/null || { echo "soak/run.sh: Playwright is not importable by $PY (pip3 install --user playwright && python3 -m playwright install chromium)" >&2; exit 2; }
command -v mitmweb >/dev/null || { echo "soak/run.sh: mitmweb not found on PATH" >&2; exit 2; }
command -v curl >/dev/null || { echo "soak/run.sh: curl not found" >&2; exit 2; }

RIVIS_TEST_RUN="s$$$(date +%s)"; export RIVIS_TEST_RUN
SOAK_OUT="${SOAK_OUT:-$TESTS/.artifacts/soak/$(date +%Y%m%d-%H%M%S)}"; export SOAK_OUT
mkdir -p "$SOAK_OUT"
RES="$(mktemp -d "${TMPDIR:-/tmp}/rivis-results.XXXXXX")"     # deliberately not named rivis-t-*: it must outlive the leftover check
SOAK_BROWSER_TMP="$(mktemp -d "${TMPDIR:-/tmp}/rivis-soakbrowser.XXXXXX")"; export SOAK_BROWSER_TMP   # not rivis-t-*: see RES
trap 'rm -rf "$RES" "$SOAK_BROWSER_TMP"' EXIT
$PY "$HERE/hermetic_check.py" snapshot "$RES/before.json" || exit 2
echo "soak: ${SOAK_MINUTES:-25} min -> $SOAK_OUT"
START=$(date +%s)
cd "$TESTS" || exit 2
PYTHONDONTWRITEBYTECODE=1 $PY "$HERE/soak.py"
RC=$?
$PY "$HERE/hermetic_check.py" report "$RES/before.json" "$SOAK_OUT"
HC=$?
echo "runtime: $(( ($(date +%s) - START) / 60 )) min $(( ($(date +%s) - START) % 60 )) s"
if [ "$RC" = 2 ]; then echo "SOAK RESULT: HARNESS ERROR (rc=2) — $SOAK_OUT/report.md"; exit 2; fi
if [ "$RC" != 0 ] || [ "$HC" != 0 ]; then echo "SOAK RESULT: FAIL (soak rc=$RC, hermetic rc=$HC) — $SOAK_OUT/report.md"; exit 1; fi
echo "SOAK RESULT: PASS — $SOAK_OUT/report.md"
exit 0
