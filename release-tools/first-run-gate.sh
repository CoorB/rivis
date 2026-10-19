#!/bin/bash
# first-run-gate.sh ZIP — exercise the shipped first run in a disposable HOME on macOS bash 3.2.
set -u
ZIP=${1:-}
[ -f "$ZIP" ] || { echo "usage: $0 ZIP" >&2; exit 2; }
case "$(/bin/bash --version | head -1)" in *"version 3.2"*) ;; *) echo "requires macOS /bin/bash 3.2" >&2; exit 2;; esac
ZIP=$(cd "$(dirname "$ZIP")" && pwd -P)/$(basename "$ZIP")
WORK=$(mktemp -d "${TMPDIR:-/tmp}/rivis-first-run.XXXXXX") || exit 2
HOME_TEST=$WORK/home
mkdir -p "$HOME_TEST/Downloads" "$HOME_TEST/tmp"
cp "$ZIP" "$HOME_TEST/Downloads/" || exit 2
VER=$(basename "$ZIP" | sed -n 's/^rivis-installer-\(.*\)\.zip$/\1/p')
[ -n "$VER" ] || { echo "unexpected zip name: $ZIP" >&2; exit 2; }
P=$(/usr/bin/python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
WP=$(/usr/bin/python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
[ "$P" != "$WP" ] || { echo "port collision" >&2; exit 2; }
case " $P $WP " in *" 8080 "*|*" 8083 "*|*" 8090 "*|*" 8093 "*) echo "protected port selected" >&2; exit 2;; esac
R=$HOME_TEST/.local/bin/rivis
CMD="cd ~/Downloads && { [ -d rivis-installer-$VER ] || unzip -q rivis-installer-$VER.zip; } && ./rivis-installer-$VER/install.sh"
BEFORE=$(lsof -nP -iTCP:8080 -iTCP:8083 -iTCP:8090 -iTCP:8093 -sTCP:LISTEN 2>/dev/null || true)
run() { env -i HOME="$HOME_TEST" PATH=/usr/bin:/bin:/usr/sbin:/sbin USER="$(id -un)" LOGNAME="$(id -un)" TMPDIR="$HOME_TEST/tmp" LANG=en_US.UTF-8 RIVIS_PORT="$P" RIVIS_WEB_PORT="$WP" RIVIS_BROWSER_APPS="$WORK/no-browsers" "$@"; }
listeners() { lsof -nP -iTCP:"$P" -iTCP:"$WP" -sTCP:LISTEN 2>/dev/null | tail -n +2 | wc -l | tr -d ' '; }
pass() { echo "PASS | $1"; }
fail() { echo "FAIL | $1 | $2"; FAILED=1; }
check_live() {
  label=$1
  token=$HOME_TEST/.rivis/web-token-$WP
  [ -f "$token" ] || token=$HOME_TEST/.rivis/web-token
  if [ ! -f "$token" ]; then
    fail "$label: curl -fsS http://127.0.0.1:$WP/?token=TOKEN" "token file absent"
  else
    code=$(curl -sS --noproxy '*' -o "$WORK/ui" -w '%{http_code}' "http://127.0.0.1:$WP/?token=$(cat "$token")" --max-time 15 2>"$WORK/ui.err")
    if [ "$code" = 200 ]; then pass "$label: curl -fsS http://127.0.0.1:$WP/?token=TOKEN"; else fail "$label: curl -fsS http://127.0.0.1:$WP/?token=TOKEN" "HTTP $code $(cat "$WORK/ui.err")"; fi
  fi
  code=$(curl -sS --noproxy '' -x "http://127.0.0.1:$P" --cacert "$HOME_TEST/.mitmproxy/mitmproxy-ca-cert.pem" -o "$WORK/https" -w '%{http_code}' https://example.com --max-time 20 2>"$WORK/https.err")
  if [ "$code" = 200 ]; then pass "$label: curl --noproxy '' -x http://127.0.0.1:$P --cacert '$HOME_TEST/.mitmproxy/mitmproxy-ca-cert.pem' https://example.com"; else fail "$label: curl --noproxy '' -x http://127.0.0.1:$P --cacert '$HOME_TEST/.mitmproxy/mitmproxy-ca-cert.pem' https://example.com" "HTTP $code $(cat "$WORK/https.err")"; fi
}
stop_check() {
  if run "$R" stop >"$WORK/stop.log" 2>&1; then pass "rivis stop"; else fail "rivis stop" "$(tail -3 "$WORK/stop.log")"; fi
  if [ "$(listeners)" = 0 ]; then pass "lsof -nP -iTCP:$P -iTCP:$WP -sTCP:LISTEN (0 listeners)"; else fail "lsof -nP -iTCP:$P -iTCP:$WP -sTCP:LISTEN (0 listeners)" "$(listeners) listeners"; fi
}
cleanup() {
  [ -x "$R" ] && run "$R" stop >/dev/null 2>&1 || true
  after=$(lsof -nP -iTCP:8080 -iTCP:8083 -iTCP:8090 -iTCP:8093 -sTCP:LISTEN 2>/dev/null || true)
  if [ "$BEFORE" = "$after" ]; then pass "lsof -nP -iTCP:8080 -iTCP:8083 -iTCP:8090 -iTCP:8093 -sTCP:LISTEN (owner ports untouched)"; else fail "lsof -nP -iTCP:8080 -iTCP:8083 -iTCP:8090 -iTCP:8093 -sTCP:LISTEN (owner ports untouched)" "listener set changed"; fi
  rm -rf "$WORK"
}
FAILED=0
trap cleanup EXIT

# A PTY makes the real installer offer its documented Start now? prompt. Send Enter to its prompts.
run /usr/bin/python3 - "$CMD" "$WORK/install.log" <<'PY'
import os, pty, select, sys, time
command, log_path = sys.argv[1:]
pid, fd = pty.fork()
if pid == 0:
    os.chdir(os.path.join(os.environ['HOME'], 'Downloads'))
    os.execv('/bin/bash', ['/bin/bash', '-c', command])
buffer = b''
answered = set()
deadline = time.time() + 180
with open(log_path, 'wb') as log:
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.25)
        if ready:
            try: data = os.read(fd, 65536)
            except OSError: break
            if not data: break
            log.write(data); log.flush(); buffer = (buffer + data)[-4096:]
            for marker in (b'Press Enter to continue', b'Start Rivis now and open its UI? [Y/n]'):
                if marker in buffer and marker not in answered:
                    os.write(fd, b'\n'); answered.add(marker)
        done, status = os.waitpid(pid, os.WNOHANG)
        if done: sys.exit(os.waitstatus_to_exitcode(status))
    try: os.kill(pid, 15)
    except ProcessLookupError: pass
    _, status = os.waitpid(pid, 0)
    sys.exit(os.waitstatus_to_exitcode(status))
PY
rc=$?
if [ "$rc" = 0 ]; then pass "$CMD [Enter at Start now?]"; else fail "$CMD [Enter at Start now?]" "rc=$rc; $(tail -4 "$WORK/install.log" | tr '\r\n' '  ')"; fi
if [ -x "$R" ]; then
  check_live "installer default start"
  stop_check
  if run "$R" start --background >"$WORK/background.log" 2>&1; then pass "rivis start --background"; else fail "rivis start --background" "$(tail -4 "$WORK/background.log")"; fi
  check_live "background start"
  stop_check
  # Plain foreground start is itself put in the background so the gate can probe and stop it.
  run "$R" start >"$WORK/foreground.log" 2>&1 & foreground=$!
  for i in 1 2 3 4 5 6 7 8 9 10; do [ "$(listeners)" -ge 2 ] && break; sleep 1; done
  if [ "$(listeners)" -ge 2 ]; then pass "rivis start (backgrounded by gate)"; else fail "rivis start (backgrounded by gate)" "$(tail -4 "$WORK/foreground.log")"; fi
  check_live "plain start"
  stop_check
  wait "$foreground" 2>/dev/null || true
fi
trap - EXIT
cleanup
if [ "$FAILED" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit "$FAILED"
