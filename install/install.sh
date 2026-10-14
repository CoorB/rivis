#!/usr/bin/env bash
# One-step installer (macOS, bash 3.2). Idempotent; safe to re-run.
#
#   install.sh [--dry-run] [--from-mirror URL] [--mitmproxy-tarball PATH] [--tool-tarball PATH]
#              [--skip-local-capture] [--no-rc] [--yes]
#   install.sh --uninstall [--dry-run]
#
# mitmproxy source, in priority order (the pinned SHA-256 in mirror.conf is verified in EVERY case; mismatch = refuse):
#   1. --from-mirror URL   (or MIRROR_BASE_URL in mirror.conf, once IT publishes it)
#   2. --mitmproxy-tarball PATH
#   3. the official URL
# A compatible mitmproxy (same pinned version) already on PATH, e.g. the Homebrew cask, is reused.
#
# Never: sudo, system proxy changes, listening beyond 127.0.0.1, touching an existing ~/.mitmproxy CA,
# deleting user data. Uninstall removes binaries, the link and the rc block; it keeps state and the CA.
set -u
umask 077

HERE="$(cd "$(dirname "$0")" && pwd -P)"
SRC_ROOT="$(cd "$HERE/.." && pwd -P)"          # the tool checkout (parent of install/) when run from source
CONF="$HERE/mirror.conf"
RC_BEGIN="# >>> proxy-tool installer (managed) >>>"
RC_END="# <<< proxy-tool installer (managed) <<<"

DRY=0; UNINSTALL=0; MIRROR=""; MITM_TARBALL=""; TOOL_TARBALL=""; SKIP_LOCAL=0; NO_RC=0; YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --from-mirror) [ $# -ge 2 ] || { echo "--from-mirror needs a URL" >&2; exit 2; }; MIRROR="$2"; shift ;;
    --mitmproxy-tarball) [ $# -ge 2 ] || { echo "needs a path" >&2; exit 2; }; MITM_TARBALL="$2"; shift ;;
    --tool-tarball) [ $# -ge 2 ] || { echo "needs a path" >&2; exit 2; }; TOOL_TARBALL="$2"; shift ;;
    --skip-local-capture) SKIP_LOCAL=1 ;;
    --no-rc) NO_RC=1 ;;
    --yes|-y) YES=1 ;;
    -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

info() { echo "• $*"; }
warn() { echo "!! $*" >&2; }
die()  { echo "install: $*" >&2; exit 1; }
# do CMD…  — runs it, or just prints it under --dry-run
do_() { if [ "$DRY" = 1 ]; then echo "  [dry-run] $*"; else "$@"; fi; }

conf() {  # conf KEY — value from mirror.conf (plain KEY=VALUE, never sourced)
  [ -f "$CONF" ] || die "missing $CONF"
  sed -n "s/^$1=//p" "$CONF" | head -1
}

[ "$(uname -s)" = Darwin ] || die "this installer is for macOS; on Windows use install.ps1"
[ "$(id -u)" -ne 0 ] || die "do not run as root — everything installs in your home directory"

# ---- identity (never hardcode the product name) ----------------------------------------------------------------
product_json=""
for c in "$SRC_ROOT/product.json" "$HOME"/.local/*/current/product.json; do [ -f "$c" ] && { product_json="$c"; break; }; done
if [ -z "$product_json" ] && [ -n "$TOOL_TARBALL" ]; then
  tmp_pj=$(mktemp -d); tar -xzf "$TOOL_TARBALL" -C "$tmp_pj" --include='*/product.json' 2>/dev/null
  product_json=$(ls "$tmp_pj"/*/product.json 2>/dev/null | head -1)
fi
[ -n "$product_json" ] || die "cannot find product.json (run from a checkout, or pass --tool-tarball)"
CLI=$(plutil -extract cli raw -o - "$product_json") || die "bad product.json"
NAME=$(plutil -extract name raw -o - "$product_json")
TOOL_VERSION=$(tr -d '[:space:]' < "$HERE/VERSION" 2>/dev/null)
[ -n "$TOOL_VERSION" ] || TOOL_VERSION=unknown
MITM_VERSION=$(conf MITMPROXY_VERSION)

ROOT="$HOME/.local/$CLI"                         # all our files live here (user-owned, no sudo)
BIN_DIR="$HOME/.local/bin"
LINK="$BIN_DIR/$CLI"
MITM_DIR="$ROOT/mitmproxy-$MITM_VERSION"
TOOL_DIR="$ROOT/tool-$TOOL_VERSION"
RECEIPT="$ROOT/install-receipt"                  # records what WE installed, so uninstall removes only that
CONFDIR="$HOME/.mitmproxy"
PREFIX_VAR=$(plutil -extract env_prefix raw -o - "$product_json" 2>/dev/null || echo RIVIS)
eval "_c=\${${PREFIX_VAR}_CONFDIR:-}"; [ -n "$_c" ] && CONFDIR="$_c"
STATE_DIR=$(plutil -extract state_dir raw -o - "$product_json" 2>/dev/null); STATE_DIR="${STATE_DIR/#\~/$HOME}"

# ---- uninstall -------------------------------------------------------------------------------------------------
strip_rc_block() {  # strip_rc_block FILE — removes only our marked block
  local f="$1"
  [ -f "$f" ] && grep -qF "$RC_BEGIN" "$f" || return 0
  info "removing PATH block from $f"
  if [ "$DRY" = 1 ]; then echo "  [dry-run] strip marked block from $f"; return 0; fi
  local t; t=$(mktemp)
  awk -v b="$RC_BEGIN" -v e="$RC_END" '$0==b{skip=1} !skip{print} $0==e{skip=0}' "$f" > "$t" && cat "$t" > "$f"
  rm -f "$t"
}

if [ "$UNINSTALL" = 1 ]; then
  info "uninstall $NAME ($CLI) — plan:"
  [ -L "$LINK" ] || [ -f "$LINK" ] && do_ rm -f "$LINK"
  if [ -f "$RECEIPT" ] && grep -q '^mitmproxy=installed-by-us' "$RECEIPT"; then
    do_ rm -rf "$MITM_DIR"
  else
    info "mitmproxy was not installed by us (or no receipt) — left alone"
  fi
  for d in "$ROOT"/tool-*; do [ -d "$d" ] && do_ rm -rf "$d"; done
  do_ rm -f "$ROOT/current" "$RECEIPT"
  [ "$DRY" = 1 ] || rmdir "$ROOT" 2>/dev/null
  for rc in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.bash_profile" "$HOME/.bashrc"; do strip_rc_block "$rc"; done
  echo
  info "kept (your data): state dir $STATE_DIR and the CA in $CONFDIR"
  echo "  To remove them too:  rm -rf \"$STATE_DIR\"   and   remove the CA from test devices first ($CLI ios off / $CLI android off)"
  echo "  The macOS 'Mitmproxy Redirector' app and its network extension were NOT touched. To remove:"
  echo "    System Settings → General → Login Items & Extensions → Network Extensions → remove it, then delete /Applications/Mitmproxy Redirector.app"
  exit 0
fi

# ---- plan ------------------------------------------------------------------------------------------------------
ARCH=$(uname -m)
case "$ARCH" in
  arm64)  KEY=MACOS_ARM64 ;;
  x86_64) KEY=MACOS_X86_64 ;;
  *) die "unsupported CPU: $ARCH" ;;
esac
M_FILE=$(conf "MITMPROXY_FILE_$KEY"); M_SHA=$(conf "MITMPROXY_SHA256_$KEY")
T_SHA=$(conf TOOL_SHA256)
[ -n "$MIRROR" ] || MIRROR=$(conf MIRROR_BASE_URL)
MIRROR="${MIRROR%/}"

installed_mitm_version() {  # prints version of a mitmdump binary, or nothing
  "$1" --version 2>/dev/null | awk '/^Mitmproxy:/{print $2; exit}'
}
REUSE=""
for cand in "$MITM_DIR/mitmproxy.app/Contents/MacOS/mitmdump" "$(command -v mitmdump 2>/dev/null)"; do
  [ -n "$cand" ] && [ -x "$cand" ] || continue
  [ "$(installed_mitm_version "$cand")" = "$MITM_VERSION" ] && { REUSE="$cand"; break; }
done

info "$NAME ($CLI) installer — tool $TOOL_VERSION, mitmproxy pinned $MITM_VERSION, $ARCH"
[ "$DRY" = 1 ] && info "DRY RUN — nothing below will be changed"
if [ -n "$REUSE" ]; then
  info "plan: mitmproxy $MITM_VERSION already present at $REUSE — reuse (no download)"
else
  if [ -n "$MIRROR" ];      then M_URL="$MIRROR/mitmproxy/$MITM_VERSION/$M_FILE"; M_FROM="internal mirror"
  elif [ -n "$MITM_TARBALL" ]; then M_URL=""; M_FROM="local tarball $MITM_TARBALL"
  else M_URL="https://downloads.mitmproxy.org/$MITM_VERSION/$M_FILE"; M_FROM="official site"; fi
  info "plan: install mitmproxy $MITM_VERSION from $M_FROM → $MITM_DIR"
  [ -n "${M_URL:-}" ] && info "      url    $M_URL"
  info "      sha256 $M_SHA (verified before use)"
  [ "$M_FROM" = "official site" ] && warn "the corporate web filter may block downloads.mitmproxy.org — use --from-mirror or --mitmproxy-tarball"
fi
if [ -n "$TOOL_TARBALL" ]; then T_FROM="tarball $TOOL_TARBALL"
elif [ -n "$MIRROR" ] && [ ! -f "$SRC_ROOT/$CLI" ]; then T_FROM="mirror $MIRROR/$CLI/$CLI-$TOOL_VERSION.tar.gz"
elif [ -f "$SRC_ROOT/$CLI" ]; then T_FROM="this checkout ($SRC_ROOT)"
else die "no tool source: run from a checkout, or pass --tool-tarball / --from-mirror"; fi
info "plan: install tool from $T_FROM → $TOOL_DIR"
info "plan: launcher $LINK (puts the pinned mitmproxy first on PATH for the tool only)"
if [ "$NO_RC" = 1 ]; then info "plan: no shell rc edits (--no-rc)"
elif echo ":$PATH:" | grep -qF ":$BIN_DIR:"; then info "plan: $BIN_DIR already on PATH — no rc edit"
else info "plan: add $BIN_DIR to PATH via a marked block in $(basename "${SHELL:-zsh}" | sed 's/zsh/.zshrc/;s/bash/.bash_profile/')"; fi
if [ -f "$CONFDIR/mitmproxy-ca-cert.pem" ]; then info "plan: CA exists in $CONFDIR — left untouched"
else info "plan: generate the per-workstation CA in $CONFDIR (mitmdump on 127.0.0.1, random port, stopped right after)"; fi
if [ "$SKIP_LOCAL" = 1 ]; then info "plan: skip local-capture setup (--skip-local-capture)"
else info "plan: local capture — check/install the Mitmproxy Redirector (user click needed on first use)"; fi
info "no sudo, no system proxy changes, nothing listens beyond 127.0.0.1"
[ "$DRY" = 1 ] && { echo; info "dry run finished — nothing changed"; exit 0; }

# ---- helpers (real run) ----------------------------------------------------------------------------------------
TMP=$(mktemp -d "${TMPDIR:-/tmp}/rivis-inst.XXXXXX"); trap 'rm -rf "$TMP"' EXIT
sha_of() { shasum -a 256 "$1" | awk '{print $1}'; }
verify() {  # verify FILE EXPECTED_SHA LABEL
  [ -n "$2" ] || die "$3: no pinned SHA-256 in mirror.conf — refusing to use an unverified file"
  local got; got=$(sha_of "$1")
  [ "$got" = "$2" ] || die "$3: SHA-256 MISMATCH — refusing.
   expected $2
   got      $got"
  info "$3: sha256 OK"
}
fetch() {  # fetch URL DEST
  curl -fL --proto '=https' --tlsv1.2 --retry 2 -sS -o "$2" "$1" \
    || die "download failed: $1  (blocked by the web filter? use --from-mirror or a local tarball)"
}

# ---- 1. mitmproxy ----------------------------------------------------------------------------------------------
MITM_BIN_DIR=""; MITM_BY_US=0
if [ -n "$REUSE" ]; then
  MITM_BIN_DIR="$(dirname "$REUSE")"
  info "reusing mitmproxy $MITM_VERSION at $MITM_BIN_DIR"
else
  mkdir -p "$ROOT"
  if [ -n "${M_URL:-}" ]; then
    fetch "$M_URL" "$TMP/mitm.tar.gz"; MITM_FILE="$TMP/mitm.tar.gz"
  else
    [ -f "$MITM_TARBALL" ] || die "no such file: $MITM_TARBALL"; MITM_FILE="$MITM_TARBALL"
  fi
  verify "$MITM_FILE" "$M_SHA" "mitmproxy tarball"
  rm -rf "$TMP/mitm-x"; mkdir "$TMP/mitm-x"
  tar -xzf "$MITM_FILE" -C "$TMP/mitm-x" || die "cannot extract mitmproxy tarball"
  [ -x "$TMP/mitm-x/mitmproxy.app/Contents/MacOS/mitmdump" ] || die "tarball has no mitmproxy.app/Contents/MacOS/mitmdump"
  rm -rf "$MITM_DIR"; mv "$TMP/mitm-x" "$MITM_DIR"
  # Quarantine only appears on browser downloads, but clear it if present so Gatekeeper does not block the CLI.
  xattr -dr com.apple.quarantine "$MITM_DIR" 2>/dev/null
  [ "$(installed_mitm_version "$MITM_DIR/mitmproxy.app/Contents/MacOS/mitmdump")" = "$MITM_VERSION" ] \
    || die "installed binary does not report version $MITM_VERSION"
  MITM_BIN_DIR="$MITM_DIR/mitmproxy.app/Contents/MacOS"; MITM_BY_US=1
  info "installed mitmproxy $MITM_VERSION → $MITM_DIR"
fi

# ---- 2. the tool -----------------------------------------------------------------------------------------------
mkdir -p "$ROOT"
rm -rf "$TMP/tool-x"; mkdir "$TMP/tool-x"
if [ -n "$TOOL_TARBALL" ]; then
  [ -f "$TOOL_TARBALL" ] || die "no such file: $TOOL_TARBALL"
  verify "$TOOL_TARBALL" "$T_SHA" "tool tarball"
  tar -xzf "$TOOL_TARBALL" -C "$TMP/tool-x" --strip-components=1 || die "cannot extract tool tarball"
elif [ -f "$SRC_ROOT/$CLI" ]; then
  # running from our own checkout: copy it, leaving out state and snapshots
  ( cd "$SRC_ROOT" && tar -cf - --exclude './install' --exclude '.DS_Store' --exclude '*.pyc' --exclude '__pycache__' . ) | tar -xf - -C "$TMP/tool-x"
else
  fetch "$MIRROR/$CLI/$CLI-$TOOL_VERSION.tar.gz" "$TMP/tool.tar.gz"
  verify "$TMP/tool.tar.gz" "$T_SHA" "tool tarball"
  tar -xzf "$TMP/tool.tar.gz" -C "$TMP/tool-x" --strip-components=1 || die "cannot extract tool tarball"
fi
[ -f "$TMP/tool-x/$CLI" ] || die "tool payload has no '$CLI' entry point"
chmod +x "$TMP/tool-x/$CLI" 2>/dev/null
rm -rf "$TOOL_DIR"; mv "$TMP/tool-x" "$TOOL_DIR"
ln -sfn "$TOOL_DIR" "$ROOT/current"
info "installed tool $TOOL_VERSION → $TOOL_DIR"

# ---- 3. launcher on PATH ---------------------------------------------------------------------------------------
mkdir -p "$BIN_DIR"
{
  echo '#!/usr/bin/env bash'
  echo "# generated by the installer — do not edit; re-run install.sh to change"
  if [ "$MITM_BY_US" = 1 ]; then echo "export PATH=\"$MITM_BIN_DIR:\$PATH\""; fi
  echo "exec \"$ROOT/current/$CLI\" \"\$@\""
} > "$TMP/launcher"
chmod 755 "$TMP/launcher"
if [ -e "$LINK" ] && ! grep -q 'generated by the installer' "$LINK" 2>/dev/null; then
  die "$LINK exists and was not created by this installer — remove or rename it, then re-run"
fi
cp "$TMP/launcher" "$LINK"
info "launcher $LINK"

add_rc() {
  local rc
  case "$(basename "${SHELL:-/bin/zsh}")" in bash) rc="$HOME/.bash_profile" ;; *) rc="$HOME/.zshrc" ;; esac
  if [ -f "$rc" ] && grep -qF "$RC_BEGIN" "$rc"; then info "PATH block already in $rc"; return; fi
  { echo; echo "$RC_BEGIN"; echo "export PATH=\"$BIN_DIR:\$PATH\""; echo "$RC_END"; } >> "$rc"
  info "added $BIN_DIR to PATH in $rc (open a new terminal to pick it up)"
}
if [ "$NO_RC" = 0 ] && ! echo ":$PATH:" | grep -qF ":$BIN_DIR:"; then add_rc; fi

{
  echo "version=$TOOL_VERSION"
  echo "mitmproxy_version=$MITM_VERSION"
  [ "$MITM_BY_US" = 1 ] && echo "mitmproxy=installed-by-us" || echo "mitmproxy=reused"
} > "$RECEIPT"

# ---- 4. CA -----------------------------------------------------------------------------------------------------
MITMDUMP="$MITM_BIN_DIR/mitmdump"
CA_PEM="$CONFDIR/mitmproxy-ca-cert.pem"
free_port() { /usr/bin/python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
if [ -f "$CA_PEM" ]; then
  info "CA already present in $CONFDIR — not modified"
else
  info "generating the per-workstation CA in $CONFDIR"
  "$MITMDUMP" --listen-host 127.0.0.1 --listen-port "$(free_port)" --set confdir="$CONFDIR" >/dev/null 2>&1 & cap=$!
  for _ in $(seq 1 30); do [ -f "$CA_PEM" ] && break; sleep 0.5; done
  kill "$cap" 2>/dev/null; wait "$cap" 2>/dev/null
  [ -f "$CA_PEM" ] || die "CA was not generated in $CONFDIR"
  info "CA generated"
fi

# ---- 5. local capture (iOS Simulator) --------------------------------------------------------------------------
ext_state() { systemextensionsctl list 2>/dev/null | grep 'org.mitmproxy.macos-redirector' | head -1; }
EXT_OK=0
if [ "$SKIP_LOCAL" = 1 ]; then
  info "local capture skipped by request"
else
  st=$(ext_state)
  if echo "$st" | grep -q 'activated enabled'; then
    info "Mitmproxy Redirector already approved and active"; EXT_OK=1
  else
    cat <<EOF

─── iOS Simulator capture needs a one-time approval ───────────────────────────────────────────────
mitmproxy copies its signed 'Mitmproxy Redirector' app to /Applications and asks macOS to load its
network extension. macOS will show a prompt; you must approve it yourself:
  1. A dialog appears — click "Open System Settings" (or open System Settings manually).
  2. Go to  General → Login Items & Extensions → Network Extensions (under "Extensions")
     and switch ON "Mitmproxy Redirector" (wording can differ slightly by macOS version).
  3. If macOS asks to "Allow" a network content filter / proxy configuration, click Allow
     and enter your Mac password or Touch ID. (This is Apple's prompt, not this installer's.)
It only captures the processes named by the tool (the Simulator); it does not touch the system proxy.
EOF
    if [ "$YES" = 0 ]; then printf 'Press Enter to start the approval (or type s + Enter to skip): '; read -r ans || ans=s
    else ans=""; fi
    if [ "$ans" = s ] || [ "$ans" = S ]; then info "skipped — iOS capture will not work until approved"
    else
      open "x-apple.systempreferences:com.apple.LoginItems-Settings.extension" 2>/dev/null \
        || open "x-apple.systempreferences:com.apple.preference.security" 2>/dev/null
      "$MITMDUMP" --listen-host 127.0.0.1 --listen-port "$(free_port)" --set confdir="$CONFDIR" --mode local:CoreSimulator >/dev/null 2>&1 & lp=$!
      for i in $(seq 1 60); do
        ext_state | grep -q 'activated enabled' && { EXT_OK=1; break; }
        kill -0 "$lp" 2>/dev/null || break
        [ "$i" = 1 ] && info "waiting up to 2 minutes for your approval…"
        sleep 2
      done
      kill "$lp" 2>/dev/null; wait "$lp" 2>/dev/null
      [ "$EXT_OK" = 1 ] && info "Mitmproxy Redirector approved" || warn "not approved yet — re-run install.sh after approving, or approve in System Settings"
    fi
  fi
fi

# ---- 6. self-check ---------------------------------------------------------------------------------------------
echo
info "self-check"
echo "  tool          $NAME $TOOL_VERSION  ($ROOT/current)"
echo "  mitmproxy     $("$MITMDUMP" --version 2>/dev/null | awk '/^Mitmproxy:/{print $2; exit}')  ($MITM_BIN_DIR)"
echo "  CA sha256     $(openssl x509 -in "$CA_PEM" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
echo "  redirector    $(ext_state | awk '{print $NF}' | grep . || echo 'not installed')"
[ "$EXT_OK" = 1 ] || echo "  NOTE: iOS Simulator capture needs the Redirector approved (see above). Android and plain proxy work without it."
echo
info "next steps"
echo "  $CLI start          # open a new terminal first if PATH was just updated"
echo "  $CLI ios on         # installs the CA in the iOS Simulator"
echo "  $CLI android on     # installs the CA + proxy in the Android emulator"
