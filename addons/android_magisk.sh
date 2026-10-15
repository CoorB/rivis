#!/usr/bin/env bash
# One-click CA install on a Google Play emulator (no `adb root`), the way Proxyman 6.14 does it, minus the root shell.
#
#   android_magisk.sh SERIAL CA_PEM CA_NAME MAGISK_DIR STATE_DIR [--yes]
#
#   1. Magisk's own scripts/host_patch.sh patches a COPY of the AVD's stock ramdisk.img, on the emulator itself.
#   2. Rivis adds one oneshot boot service + the CA to that copy (addons/android/rivis_inject.sh).
#   3. The AVD is cold-booted once with `-ramdisk <copy>` (-no-snapshot-load/-save): the service copies the CA into
#      the user CA store as root and writes a status file. Nothing else gets root: not adb shell, not apps.
#   4. The AVD is cold-booted again from its stock ramdisk. The CA stays (it lives in userdata); Magisk is gone.
# The SDK system image and the AVD config are never written. Patched ramdisks are cached per (stock image, Magisk,
# Rivis files, CA) hash under STATE_DIR, so a second emulator from the same image skips step 1.
# Magisk files come from MAGISK_DIR (installed by install.sh) and are verified against addons/android/magisk.pins.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"
SERIAL="$1" CA_PEM="$2" CA_NAME="$3" MAGISK_DIR="$4" STATE_DIR="$5" YES="${6:-}"
ADB="${ADB:-adb}"
PINS="$HERE/android/magisk.pins"

info() { echo "• $*"; }
die()  { echo "android: $*" >&2; exit 1; }
pin()  { sed -n "s/^$1=//p" "$PINS" | head -1; }
sha()  { shasum -a 256 "$1" | awk '{print $1}'; }
sh_()  { "$ADB" -s "$SERIAL" shell "$@" 2>/dev/null | tr -d '\r'; }

[[ "$SERIAL" =~ ^emulator-([0-9]+)$ ]] || die "$SERIAL is not an Android Studio emulator"
PORT="${BASH_REMATCH[1]}"
[[ "$CA_NAME" =~ ^[0-9a-f]{8}\.0$ ]] || die "bad CA file name $CA_NAME"

# ---- which AVD, which image ---------------------------------------------------------------------------------------
AVD=$("$ADB" -s "$SERIAL" emu avd name 2>/dev/null | tr -d '\r' | awk 'NF && $0 != "OK" {print; exit}')
[[ "$AVD" =~ ^[A-Za-z0-9._-]+$ ]] || die "$SERIAL: could not read the AVD name"
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
[ -n "$SDK" ] || { a=$(command -v "$ADB"); SDK="$(cd "$(dirname "$a")/.." && pwd -P)"; }
EMULATOR="$SDK/emulator/emulator"
[ -x "$EMULATOR" ] || die "emulator binary not found under $SDK (set ANDROID_SDK_ROOT)"
AVD_HOME="${ANDROID_AVD_HOME:-$HOME/.android/avd}"
AVD_DIR=$(sed -n 's/^path=//p' "$AVD_HOME/$AVD.ini" 2>/dev/null | head -1); [ -d "$AVD_DIR" ] || AVD_DIR="$AVD_HOME/$AVD.avd"
CONFIG="$AVD_DIR/config.ini"
cfg() { awk -F' *= *' -v k="$1" '$1 == k {print $2; exit}' "$CONFIG"; }   # the emulator rewrites it as "key = value"
[ -f "$CONFIG" ] || die "$AVD: no config.ini in $AVD_DIR"
{ [ "$(cfg PlayStore.enabled)" = true ] || cfg tag.ids | grep -q playstore || cfg tag.id | grep -q playstore; } || die "$AVD is not a Google Play AVD (use adb root instead)"
SYSDIR=$(cfg image.sysdir.1)
STOCK="$SDK/${SYSDIR%/}/ramdisk.img"
[ -r "$STOCK" ] || die "$AVD: no ramdisk.img in $SDK/$SYSDIR (this image type is not supported)"
API=$(sh_ getprop ro.build.version.sdk)
ABI=$(sh_ getprop ro.product.cpu.abi)

# ---- pinned Magisk files ------------------------------------------------------------------------------------------
APK="$MAGISK_DIR/$(pin MAGISK_APK)"; HOST_PATCH="$MAGISK_DIR/host_patch.sh"
[ -f "$APK" ] && [ -f "$HOST_PATCH" ] || die "Magisk $(pin MAGISK_VERSION) is not installed ($MAGISK_DIR). Re-run the installer, or use: rivis android on --manual"
[ "$(sha "$APK")" = "$(pin MAGISK_APK_SHA256)" ] || die "Magisk APK SHA-256 mismatch — refusing ($APK)"
[ "$(sha "$HOST_PATCH")" = "$(pin MAGISK_HOST_PATCH_SHA256)" ] || die "host_patch.sh SHA-256 mismatch — refusing"

# ---- consent ------------------------------------------------------------------------------------------------------
cat <<EOF

─── Google Play emulator: one-time certificate setup ───────────────────────────────────────────────
'$AVD' (Android API $API, $ABI) refuses adb root, so Rivis installs its certificate like Proxyman does:
  • Magisk $(pin MAGISK_VERSION) (official release, GPLv3, checksum verified) patches a temporary COPY of the ramdisk
  • '$AVD' restarts twice: once with that copy, where a one-shot service copies the certificate
    into the user store as root, then normally. About 2 minutes; the emulator window will close and reopen.
  • Nothing else gets root (not adb shell, not apps). The SDK image and the AVD settings are not changed;
    after the second restart Magisk is gone and only the certificate remains.
Use a test AVD only: no personal Google account or data.
EOF
if [ "$YES" != --yes ]; then
  # from the terminal itself: adb calls read stdin and would swallow a piped answer
  printf 'Continue? [y/N] '; { read -r ans < /dev/tty; } 2>/dev/null || ans=n
  case "$ans" in y|Y|yes|YES) ;; *) die "cancelled — nothing changed. 'rivis android on --manual' prints the Settings steps instead" ;; esac
fi

# ---- 1+2. patched ramdisk (cached) --------------------------------------------------------------------------------
ca_sha=$(sha "$CA_PEM")
files_sha=$(cat "$HERE/android/rivis_ca.rc" "$HERE/android/rivis_ca.sh" "$HERE/android/rivis_inject.sh" | shasum -a 256 | awk '{print $1}')
key=$(printf '%s %s %s %s' "$(sha "$STOCK")" "$(pin MAGISK_APK_SHA256)" "$files_sha" "$ca_sha" | shasum -a 256 | awk '{print $1}')
CACHE="$STATE_DIR/android-ramdisk"; mkdir -p -m 700 "$CACHE"
PATCHED="$CACHE/$key.img"
if [ -s "$PATCHED" ] && [ "$(sha "$PATCHED")" = "$(cat "$PATCHED.sha256" 2>/dev/null)" ]; then
  info "patched ramdisk ready (cached)"
else
  info "patching a copy of the ramdisk with Magisk…"
  tmp=$(mktemp -d "$CACHE/.work.XXXXXX") || die "cannot create a work directory"
  trap 'rm -rf "$tmp"; "$ADB" -s "$SERIAL" shell rm -rf /data/local/tmp/rivis-magisk >/dev/null 2>&1' EXIT
  unzip -p "$APK" "lib/$ABI/libbusybox.so" > "$tmp/busybox" 2>/dev/null && [ -s "$tmp/busybox" ] || die "no busybox for $ABI in the Magisk APK"
  echo "$CA_NAME" > "$tmp/rivis_ca.name"
  W=/data/local/tmp/rivis-magisk
  sh_ "rm -rf $W && mkdir -p $W" >/dev/null
  for f in "$tmp/busybox" "$HOST_PATCH" "$HERE/android/rivis_ca.rc" "$HERE/android/rivis_ca.sh" "$HERE/android/rivis_inject.sh" "$tmp/rivis_ca.name"; do
    "$ADB" -s "$SERIAL" push "$f" "$W/" >/dev/null 2>&1 || die "could not copy $(basename "$f") to the emulator"
  done
  "$ADB" -s "$SERIAL" push "$APK" "$W/magisk.apk" >/dev/null 2>&1 && "$ADB" -s "$SERIAL" push "$CA_PEM" "$W/rivis_ca.0" >/dev/null 2>&1 \
    && "$ADB" -s "$SERIAL" push "$STOCK" "$W/ramdisk.img" >/dev/null 2>&1 || die "could not copy Magisk or the ramdisk to the emulator"
  # host_patch.sh works in /data/local/tmp by design: run it from a private copy of that layout
  log="$tmp/patch.log"
  "$ADB" -s "$SERIAL" shell "cd $W && sed 's|cd /data/local/tmp|cd $W|' host_patch.sh > hp.sh && sh hp.sh $W/ramdisk.img" > "$log" 2>&1 \
    || { tail -5 "$log" >&2; die "Magisk could not patch this ramdisk (API $API)"; }
  "$ADB" -s "$SERIAL" shell "cd $W && sed 's|cd /data/local/tmp|cd $W|' rivis_inject.sh > ri.sh && sh ri.sh $W/ramdisk.img.magisk" >> "$log" 2>&1 \
    || { tail -5 "$log" >&2; die "could not add the Rivis service to the patched ramdisk"; }
  "$ADB" -s "$SERIAL" pull "$W/ramdisk.img.magisk" "$tmp/patched.img" >/dev/null 2>&1 || die "could not copy the patched ramdisk back"
  [ -s "$tmp/patched.img" ] && [ "$(sha "$tmp/patched.img")" != "$(sha "$STOCK")" ] || die "Magisk produced no change — refusing"
  mv "$tmp/patched.img" "$PATCHED" && chmod 600 "$PATCHED" && sha "$PATCHED" > "$PATCHED.sha256"
  info "patched ramdisk ready"
fi

# ---- 3. boot the copy once ----------------------------------------------------------------------------------------
gone() { local i; for i in $(seq 1 60); do "$ADB" -s "$SERIAL" get-state >/dev/null 2>&1 || return 0; sleep 1; done; return 1; }
booted() { local i; for i in $(seq 1 300); do [ "$(sh_ getprop sys.boot_completed)" = 1 ] && return 0; sleep 1; done; return 1; }
start_avd() {   # start_avd LOG [extra emulator args]
  local log="$1"; shift
  ANDROID_AVD_HOME="$AVD_HOME" nohup "$EMULATOR" -avd "$AVD" -port "$PORT" -no-snapshot-load "$@" > "$log" 2>&1 < /dev/null &
  disown $! 2>/dev/null || true
}
restore_stock() {
  "$ADB" -s "$SERIAL" emu kill >/dev/null 2>&1; gone
  start_avd "$CACHE/stock.log"
  booted && info "'$AVD' restarted normally" || info "'$AVD' did not come back by itself — Cold Boot it from Android Studio's Device Manager"
}
info "restarting '$AVD' with the temporary ramdisk…"
"$ADB" -s "$SERIAL" emu kill >/dev/null 2>&1 || die "the emulator did not accept the stop command"
gone || die "the emulator did not stop within 60 seconds"
start_avd "$CACHE/rooted.log" -ramdisk "$PATCHED" -no-snapshot-save
booted || { restore_stock; die "the emulator did not boot with the patched ramdisk (log: $CACHE/rooted.log)"; }
[ "$("$ADB" -s "$SERIAL" emu avd name 2>/dev/null | tr -d '\r' | head -1)" = "$AVD" ] || die "a different emulator answered on $SERIAL"
st=""; for i in $(seq 1 60); do st=$(sh_ cat /data/local/tmp/rivis-ca.status); [ -n "$st" ] && break; sleep 1; done
sh_ rm -f /data/local/tmp/rivis-ca.status >/dev/null

# ---- 4. back to stock ---------------------------------------------------------------------------------------------
info "restarting '$AVD' normally…"
restore_stock
case "$st" in
  "ok $CA_NAME") info "$SERIAL: CA installed in the user store (one-shot root service: $st)" ;;
  "") die "the one-shot service did not report back — CA not confirmed. Retry, or: rivis android on --manual" ;;
  *) die "the one-shot service failed ($st) — CA not installed. Retry, or: rivis android on --manual" ;;
esac
