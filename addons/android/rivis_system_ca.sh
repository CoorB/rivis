#!/system/bin/sh
# Runs on an Android emulator as root: puts the workstation CA in the SYSTEM certificate store too, for apps that trust
# only system certificates (the default for apps targeting Android 7+). The way HTTP Toolkit and other proxies do it:
#   - a tmpfs over /system/etc/security/cacerts holding the image's own CAs plus this one (the image is not written);
#   - Android 14+ reads system CAs from the Conscrypt APEX, and each app has its own mount namespace: the tmpfs is
#     bind-mounted over /apex/com.android.conscrypt/cacerts in this shell, in the zygotes (apps started later inherit it)
#     and in every running app.
# Nothing survives a reboot: the running proxy puts it back on an emulator with adb root (rivis android on --system).
# A system CA does not bypass certificate pinning.
#
# Every mount this script makes is the one tmpfs it mounted itself (or a bind of it), recognised by that filesystem's
# device number, recorded in $MARK with the boot id. It never unmounts anything else (another tool's CA layer stays),
# and a failed install takes back what it mounted (review 2026-10-23).
#
#   rivis_system_ca.sh inject CA_FILE NAME     (NAME = <subject_hash_old>.0)
#        last line "rivis-system-ca: ok", "rivis-system-ca: ok partial N" (N running apps kept the old store: restart
#        them) or "rivis-system-ca: fail <reason>"
#   rivis_system_ca.sh remove NAME             → "rivis-system-ca: removed" / "absent" / "fail <reason>"
#   rivis_system_ca.sh status NAME             → "rivis-system-ca: present" or "rivis-system-ca: absent"
set -u
SYS=/system/etc/security/cacerts
APEX=/apex/com.android.conscrypt/cacerts
COPY=/data/local/tmp/rivis-ca-copy
MARK=/data/local/tmp/rivis-system-ca.boot        # "<boot id> <name> <device>" for this boot's own tmpfs
action="${1:-}"
name=""

say() { echo "rivis-system-ca: $*"; }
boot_id() { cat /proc/sys/kernel/random/boot_id 2>/dev/null; }
# the device (major:minor) of the filesystem mounted last at PATH in the mount namespace of PID (mountinfo field 3)
top_dev() {
  _d=""
  while read -r _id _parent _dev _root _mnt _rest; do
    [ "$_mnt" = "$2" ] && _d="$_dev"
  done < "/proc/$1/mountinfo" 2>/dev/null
  echo "$_d"
}
# this boot's own tmpfs for NAME, or nothing
our_dev() {
  _m=$(cat "$MARK" 2>/dev/null) || return 0
  set -- $_m
  [ "${1:-}" = "$(boot_id)" ] && [ "${2:-}" = "$name" ] && echo "${3:-}"
}
zygotes() { pidof zygote zygote64 2>/dev/null; }
# the mount namespaces that need the bind: zygote(s), then every process a zygote started (the apps)
namespaces() {
  for z in $(zygotes); do
    echo "$z"
    ps -o PID= -P "$z" 2>/dev/null
  done
}
in_ns() { _p="$1"; shift; nsenter --mount="/proc/$_p/ns/mnt" -- "$@"; }
# take back every mount of device $1: the APEX binds in every namespace, then the tmpfs itself
undo() {
  _dev="$1"
  [ -n "$_dev" ] || return 0
  if [ -d "$APEX" ]; then
    for p in $(namespaces); do
      [ "$(top_dev "$p" "$APEX")" = "$_dev" ] && in_ns "$p" /system/bin/umount "$APEX" >/dev/null 2>&1
    done
    [ "$(top_dev self "$APEX")" = "$_dev" ] && umount "$APEX"
  fi
  [ "$(top_dev self "$SYS")" = "$_dev" ] && umount "$SYS"
  rm -rf "$COPY"
}
fail() { [ -n "${dev:-}" ] && undo "$dev" && rm -f "$MARK"; say "fail $*"; exit 1; }
# test hook (the suite's fake emulator and the device pass): fail right after the given step, to prove the rollback
test_fail() { [ "${RIVIS_SYSCA_TEST_FAIL:-}" = "$1" ] && fail "test-$1"; return 0; }

case "$action" in
  inject)
    ca="${2:-}"; name="${3:-}"
    case "$name" in [0-9a-f]*.0) ;; *) say "fail bad-name"; exit 1 ;; esac
    [ -s "$ca" ] || { say "fail no-ca"; exit 1; }
    [ "$(id -u)" = 0 ] || { say "fail not-root"; exit 1; }
    dev=$(our_dev)
    if [ -z "$dev" ] || [ "$(top_dev self "$SYS")" != "$dev" ]; then
      dev=""
      rm -rf "$COPY"; mkdir -p "$COPY" || fail mkdir
      if [ -d "$APEX" ]; then cp "$APEX"/* "$COPY"/ || fail copy-apex; else cp "$SYS"/* "$COPY"/ || fail copy-system; fi
      mount -t tmpfs tmpfs "$SYS" || fail mount-tmpfs
      dev=$(top_dev self "$SYS")
      [ -n "$dev" ] || { umount "$SYS"; say "fail no-mount-id"; exit 1; }
      echo "$(boot_id) $name $dev" > "$MARK" && chmod 644 "$MARK"     # from here on, fail() takes it all back
      test_fail mount
      mv "$COPY"/* "$SYS"/ || fail restore
      cp "$ca" "$SYS/$name" || fail copy-ca
      chown root:root "$SYS" "$SYS"/*
      chmod 755 "$SYS"; chmod 644 "$SYS"/*
      chcon u:object_r:system_file:s0 "$SYS" "$SYS"/* 2>/dev/null
      rm -rf "$COPY"
    fi
    cmp -s "$ca" "$SYS/$name" || fail verify-system
    partial=0
    if [ -d "$APEX" ]; then
      [ "$(top_dev self "$APEX")" = "$dev" ] || mount --bind "$SYS" "$APEX" || fail bind-self
      test_fail bind
      for round in 1 2; do                  # once, then again for whatever did not take
        for p in $(namespaces); do
          [ "$(top_dev "$p" "$APEX")" = "$dev" ] && continue
          ( in_ns "$p" /system/bin/mount --bind "$SYS" "$APEX" ) >/dev/null 2>&1 &
        done
        wait
      done
      for z in $(zygotes); do                 # every zygote must have it, or new apps would not
        [ "$(top_dev "$z" "$APEX")" = "$dev" ] || fail "zygote-$z"
      done
      for p in $(namespaces); do              # a running app that still has the old store (exited ones do not count)
        [ -d "/proc/$p" ] || continue
        [ "$(top_dev "$p" "$APEX")" = "$dev" ] || partial=$((partial + 1))
      done
    fi
    rm -f "$ca"
    if [ "$partial" -gt 0 ]; then say "ok partial $partial"; else say ok; fi
    ;;
  remove)
    name="${2:-}"
    case "$name" in [0-9a-f]*.0) ;; *) say "fail bad-name"; exit 1 ;; esac
    dev=$(our_dev)
    [ -n "$dev" ] || { say absent; exit 0; }              # nothing of ours on this boot: never unmount someone else's
    undo "$dev"
    [ "$(top_dev self "$SYS")" = "$dev" ] && { say "fail still-mounted"; exit 1; }
    rm -f "$MARK"
    say removed
    ;;
  status)
    name="${2:-}"
    dev=$(our_dev)
    if [ "$(id -u)" != 0 ]; then   # no root (Google Play image): what the one-shot service recorded for THIS boot
      [ -n "$dev" ] && say present || say absent
      exit 0
    fi
    [ -n "$dev" ] || { say absent; exit 0; }
    if [ -d "$APEX" ]; then
      for z in $(zygotes); do [ "$(top_dev "$z" "$APEX")" = "$dev" ] || { say absent; exit 0; }; done
      say present
    else
      [ "$(top_dev self "$SYS")" = "$dev" ] && say present || say absent
    fi
    ;;
  *) say "fail usage"; exit 1 ;;
esac
