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
#   rivis_system_ca.sh inject CA_FILE NAME     (NAME = <subject_hash_old>.0)    → last line "rivis-system-ca: ok"
#   rivis_system_ca.sh remove NAME             only when /system/etc/security/cacerts is OUR tmpfs (holds NAME)
#   rivis_system_ca.sh status NAME             → "rivis-system-ca: present" or "rivis-system-ca: absent"
set -u
SYS=/system/etc/security/cacerts
APEX=/apex/com.android.conscrypt/cacerts
COPY=/data/local/tmp/rivis-ca-copy
MARK=/data/local/tmp/rivis-system-ca.boot
action="${1:-}"

say() { echo "rivis-system-ca: $*"; }
fail() { say "fail $*"; exit 1; }
# the mount namespaces that need the bind: zygote(s), then every process a zygote started (the apps)
namespaces() {
  for z in $(pidof zygote zygote64 2>/dev/null); do
    echo "$z"
    ps -o PID= -P "$z" 2>/dev/null
  done
}
in_ns() { p="$1"; shift; nsenter --mount="/proc/$p/ns/mnt" -- "$@"; }
sys_is_ours() { grep -q " $SYS .* - tmpfs " /proc/self/mountinfo 2>/dev/null && [ -f "$SYS/$1" ]; }

case "$action" in
  inject)
    ca="${2:-}"; name="${3:-}"
    case "$name" in [0-9a-f]*.0) ;; *) fail bad-name ;; esac
    [ -s "$ca" ] || fail no-ca
    [ "$(id -u)" = 0 ] || fail not-root
    if ! sys_is_ours "$name"; then
      rm -rf "$COPY"; mkdir -p "$COPY" || fail mkdir
      if [ -d "$APEX" ]; then cp "$APEX"/* "$COPY"/ || fail copy-apex; else cp "$SYS"/* "$COPY"/ || fail copy-system; fi
      mount -t tmpfs tmpfs "$SYS" || fail mount-tmpfs
      mv "$COPY"/* "$SYS"/ || fail restore
      cp "$ca" "$SYS/$name" || fail copy-ca
      chown root:root "$SYS" "$SYS"/*
      chmod 755 "$SYS"; chmod 644 "$SYS"/*
      chcon u:object_r:system_file:s0 "$SYS" "$SYS"/* 2>/dev/null
      rm -rf "$COPY"
    fi
    cmp -s "$ca" "$SYS/$name" || fail verify-system
    if [ -d "$APEX" ]; then
      [ -f "$APEX/$name" ] || mount --bind "$SYS" "$APEX" || fail bind-self
      for p in $(namespaces); do
        ( in_ns "$p" /system/bin/sh -c "[ -f $APEX/$name ] || mount --bind $SYS $APEX" ) >/dev/null 2>&1 &
      done
      wait
      for z in $(pidof zygote zygote64 2>/dev/null); do
        in_ns "$z" /system/bin/ls "$APEX/$name" >/dev/null 2>&1 || fail "zygote-$z"
      done
    fi
    rm -f "$ca"
    # for a status check without root (Google Play images): this boot has the CA in the system store
    echo "$(cat /proc/sys/kernel/random/boot_id) $name" > "$MARK" && chmod 644 "$MARK"
    say ok
    ;;
  remove)
    name="${2:-}"
    case "$name" in [0-9a-f]*.0) ;; *) fail bad-name ;; esac
    sys_is_ours "$name" || { say absent; exit 0; }
    if [ -d "$APEX" ]; then
      for p in $(namespaces); do
        ( in_ns "$p" /system/bin/sh -c "[ -f $APEX/$name ] && umount $APEX" ) >/dev/null 2>&1 &
      done
      wait
      [ -f "$APEX/$name" ] && umount "$APEX"
    fi
    umount "$SYS" || fail umount-system
    [ -f "$SYS/$name" ] && fail still-present
    rm -f "$MARK"
    say removed
    ;;
  status)
    name="${2:-}"
    if [ "$(id -u)" != 0 ]; then   # no root (Google Play image): what the one-shot service recorded for THIS boot
      [ "$(cat "$MARK" 2>/dev/null)" = "$(cat /proc/sys/kernel/random/boot_id) $name" ] && say present || say absent
      exit 0
    fi
    if [ -d "$APEX" ]; then
      z=$(pidof zygote64 zygote 2>/dev/null | awk '{print $1}')
      [ -n "$z" ] && in_ns "$z" /system/bin/ls "$APEX/$name" >/dev/null 2>&1 && { say present; exit 0; }
    elif [ -f "$SYS/$name" ]; then say present; exit 0; fi
    say absent
    ;;
  *) fail usage ;;
esac
