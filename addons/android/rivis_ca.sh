#!/system/bin/sh
# Runs on the emulator as root, once, from rivis_ca.rc. Copies the CA that sits next to this script into the user CA
# store (what debug builds trust) and leaves a status line that adb shell can read: "ok <file>" or "fail <reason>";
# "ok <file> system" when it was also asked to add it to the system store (rivis_system_ca.sh), for this boot.
here=$(dirname "$0")
status=/data/local/tmp/rivis-ca.status
store=/data/misc/user/0/cacerts-added
name=$(cat "$here/rivis_ca.name" 2>/dev/null)

done_with() { echo "$1" > "$status"; chown shell:shell "$status"; chmod 644 "$status"; exit 0; }

case "$name" in [0-9a-f]*.0) ;; *) done_with "fail bad-name" ;; esac
[ -s "$here/rivis_ca.0" ] || done_with "fail no-ca"
mkdir -p "$store" && chown system:system "$store" && chmod 755 "$store" || done_with "fail mkdir"
cp "$here/rivis_ca.0" "$store/$name" && chown system:system "$store/$name" && chmod 644 "$store/$name" \
  || done_with "fail copy"
restorecon -R "$store" 2>/dev/null
cmp -s "$here/rivis_ca.0" "$store/$name" || done_with "fail verify"
# `android on --system` asked for the system store too (apps that trust only system certificates)
if [ -f /data/local/tmp/rivis-ca.want-system ]; then
  rm -f /data/local/tmp/rivis-ca.want-system
  cp "$here/rivis_ca.0" /data/local/tmp/rivis-sys-ca.0
  if sh "$here/rivis_system_ca.sh" inject /data/local/tmp/rivis-sys-ca.0 "$name" 2>&1 | grep -q "^rivis-system-ca: ok$"; then
    done_with "ok $name system"
  fi
  done_with "ok $name system-failed"
fi
done_with "ok $name"
