#!/system/bin/sh
# Runs on the emulator as root, once, from rivis_ca.rc. Copies the CA that sits next to this script into the user CA
# store (what debug builds trust) and leaves a status line that adb shell can read: "ok <file>" or "fail <reason>".
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
done_with "ok $name"
