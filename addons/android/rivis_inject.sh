#!/system/bin/sh
# Runs on the emulator (in /data/local/tmp) after Magisk's own host_patch.sh. Adds the Rivis one-shot service and the
# CA to the patched ramdisk's overlay.d, using the magiskboot that host_patch.sh unpacked. Upstream Magisk files are not
# modified; everything Rivis adds is these four overlay entries.
#   rivis_inject.sh RAMDISK.magisk
set -e
cd /data/local/tmp
img="$1"
[ -s "$img" ] && [ -x ./magiskboot ] || exit 2
for f in rivis_ca.rc rivis_ca.sh rivis_ca.0 rivis_ca.name; do [ -s "$f" ] || exit 3; done
rm -f rivis.cpio rivis.img
./magiskboot decompress "$img" rivis.cpio
./magiskboot cpio rivis.cpio \
  "add 0644 overlay.d/rivis_ca.rc rivis_ca.rc" \
  "add 0750 overlay.d/sbin/rivis_ca.sh rivis_ca.sh" \
  "add 0644 overlay.d/sbin/rivis_ca.0 rivis_ca.0" \
  "add 0644 overlay.d/sbin/rivis_ca.name rivis_ca.name"
./magiskboot compress=gzip rivis.cpio rivis.img
[ -s rivis.img ] || exit 4
mv -f rivis.img "$img"
rm -f rivis.cpio
