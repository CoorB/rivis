#!/usr/bin/python3 -I
"""A fake `adb` for one emulator (emulator-5554), state in $FAKE_EMU (a directory):
  root            present = `adb root` works (Google APIs image); absent = a Google Play image
  cacerts/<h>.0   the user CA store (root path)
  user/<n>.pem    the Settings → Trusted credentials → User list, in order (Play path)
  screen          what Settings shows: list | detail:<n> | confirm:<n>
  proxy           the global http_proxy setting (":0" when absent)
  avd             the AVD name `emu avd name` answers (absent = it answers nothing, as right after a boot)
  api37           present = Android 17's Settings layout: two "mitmproxy" lines per list entry (organization + name) and
                  the dialog's buttons in the bottom 12% of the screen; opened: one line per certificate opened
  tmp/<name>      files pushed to /data/local/tmp (a root install copies them into cacerts/)
  system/<h>.0    the SYSTEM store tmpfs that rivis_system_ca.sh adds (gone after a "reboot": a new boot_id)
  boot_id         this boot's id (default "boot-1"); mark: what rivis_system_ca.sh recorded ("<boot id> <name>")
  system_fail     present = rivis_system_ca.sh inject fails
  log             every call
Only what `rivis android off` uses is implemented; anything else answers nothing, exit 0."""
import os
import re
import subprocess
import sys

D = os.environ["FAKE_EMU"]
args = sys.argv[1:]
with open(os.path.join(D, "log"), "a") as fh:
    fh.write(" ".join(args) + "\n")
if args[:2] == ["-s", "emulator-5554"]:
    args = args[2:]
cmd = " ".join(args)
W, H, ROW = 1080, 2400, 120


def read(name, default=""):
    try:
        return open(os.path.join(D, name)).read()
    except OSError:
        return default


def users():
    d = os.path.join(D, "user")
    return sorted(os.listdir(d)) if os.path.isdir(d) else []


def fingerprint(pem_path):
    out = subprocess.run(["openssl", "x509", "-in", pem_path, "-noout", "-fingerprint", "-sha256"],
                         capture_output=True, text=True).stdout
    return out.split("=", 1)[1].strip()


def node(text, y):
    return '<node text="%s" bounds="[0,%d][%d,%d]" />' % (text, y, W, y + ROW // 2)


def screen_xml():
    s = read("screen", "list").strip()
    if s == "list":
        rows = [node("User", 100)] + [node("mitmproxy", 300 + i * ROW) for i, _ in enumerate(users())]
        if os.path.exists(os.path.join(D, "api37")):
            rows = [node("User", 100)] + [node("mitmproxy", 300 + 2 * i * ROW + k * ROW // 2) for i, _ in enumerate(users()) for k in (0, 1)]
    elif s.startswith("detail:"):
        n = users()[int(s.split(":")[1])]
        low = 2161 if os.path.exists(os.path.join(D, "api37")) else 1800
        rows = [node("mitmproxy", 200), node(fingerprint(os.path.join(D, "user", n)), 400), node("Remove", low),
                node("OK", low + 200 if low == 1800 else low + ROW // 2 + 1)]
    else:
        rows = [node("Remove this certificate?", 600), node("OK", 2000)]
    return "<hierarchy>" + "".join(rows) + "</hierarchy>"


def tapped(y):
    for line in screen_xml().split("/>"):
        m = re.search(r'text="([^"]*)" bounds="\[0,(\d+)\]\[\d+,(\d+)\]"', line)
        if m and int(m.group(2)) <= y <= int(m.group(3)):
            return m.group(1), int(m.group(2))
    return None, None


def setscreen(v):
    open(os.path.join(D, "screen"), "w").write(v)


if cmd == "devices":
    print("List of devices attached\nemulator-5554\tdevice\n")
elif cmd == "emu avd name" and read("avd").strip():
    print(read("avd").strip() + "\r\nOK\r")
elif cmd in ("root", "wait-for-device") or cmd.startswith("emu "):
    pass
elif cmd == "shell id -u":
    print("0" if os.path.exists(os.path.join(D, "root")) else "2000")
elif cmd in ("shell getprop ro.kernel.qemu", "shell getprop ro.boot.qemu"):
    print("1")
elif cmd.startswith("shell settings get global http_proxy"):
    print(read("proxy", ":0").strip() or ":0")
elif cmd.startswith("shell settings put global http_proxy"):
    open(os.path.join(D, "proxy"), "w").write(args[-1])
elif args[0] == "push":
    dst = args[2]
    if dst.startswith("/data/local/tmp/"):
        os.makedirs(os.path.join(D, "tmp"), exist_ok=True)
        open(os.path.join(D, "tmp", os.path.basename(dst)), "w").write(open(args[1]).read())
elif cmd.startswith("shell mkdir -p /data/misc/user/0/cacerts-added && cp /data/local/tmp/"):
    name = re.search(r"cp /data/local/tmp/(\S+)", cmd).group(1)
    os.rename(os.path.join(D, "tmp", name), os.path.join(D, "cacerts", name))
elif cmd == "shell wm size":
    print("Physical size: %dx%d" % (W, H))
elif cmd.startswith("shell am start -W") and "TRUSTED_CREDENTIALS_USER" in cmd:
    setscreen("list")
    print("Status: ok")
elif cmd == "shell cat /sdcard/proxy-ui.xml":
    print(screen_xml())
elif cmd.startswith("shell input tap"):
    text, top = tapped(int(args[-1]))
    s = read("screen", "list").strip()
    if s == "list" and text == "mitmproxy":
        i = (top - 300) // (2 * ROW if os.path.exists(os.path.join(D, "api37")) else ROW)
        setscreen("detail:%d" % i)
        with open(os.path.join(D, "opened"), "a") as fh:
            fh.write("%d\n" % i)
    elif s.startswith("detail:") and text == "Remove":
        setscreen("confirm:" + s.split(":")[1])
    elif s.startswith("detail:") and text == "OK":
        setscreen("list")
    elif s.startswith("confirm:") and text == "OK":
        os.remove(os.path.join(D, "user", users()[int(s.split(":")[1])]))
        setscreen("list")
elif cmd.startswith("shell input keyevent KEYCODE_BACK"):
    setscreen("list")
elif cmd.startswith("shell cat /data/misc/user/0/cacerts-added/"):
    sys.stdout.write(read("cacerts/" + os.path.basename(args[-1])))
elif cmd.startswith("shell [ -e /data/misc/user/0/cacerts-added/") or cmd.startswith("shell [ ! -e "):
    f = re.search(r"cacerts-added/(\S+)", cmd).group(1)
    there = os.path.exists(os.path.join(D, "cacerts", f))
    sys.exit(0 if there != ("!" in cmd) else 1)
elif cmd == "shell getprop ro.build.type":
    print("userdebug" if os.path.exists(os.path.join(D, "root")) else "user")
elif cmd.startswith("shell sh /data/local/tmp/rivis_system_ca.sh "):
    act, rest = args[3], args[4:]
    boot = read("boot_id", "boot-1").strip()
    sysd = os.path.join(D, "system")
    if not os.path.exists(os.path.join(D, "root")):
        if act == "status":
            print("rivis-system-ca: present" if read("mark").strip() == "%s %s" % (boot, rest[0]) else "rivis-system-ca: absent")
        else:
            print("rivis-system-ca: fail not-root")
    elif act == "inject":
        if os.path.exists(os.path.join(D, "system_fail")):
            print("rivis-system-ca: fail zygote-123")
        else:
            os.makedirs(sysd, exist_ok=True)
            open(os.path.join(sysd, rest[1]), "w").write(read("tmp/" + os.path.basename(rest[0])))
            open(os.path.join(D, "mark"), "w").write("%s %s" % (boot, rest[1]))
            print("rivis-system-ca: ok")
    elif act == "remove":
        if os.path.exists(os.path.join(sysd, rest[0])):
            os.remove(os.path.join(sysd, rest[0]))
            print("rivis-system-ca: removed")
        else:
            print("rivis-system-ca: absent")
    elif act == "status":
        print("rivis-system-ca: present" if os.path.exists(os.path.join(sysd, rest[0])) else "rivis-system-ca: absent")
elif cmd.startswith("shell cat /data/local/tmp/rivis-system-ca.boot"):
    print(read("mark").strip())
    print(read("boot_id", "boot-1").strip())
elif cmd.startswith("shell cat /system/etc/security/cacerts/"):
    sys.stdout.write(read("system/" + os.path.basename(args[-1])))
elif cmd.startswith("shell rm -f"):
    for a in re.findall(r"/data/misc/user/0/cacerts-added/(\S+)", cmd):
        try:
            os.remove(os.path.join(D, "cacerts", a))
        except OSError:
            pass
sys.exit(0)
