"""Devices tab (Proxyman's "Certificate → iOS Simulator / Android Emulator" menu, in the panel).

Status is read-only and cheap enough to poll: booted simulators (CA trust read straight from each simulator's trust
store) and running emulators (proxy setting, image type, and whether Rivis set them up: the CLI records
"<avd>\\t<CA sha256>" in $STATE_ROOT/android-ca after a verified install). Setup runs the CLI's own commands
(`rivis ios on`, `rivis android on`) as one background job at a time, so the UI and the terminal share one tested path.
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(os.path.dirname(HERE), "rivis")
UDID = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
SERIAL = re.compile(r"^emulator-[0-9]{1,5}$")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
QUICK = 8          # seconds for any one status command
JOB_LIMIT = 900    # a setup job (Magisk path: ~3.5 min) is killed after 15 minutes
MAX_LINES = 400


def _run(argv, timeout=QUICK):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout.replace("\r", "")
    except (OSError, subprocess.TimeoutExpired):
        return None, ""


def ca_sha256(pem_path):
    """SHA-256 of the CA's DER bytes, upper-case hex (what the trust stores and the CLI's record hold)."""
    try:
        text = open(pem_path).read()
    except OSError:
        return ""
    m = re.search(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", text, re.S)
    if not m:
        return ""
    return hashlib.sha256(base64.b64decode("".join(m.group(1).split()))).hexdigest().upper()


def adb_path():
    for cand in (os.environ.get("ADB"), os.path.join(os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME") or "",
                                                   "platform-tools", "adb"),
                 os.path.expanduser("~/Library/Android/sdk/platform-tools/adb"), "/usr/local/bin/adb", "/opt/homebrew/bin/adb"):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def _sim_trusted(udid, want):
    # the sqlite3 command, not the module: mitmproxy's bundled Python has no sqlite3 (the CLI uses the same tool)
    if not re.fullmatch(r"[0-9A-F]{64}", want or ""):
        return False
    base = os.path.expanduser("~/Library/Developer/CoreSimulator/Devices/%s/data/private/var/protected/trustd" % udid)
    for root, _dirs, names in os.walk(base):
        for name in names:
            if name.startswith("TrustStore.sqlite") and "-" not in name:
                rc, out = _run(["/usr/bin/sqlite3", "-readonly", os.path.join(root, name),
                                "select count(*) from tsettings where hex(sha256)='%s';" % want])
                if rc == 0 and out.strip() not in ("", "0"):
                    return True
    return False


def ios_devices(want):
    rc, out = _run(["xcrun", "simctl", "list", "devices", "booted", "-j"])
    if rc != 0:
        return None                                   # no Xcode tools: the tab says so
    try:
        runtimes = json.loads(out).get("devices", {})
    except ValueError:
        return []
    devices = []
    for runtime, items in runtimes.items():
        os_name = runtime.rsplit(".", 1)[-1].replace("iOS-", "iOS ").replace("-", ".")
        for d in items:
            if d.get("state") == "Booted" and UDID.match(d.get("udid", "")):
                devices.append({"id": d["udid"], "name": d.get("name", "Simulator"), "os": os_name,
                                "ready": bool(want) and _sim_trusted(d["udid"], want)})
    return sorted(devices, key=lambda d: d["name"])


def _android_records(state_root):
    rec = {}
    try:
        for line in open(os.path.join(state_root, "android-ca")):
            parts = line.rstrip("\n").split("\t")
            if len(parts) == 2:
                rec[parts[0]] = parts[1]
    except OSError:
        pass
    return rec


def android_devices(adb, want, state_root, proxy_port):
    if not adb:
        return None
    rc, out = _run([adb, "devices"])
    if rc != 0:
        return []
    records = _android_records(state_root)
    devices = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2 or parts[1] != "device" or not SERIAL.match(parts[0]):
            continue
        s = parts[0]
        _, avd = _run([adb, "-s", s, "emu", "avd", "name"])
        avd = next((x.strip() for x in avd.splitlines() if x.strip() and x.strip() != "OK"), s)
        _, proxy = _run([adb, "-s", s, "shell", "settings", "get", "global", "http_proxy"])
        _, btype = _run([adb, "-s", s, "shell", "getprop", "ro.build.type"])
        _, release = _run([adb, "-s", s, "shell", "getprop", "ro.build.version.release"])
        proxy = proxy.strip()
        ca_ok = bool(want) and records.get(avd) == want
        devices.append({"id": s, "name": avd, "os": "Android %s" % release.strip(),
                        "play": btype.strip() == "user",       # Google Play images are 'user' builds: no adb root
                        "proxy": proxy, "proxy_ok": proxy == "10.0.2.2:%s" % proxy_port,
                        "ca_ok": ca_ok, "ready": ca_ok and proxy == "10.0.2.2:%s" % proxy_port})
    return devices


class Jobs:
    """One setup job at a time; its output is kept for the tab to show."""

    def __init__(self):
        self.lock = threading.Lock()
        self.job = None
        self.seq = 0

    def summary(self):
        with self.lock:
            if not self.job:
                return None
            j = self.job
            return {"id": j["id"], "label": j["label"], "running": j["rc"] is None, "rc": j["rc"],
                    "lines": list(j["lines"][-60:]), "started": j["started"], "ended": j["ended"]}

    def start(self, argv, label):
        with self.lock:
            if self.job and self.job["rc"] is None:
                raise RuntimeError("a device setup is already running — wait for it to finish")
            self.seq += 1
            job = {"id": self.seq, "label": label, "lines": [], "rc": None, "started": time.time(), "ended": None}
            self.job = job
        threading.Thread(target=self._run, args=(job, argv), daemon=True).start()
        return job["id"]

    def _run(self, job, argv):
        try:
            p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                 text=True, bufsize=1, start_new_session=True)
        except OSError as e:
            job["lines"].append("could not start: %s" % e)
            job["rc"], job["ended"] = 127, time.time()
            return
        timer = threading.Timer(JOB_LIMIT, p.kill)
        timer.start()
        try:
            for line in p.stdout:
                line = ANSI.sub("", line.rstrip("\n"))
                if line.strip():
                    job["lines"].append(line[:400])
                    del job["lines"][:-MAX_LINES]
            p.wait()
        finally:
            timer.cancel()
        job["rc"], job["ended"] = p.returncode, time.time()


def setup_argv(platform, target, consent=False):
    """CLI command for one device or all of them. target: a UDID / emulator serial, or 'all'."""
    if platform == "ios":
        if target == "all":
            return [CLI, "ios", "on", "--all"]
        if not UDID.match(target or ""):
            raise ValueError("not a simulator UDID")
        return [CLI, "ios", "on", "--udid", target]
    if platform == "android":
        argv = [CLI, "android", "on"] + (["--all"] if target == "all" else ["-s", target])
        if target != "all" and not SERIAL.match(target or ""):
            raise ValueError("not an emulator serial")
        return argv + (["--yes"] if consent else [])
    raise ValueError("platform must be ios or android")
