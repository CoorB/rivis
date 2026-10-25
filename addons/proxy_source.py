"""
proxy_source — which device and which app sent each call (Proxyman's per-app / per-device view).

mitmproxy does not record the sending process on flow.client_conn, so this add-on attributes every client connection
once, off the event loop, and stamps the result on each of that connection's flows:

  flow.metadata["rivis_source"]      {"kind", "device", "app", "id", "pid", "key", "label"}   (kept by sessions)
  flow.metadata["rivis_source_key"]  "<kind>|<device>|<app id>"   one line, so the list filter can select it with
                                     ~meta '^rivis_source_key: ios\\|iPhone 17\\|'  (one device) or with  ...$  (one app)

Where the process comes from:
  - local mode (iOS Simulator, --mode local:CoreSimulator): the redirector hands mitmproxy a mitmproxy_rs Stream that
    knows its pid, but mitmproxy/proxy/mode_servers.py does not copy it onto the Client. A small wrap of
    LocalRedirectorInstance.handle_stream puts it in a context variable for the duration of that connection's handler
    task (client_connected runs inside it). If a mitmproxy upgrade renames any of this, the wrap is skipped and those
    calls read "unknown"; capture itself is never touched.
  - regular mode (Android emulators via 10.0.2.2, `rivis browser`, Mac tools): the client's (ip, port) is on loopback,
    so `lsof` names the process holding the other end of that socket.
  - a phone or tablet on the Wi-Fi (`rivis start --lan`): its address, named as it was allowed (lan-devices.json)
Then the pid is classified from its executable path / argv / environment:
  qemu-system-* -avd NAME           → android, device = the AVD (the app inside it: best effort over adb, see below)
  …/CoreSimulator/Devices/<UDID>/…/X.app/X   → ios, device = the simulator's name, app = the bundle's display name
  a simulator system process (Safari, WebKit networking) → ios, device from SIMULATOR_UDID in its environment
  a browser started by `rivis browser` (its --user-data-dir under ~/.rivis/browser) → browser
  anything else on this Mac         → mac, app = the enclosing .app's name or the executable's
Nothing here may raise into mitmproxy: every failure ends in kind "unknown".
"""
import asyncio
import contextvars
import ctypes
import ctypes.util
import inspect
import json
import os
import plistlib
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor

try:
    from mitmproxy import ctx
except ImportError:          # unit tests import the parsing helpers with the system Python, without mitmproxy
    ctx = None

HERE = os.path.dirname(os.path.abspath(__file__))
KINDS = ("ios", "android", "phone", "browser", "mac", "unknown")
KIND_LABEL = {"ios": "iOS Simulator", "android": "Android emulator", "phone": "Phone or tablet (Wi-Fi)",
              "browser": "Web browser", "mac": "This Mac", "unknown": "Unknown"}
SIM_APP = re.compile(r"/CoreSimulator/Devices/([0-9A-Fa-f-]{36})/data/Containers/Bundle/Application/[0-9A-Fa-f-]{36}/([^/]+\.app)/")
SIM_RUNTIME = re.compile(r"/(?:Library/Developer/CoreSimulator/Volumes/|Platforms/iPhoneSimulator\.platform/|"
                         r"Library/Developer/CoreSimulator/Profiles/Runtimes/)")
UDID = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
SAFE_TEXT = re.compile(r"[\x00-\x1f\x7f|]")          # no control characters or the key separator in a name
LOOPBACK = ("127.0.0.1", "::1", "::ffff:127.0.0.1")
# Simulator system services that do the networking for an app. Named for what a tester sees, not the XPC name.
SIM_SERVICES = {"com.apple.WebKit.Networking": "Web content (Safari / web views)", "nsurlsessiond": "Background downloads",
                "com.apple.mobilesafari": "Safari"}

# The context variable lives on mitmproxy's module, not on this one: a hot reload re-runs this file, and the wrap
# installed by the first load (kept, see install_local_hook) must keep feeding the variable the new copy reads.
_STREAM = contextvars.ContextVar("rivis_stream_process", default=None)
try:
    from mitmproxy.proxy import mode_servers as _ms
    _STREAM = getattr(_ms, "_rivis_stream_process", None) or _STREAM
    _ms._rivis_stream_process = _STREAM
except ImportError:
    pass


class _NoLan:
    @staticmethod
    def get(ip):
        return None


def _lan_devices():
    try:
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        import proxy_lan
        return proxy_lan.Devices()
    except Exception:          # never take attribution down over the phone list
        return _NoLan()


def clean(text, limit=80):
    return SAFE_TEXT.sub(" ", str(text or "")).strip()[:limit]


def make_source(kind, device="", app="", ident="", pid=None):
    kind = kind if kind in KINDS else "unknown"
    device, app, ident = clean(device), clean(app), clean(ident, 160)
    label = app or device or KIND_LABEL[kind]
    return {"kind": kind, "device": device, "app": app, "id": ident, "pid": pid if isinstance(pid, int) else None,
            "key": "%s|%s|%s" % (kind, device, ident or app), "label": label}


UNKNOWN = make_source("unknown")


# ── local mode: carry the redirector's pid from the Stream to client_connected ────────────────────────────────────
def install_local_hook():
    """Wrap LocalRedirectorInstance.handle_stream once per process (a hot reload re-runs this module: the marker keeps
    it from wrapping the wrapper). Returns True when the hook is active."""
    try:
        from mitmproxy.proxy import mode_servers
        cls = mode_servers.LocalRedirectorInstance
        original = cls.handle_stream
    except (ImportError, AttributeError):
        return False
    if getattr(original, "_rivis_source", False):
        return True

    async def handle_stream(self, *args, **kwargs):
        token = None
        try:
            reader = args[0] if args else kwargs.get("reader", kwargs.get("stream"))
            pid = reader.get_extra_info("pid", None)
            if isinstance(pid, int) and pid > 0:
                token = _STREAM.set((pid, reader.get_extra_info("process_name", None)))
        except Exception:            # an upgraded Stream without these keys: attribution reads unknown, capture goes on
            token = None
        try:
            result = original(self, *args, **kwargs)
            return await result if inspect.isawaitable(result) else result
        finally:
            if token is not None:
                _STREAM.reset(token)

    handle_stream._rivis_source = True
    handle_stream._rivis_original = original
    cls.handle_stream = handle_stream
    return True


# ── process facts: path, argv, environment (libproc / sysctl; same-user processes only, which all ours are) ──────
_LIBC = None


def install_har_hook():
    """R8C-04: a HAR that Rivis exported carries each call's source as "_rivisSource" (a custom HAR field), but
    mitmproxy's own HAR reader (File → Open) drops unknown fields. Wrap its entry → flow function so the source comes
    back. Wrapped where the function is defined and wherever it was imported by name; a mitmproxy that renames it
    just opens HARs without sources, as before."""
    try:
        from mitmproxy.io import har
    except Exception:
        return False
    original = getattr(har, "request_to_flow", None)
    if original is None or getattr(original, "_rivis_source", False):
        return original is not None

    def request_to_flow(entry, *args, **kwargs):
        flow = original(entry, *args, **kwargs)
        try:
            src = entry.get("_rivisSource") if isinstance(entry, dict) else None
            if isinstance(src, dict) and src.get("kind") in KINDS and flow is not None:
                stamp(flow, make_source(src["kind"], src.get("device", ""), src.get("app", ""), src.get("id", "")))
        except Exception:
            pass
        return flow
    request_to_flow._rivis_source = True
    for name, module in list(sys.modules.items()):
        if (name == "mitmproxy" or name.startswith("mitmproxy.")) and getattr(module, "request_to_flow", None) is original:
            setattr(module, "request_to_flow", request_to_flow)
    return True


def _libc():
    global _LIBC
    if _LIBC is None:
        try:
            _LIBC = ctypes.CDLL(ctypes.util.find_library("c") or "libc.dylib", use_errno=True)
        except OSError:
            _LIBC = False
    return _LIBC or None


def proc_path(pid):
    libc = _libc()
    if libc is not None and hasattr(libc, "proc_pidpath"):
        buf = ctypes.create_string_buffer(4096)
        n = libc.proc_pidpath(ctypes.c_int(pid), buf, ctypes.c_uint32(4096))
        if n > 0:
            return buf.raw[:n].decode("utf-8", "replace")
    out = _run(["/bin/ps", "-o", "comm=", "-p", str(pid)])
    return out.strip() if out else ""


class SocketScan:
    """In-process check "does pid hold the TCP socket local_port → remote_port?" through libproc (microseconds, no
    process to start). R8C-02: an lsof per new connection cost ~35 ms. The kernel struct's layout is not hard-coded: it
    is calibrated at start on a loopback pair of our own with known ports. Calibration failing → unavailable (lsof)."""
    LISTFDS, FDTYPE_SOCKET, FDSOCKETINFO, BUF = 1, 2, 3, 2048

    def __init__(self):
        self.offset = None
        try:
            libc = _libc()
            if libc is not None and hasattr(libc, "proc_pidfdinfo") and hasattr(libc, "proc_pidinfo"):
                self.libc = libc
                self.offset = self._calibrate()
        except Exception:
            self.offset = None

    def _socket_fds(self, pid):
        n = self.libc.proc_pidinfo(ctypes.c_int(pid), self.LISTFDS, ctypes.c_uint64(0), None, 0)
        if n <= 0:
            return []
        buf = ctypes.create_string_buffer(n + 512)
        n = self.libc.proc_pidinfo(ctypes.c_int(pid), self.LISTFDS, ctypes.c_uint64(0), buf, len(buf))
        if n <= 0:
            return []
        return [fd for fd, kind in struct.iter_unpack("iI", buf.raw[:n - n % 8]) if kind == self.FDTYPE_SOCKET]

    def _info(self, pid, fd):
        buf = ctypes.create_string_buffer(self.BUF)
        n = self.libc.proc_pidfdinfo(ctypes.c_int(pid), ctypes.c_int(fd), self.FDSOCKETINFO, buf, self.BUF)
        return buf.raw[:n] if n > 0 else b""

    def _calibrate(self):
        found = None
        for _ in range(2):                                   # two pairs with different ports must agree
            srv = socket.socket()
            try:
                srv.bind(("127.0.0.1", 0))
                srv.listen(1)
                c = socket.create_connection(srv.getsockname(), 2)
                a, _ = srv.accept()
                try:
                    raw = self._info(os.getpid(), c.fileno())
                    want = (socket.htons(c.getpeername()[1]), socket.htons(c.getsockname()[1]))
                    offs = {i for i in range(0, len(raw) - 8, 4) if struct.unpack_from("<ii", raw, i) == want}
                finally:
                    a.close()
                    c.close()
            finally:
                srv.close()
            found = offs if found is None else found & offs
        return min(found) if found else None

    def holds(self, pid, local_port, remote_port):
        if self.offset is None:
            return False
        want, off = (socket.htons(remote_port), socket.htons(local_port)), self.offset
        for fd in self._socket_fds(pid):
            raw = self._info(pid, fd)
            if len(raw) >= off + 8 and struct.unpack_from("<ii", raw, off) == want:
                return True
        return False


def parse_procargs(raw):
    """KERN_PROCARGS2 → (argv, env). Layout: int argc, exec path, NUL padding, argc strings, then env strings."""
    if not raw or len(raw) < 4:
        return [], {}
    argc = struct.unpack_from("i", raw)[0]
    parts = raw[4:].split(b"\0")
    i = 1                                    # parts[0] is the exec path
    while i < len(parts) and parts[i] == b"":
        i += 1
    argv = [p.decode("utf-8", "replace") for p in parts[i:i + argc]]
    env = {}
    for p in parts[i + argc:]:
        if not p:
            continue
        k, sep, v = p.decode("utf-8", "replace").partition("=")
        if sep and k not in env:
            env[k] = v
    return argv, env


def proc_args(pid):
    libc = _libc()
    if libc is None or not hasattr(libc, "sysctl"):
        return [], {}
    mib = (ctypes.c_int * 3)(1, 49, pid)        # CTL_KERN, KERN_PROCARGS2
    size = ctypes.c_size_t(0)
    if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0 or not size.value:
        return [], {}
    buf = ctypes.create_string_buffer(size.value)
    if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0) != 0:
        return [], {}
    return parse_procargs(buf.raw[:size.value])


def responsible_pid(pid):
    """The app an XPC service works for (Safari for its WebKit networking process). Private but long-stable libSystem
    call that Activity Monitor uses; absent → the service is named for itself."""
    libc = _libc()
    fn = getattr(libc, "responsibility_get_pid_responsible_for_pid", None) if libc is not None else None
    if fn is None:
        return None
    try:
        r = fn(ctypes.c_int(pid))
    except Exception:
        return None
    return r if isinstance(r, int) and r > 0 and r != pid else None


def _run(argv, timeout=4):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return p.stdout if p.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def lsof_owner(ip, port, own_pid, runner=_run):
    """The process on the other end of our client socket (ip:port is the client's address). lsof lists both ends of
    the loopback pair; ours is skipped. Output fields: p<pid> then c<command>."""
    lsof = "/usr/sbin/lsof" if os.path.exists("/usr/sbin/lsof") else shutil.which("lsof")
    if not lsof:
        return None
    host = "[%s]" % ip if ":" in ip else ip
    out = runner([lsof, "-nP", "-a", "-iTCP@%s:%d" % (host, port), "-sTCP:ESTABLISHED", "-Fpc"])
    for line in (out or "").splitlines():
        if line.startswith("p") and line[1:].isdigit() and int(line[1:]) != own_pid:
            return int(line[1:])
    return None


def lsof_table(proxy_port, own_pid, runner=_run):
    """Every loopback connection to the proxy port in ONE lsof run: {client port: pid}. R8C-01/02: one lsof per
    connection (~35 ms each, two at a time) capped attribution near 55 new connections/s and lost bursts; one
    snapshot answers every connection that existed when it was taken. Output fields: p<pid>, n<local>-><remote>."""
    lsof = "/usr/sbin/lsof" if os.path.exists("/usr/sbin/lsof") else shutil.which("lsof")
    if not lsof:
        return None
    out = runner([lsof, "-nP", "-a", "-iTCP:%d" % proxy_port, "-sTCP:ESTABLISHED", "-Fpn"])
    table, pid = {}, None
    for line in (out or "").splitlines():
        if line.startswith("p") and line[1:].isdigit():
            pid = int(line[1:])
        elif line.startswith("n") and "->" in line and pid is not None and pid != own_pid:
            local, remote = line[1:].split("->", 1)
            try:
                lport, rport = int(local.rsplit(":", 1)[1]), int(remote.rsplit(":", 1)[1])
            except (ValueError, IndexError):
                continue
            if rport == proxy_port:          # the client's end: its local port is the one mitmproxy sees as peer
                table[lport] = pid
    return table


def bundle_info(app_dir):
    """(display name, bundle id) from <X.app>/Info.plist; the folder name when unreadable."""
    try:
        with open(os.path.join(app_dir, "Info.plist"), "rb") as fh:
            info = plistlib.load(fh)
        name = info.get("CFBundleDisplayName") or info.get("CFBundleName") or ""
        return clean(name) or os.path.basename(app_dir)[:-4], clean(info.get("CFBundleIdentifier") or "", 160)
    except (OSError, ValueError, plistlib.InvalidFileException, AttributeError):
        return os.path.basename(app_dir)[:-4], ""


def enclosing_app(path):
    """The .app an executable belongs to: its own bundle (Python.app inside Xcode is Python), except for helper bundles,
    which belong to the outermost app (Google Chrome Helper.app → Google Chrome)."""
    apps = [m.end() for m in re.finditer(r"/[^/]+\.app(?=/|$)", path or "")]
    if not apps:
        return ""
    inner = path[:apps[-1]]
    return path[:apps[0]] if " Helper" in os.path.basename(inner) else inner


def avd_from_argv(argv):
    for i, a in enumerate(argv):
        if a == "-avd" and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith("@") and len(a) > 1 and i > 0 and "qemu" not in a:
            return a[1:]
    return ""


def classify(pid, path, argv, env, sim_names, browser_root=""):
    """Pure: pid + its executable path / argv / env → a source. sim_names maps simulator UDID → name."""
    base = os.path.basename(path or "")
    if base.startswith("qemu-system") or base == "emulator" or "/emulator/qemu/" in (path or ""):
        return make_source("android", avd_from_argv(argv) or "Android emulator", pid=pid)
    if base == "netsimd":       # emulator 36+: one shared network daemon for every emulator; Attributor picks the AVD
        return make_source("android", "", pid=pid)
    m = SIM_APP.search(path or "")
    if m:
        udid = m.group(1).upper()
        app_dir = path[:m.end() - 1]
        name, ident = bundle_info(app_dir)
        return make_source("ios", sim_names.get(udid, udid), name, ident or name, pid)
    udid = (env.get("SIMULATOR_UDID") or "").upper()
    if (udid and UDID.match(udid)) or SIM_RUNTIME.search(path or ""):
        app_dir = enclosing_app(path)
        if base in SIM_SERVICES or os.path.basename(app_dir)[:-4] in ("MobileSafari",):
            name = SIM_SERVICES.get(base) or "Safari"
            ident = base if base in SIM_SERVICES else "com.apple.mobilesafari"
        elif app_dir:
            name, ident = bundle_info(app_dir)
        else:
            name, ident = base, base
        return make_source("ios", sim_names.get(udid, udid or "iOS Simulator"), name, ident or name, pid)
    if browser_root and any(a.startswith("--user-data-dir=" + browser_root) for a in argv):
        app_dir = enclosing_app(path)
        return make_source("browser", "Rivis browser", bundle_info(app_dir)[0] if app_dir else base, pid=pid)
    app_dir = enclosing_app(path)
    if app_dir:
        name, ident = bundle_info(app_dir)
        return make_source("mac", "This Mac", name, ident or name, pid)
    if base:
        return make_source("mac", "This Mac", base, base, pid)
    return dict(UNKNOWN, pid=pid)


# ── Android: which app inside the emulator (best effort) ───────────────────────────────────────────────────────────
def guest_uids(proc_net, proxy_port):
    """uids of guest sockets talking to the host proxy (10.0.2.2:<port>) in /proc/net/tcp{,6} text. The emulator's
    NAT hides which guest socket became which host connection, so this is only conclusive when one uid is talking."""
    want4 = "0202000A:%04X" % proxy_port
    want6 = "0000000000000000FFFF00000202000A:%04X" % proxy_port
    uids = set()
    for line in (proc_net or "").splitlines():
        f = line.split()
        if len(f) > 7 and f[2].upper() in (want4, want6) and f[3] in ("01", "02"):   # ESTABLISHED / SYN_SENT
            uids.add(f[7])
    return uids


def packages_by_uid(listing):
    out = {}
    for line in (listing or "").splitlines():       # package:com.example uid:10123
        m = re.match(r"package:(\S+)\s+uid:(\d+)", line.strip())
        if m:
            out.setdefault(m.group(2), []).append(m.group(1))
    return out


class Attributor:
    """Thread-safe resolver with small caches (the expensive steps: lsof, simctl, adb)."""

    def __init__(self, runner=_run):
        self.run = runner
        self.own_pid = os.getpid()
        self._lock = threading.Lock()
        self._pid_cache = {}          # pid → (expires, path, source)
        self._sims = (0.0, {})
        self._adb = (0.0, {})         # AVD → serial
        self._pkgs = {}               # serial → (expires, uid → [packages])
        self.browser_root = os.path.join(os.path.expanduser("~"), ".rivis", "browser")
        self.lan = _lan_devices()         # phones allowed with `--lan` (read only when the file changes)
        self._snap_lock = threading.Lock()
        self._snap = {}               # proxy port → (monotonic time the snapshot STARTED, {client port: pid} or None)
        self.scan = SocketScan() if sys.platform == "darwin" else None
        self._recent = {}             # pid → last time it was a client (checked first, in-process)

    def loopback_owner(self, ip, port, proxy_port, since):
        """pid of the client on ip:port, from a snapshot started after `since` (the connection's start). Callers that
        arrive while a snapshot runs wait for it and share it, so a burst costs one lsof, not one per connection."""
        if not proxy_port:
            return lsof_owner(ip, port, self.own_pid, self.run)
        if self.scan is not None and self.scan.offset is not None:
            with self._lock:
                recent = sorted(self._recent, key=self._recent.get, reverse=True)[:32]
            for pid in recent:                       # nearly always: an app that already talked to us (µs, no lsof)
                try:
                    if self.scan.holds(pid, port, proxy_port):
                        self._seen(pid)
                        return pid
                except Exception:
                    break
        with self._snap_lock:
            started, table = self._snap.get(proxy_port, (-1.0, {}))
            if started < since:
                started = time.monotonic()
                table = lsof_table(proxy_port, self.own_pid, self.run)
                self._snap[proxy_port] = (started, table)
        if table is None:                    # no lsof at all
            return None
        pid = table.get(port)
        if pid:
            self._seen(pid)
        return pid

    def _seen(self, pid):
        with self._lock:
            self._recent[pid] = time.monotonic()
            if len(self._recent) > 64:
                for old in sorted(self._recent, key=self._recent.get)[:32]:
                    del self._recent[old]

    def sim_names(self):
        at, names = self._sims
        if time.time() - at < 30:
            return names
        out = self.run(["/usr/bin/xcrun", "simctl", "list", "-j", "devices"], timeout=8)
        try:
            data = json.loads(out)["devices"]
            names = {d["udid"].upper(): d["name"] for v in data.values() for d in v if d.get("udid") and d.get("name")}
        except (ValueError, KeyError, TypeError, AttributeError):
            pass
        self._sims = (time.time(), names)
        return names

    def by_pid(self, pid):
        path = proc_path(pid)
        with self._lock:
            hit = self._pid_cache.get(pid)
        if hit and hit[0] > time.time() and hit[1] == path:
            return hit[2]
        argv, env = proc_args(pid)
        names = self.sim_names() if ("CoreSimulator" in path or env.get("SIMULATOR_UDID")) else {}
        src = classify(pid, path, argv, env, names, self.browser_root)
        if src["kind"] == "ios" and src["id"] in SIM_SERVICES and src["id"] != "com.apple.mobilesafari":
            owner = responsible_pid(pid)        # the WebKit networking process works for one app: name that app
            if owner:
                o_argv, o_env = proc_args(owner)
                o = classify(owner, proc_path(owner), o_argv, o_env, names, self.browser_root)
                if o["kind"] == "ios" and o["app"]:
                    src = make_source("ios", src["device"], o["app"], o["id"], pid)
        with self._lock:
            if len(self._pid_cache) > 512:
                self._pid_cache.clear()
            self._pid_cache[pid] = (time.time() + 60, path, src)
        return src

    def running_avds(self):
        """AVD names of the emulators running on this Mac (their qemu command lines)."""
        avds = []
        for line in self.run(["/bin/ps", "-axww", "-o", "args="]).splitlines():
            exe = line.split(" ", 1)[0]
            if os.path.basename(exe).startswith("qemu-system"):
                avd = avd_from_argv(line.split())
                if avd and avd not in avds:
                    avds.append(avd)
        return avds

    def android(self, src, proxy_port):
        """Fill in the AVD (netsimd serves every emulator, so the Mac side cannot tell them apart: with one emulator
        running it is that one; with several, the one whose guest has a socket to the proxy now) and, when exactly one
        app in it is talking to the proxy, that app."""
        if not src["device"]:
            avds = self.running_avds()
            if len(avds) == 1:
                src = make_source("android", avds[0], pid=src["pid"])
            elif len(avds) > 1:
                talking = [a for a in avds if self._guest_uids(a, proxy_port)]
                src = make_source("android", talking[0] if len(talking) == 1 else "Android emulator", pid=src["pid"])
            else:
                src = make_source("android", "Android emulator", pid=src["pid"])
        if src["app"] or src["device"] == "Android emulator":
            return src
        return self.android_app(src, proxy_port)

    def _serial(self, avd):
        from devices import adb_path, avd_name
        adb = adb_path()
        if not adb:
            return None, None
        at, serials = self._adb
        if time.time() - at > 30 or avd not in serials:
            serials = {}
            for line in self.run([adb, "devices"]).splitlines():
                p = line.split()
                if len(p) == 2 and p[1] == "device" and p[0].startswith("emulator-"):
                    serials[avd_name(adb, p[0], runner=lambda argv: (0, self.run(argv)))] = p[0]
            self._adb = (time.time(), serials)
        return adb, serials.get(avd)

    def _guest_uids(self, avd, proxy_port):
        adb, serial = self._serial(avd)
        if not serial or not proxy_port:
            return set()
        return guest_uids(self.run([adb, "-s", serial, "shell", "cat", "/proc/net/tcp", "/proc/net/tcp6"]), proxy_port)

    def android_app(self, src, proxy_port):
        """Name the app when exactly one app in that emulator is talking to the proxy right now."""
        adb, serial = self._serial(src["device"])
        if not serial or not proxy_port:
            return src
        uids = self._guest_uids(src["device"], proxy_port)
        if len(uids) != 1:
            return src
        at, table = self._pkgs.get(serial, (0, {}))
        if time.time() > at or next(iter(uids)) not in table:
            table = packages_by_uid(self.run([adb, "-s", serial, "shell", "cmd", "package", "list", "packages", "-U"]))
            self._pkgs[serial] = (time.time() + 120, table)
        pkgs = table.get(next(iter(uids))) or []
        if len(pkgs) != 1:                      # a shared uid (system apps) names no single app
            return src
        return make_source("android", src["device"], pkgs[0], pkgs[0], src["pid"])

    def resolve(self, stream, peer, sock_port, since=None):
        """stream = (pid, process_name) from local mode, or None; peer = the client's (ip, port); sock_port = the proxy
        port it connected to; since = monotonic time the connection was accepted."""
        try:
            pid = stream[0] if stream else None
            if pid is None and peer and peer[0] and peer[0] not in LOOPBACK and not str(peer[0]).startswith("127."):
                ip = str(peer[0])[7:] if str(peer[0]).startswith("::ffff:") else str(peer[0])
                dev = self.lan.get(ip)
                return make_source("phone", dev["name"] if dev else ip, "", ident=ip)
            if pid is None and peer and peer[0] in LOOPBACK and peer[1]:
                pid = self.loopback_owner(peer[0], int(peer[1]), sock_port, time.monotonic() if since is None else since)
            if not pid:
                return UNKNOWN
            src = self.by_pid(pid)
            if src["kind"] == "unknown" and stream and stream[1]:
                src = make_source("mac", "This Mac", os.path.basename(str(stream[1])), pid=pid)
            if src["kind"] == "android":
                src = self.android(src, sock_port)
            return src
        except Exception:
            return UNKNOWN


def stamp(flow, src):
    flow.metadata["rivis_source"] = dict(src)
    flow.metadata["rivis_source_key"] = src["key"]


class ProxySource:
    """Attributes each client connection once and stamps its flows."""

    WAIT = 0.5      # R8C-02: seconds a connection's first RESPONSE may wait for its source. The request is never held: it goes
                    # to the server at once, so the lookup overlaps the server's own time (a real API call sees no delay).
                    # Holding the response keeps a short-lived connection open until lsof has seen it; a slower answer
                    # stamps the flows afterwards and re-runs the list filter on them (_apply_late).
    MAX_LOOKUPS = 512               # queued lookups are cheap now (they share one lsof snapshot); still bounded

    def __init__(self):
        self.attributor = Attributor()
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="rivis-source")
        self.lookup_slots = threading.BoundedSemaphore(self.MAX_LOOKUPS)
        self.conns = {}          # client id → concurrent Future[source]
        self.late = {}           # client id → flows seen before the answer
        self.closed = set()      # closed connections whose captured flows still await an answer
        self.hooked = False
        self.loop = None

    def running(self):
        install_har_hook()
        if sys.platform == "darwin":
            self.hooked = install_local_hook()
            if not self.hooked and ctx is not None:
                ctx.log.warn("proxy_source: this mitmproxy's local mode cannot be attributed; simulator calls read 'Unknown'")
        try:
            self.loop = asyncio.get_running_loop()
        except RuntimeError:
            self.loop = None

    def client_connected(self, client):
        if sys.platform != "darwin":
            return
        stream = _STREAM.get()
        peer = tuple(client.peername[:2]) if client.peername else None
        sock_port = client.sockname[1] if client.sockname else None
        if self.lookup_slots.acquire(blocking=False):
            try:
                fut = self.pool.submit(self.attributor.resolve, stream, peer, sock_port, time.monotonic())
            except RuntimeError:
                self.lookup_slots.release()
                fut = Future()
                fut.set_result(UNKNOWN)
            else:
                fut.add_done_callback(lambda _f: self.lookup_slots.release())
        else:
            # A slow lsof/adb must not build an unbounded executor queue or delay every new request by WAIT.
            fut = Future()
            fut.set_result(UNKNOWN)
        self.conns[client.id] = fut
        fut.add_done_callback(lambda f, cid=client.id: self._done(cid))

    def _done(self, cid):
        if self.loop is not None:
            try:
                self.loop.call_soon_threadsafe(self._apply_late, cid)
            except RuntimeError:
                pass

    def _apply_late(self, cid):
        fut, flows = self.conns.get(cid), self.late.pop(cid, [])
        if fut is None:
            return
        if flows:
            try:
                src = fut.result()
            except Exception:
                src = UNKNOWN
            for f in flows:
                stamp(f, src)
            try:
                ctx.master.view.update(flows)      # re-run the list filter: a source filter may now match these
            except Exception:
                pass
        if cid in self.closed:
            self.closed.remove(cid)
            self.conns.pop(cid, None)

    def client_disconnected(self, client):
        cid = client.id
        fut = self.conns.get(cid)
        if fut is not None and self.late.get(cid):
            # A short-lived connection can close while lsof is still working. Keep its flows until the lookup
            # finishes; otherwise they remain forever unlabelled in the captured session.
            self.closed.add(cid)
            if fut.done():
                self._apply_late(cid)
        else:
            self.conns.pop(cid, None)
            self.late.pop(cid, None)

    def source_of(self, flow):
        fut = self.conns.get(flow.client_conn.id)
        if fut is None or not fut.done():
            return None
        try:
            return fut.result()
        except Exception:
            return UNKNOWN

    def _tag_now(self, flow):
        if "rivis_source" in flow.metadata:
            return
        fut = self.conns.get(flow.client_conn.id)
        if fut is None:
            return
        if fut.done():
            stamp(flow, self.source_of(flow))
        else:
            pending = self.late.setdefault(flow.client_conn.id, [])
            if not any(f is flow for f in pending):      # requestheaders and the response hook may both queue it
                pending.append(flow)

    def requestheaders(self, flow):
        if "rivis_source" in flow.metadata:      # a replay or a loaded session keeps its original source
            return
        self._tag_now(flow)                      # labelled now if already known; never held here (R8C-02)

    async def responseheaders(self, flow):
        await self._await_source(flow)

    async def response(self, flow):              # a locally answered call (Map Local, mock) has no responseheaders
        await self._await_source(flow)

    async def _await_source(self, flow):
        if "rivis_source" in flow.metadata:
            return
        fut = self.conns.get(flow.client_conn.id)
        if fut is not None and not fut.done() and self.WAIT > 0:
            try:
                # wait_for cancels an unstarted concurrent future on timeout unless it is shielded. That left
                # the call unlabelled and raised CancelledError in _tag_now when lsof queued behind other work.
                await asyncio.wait_for(asyncio.shield(asyncio.wrap_future(fut)), self.WAIT)
            except Exception:
                pass
        self._tag_now(flow)

    def tcp_start(self, flow):
        self._tag_now(flow)

    def udp_start(self, flow):
        self._tag_now(flow)

    def dns_request(self, flow):
        self._tag_now(flow)

    def done(self):
        self.pool.shutdown(wait=False)


def summarize(flows, listed=lambda f: True):
    """Panel / `rivis status` view: every source with the number of its calls the list can show (listed(f): an app
    whose every call failed TLS has only connection records, which the list hides, so offering it would show an empty
    list), and each live flow's key by client connection (mitmweb's flow JSON carries client_conn.id, not metadata)."""
    seen, by_conn = {}, {}
    for f in flows:
        src = getattr(f, "metadata", {}).get("rivis_source")
        if not isinstance(src, dict) or not src.get("key"):
            # R8C-03: calls with no source (made in Compose, opened from a HAR, attribution failed) are listed as
            # Unknown, as the reference promises, so choosing a source never hides calls without a word. They get no
            # per-row chip (by_conn): a call whose lookup is still running must not flash "Unknown".
            row = seen.get(UNKNOWN["key"])
            if row is None:
                row = seen[UNKNOWN["key"]] = {k: UNKNOWN.get(k, "") for k in ("key", "kind", "device", "app", "id", "label")}
                row["count"] = 0
            row["count"] += 1 if listed(f) else 0
            continue
        row = seen.get(src["key"])
        if row is None:
            row = seen[src["key"]] = {k: src.get(k, "") for k in ("key", "kind", "device", "app", "id", "label")}
            row["count"] = 0
        row["count"] += 1 if listed(f) else 0
        conn = getattr(getattr(f, "client_conn", None), "id", None)
        if conn:
            by_conn[conn] = src["key"]
    order = {k: i for i, k in enumerate(KINDS)}
    rows = sorted((r for r in seen.values() if r["count"]), key=lambda r: (order.get(r["kind"], 9), r["device"].lower(), r["app"].lower()))
    return {"list": rows, "by_conn": by_conn}


def filter_clause(selection):
    """mitmproxy filter for a chosen source: a full key (one app) or "<kind>|<device>|" (every app on one device)."""
    if not selection:
        return ""
    if selection.startswith(UNKNOWN["kind"] + "|"):   # R8C-03: stamped Unknown, or never stamped at all
        return "( ~meta '^rivis_source_key: unknown\\\\|' | !~meta '^rivis_source_key: ' )"   # \\| survives the parser
    body = re.escape(selection) + ("$" if not selection.endswith("|") else "")
    return "~meta '^rivis_source_key: " + body.replace("\\", "\\\\").replace("'", "\\'") + "'"


addons = [ProxySource()]
