"""Hermetic test harness for Rivis (stdlib only, runs on /usr/bin/python3 3.9).

Everything a test starts lives under ONE temp root (realpath'd) with a fake HOME, a private CA and a shim
directory first on PATH. Subprocess environments are built from scratch (never inherited), so the real
~/.rivis, ~/.mitmproxy, ~/.neo-mitm, the system proxy, adb, simulators and the VPN are never reachable.
"""
import atexit
import http.client
import http.cookiejar
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS)
RIVIS = os.path.join(REPO, "rivis")
NEO_MITM = os.path.join(REPO, "neo-mitm")
ARTIFACTS = os.path.join(TESTS, ".artifacts")
FORBIDDEN_PORTS = {8080, 8083, 8090, 8093, 9090, 9091}
REAL_MITMWEB = shutil.which("mitmweb") or "/opt/homebrew/bin/mitmweb"
REAL_MITMDUMP = shutil.which("mitmdump") or "/opt/homebrew/bin/mitmdump"
PWSH = "/opt/pwsh/pwsh"
NODE = shutil.which("node")
REAL_HOME = os.path.expanduser("~")


def free_port():
    for _ in range(50):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        if port not in FORBIDDEN_PORTS:
            return port
    raise RuntimeError("no free port")


def port_open(port):
    s = socket.socket()
    s.settimeout(0.3)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


def wait_for(fn, timeout=10.0, interval=0.1, desc="condition"):
    """Poll fn() until it returns something truthy (returned). Raises AssertionError on timeout."""
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            last = fn()
            if last:
                return last
        except Exception as exc:       # noqa: BLE001 - polling helper: remember, retry
            last = exc
        time.sleep(interval)
    raise AssertionError("timed out after %.0fs waiting for %s (last: %r)" % (timeout, desc, last))


SHIMS = {
    "bash": '#!/bin/sh\nexec /bin/bash "$@"\n',
    "open": '#!/bin/sh\necho "$@" >> "$SHIM_LOG/open.log"\nexit 0\n',
    "xcrun": '#!/bin/sh\necho "$@" >> "$SHIM_LOG/xcrun.log"\nexit 0\n',
    "networksetup": '''#!/bin/sh
echo "$@" >> "$SHIM_LOG/networksetup.log"
case "$1" in
  -set*|-add*|-remove*|-delete*|-create*|-order*|-duplicate*|-rename*|-switch*|-detect*|-ordernetworkservices)
    echo "REFUSED by test shim: $*" >> "$SHIM_LOG/networksetup.log"; echo "networksetup shim: refused $1" >&2; exit 1 ;;
esac
exec /usr/sbin/networksetup "$@"
''',
    "mitmweb": '#!/bin/sh\necho "mitmweb $@" >> "$SHIM_LOG/mitm-argv.log"\n[ -n "${SHIM_DRYRUN:-}" ] && exit 0\nexec %s "$@"\n' % REAL_MITMWEB,
    "mitmdump": '#!/bin/sh\necho "mitmdump $@" >> "$SHIM_LOG/mitm-argv.log"\n[ -n "${SHIM_DRYRUN:-}" ] && exit 0\nexec %s "$@"\n' % REAL_MITMDUMP,
}


class Suite:
    """One per test process: temp root, shims, private CA, upstreams. Cleaned up at exit."""
    _inst = None

    @classmethod
    def get(cls):
        if cls._inst is None:
            cls._inst = Suite()
        return cls._inst

    def __init__(self):
        os.makedirs(ARTIFACTS, exist_ok=True)
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="rivis-t-"))
        self.shim = os.path.join(self.root, "shim")
        self.shimlog = os.path.join(self.root, "shimlog")
        for d in (self.shim, self.shimlog):
            os.makedirs(d)
        for name, text in SHIMS.items():
            path = os.path.join(self.shim, name)
            with open(path, "w") as fh:
                fh.write(text)
            os.chmod(path, 0o755)
        self.instances = []
        self.upstreams = []
        self._counter = 0
        self.ca_dir = os.path.join(self.root, "ca")
        self._make_ca()
        atexit.register(self.close)

    # -- environment ------------------------------------------------------------------------------------
    def env(self, home, extra=None, confdir=None, ports=None, password=None):
        home_tmp = os.path.join(os.path.dirname(home), os.path.basename(home) + "-tmp")
        os.makedirs(home, exist_ok=True)
        os.makedirs(home_tmp, exist_ok=True)
        env = {
            "PATH": ":".join([self.shim, "/usr/bin", "/bin", "/usr/sbin", "/sbin", "/opt/homebrew/bin"]),
            "HOME": home, "TMPDIR": home_tmp, "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8",
            "USER": "rivistest", "LOGNAME": "rivistest", "SHELL": "/bin/zsh",
            "EDITOR": "/usr/bin/true", "VISUAL": "/usr/bin/true",
            "ADB": "/nonexistent/adb", "SHIM_LOG": self.shimlog,
            "NO_COLOR": "1", "PYTHONDONTWRITEBYTECODE": "1",
        }
        if confdir:
            env["RIVIS_CONFDIR"] = confdir
        if ports:
            env["RIVIS_PORT"], env["RIVIS_WEB_PORT"] = str(ports[0]), str(ports[1])
        if password:
            env["RIVIS_WEB_PASSWORD"] = password
        env.update(extra or {})
        return env

    def new_home(self, name=None):
        self._counter += 1
        home = os.path.join(self.root, "home-%s-%d" % (name or "h", self._counter))
        os.makedirs(home, exist_ok=True)
        return home

    def cli_env(self, home, **extra):
        """Env for one-shot CLI calls: private CA dir, ports that nothing listens on."""
        confdir = os.path.join(home, ".mitmproxy")
        if not os.path.isdir(confdir):
            shutil.copytree(self.ca_dir, confdir)
        return self.env(home, extra=extra, confdir=confdir, ports=(free_port(), free_port()), password="x")

    def run(self, argv, home=None, env=None, timeout=60, input=None, cwd=None):
        """Run a command with a clean env; returns CompletedProcess (text mode)."""
        home = home or self.new_home("run")
        e = env if env is not None else self.cli_env(home)
        return subprocess.run(argv, env=e, cwd=cwd or self.root, stdin=subprocess.DEVNULL if input is None else None,
                              input=input, capture_output=True, text=True, timeout=timeout)

    def rivis(self, *args, home=None, env=None, timeout=60, bin=None, **kw):
        return self.run(["/bin/bash", bin or RIVIS] + list(args), home=home, env=env, timeout=timeout, **kw)

    def shim_log(self, name):
        try:
            with open(os.path.join(self.shimlog, name)) as fh:
                return fh.read()
        except FileNotFoundError:
            return ""

    # -- CA / upstream ----------------------------------------------------------------------------------
    def _make_ca(self):
        os.makedirs(self.ca_dir)
        port = free_port()
        env = self.env(os.path.join(self.root, "ca-home"))
        proc = subprocess.Popen([REAL_MITMDUMP, "--listen-host", "127.0.0.1", "-p", str(port), "--set",
                                 "confdir=" + self.ca_dir], env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            wait_for(lambda: os.path.exists(os.path.join(self.ca_dir, "mitmproxy-ca-cert.pem")), 30, desc="CA generation")
        finally:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
        self.ca_pem = os.path.join(self.ca_dir, "mitmproxy-ca-cert.pem")

    def upstream(self):
        from upstream import Upstream
        up = Upstream(self.root)
        self.upstreams.append(up)
        return up

    # -- lifecycle --------------------------------------------------------------------------------------
    def close(self):
        for inst in list(self.instances):
            inst.stop()
        for up in self.upstreams:
            up.close()
        shutil.rmtree(self.root, ignore_errors=True)


class Resp:
    def __init__(self, status, headers, body, rc, err=""):
        self.status, self.headers, self.body, self.rc, self.err = status, headers, body, rc, err

    def header(self, name):
        vals = [v for k, v in self.headers if k.lower() == name.lower()]
        return vals[-1] if vals else None

    def header_all(self, name):
        return [v for k, v in self.headers if k.lower() == name.lower()]

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.body.decode())

    def __repr__(self):
        return "<Resp %s rc=%s %r>" % (self.status, self.rc, self.body[:80])


class Panel:
    """mitmweb session: ?token= login, cookie jar, XSRF pair — the same scheme the browser and compose_cli use."""

    def __init__(self, port, token):
        self.port, self.token = port, token
        self.base = "http://127.0.0.1:%d" % port
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),
                                                  urllib.request.ProxyHandler({}))

    def login(self):
        self.opener.open(self.base + "/?token=" + self.token, timeout=10).read()
        if not self.xsrf:      # mitmweb 12 does not issue the cookie; tornado only needs a matching cookie/header pair
            self.jar.set_cookie(http.cookiejar.Cookie(
                0, "_mitmproxy_xsrf", os.urandom(16).hex(), None, False, "127.0.0.1", True, False, "/", True,
                False, None, False, None, None, {}))

    @property
    def xsrf(self):
        return next((c.value for c in self.jar if c.name == "_mitmproxy_xsrf"), "")

    def _do(self, req, timeout=30):
        try:
            with self.opener.open(req, timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def get(self, path, timeout=30):
        return self._do(urllib.request.Request(self.base + path), timeout)

    def get_json(self, path):
        code, body = self.get(path)
        assert code == 200, "GET %s -> %s %r" % (path, code, body[:200])
        return json.loads(body)

    def state(self):
        return self.get_json("/proxy/api/state")

    def post(self, op, body=None, timeout=30, raw=None):
        """POST /proxy/api/<op>. Returns (http_status, parsed_json_or_None, raw_bytes)."""
        data = raw if raw is not None else json.dumps(body if body is not None else {}).encode()
        req = urllib.request.Request(self.base + "/proxy/api/" + op, data=data, method="POST",
                                     headers={"Content-Type": "application/json", "X-XSRFToken": self.xsrf})
        code, payload = self._do(req, timeout)
        try:
            return code, json.loads(payload), payload
        except ValueError:
            return code, None, payload

    def ok(self, op, body=None, **kw):
        code, doc, raw = self.post(op, body, **kw)
        assert code == 200, "%s -> HTTP %s %r" % (op, code, raw[:300])
        return doc

    def flows(self):
        return self.get_json("/flows")

    def option(self, name):
        return self.get_json("/options")[name]["value"]

    def set_option(self, name, value):
        req = urllib.request.Request(self.base + "/options", data=json.dumps({name: value}).encode(), method="PUT",
                                     headers={"Content-Type": "application/json", "X-XSRFToken": self.xsrf})
        code, body = self._do(req)
        assert code == 200, "PUT /options %s -> %s %r" % (name, code, body[:200])


class Background:
    """Run a blocking call (a curl that will be paused at a breakpoint) in a thread; .result() joins it."""

    def __init__(self, fn, *a, **kw):
        import threading
        self._out = {}

        def run():
            try:
                self._out["v"] = fn(*a, **kw)
            except BaseException as exc:      # noqa: BLE001 - re-raised in result()
                self._out["e"] = exc
        self._t = threading.Thread(target=run, daemon=True)
        self._t.start()

    def result(self, timeout=30):
        self._t.join(timeout)
        if self._t.is_alive():
            raise AssertionError("background call still running after %ss" % timeout)
        if "e" in self._out:
            raise self._out["e"]
        return self._out["v"]


def raw_http(port, method, path, headers=None, body=None):
    """No cookie jar, no helper: for auth / XSRF negative tests."""
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data, r.getheaders()


class Instance:
    """A throw-away Rivis (mitmweb) started through the real `rivis start` CLI."""

    def __init__(self, suite, name, project=None, setup=None, extra_env=None, start_args=("--insecure",),
                 pre=None, node=True, rivis_bin=None, fresh_ca=False, allow_private=True):
        self.suite, self.name, self.project = suite, name, project or "default"
        self.home = suite.new_home(name)
        self.proc = None
        self.extra_env, self.start_args, self.pre, self.setup = extra_env or {}, list(start_args), pre, setup
        if allow_private and "--allow-private-hosts" not in self.start_args:
            self.start_args += ["--allow-private-hosts", r"^(127\.0\.0\.1|localhost)$"]
        self.rivis_bin = rivis_bin or RIVIS
        self.fresh_ca = fresh_ca          # True: let `rivis start` generate the CA itself instead of copying the suite's
        self.password = "pw" + os.urandom(6).hex()
        self.panel = None
        self.logpath = os.path.join(ARTIFACTS, "%s-%d.log" % (name, os.getpid()))
        self.proxy_port = self.web_port = None

    # paths
    @property
    def state_dir(self):
        return os.path.join(self.home, ".rivis", "projects", self.project)

    @property
    def rules_path(self):
        return os.path.join(self.state_dir, "rules.json")

    def path(self, *parts):
        return os.path.join(self.state_dir, *parts)

    def start(self):
        suite = self.suite
        last = None
        for attempt in range(4):
            self.proxy_port, self.web_port = free_port(), free_port()
            env = suite.env(self.home, extra=self.extra_env, confdir=os.path.join(self.home, ".mitmproxy"),
                            ports=(self.proxy_port, self.web_port), password=self.password)
            if not os.path.isdir(env["RIVIS_CONFDIR"]) and not self.fresh_ca:
                shutil.copytree(suite.ca_dir, env["RIVIS_CONFDIR"])
            self.env = env
            if self.pre:
                self.pre(self)
            argv = ["/bin/bash", self.rivis_bin] + (["--project", self.project] if self.project != "default" else []) \
                + ["start", "--no-ios", "--no-open"] + self.start_args
            logfh = open(self.logpath, "ab")
            self.proc = subprocess.Popen(argv, env=env, cwd=suite.root, stdin=subprocess.DEVNULL, stdout=logfh,
                                         stderr=subprocess.STDOUT, start_new_session=True)
            suite.instances.append(self)
            self.panel = Panel(self.web_port, self.password)
            try:
                def ready():
                    if self.proc.poll() is not None:
                        raise RuntimeError("rivis start exited rc=%s" % self.proc.returncode)
                    self.panel.login()
                    return self.panel.state()
                wait_for(ready, 45, 0.25, "rivis start (%s)" % self.name)
                if self.setup:
                    self.setup(self)
                return self
            except AssertionError as exc:
                last = exc
                with open(self.logpath, "rb") as fh:
                    tail = fh.read()[-1500:].decode("utf-8", "replace")
                self.stop()
                if "already taken" in tail:
                    continue
                raise AssertionError("%s\n--- log tail ---\n%s" % (exc, tail))
        raise last

    def stop(self):
        proc = self.proc
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(5)
        elif proc is not None:
            try:       # leader gone: make sure no sidecar (node) survives in the group
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        if self in self.suite.instances:
            self.suite.instances.remove(self)

    def log(self):
        with open(self.logpath, "rb") as fh:
            return fh.read().decode("utf-8", "replace")

    # -- clients ----------------------------------------------------------------------------------------
    def fetch(self, url, method=None, headers=None, data=None, timeout=20, cacert=None, extra=(), insecure_client=False):
        """curl through the proxy (always --noproxy '' -x … --cacert …, HTTP/1.1)."""
        tmp = tempfile.mkdtemp(dir=self.suite.root)
        hdr, out = os.path.join(tmp, "h"), os.path.join(tmp, "b")
        argv = ["curl", "-sS", "--noproxy", "", "-x", "http://127.0.0.1:%d" % self.proxy_port,
                "--cacert", cacert or self.suite.ca_pem, "--http1.1", "--max-time", str(timeout),
                "-D", hdr, "-o", out, "-w", "%{http_code}"]
        if method:
            argv += ["-X", method]
        for k, v in (headers or {}).items() if isinstance(headers, dict) else (headers or []):
            argv += ["-H", "%s: %s" % (k, v)]
        if data is not None:
            argv += ["--data-binary", "@-"]
        argv += list(extra) + [url]
        cp = subprocess.run(argv, env=self.suite.env(self.home), input=data if isinstance(data, bytes) else
                            (data.encode() if data is not None else None), stdin=None if data is not None else subprocess.DEVNULL,
                            capture_output=True, timeout=timeout + 15)
        headers_out, status = [], 0
        try:
            blocks = open(hdr, "rb").read().decode("latin-1").replace("\r\n", "\n").strip().split("\n\n")
            last = [b for b in blocks if b.startswith("HTTP/")][-1] if blocks and blocks[0] else ""
            lines = last.split("\n")
            if lines and lines[0]:
                status = int(lines[0].split()[1])
                headers_out = [tuple(x.split(":", 1)[0:1] + [x.split(":", 1)[1].strip()]) for x in lines[1:] if ":" in x]
        except (OSError, ValueError, IndexError):
            pass
        try:
            body = open(out, "rb").read()
        except OSError:
            body = b""
        shutil.rmtree(tmp, ignore_errors=True)
        return Resp(status or int(cp.stdout.decode() or 0), headers_out, body, cp.returncode, cp.stderr.decode("utf-8", "replace"))

    def flows(self):
        return self.panel.flows()

    def flow_for(self, url_part, timeout=5):
        """Newest flow whose URL contains url_part (mitmweb /flows JSON: has .comment, .metadata via request)."""
        def find():
            for f in reversed(self.flows()):
                req = f.get("request") or {}
                u = "%s://%s:%s%s" % (req.get("scheme"), req.get("pretty_host") or req.get("host"), req.get("port"), req.get("path"))
                if url_part in u or url_part in (req.get("path") or ""):
                    return f
        return wait_for(find, timeout, 0.2, "flow %s" % url_part)

    # -- rules file -------------------------------------------------------------------------------------
    def cfg(self):
        with open(self.rules_path) as fh:
            return json.load(fh)

    def write_cfg(self, cfg, sync=True):
        """Atomically replace rules.json; sync=True waits until the engine has provably reloaded it."""
        base = {"throttle": "off", "throttle_match": "", "loss": 0, "rules": [], "breakpoints": [], "scripts": [],
                "collections": {"recording": None, "record_match": ".", "replay": [], "strict": False},
                "tls": {"mode": "all", "allow": [], "ignore": []}}
        base.update(cfg)
        marker = None
        if sync:
            marker = "sync-%s" % os.urandom(4).hex()
            base["rules"] = [dict(name=marker, enabled=True, match=r"/__sync__/" + marker, action="respond",
                                  status=200, body="ok-" + marker)] + list(base["rules"])
        os.makedirs(os.path.dirname(self.rules_path), exist_ok=True)
        tmp = self.rules_path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(base, fh, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.rules_path)
        if marker:
            url = "http://127.0.0.1:1/__sync__/" + marker
            if float(base.get("loss") or 0) >= 100 and not base.get("throttle_match"):       # every call is killed before rules run: a kill IS the proof
                wait_for(lambda: (lambda r: r.rc != 0 and r.status == 0)(self.fetch(url, timeout=5)), 12, 0.2, "loss reload")
            else:
                wait_for(lambda: self.fetch(url, timeout=5).text == "ok-" + marker, 12, 0.2, "rules reload")
            time.sleep(0.15)
        return base

    def reset(self, **cfg):
        return self.write_cfg(cfg)

    def clear_dir(self, sub):
        d = self.path(sub)
        if os.path.isdir(d):
            for name in os.listdir(d):
                p = os.path.join(d, name)
                if os.path.islink(p) or os.path.isfile(p):
                    os.unlink(p)
                else:
                    shutil.rmtree(p)


class LiveCase(unittest.TestCase):
    """One throw-away Rivis per class (started via the real CLI) plus two deterministic upstreams.
    Every test starts from a clean, provably-reloaded rules file."""
    PROJECT = None
    INSTANCE_KW = {}

    @classmethod
    def make_instance(cls):
        return Instance(cls.suite, cls.__name__.lower(), project=cls.PROJECT, **cls.INSTANCE_KW)

    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()
        cls.up = cls.suite.upstream()
        cls.up2 = cls.suite.upstream()
        cls.inst = cls.make_instance().start()
        cls.panel = cls.inst.panel

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()

    def setUp(self):
        self.reset_state()

    def reset_state(self, **cfg):
        self.inst.reset(**cfg)
        self.up.reset_hits()
        self.up2.reset_hits()

    # tiny helpers
    def rule(self, name, action, match=".", **kw):
        d = {"name": name, "enabled": True, "match": match, "action": action}
        d.update(kw)
        return d

    def fetch(self, path, up=None, tls=False, **kw):
        return self.inst.fetch((up or self.up).url(path, tls=tls), **kw)

    def comment(self, path):
        return self.inst.flow_for(path)["comment"]


def node_ok():
    return bool(NODE)


def skip_unless(cond, reason):
    return unittest.skipUnless(cond, reason)


EXPECTED_FAIL_NOTE = "expected failure — see tests/FOUND-BUGS.md"


def main():
    unittest.main(verbosity=2)
