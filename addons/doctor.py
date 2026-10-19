"""doctor — one command that says exactly what is wrong and how to fix it.

Stdlib only, runs on system Python 3.9 with `/usr/bin/python3 -I` (like rules_cli.py).
Read-only by default; `--fix-safe` performs only safe, reversible fixes after y/N.

Invoked by the `rivis`/`rivis.ps1` wrappers, which pass the already-resolved context:

  doctor.py --project ID --rules FILE --confdir DIR --port N --web-port N
            --script-dir DIR [--adb PATH] [--json] [--no-net] [--fix-safe] [--yes]

Checks (each → ✓ ok / ⚠ warn / ✗ error, one line + the exact fix):
  1  mitmproxy pinned version + path; node present + version
  2  CA present, key private (0600), age, fingerprint
  3  macOS local-capture system extension activated+enabled
  4  proxy/web ports free or owned by us
  5  system proxy (stale localhost vs corporate) — steals simulator traffic
  6  Proxyman / FRTMProxy running
  7  iOS Simulator booted + CA trusted (read-only TrustStore.sqlite*)
  8  Android emulator running, http_proxy, CA in user store, image type
  9  running instance state (rules, skipped, scripts, throttle, TLS, blocks)
  10 network reachability for the project's doctor_hosts (DNS/TCP/TLS)
  11 disk: state dir size, largest collections/sessions, free space
  12 /usr/bin/python3 (3.9) present (macOS helpers need it)

Exit: 0 all ✓, 1 any ⚠, 2 any ✗.
"""
import argparse
import calendar
import csv
import io
import json
import os
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:       # /usr/bin/python3 -I removes the script directory
    sys.path.insert(0, HERE)
from proxy_common import (  # noqa: E402
    PRODUCT, STATE_ROOT, project_profile, project_state, tls_config, tls_covering,
)

REPO_ROOT = os.path.dirname(HERE)
PINNED_MITMPROXY = "12.2.3"
CA_MAX_AGE_DAYS = 365          # warn when the workstation CA is older than this
DISK_FREE_WARN_GIB = 2.0       # warn when the volume holding the state dir drops below this
NET_TIMEOUT = 3.0              # seconds per network check (brief: ≤3 s)
SUBPROC_TIMEOUT = 4.0

OK, WARN, ERR, INFO, SKIP = "ok", "warn", "error", "info", "skip"
_SYMBOL = {OK: "\u2713", WARN: "\u26a0", ERR: "\u2717", INFO: "\u2022", SKIP: "\u2013"}
_COLOR = {OK: "32", WARN: "33", ERR: "31", INFO: "36", SKIP: "90"}
MAC, WIN = sys.platform == "darwin", sys.platform.startswith("win")


# ───────────────────────── result model ─────────────────────────
class Report:
    def __init__(self):
        self.items = []   # (section, level, title, detail, fix)
        self.fixes = []   # (label, callable) queued safe fixes

    def add(self, section, level, title, detail="", fix=""):
        self.items.append((section, level, title, detail, fix))

    def worst(self):
        levels = [lvl for _, lvl, _, _, _ in self.items]
        if ERR in levels:
            return 2
        if WARN in levels:
            return 1
        return 0


# ───────────────────────── pure, unit-tested classifiers ─────────────────────────
def parse_lsof_listener(output):
    """Parse `lsof -nP -iTCP:P -sTCP:LISTEN` into [{command,pid,name}]. Ignores the header."""
    rows = []
    for line in (output or "").splitlines():
        parts = line.split()
        if len(parts) < 9 or parts[0] == "COMMAND":
            continue
        rows.append({"command": parts[0], "pid": parts[1], "name": parts[8]})
    return rows


def parse_networksetup_proxy(details):
    """Parse one `networksetup -getwebproxy/-getsecurewebproxy` block → {enabled,server,port}."""
    out = {"enabled": False, "server": "", "port": ""}
    for line in (details or "").splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "enabled":
            out["enabled"] = value.lower() in ("yes", "1", "true")
        elif key == "server":
            out["server"] = value
        elif key == "port":
            out["port"] = value
    return out


def is_loopback(host):
    return str(host or "").strip().lower() in ("127.0.0.1", "localhost", "::1", "0.0.0.0")


def classify_system_proxy(server, port, port_listening):
    """A system proxy is a stale local leftover, an active local proxy, or a corporate one."""
    if is_loopback(server):
        if port_listening:
            return "local_active"      # another local tool owns it (Proxyman/FRTMProxy/…)
        return "local_stale"           # loopback host, nothing listening → net-reset is safe
    return "corporate"                 # non-loopback → never touch


def classify_network_failure(stage, exc_type, message):
    """Map a DNS/TCP/TLS failure to a category. Pure so it can be unit-tested with strings."""
    msg = (message or "").lower()
    if stage == "dns":
        return "dns_fail"
    if stage == "tcp":
        if "timed out" in msg or "timeout" in msg:
            return "no_route"          # VPN down / host unreachable
        if "refused" in msg:
            return "refused"
        if "no route" in msg or "unreachable" in msg:
            return "no_route"
        return "tcp_fail"
    # stage == "tls"
    if "hostname mismatch" in msg or "ip address mismatch" in msg or \
       "doesn't match" in msg or "san" in msg:
        return "cert_san_mismatch"
    if "has expired" in msg or "certificate expired" in msg:
        return "cert_expired"
    if "certificate verify failed" in msg or "self-signed" in msg or \
       "self signed" in msg or "unable to get local issuer" in msg:
        return "cert_untrusted"
    if "reset" in msg or exc_type in ("ConnectionResetError",):
        return "tls_reset"
    if "unsupported protocol" in msg or "wrong_version" in msg or \
       "handshake failure" in msg or "sslv3_alert" in msg or "protocol" in msg:
        return "tls_refused"
    if "timed out" in msg or "timeout" in msg:
        return "tls_timeout"
    return "tls_fail"


NET_EXPLAIN = {
    "ok": (OK, "reachable (DNS + TCP 443 + TLS ok)", ""),
    "dns_fail": (ERR, "DNS does not resolve", "connect to the VPN (FortiClient) — the host is a *.neo.sa private name"),
    "no_route": (ERR, "no route to :443 (VPN down?)", "connect to the VPN, then retry"),
    "refused": (ERR, "TCP :443 refused", "the gateway is not listening — check the host/env"),
    "tcp_fail": (ERR, "TCP :443 failed", "check connectivity / VPN"),
    "tls_reset": (ERR, "TLS connection reset (dropped tunnel)", "reconnect the VPN — the tunnel dropped mid-handshake"),
    "tls_refused": (WARN, "TLS handshake refused (protocol/cipher)", "the gateway is TLS 1.2 static-RSA only; a forced TLS1.3/ECDHE client fails here"),
    "tls_timeout": (ERR, "TLS handshake timed out", "check the VPN / network path"),
    "cert_san_mismatch": (WARN, "server cert does not cover this host (SAN mismatch)", "expected for a shared gateway cert; not a client problem"),
    "cert_expired": (WARN, "server certificate has expired", "apps with strict TLS fail here; through Rivis only with `start --insecure`"),
    "cert_untrusted": (INFO, "server cert not trusted by the system store", "normal for a test gateway; this check does not use the workstation CA"),
    "tls_fail": (WARN, "TLS handshake failed", "check the host/VPN"),
}


# ───────────────────────── small shell helpers ─────────────────────────
def run(cmd, timeout=SUBPROC_TIMEOUT):
    """Run a command read-only; return (rc, stdout, stderr) or (None, '', 'reason') if it can't run."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except FileNotFoundError:
        return None, "", "not found"
    except subprocess.TimeoutExpired:
        return None, "", "timed out"
    except OSError as e:
        return None, "", str(e)


def which(name):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def executable_is_safe(path):
    """Only execute a regular PATH tool owned by this user/root and not group/world writable."""
    try:
        resolved = os.path.realpath(path)
        st = os.stat(resolved)
    except OSError as e:
        return False, str(e)
    if not stat.S_ISREG(st.st_mode):
        return False, "not a regular file"
    if not WIN and st.st_uid not in (0, os.getuid()):
        return False, "owned by uid %s" % st.st_uid
    if st.st_mode & 0o022:
        return False, "executable is writable by group/other"
    return True, resolved


def port_owner(port):
    if WIN:
        rc, out, _ = run(["netstat", "-ano", "-p", "tcp"])
        if rc is None:
            return []
        rows = parse_netstat_listener(out, port)
        for row in rows:
            rc, listing, _ = run(["tasklist", "/FI", "PID eq %s" % row["pid"], "/FO", "CSV", "/NH"])
            try:
                record = next(csv.reader(io.StringIO(listing))) if rc == 0 else []
            except (csv.Error, StopIteration):
                record = []
            if record and not record[0].startswith("INFO:"):
                row["command"] = record[0]
        return rows
    rc, out, _ = run(["lsof", "-nP", "-iTCP:%d" % port, "-sTCP:LISTEN"])
    if rc is None:
        return []
    return parse_lsof_listener(out)


def parse_netstat_listener(text, port):
    """Parse Windows `netstat -ano -p tcp`; return listeners for exactly `port`."""
    rows = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP" or parts[-2].upper() != "LISTENING":
            continue
        endpoint, pid = parts[1], parts[-1]
        try:
            found_port = int(endpoint.rsplit(":", 1)[1])
        except (IndexError, ValueError):
            continue
        if found_port == int(port) and pid.isdigit():
            rows.append({"command": "process", "pid": pid, "name": endpoint})
    return rows


# ───────────────────────── checks ─────────────────────────
def check_mitmproxy_node(rep):
    sec = "Tooling"
    mitm = which("mitmdump") or which("mitmweb")
    if not mitm:
        rep.add(sec, ERR, "mitmproxy not found",
                "neither mitmdump nor mitmweb is on PATH",
                "install the pinned %s build from the internal mirror" % PINNED_MITMPROXY)
    else:
        safe, reason = executable_is_safe(mitm)
        if not safe:
            rep.add(sec, ERR, "unsafe mitmproxy executable", "%s: %s" % (mitm, reason),
                    "remove the writable/untrusted PATH entry and install the pinned build from the internal mirror")
        else:
            rc, out, err = run([mitm, "--version"])
            ver = ""
            m = re.search(r"[Mm]itmproxy:?\s*v?([0-9]+\.[0-9]+\.[0-9]+)", (out or "") + (err or ""))
            if m:
                ver = m.group(1)
            if ver == PINNED_MITMPROXY:
                rep.add(sec, OK, "mitmproxy %s" % ver, "at %s" % mitm)
            elif ver:
                rep.add(sec, WARN, "mitmproxy %s (pinned is %s)" % (ver, PINNED_MITMPROXY),
                        "at %s — each upgrade needs IT review" % mitm,
                        "install the pinned %s build from the internal mirror" % PINNED_MITMPROXY)
            else:
                rep.add(sec, WARN, "mitmproxy version unknown", "at %s; --version did not report a version" % mitm)

    node = find_node()
    if not node:
        rep.add(sec, INFO, "Node.js not installed",
                "JavaScript scripts are disabled (Python scripts still work)",
                "install Node.js only if you need JS scripting rules")
    else:
        safe, reason = executable_is_safe(node)
        if not safe:
            rep.add(sec, WARN, "unsafe Node.js executable", "%s: %s" % (node, reason),
                    "remove the writable/untrusted PATH entry; JavaScript scripts stay disabled")
        else:
            rc, out, err = run([node, "--version"])
            rep.add(sec, OK, "node %s" % (out.strip() or "present"), "at %s" % node)


def _read_cert_der(path):
    with open(path, "rb") as fh:
        raw = fh.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("certificate is larger than 1 MiB")
    if b"-----BEGIN CERTIFICATE-----" in raw:
        try:
            return ssl.PEM_cert_to_DER_cert(raw.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as e:
            raise ValueError("invalid PEM certificate: %s" % e)
    if not raw:
        raise ValueError("certificate is empty")
    return raw


def _pem_sha256(path):
    import hashlib
    return hashlib.sha256(_read_cert_der(path)).hexdigest().upper()


def _der_tlv(data, offset):
    """Return (tag, value, next_offset) for one bounded DER TLV."""
    if offset >= len(data):
        raise ValueError("truncated DER")
    tag, offset = data[offset], offset + 1
    if offset >= len(data):
        raise ValueError("truncated DER length")
    first, offset = data[offset], offset + 1
    if first & 0x80:
        count = first & 0x7f
        if count == 0 or count > 4 or offset + count > len(data):
            raise ValueError("invalid DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    else:
        length = first
    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return tag, data[offset:end], end


def _parse_asn1_time(tag, value):
    try:
        text = value.decode("ascii")
        if not text.endswith("Z"):
            raise ValueError("certificate time is not UTC")
        if tag == 0x17:  # UTCTime: 1950..2049 pivot from RFC 5280
            if len(text) != 13 or not text[:2].isdigit():
                raise ValueError("malformed UTCTime")
            year = (1900 if int(text[:2]) >= 50 else 2000) + int(text[:2])
            parsed = time.strptime(str(year) + text[2:], "%Y%m%d%H%M%SZ")
        elif tag == 0x18:  # GeneralizedTime
            parsed = time.strptime(text, "%Y%m%d%H%M%SZ")
        else:
            raise ValueError("certificate validity has an unknown time type")
        return calendar.timegm(parsed)
    except (UnicodeDecodeError, ValueError) as e:
        raise ValueError("invalid certificate time: %s" % e)


def _cert_dates(path):
    return _der_cert_dates(_read_cert_der(path))


def _der_cert_dates(der):
    tag, cert, end = _der_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError("certificate is not one DER sequence")
    tag, tbs, _ = _der_tlv(cert, 0)
    if tag != 0x30:
        raise ValueError("certificate has no TBSCertificate")
    offset = 0
    tag, _value, next_offset = _der_tlv(tbs, offset)
    if tag == 0xa0:  # optional explicit version
        offset = next_offset
    for _name in ("serial", "signature", "issuer"):
        _tag, _value, offset = _der_tlv(tbs, offset)
    tag, validity, _ = _der_tlv(tbs, offset)
    if tag != 0x30:
        raise ValueError("certificate has no validity sequence")
    before_tag, before, offset = _der_tlv(validity, 0)
    after_tag, after, offset = _der_tlv(validity, offset)
    if offset != len(validity):
        raise ValueError("certificate validity contains trailing data")
    return _parse_asn1_time(before_tag, before), _parse_asn1_time(after_tag, after)


def check_ca(rep, confdir):
    sec = "Certificate"
    ca = os.path.join(confdir, "mitmproxy-ca-cert.pem")
    key = os.path.join(confdir, "mitmproxy-ca.pem")
    if not os.path.isfile(ca):
        rep.add(sec, ERR, "no CA in %s" % confdir, "the CA is generated on the first proxy run",
                "run `%s start` once (or `%s cert`)" % (PRODUCT["cli"], PRODUCT["cli"]))
        return
    try:
        fp = _pem_sha256(ca)
        not_before, not_after = _cert_dates(ca)
    except (OSError, ValueError) as e:
        rep.add(sec, ERR, "CA certificate is unreadable or corrupt", str(e),
                "move the broken certificate aside, then run `%s start` to regenerate it" % PRODUCT["cli"])
        return
    short = (fp[:8] + "\u2026" + fp[-4:]) if fp else "?"
    rep.add(sec, OK, "CA present (sha256 %s)" % short,
            "%s — one CA per workstation; if this fingerprint shows on another machine, regenerate it" % ca)
    # key privacy
    if os.path.isfile(key):
        mode = os.stat(key).st_mode & 0o777
        if mode == 0o600:
            rep.add(sec, OK, "CA private key is private (0600)", key)
        else:
            rep.add(sec, WARN, "CA private key is %o (should be 0600)" % mode,
                    "a group/other-readable key can be copied off the workstation",
                    "chmod 600 %s" % key)
    else:
        rep.add(sec, INFO, "CA private key not found", key)
    # age / expiry
    now = time.time()
    if not_after and not_after < now:
        rep.add(sec, ERR, "CA has expired", time.strftime("%Y-%m-%d", time.localtime(not_after)),
                "regenerate: remove %s and run `%s start`" % (confdir, PRODUCT["cli"]))
    elif not_after and not_after - now < 30 * 86400:
        rep.add(sec, WARN, "CA expires in under 30 days",
                time.strftime("%Y-%m-%d", time.localtime(not_after)))
    if not_before:
        age = int((now - not_before) / 86400)
        if age > CA_MAX_AGE_DAYS:
            rep.add(sec, WARN, "CA is %d days old (> %d)" % (age, CA_MAX_AGE_DAYS),
                    "an old shared CA is a liability",
                    "regenerate on retired/shared workstations: remove %s and run `%s start`" % (confdir, PRODUCT["cli"]))


def check_sysext(rep):
    if not MAC:
        return
    sec = "Local capture (macOS)"
    rc, out, _ = run(["systemextensionsctl", "list"])
    if rc is None:
        rep.add(sec, INFO, "could not query system extensions", "systemextensionsctl unavailable")
        return
    hit = [l for l in out.splitlines() if "redirector" in l.lower() or "mitmproxy" in l.lower()]
    if any("activated enabled" in l for l in hit):
        rep.add(sec, OK, "Mitmproxy Redirector extension activated + enabled",
                "iOS Simulator local capture will work")
    elif hit:
        rep.add(sec, WARN, "Mitmproxy Redirector extension present but not enabled",
                hit[0].strip(),
                "System Settings \u2192 General \u2192 Login Items & Extensions \u2192 Network Extensions \u2192 enable Mitmproxy Redirector")
    else:
        rep.add(sec, WARN, "Mitmproxy Redirector extension not installed",
                "iOS Simulator local capture needs it (installed on first local-capture run)",
                "run `%s start` (approve the prompt), then System Settings \u2192 General \u2192 Login Items & Extensions \u2192 Network Extensions" % PRODUCT["cli"])


def check_ports(rep, port, web_port):
    sec = "Ports"
    for label, p in (("proxy", port), ("web UI", web_port)):
        owners = port_owner(p)
        if not owners:
            rep.add(sec, OK, "%s port :%d is free" % (label, p))
            continue
        o = owners[0]
        comm = o["command"].lower()
        if comm.startswith("mitmweb") or comm.startswith("mitmdump"):
            rep.add(sec, OK, "%s port :%d owned by %s (pid %s)" % (label, p, o["command"], o["pid"]),
                    "a %s / mitmproxy instance" % PRODUCT["name"],
                    "if it is a leftover: `%s stop`" % PRODUCT["cli"])
        elif "proxyman" in comm:
            rep.add(sec, ERR, "%s port :%d owned by Proxyman (pid %s)" % (label, p, o["pid"]),
                    "Proxyman will also steal simulator traffic via the system proxy",
                    "quit Proxyman, then `%s start`" % PRODUCT["cli"])
        elif "frtm" in comm:
            rep.add(sec, ERR, "%s port :%d owned by FRTMProxy (pid %s)" % (label, p, o["pid"]),
                    "FRTMProxy binds this port",
                    "quit FRTMProxy, or set %s_PORT/%s_WEB_PORT to free ports" % (PRODUCT["env_prefix"], PRODUCT["env_prefix"]))
        else:
            rep.add(sec, ERR, "%s port :%d owned by %s (pid %s)" % (label, p, o["command"], o["pid"]),
                    o["name"],
                    "stop that process, or set %s_PORT/%s_WEB_PORT to free ports" % (PRODUCT["env_prefix"], PRODUCT["env_prefix"]))


def check_system_proxy(rep):
    if not MAC:
        return
    sec = "System proxy"
    rc, out, _ = run(["scutil", "--proxy"])
    enabled = False
    if rc == 0:
        e = {}
        for line in out.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                e[k.strip()] = v.strip()
        enabled = e.get("HTTPSEnable") == "1" or e.get("HTTPEnable") == "1"
    if not enabled:
        rep.add(sec, OK, "no macOS system proxy set", "simulator traffic reaches the proxy directly")
        return
    # find the service(s) and classify
    rc, svc_out, _ = run(["networksetup", "-listallnetworkservices"])
    services = [s for s in (svc_out or "").splitlines()[1:] if s and not s.startswith("*")]
    flagged = False
    for svc in services:
        for getter, label in (("-getsecurewebproxy", "https"), ("-getwebproxy", "http")):
            rc, det, _ = run(["networksetup", getter, svc])
            if rc != 0:
                continue
            info = parse_networksetup_proxy(det)
            if not info["enabled"]:
                continue
            flagged = True
            try:
                listening = bool(port_owner(int(info["port"]))) if info["port"].isdigit() else False
            except ValueError:
                listening = False
            kind = classify_system_proxy(info["server"], info["port"], listening)
            where = "%s %s=%s:%s" % (svc, label, info["server"], info["port"])
            if kind == "local_stale":
                rep.add(sec, ERR, "stale localhost proxy — Mac apps have no network", where,
                        "`%s net-reset` (safe: only clears dead loopback proxies)" % PRODUCT["cli"],
                        )
                rep.fixes.append(("clear stale localhost system proxy (%s)" % where, _fix_net_reset))
            elif kind == "local_active":
                rep.add(sec, WARN, "a local proxy owns the system proxy — it steals simulator traffic", where,
                        "quit that tool (Proxyman/FRTMProxy); iOS Simulator traffic goes there, not to %s" % PRODUCT["name"])
            else:
                rep.add(sec, WARN, "a corporate/non-local system proxy is set", where,
                        "left alone (never touched); it may intercept simulator TLS — expect SAN mismatches")
    if not flagged:
        rep.add(sec, WARN, "system proxy is enabled but no service exposes it",
                "scutil reports a proxy but networksetup shows none",
                "`%s net-reset` if the simulator has no capture" % PRODUCT["cli"])


PROXY_APPS = {"proxyman": "Proxyman", "frtmproxy": "FRTMProxy"}


def running_proxy_apps(ps_comm):
    """Names of other proxy apps among `ps -o comm=` lines (full executable paths): matched on the file name."""
    return [PROXY_APPS[os.path.basename(line.strip()).lower()] for line in ps_comm.splitlines()
            if os.path.basename(line.strip()).lower() in PROXY_APPS]


# the same places addons/proxy_scripts.py find_node() looks, so doctor never says "disabled" while scripts run
NODE_CANDIDATES = (
    "/opt/homebrew/bin/node", "/usr/local/bin/node", "/usr/bin/node",
    os.path.expanduser("~/.nvm/versions/node/current/bin/node"),
    r"C:\Program Files\nodejs\node.exe", r"C:\Program Files (x86)\nodejs\node.exe",
)


def find_node():
    import glob
    override = os.environ.get("%s_NODE" % PRODUCT["env_prefix"])
    candidates = ([override] if override else []) + [which("node")] + list(NODE_CANDIDATES)
    candidates += sorted(glob.glob(os.path.expanduser("~/.nvm/versions/node/*/bin/node")), reverse=True)
    if os.environ.get("NVM_HOME"):
        candidates.append(os.path.join(os.environ["NVM_HOME"], "node.exe"))
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def check_other_tools(rep):
    if not MAC:
        return
    sec = "Other proxy apps"
    # by executable name: `pgrep -f` also matched any command line that merely mentions Proxyman (a grep, an editor,
    # Proxyman's leftover helper), so doctor warned on Macs where Proxyman was not running (night QA lane B, F2)
    rc, out, _ = run(["ps", "-A", "-o", "comm="])
    found = sorted(set(running_proxy_apps(out))) if rc == 0 else []
    if not found:
        rep.add(sec, OK, "no Proxyman / FRTMProxy running")
    else:
        rep.add(sec, WARN, "%s running" % " and ".join(found),
                "these set the system proxy and capture simulator traffic instead of %s" % PRODUCT["name"],
                "quit %s before iOS testing" % " / ".join(found))


def _sim_truststores(udid):
    # iOS ≤17: TrustStore.sqlite, iOS 18+/26: .sqlite3; it sits under trustd/ or trustd/private/.
    # Match the CLI's `find … -name TrustStore.sqlite* -not -name *-*` (skip -wal/-shm).
    base = os.path.expanduser(
        "~/Library/Developer/CoreSimulator/Devices/%s/data/private/var/protected/trustd" % udid)
    out = []
    if os.path.isdir(base):
        for root, _dirs, names in os.walk(base):
            for name in names:
                if name.startswith("TrustStore.sqlite") and "-" not in name:
                    out.append(os.path.join(root, name))
    return out


def check_ios(rep, confdir):
    if not MAC:
        return
    sec = "iOS Simulator"
    rc, out, _ = run(["xcrun", "simctl", "list", "devices", "booted"])
    if rc is None:
        rep.add(sec, INFO, "could not query simulators", "xcrun/simctl unavailable")
        return
    booted = []
    for line in out.splitlines():
        m = re.search(r"(.+?)\s+\(([0-9A-Fa-f-]{36})\)\s+\(Booted\)", line)
        if m:
            booted.append((m.group(1).strip(), m.group(2)))
    if not booted:
        rep.add(sec, INFO, "no booted simulator", "boot one in Simulator.app to test iOS")
        return
    ca = os.path.join(confdir, "mitmproxy-ca-cert.pem")
    try:
        want = _pem_sha256(ca) if os.path.isfile(ca) else ""
    except Exception:
        want = ""
    import sqlite3
    for name, udid in booted:
        stores = _sim_truststores(udid)
        if not stores or not want:
            rep.add(sec, WARN, "%s: cannot verify CA trust" % name,
                    "no trust store yet" if not stores else "CA fingerprint unknown",
                    "`%s ios on` to trust the CA" % PRODUCT["cli"])
            continue
        trusted = False
        for db in stores:
            try:
                con = sqlite3.connect("file:%s?mode=ro" % db, uri=True, timeout=1.0)
                try:
                    n = con.execute(
                        "select count(*) from tsettings where hex(sha256)=?", (want,)).fetchone()[0]
                finally:
                    con.close()
                if n:
                    trusted = True
                    break
            except sqlite3.Error:
                continue
        if trusted:
            rep.add(sec, OK, "%s: %s CA trusted" % (name, PRODUCT["name"]))
        else:
            rep.add(sec, WARN, "%s: %s CA not trusted" % (name, PRODUCT["name"]),
                    "TLS from the app will fail until the CA is trusted",
                    "`%s ios on`" % PRODUCT["cli"])


def _android_ca_recorded(adb, serial, confdir):
    """True when `android on` recorded a verified install of THIS CA on this AVD (the Devices tab's own check)."""
    import devices
    ca = os.path.join(confdir or "", "mitmproxy-ca-cert.pem")
    want = devices.ca_sha256(ca) if confdir and os.path.isfile(ca) else ""
    avd = devices.avd_name(adb, serial, runner=lambda argv: run(argv)[:2]) if want else ""
    return bool(avd) and devices._android_records(STATE_ROOT).get(avd) == want


def check_android(rep, adb, port=None, confdir=None):
    sec = "Android emulator"
    adb = adb or which("adb") or os.path.expanduser("~/Library/Android/sdk/platform-tools/adb")
    if not (adb and os.path.exists(adb)):
        rep.add(sec, INFO, "adb not found", "install Android SDK platform-tools to test Android")
        return
    rc, out, _ = run([adb, "devices"])
    if rc is None:
        rep.add(sec, INFO, "adb devices failed", "")
        return
    emulators, physical = [], 0
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            if re.match(r"^emulator-\d+$", parts[0]):
                emulators.append(parts[0])
            else:
                physical += 1
    if physical:
        rep.add(sec, INFO, "%d physical device(s) ignored" % physical,
                "physical devices need a separate approval; %s refuses them" % PRODUCT["name"])
    if not emulators:
        rep.add(sec, INFO, "no running emulator", "start a Google-image AVD to test Android")
        return
    for s in emulators:
        rc, prox, _ = run([adb, "-s", s, "shell", "settings", "get", "global", "http_proxy"])
        prox = (prox or "").strip()
        if prox in ("", "null", ":0"):
            rep.add(sec, INFO, "%s: no http_proxy set" % s, "run `%s android on`" % PRODUCT["cli"])
        else:
            # a proxy on the Mac (10.0.2.2 = the Mac from the emulator) with nothing listening = no network at all on
            # the emulator: doctor called that healthy (overnight QA r1 B-02)
            host, _, pport = prox.rpartition(":")
            if host in ("10.0.2.2", "127.0.0.1", "localhost") and pport.isdigit():
                owners = port_owner(int(pport))
                if not owners:
                    rep.add(sec, ERR, "%s: http_proxy=%s but nothing listens on :%s" % (s, prox, pport),
                            "the emulator has no network until a proxy runs there",
                            "`%s start`%s, or `%s android off`" % (
                                PRODUCT["cli"], "" if port is None or int(pport) == int(port) else
                                " on that port (%s_PORT=%s)" % (PRODUCT["env_prefix"], pport), PRODUCT["cli"]))
                elif port is not None and int(pport) != int(port):
                    rep.add(sec, WARN, "%s: http_proxy=%s is not this %s (:%s)" % (s, prox, PRODUCT["name"], port),
                            "owned by %s (pid %s)" % (owners[0]["command"], owners[0]["pid"]),
                            "`%s android on` points it at this %s" % (PRODUCT["cli"], PRODUCT["name"]))
                else:
                    rep.add(sec, OK, "%s: http_proxy=%s" % (s, prox), "")
            else:
                rep.add(sec, OK, "%s: http_proxy=%s" % (s, prox), "")
        # image type
        rc, pkg, _ = run([adb, "-s", s, "shell", "pm", "list", "packages", "com.android.vending"])
        is_play = bool(rc == 0 and "com.android.vending" in (pkg or ""))
        # CA presence (only verifiable with root / non-Play images)
        rc, uid, _ = run([adb, "-s", s, "shell", "id", "-u"])
        if rc == 0 and (uid or "").strip() == "0":
            rc, ls, _ = run([adb, "-s", s, "shell", "ls", "/data/misc/user/0/cacerts-added"])
            n = len([x for x in (ls or "").split() if x.strip()]) if rc == 0 else 0
            if n:
                rep.add(sec, OK, "%s: %d user-store CA(s) present" % (s, n), "")
            else:
                rep.add(sec, WARN, "%s: no user-store CA" % s, "", "`%s android on`" % PRODUCT["cli"])
        elif _android_ca_recorded(adb, s, confdir):
            # R5B-02: a Play image has no root to read the store, but `android on` verified and recorded this CA
            rep.add(sec, OK, "%s: CA installed by `%s android on` (fingerprint matches)" % (s, PRODUCT["cli"]), "")
            continue
        else:
            img = "Google Play image" if is_play else "image"
            rep.add(sec, INFO, "%s: %s (no adb root)" % (s, img),
                    "can't read the CA store without root",
                    "check Settings \u2192 Security \u2192 Trusted credentials \u2192 User, or `%s android on`" % PRODUCT["cli"])
        if is_play:
            rep.add(sec, INFO, "%s: Google Play image" % s,
                    "`%s android on` installs the CA with one emulator restart (about 30–40 s)" % PRODUCT["cli"])


def _mask(tok):
    if not tok:
        return ""
    return tok[:4] + "\u2026" if len(tok) > 4 else "\u2026"


def summarize_state(state):
    """Pure: turn a /proxy/api/state document into (lines, flags) for the running-instance check.

    lines: list of (level, title, detail). flags: list of traffic-altering warnings.
    """
    lines, flags = [], []
    project = state.get("active_project") or state.get("project", {}).get("id") or "?"
    rules = state.get("rules") or []
    enabled = [r for r in rules if isinstance(r, dict) and r.get("enabled", True)]  # R3A-07
    lines.append((OK, "running: project %s" % project,
                  "%d rule(s), %d enabled" % (len(rules), len(enabled))))
    bad = [i for i, r in enumerate(rules, 1) if not isinstance(r, dict)]
    if bad:
        lines.append((WARN, "%d rules.json entry(s) are not objects (skipped)" % len(bad),
                      ", ".join("rules.json entry %d is not an object (skipped)" % i for i in bad)))  # R3A-07
    if state.get("rules_error"):    # R2A-08: the proxy keeps the last good rules, so the user's next edits seem to "not work"
        lines.append((WARN, "rules.json is unreadable — the proxy runs the last good copy", str(state["rules_error"])))
    skipped = state.get("skipped_rules") or []
    if skipped:
        names = ", ".join(str(s.get("name", s)) if isinstance(s, dict) else str(s) for s in skipped)
        lines.append((WARN, "%d rule(s) skipped (broken)" % len(skipped), names))
    script_status = state.get("script_status") or {}
    errs = script_status.get("errors") or {}
    if errs:
        lines.append((WARN, "%d script error(s)" % len(errs), ", ".join("%s: %s" % (n, (e.get("message") if isinstance(e, dict) else e)) for n, e in sorted(errs.items()))))  # R3A-06
    # traffic-altering, often-forgotten state
    throttle = state.get("throttle", "off")
    if throttle and throttle != "off":
        flags.append("throttle active: %s (match %s)" % (throttle, state.get("throttle_match", "") or "all"))
    loss = state.get("loss") or 0
    if loss:
        flags.append("packet loss %s%%" % loss)
    blocking = [r.get("name", "?") for r in enabled if r.get("action") in ("block", "respond", "map_local", "status", "json_patch", "map_remote")]
    if blocking:
        # R4A-03: a large hot-reloaded rules file should not bury the health report in one warning.
        sample = ", ".join(str(n) for n in blocking[:5])
        flags.append("%d rule(s) rewrite/replace traffic: %s%s" % (len(blocking), sample,
                     " +%d more (%s rules list)" % (len(blocking) - 5, PRODUCT["cli"]) if len(blocking) > 5 else ""))
    bps = [b for b in (state.get("breakpoints") or []) if b.get("enabled", True)]
    if bps:
        flags.append("%d breakpoint(s) armed — matching calls will pause" % len(bps))
    coll = state.get("collections") or {}
    if coll.get("strict"):
        flags.append("strict replay ON — unrecorded calls get 404")
    replay = [x.get("name", "?") for x in coll.get("items", []) if isinstance(x, dict) and x.get("replay")]
    if replay:
        flags.append("replaying collection(s): %s" % ", ".join(replay))  # R3A-05: state exposes items, not replay list
    tls = state.get("tls") or {}
    if tls.get("mode") and tls["mode"] != "all":
        flags.append("TLS decryption mode=%s (some hosts not decrypted)" % tls["mode"])
    return lines, flags


def _trusted_panel_listener(owners, rules_path):
    """Return (trusted, detail). Never authenticate until the listener is identified as this Rivis run."""
    if len(owners) != 1:
        return False, "expected one listener, found %d" % len(owners)
    owner = owners[0]
    endpoint = owner.get("name", "")
    if not (endpoint.startswith("127.0.0.1:") or endpoint.startswith("localhost:") or
            endpoint.startswith("[::1]:") or endpoint.startswith("::1:")):
        return False, "listener is not bound to loopback (%s)" % (endpoint or "unknown address")
    if not str(owner.get("pid", "")).isdigit():
        return False, "listener PID is unavailable"
    if WIN:
        query = ("$p=Get-CimInstance Win32_Process -Filter 'ProcessId = %s'; "
                 "if ($p) { [Console]::Out.Write($p.CommandLine) }") % owner["pid"]
        rc, out, err = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", query])
        command = out.strip()
        first = ""
    else:
        rc, out, err = run(["ps", "-p", owner["pid"], "-o", "uid=", "-o", "command="])
        first, _, command = out.strip().partition(" ")
    if rc != 0 or not out.strip():
        return False, "cannot inspect listener process: %s" % (err.strip() or "ps failed")
    if not WIN:
        try:
            uid = int(first)
        except ValueError:
            return False, "cannot read listener owner"
        if uid != os.getuid():
            return False, "listener belongs to uid %d" % uid
    expected_panel = os.path.realpath(os.path.join(HERE, "proxy_panel.py"))
    if "mitmweb" not in command or expected_panel not in command:
        return False, "listener command is not this Rivis mitmweb"
    if rules_path:
        expanded = os.path.abspath(os.path.expanduser(rules_path))
        expected_rules = {"proxy_rules_file=" + expanded, "proxy_rules_file=" + os.path.realpath(expanded)}
        if not any(value in command for value in expected_rules):
            return False, "listener serves a different rules file"
    return True, "pid %s" % owner["pid"]


def check_running(rep, web_port, rules_path=""):
    sec = "Running instance"
    owners = port_owner(web_port)
    if not owners:
        rep.add(sec, INFO, "not running", "start it with `%s start`" % PRODUCT["cli"])
        return
    trusted, detail = _trusted_panel_listener(owners, rules_path)
    if not trusted:
        if detail == "listener serves a different rules file":
            rep.add(sec, WARN, "another verified %s project is running on :%d" % (PRODUCT["name"], web_port),
                    detail + "; the saved UI token was not sent",
                    "run doctor with that project's --project, or stop it before starting this project")
            return
        rep.add(sec, ERR, "web port :%d is not a verified %s instance" % (web_port, PRODUCT["name"]),
                detail + "; the saved UI token was not sent",
                "stop the other listener or choose another %s_WEB_PORT" % PRODUCT["env_prefix"])
        return
    tokfile = os.path.join(STATE_ROOT, "web-token" if web_port == 8083 else "web-token-%d" % web_port)  # R4A-05
    if not os.path.isfile(tokfile):
        rep.add(sec, WARN, "something listens on :%d but no %s token found" % (web_port, PRODUCT["name"]),
                "%s absent — likely a different/older instance" % tokfile,
                "if it is a leftover: `%s stop`" % PRODUCT["cli"])
        return
    try:
        with open(tokfile) as fh:
            token = fh.read().strip()
    except OSError as e:
        rep.add(sec, WARN, "running, but the saved UI token is unreadable", str(e),
                "repair the file permissions, or `%s stop` then `%s start`" % (PRODUCT["cli"], PRODUCT["cli"]))
        return
    import http.cookiejar
    import urllib.request
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    base = "http://127.0.0.1:%d" % web_port
    try:
        query = urllib.parse.urlencode({"token": token})
        opener.open(base + "/?" + query, timeout=NET_TIMEOUT).read(1)
        body = opener.open(base + "/proxy/api/state?" + query, timeout=NET_TIMEOUT).read()
        state = json.loads(body.decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        rep.add(sec, WARN, "running, but the saved token did not authenticate (HTTP %d)" % e.code,
                "token %s in %s may be stale (a later run overwrote it)" % (_mask(token), tokfile),
                "reopen with `%s ui`, or `%s stop` then `%s start`" % (PRODUCT["cli"], PRODUCT["cli"], PRODUCT["cli"]))
        return
    except (urllib.error.URLError, OSError, ValueError) as e:
        rep.add(sec, WARN, "running, but could not read its state", str(e))
        return
    lines, flags = summarize_state(state)
    rep.running_state = state
    for lvl, title, detail in lines:
        rep.add(sec, lvl, title, detail)
    for f in flags:
        fix = ("turn off Replay / Strict replay in Tools → Collections" if "replay" in f.lower() else
               "clear it: `%s throttle off`, `%s rules off NAME`, `%s breakpoint off`" %
               (PRODUCT["cli"], PRODUCT["cli"], PRODUCT["cli"]))  # R3A-05
        rep.add(sec, WARN, "traffic is being changed: " + f,
                "if the app looks broken, this may be why",
                fix)


CERT_CATEGORIES = ("cert_expired", "cert_san_mismatch", "cert_untrusted")


def _peer_cert_not_after(host, port=443):
    """Expiry of the certificate the host serves (unverified handshake, no credentials sent); None if unreadable."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=NET_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        return _der_cert_dates(der)[1] if der else None
    except (OSError, ValueError, ssl.SSLError):
        return None


def check_network(rep, project, no_net, allow_profile_network=False):
    sec = "Network"
    try:
        profile = project_profile(project)
    except ValueError:
        profile = {}
    hosts = profile.get("doctor_hosts") or []
    if not isinstance(hosts, list) or not hosts:
        rep.add(sec, INFO, "no doctor_hosts in the %s profile" % project,
                "add a \"doctor_hosts\" list to project.json to enable reachability checks")
        return
    if no_net:
        rep.add(sec, SKIP, "network checks skipped (--no-net)", "%d host(s) not probed" % len(hosts))
        return
    override = os.path.join(STATE_ROOT, "profiles", project, "project.json")
    if os.path.isfile(override) and not allow_profile_network:
        rep.add(sec, SKIP, "network checks skipped for a user profile",
                "%d doctor_hosts not probed without explicit consent" % len(hosts),
                "rerun with --allow-profile-network after reviewing %s" % override)
        return
    # this probe verifies the certificate itself; a running Rivis started with --insecure does not, so a certificate
    # problem here does not affect traffic through it
    state = getattr(rep, "running_state", None) or {}
    insecure = bool(state.get("ssl_insecure"))
    tls = tls_config({"tls": state.get("tls") or {}})
    for host in hosts:
        cat = _probe_host(str(host))
        lvl, msg, fix = NET_EXPLAIN.get(cat, (WARN, cat, ""))
        detail = ""
        if cat == "cert_expired":
            not_after = _peer_cert_not_after(str(host))
            if not_after:
                msg = "server certificate expired on %s" % time.strftime("%Y-%m-%d", time.gmtime(not_after))
        decrypted = tls["mode"] == "all" or (tls["mode"] == "allow" and bool(tls_covering(tls, host, "allow"))) or \
            (tls["mode"] == "ignore" and not tls_covering(tls, host, "ignore"))
        if insecure and decrypted and cat in CERT_CATEGORIES:
            lvl, fix = INFO, ""
            detail = "the running %s skips upstream verification (--insecure), so its traffic is not affected" % PRODUCT["name"]
        rep.add(sec, lvl, "%s: %s" % (host, msg), detail, fix)


def _probe_host(host, port=443):
    # DNS
    try:
        socket.setdefaulttimeout(NET_TIMEOUT)
        addrs = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return classify_network_failure("dns", type(e).__name__, str(e))
    except OSError as e:
        return classify_network_failure("dns", type(e).__name__, str(e))
    # TCP: every resolved address in turn (an unreachable IPv6 answer first must not hide a working IPv4 one)
    sock, err, seen = None, None, set()
    for family, _, _, _, sockaddr in addrs:
        if sockaddr[:2] in seen:
            continue
        seen.add(sockaddr[:2])
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(NET_TIMEOUT)
        try:
            s.connect(sockaddr)
            sock = s
            break
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            err = e
            s.close()
    if sock is None:
        return classify_network_failure("tcp", type(err).__name__, str(err))
    # TLS (no credentials ever sent — handshake only)
    try:
        ctx = ssl.create_default_context()
        trust = os.path.join(STATE_ROOT, "upstream-trust.pem")   # what Rivis itself trusts upstream (rivis start)
        if os.path.isfile(trust):
            ctx.load_verify_locations(cafile=trust)
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            tls.getpeercert()
        return "ok"
    except ssl.SSLCertVerificationError as e:
        return classify_network_failure("tls", type(e).__name__, getattr(e, "verify_message", "") or str(e))
    except ssl.SSLError as e:
        return classify_network_failure("tls", type(e).__name__, str(e))
    except (socket.timeout, ConnectionResetError, OSError) as e:
        return classify_network_failure("tls", type(e).__name__, str(e))
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _dir_size_and_largest(root):
    total, files = 0, []
    for base, _dirs, names in os.walk(root):
        for name in names:
            p = os.path.join(base, name)
            try:
                sz = os.path.getsize(p)
            except OSError:
                continue
            total += sz
            files.append((sz, p))
    files.sort(reverse=True)
    return total, files


def _human(n):
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return "%.1f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1024.0


def check_disk(rep, project):
    sec = "Disk"
    if not os.path.isdir(STATE_ROOT):
        rep.add(sec, INFO, "state dir not created yet", STATE_ROOT)
    else:
        total, _ = _dir_size_and_largest(STATE_ROOT)
        rep.add(sec, OK, "state dir %s" % _human(total), STATE_ROOT)
        try:
            pstate = project_state(project)
        except ValueError:
            pstate = ""
        biggest = []
        for sub in ("collections", "sessions"):
            d = os.path.join(pstate, sub) if pstate else ""
            if d and os.path.isdir(d):
                _, files = _dir_size_and_largest(d)
                if files:
                    biggest.append((files[0][0], "%s/%s" % (sub, os.path.basename(files[0][1]))))
        if biggest:
            biggest.sort(reverse=True)
            detail = ", ".join("%s (%s)" % (name, _human(sz)) for sz, name in biggest[:3])
            rep.add(sec, INFO, "largest captures", detail)
    try:
        import shutil
        free = shutil.disk_usage(STATE_ROOT if os.path.isdir(STATE_ROOT) else os.path.expanduser("~")).free
        gib = free / (1024.0 ** 3)
        if gib < DISK_FREE_WARN_GIB:
            rep.add(sec, WARN, "low free space: %.1f GiB" % gib,
                    "all-day capture can fill the disk",
                    "delete old sessions/collections in the panel")
        else:
            rep.add(sec, OK, "free space %.1f GiB" % gib)
    except OSError as e:
        rep.add(sec, INFO, "could not read free space", str(e))


def check_python(rep):
    sec = "Python"
    if WIN:
        return
    p = "/usr/bin/python3"
    if not os.path.exists(p):
        rep.add(sec, ERR, "%s is missing" % p,
                "the CLI helpers run on the system Python 3.9",
                "install the Command Line Tools (xcode-select --install)")
        return
    rc, out, err = run([p, "--version"])
    ver = (out or err or "").strip()
    rep.add(sec, OK, "%s (%s)" % (p, ver or "present"),
            "homebrew python must stay unlinked or bare python3 shadows it")


# ───────────────────────── fixes (--fix-safe only) ─────────────────────────
def _fix_net_reset():
    cli = os.path.join(REPO_ROOT, PRODUCT["cli"])
    if not os.path.exists(cli):
        return "cannot find %s" % cli
    rc, out, err = run([cli, "net-reset"], timeout=20)
    return (out or "").strip() or (err or "").strip() or ("rc=%s" % rc)


def _fix_stale_current_project(path):
    def do():
        try:
            os.remove(path)
            return "removed %s (falls back to the default project)" % path
        except OSError as e:
            return "could not remove %s: %s" % (path, e)
    return do


def queue_stale_current_project(rep):
    path = os.path.join(STATE_ROOT, "current-project")
    if not os.path.isfile(path):
        return
    try:
        name = open(path).read().strip()
    except OSError:
        return
    try:
        project_profile(name)
        return   # valid, nothing to fix
    except ValueError:
        rep.add("Project", WARN, "current-project points at a missing project '%s'" % name,
                path, "`%s projects use default` or delete %s" % (PRODUCT["cli"], path))
        rep.fixes.append(("delete stale current-project (%s)" % name,
                          _fix_stale_current_project(path)))


# ───────────────────────── output ─────────────────────────
def render_human(rep, use_color):
    def paint(level, text):
        if not use_color:
            return text
        return "\033[%sm%s\033[0m" % (_COLOR[level], text)
    section = None
    for sec, level, title, detail, fix in rep.items:
        if sec != section:
            section = sec
            print("\n%s" % paint(INFO, section))
        line = "  %s %s" % (paint(level, _SYMBOL[level]), title)
        print(line)
        if detail:
            print("      %s" % detail)
        if fix and level in (WARN, ERR):
            print("      %s %s" % (paint(INFO, "fix:"), fix))
    counts = {OK: 0, WARN: 0, ERR: 0}
    for _, level, _, _, _ in rep.items:
        if level in counts:
            counts[level] += 1
    print("\n%s  %d ok, %d warning(s), %d error(s)" % (
        paint(OK if rep.worst() == 0 else (WARN if rep.worst() == 1 else ERR), "summary:"),
        counts[OK], counts[WARN], counts[ERR]))


def render_json(rep):
    counts = {OK: 0, WARN: 0, ERR: 0, INFO: 0, SKIP: 0}
    checks = []
    for sec, level, title, detail, fix in rep.items:
        counts[level] = counts.get(level, 0) + 1
        checks.append({"section": sec, "level": level, "title": title,
                       "detail": detail, "fix": fix})
    print(json.dumps({
        "product": PRODUCT["name"],
        "summary": {"ok": counts[OK], "warn": counts[WARN], "error": counts[ERR],
                    "info": counts[INFO], "skip": counts[SKIP]},
        "exit": rep.worst(),
        "checks": checks,
    }, indent=2))


def run_fixes(rep, assume_yes):
    if not rep.fixes:
        return
    print("\nSafe fixes available (reversible, never touch the CA/devices/corporate proxy):")
    for label, action in rep.fixes:
        if assume_yes:
            go = True
        else:
            try:
                go = input("  apply: %s ? [y/N] " % label).strip().lower() in ("y", "yes")
            except (EOFError, KeyboardInterrupt):
                go = False
                print()
        if go:
            result = action()
            print("    \u2192 %s" % result)
        else:
            print("    skipped")


def main(argv):
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--project", default="default")
    ap.add_argument("--rules", default="")
    ap.add_argument("--confdir", default=os.path.expanduser("~/.mitmproxy"))
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--web-port", type=int, default=8083)
    ap.add_argument("--script-dir", default="")
    ap.add_argument("--adb", default="")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-net", action="store_true")
    ap.add_argument("--allow-profile-network", action="store_true")
    ap.add_argument("--fix-safe", action="store_true")
    ap.add_argument("--yes", action="store_true")
    args = ap.parse_args(argv)

    rep = Report()
    check_mitmproxy_node(rep)
    check_python(rep)
    check_ca(rep, args.confdir)
    check_sysext(rep)
    check_ports(rep, args.port, args.web_port)
    check_system_proxy(rep)
    check_other_tools(rep)
    check_ios(rep, args.confdir)
    check_android(rep, args.adb, args.port, args.confdir)
    check_running(rep, args.web_port, args.rules)
    check_network(rep, args.project, args.no_net, args.allow_profile_network)
    check_disk(rep, args.project)
    queue_stale_current_project(rep)

    if args.json:
        render_json(rep)
    else:
        use_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        render_human(rep, use_color)
        if args.fix_safe:
            run_fixes(rep, args.yes)

    return rep.worst()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
