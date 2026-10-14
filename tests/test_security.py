"""Security regressions: loopback-only listeners, no outbound connections by Rivis itself, no system-proxy change,
private file modes, no secrets in argv, nothing written outside the state dirs."""
import os
import re
import socket
import stat
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import LiveCase, raw_http

LSOF = "/usr/sbin/lsof"
NETWORKSETUP = "/usr/sbin/networksetup"


def group_pids(pgid):
    out = subprocess.run(["pgrep", "-g", str(pgid)], capture_output=True, text=True).stdout.split()
    return [int(x) for x in out]


def lsof(*args):
    cp = subprocess.run([LSOF, "-nP", "-F", "pcnTP"] + list(args), capture_output=True, text=True, timeout=30)
    return cp.stdout


def sockets(pids, mode):
    """[(pid, command, name, state)] for the given pids. mode: 'listen' or 'all'."""
    if not pids:
        return []
    out = lsof("-a", "-p", ",".join(map(str, pids)), "-i", "TCP" if mode == "listen" else "-i")
    rows, pid, cmd, name = [], None, None, None
    cur = {}
    for line in out.splitlines():
        tag, val = line[0], line[1:]
        if tag == "p":
            pid = int(val)
        elif tag == "c":
            cmd = val
        elif tag == "P":
            cur = {"proto": val}
        elif tag == "n":
            cur["name"] = val
        elif tag == "T" and val.startswith("ST="):
            cur["state"] = val[3:]
        if tag == "T" and val.startswith("ST="):
            rows.append((pid, cmd, cur.get("name"), cur.get("state")))
    if mode == "listen":
        rows = [r for r in rows if r[3] == "LISTEN"]
    return rows


def proxy_state():
    """Everything networksetup/scutil can tell about the system proxy (read-only)."""
    out = {}
    services = subprocess.run([NETWORKSETUP, "-listallnetworkservices"], capture_output=True, text=True).stdout.splitlines()[1:]
    for svc in services:
        svc = svc.lstrip("*")
        for flag in ("-getwebproxy", "-getsecurewebproxy", "-getautoproxyurl", "-getsocksfirewallproxy", "-getproxybypassdomains"):
            out[(svc, flag)] = subprocess.run([NETWORKSETUP, flag, svc], capture_output=True, text=True).stdout
    out["scutil"] = subprocess.run(["scutil", "--proxy"], capture_output=True, text=True).stdout
    return out


def mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


class Network(LiveCase):
    def setUp(self):
        super().setUp()
        self.pids = group_pids(self.inst.proc.pid)

    def test_proxy_and_ui_listen_on_loopback_only(self):
        rows = sockets(self.pids, "listen")
        ports = {int(r[2].rsplit(":", 1)[1]): r[2] for r in rows}
        self.assertIn(self.inst.proxy_port, ports, rows)
        self.assertIn(self.inst.web_port, ports, rows)
        for pid, cmd, name, state in rows:
            self.assertTrue(name.startswith("127.0.0.1:") or name.startswith("[::1]:"), "listening beyond loopback: %s (%s)" % (name, cmd))

    def test_nothing_answers_on_the_lan_address(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.0.2.1", 9))              # no packet is sent; this only asks the kernel for the outbound interface address
            lan = s.getsockname()[0]
        except OSError:
            lan = None
        finally:
            s.close()
        if not lan or lan.startswith("127."):
            self.skipTest("this Mac has no non-loopback IPv4 address to probe")
        for port in (self.inst.proxy_port, self.inst.web_port):
            c = socket.socket()
            c.settimeout(2)
            try:
                self.assertNotEqual(c.connect_ex((lan, port)), 0, "port %d is reachable on %s" % (port, lan))
            finally:
                c.close()

    def test_rivis_makes_no_outbound_connections_of_its_own(self):
        for p in ("/json/small", "/echo", "/text"):
            self.fetch(p)
        self.fetch("/json/small", tls=True)
        self.panel.state()
        for pid, cmd, name, state in sockets(group_pids(self.inst.proc.pid), "all"):
            if state in ("LISTEN", None) and "->" not in (name or ""):
                continue
            peers = re.findall(r"->\[?([0-9a-f:.]+?)\]?:\d+", name or "")
            for peer in peers:
                self.assertIn(peer, ("127.0.0.1", "::1"), "outbound connection to %s from %s (%s)" % (name, cmd, state))

    def test_no_system_proxy_change_while_running_and_working(self):
        before = proxy_state()
        shim_before = self.suite.shim_log("networksetup.log")
        for p in ("/json/small", "/echo"):
            self.fetch(p)
        self.panel.ok("profile", {"id": "3g-urban"})
        self.panel.ok("profile", {"id": "off"})
        self.assertEqual(proxy_state(), before)
        new = self.suite.shim_log("networksetup.log")[len(shim_before):]
        self.assertNotRegex(new, r"(?m)^-set|REFUSED")


class PrivateRelay(LiveCase):
    """Starts without the harness's explicit private-upstream allow-list."""
    INSTANCE_KW = {"start_args": ("--insecure",), "allow_private": False}

    def setUp(self):
        self.up.reset_hits()  # do not use LiveCase.reset_state: its sync endpoint is intentionally private

    def test_plain_proxy_refuses_origin_form_host_header_relay(self):
        """F-01: GET /path + Host must not relay to a local/VPN destination."""
        status, body, _ = raw_http(self.inst.proxy_port, "GET", "/secret",
                                   {"Host": "127.0.0.1:%d" % self.up.http_port, "Connection": "close"})
        self.assertEqual(status, 403)
        self.assertEqual(self.up.hits_for("/secret"), [], "origin-form request reached the Host destination")
        self.assertNotIn(b"RivisUpstream", body)


class FreshCa(LiveCase):
    """The CA the CLI generates itself on first start (no pre-seeded copy)."""
    INSTANCE_KW = {"fresh_ca": True}

    def test_generated_ca_dir_and_files_are_private(self):
        conf = os.path.join(self.inst.home, ".mitmproxy")
        self.assertTrue(os.path.exists(os.path.join(conf, "mitmproxy-ca.pem")))
        self.assertEqual(oct(mode(os.path.join(conf, "mitmproxy-ca.pem"))), "0o600")          # the private key

    def test_generated_public_certificates_and_dir_are_private_too(self):
        conf = os.path.join(self.inst.home, ".mitmproxy")
        loose = sorted((f, oct(mode(os.path.join(conf, f)))) for f in os.listdir(conf) if mode(os.path.join(conf, f)) & 0o077)
        self.assertEqual(loose, [])
        self.assertEqual(oct(mode(conf)), "0o700", ".mitmproxy dir")


class Argv(LiveCase):
    @unittest.expectedFailure
    def test_web_password_is_not_visible_in_the_process_list(self):
        """FOUND-BUGS B11: `rivis start` passes --set web_password=<token> on mitmweb's command line."""
        for pid in group_pids(self.inst.proc.pid):
            args = subprocess.run(["ps", "-ww", "-o", "args=", "-p", str(pid)], capture_output=True, text=True).stdout
            self.assertNotIn(self.inst.password, args, "secret visible in argv of pid %d" % pid)


class Modes(LiveCase):
    def test_state_files_are_0600_and_dirs_0700_after_every_kind_of_write(self):
        self.fetch("/json/small")
        self.panel.ok("sess_save", {"name": "m1", "note": "x"})
        self.panel.ok("coll_record", {"name": "c1"})
        self.fetch("/echo")
        self.panel.ok("coll_stop")
        self.panel.ok("compose_save", {"name": "r1", "spec": {"method": "GET", "url": "https://h.test/"}})
        self.panel.ok("compose_vars", {"vars": {"a": "1"}})
        self.panel.ok("script_new", {"name": "s1", "lang": "py"})
        self.panel.ok("add", {"rule": {"name": "r", "action": "block"}})
        self.panel.ok("bp_add", {"host": "127.0.0.1", "path": "/x", "request": True})
        self.panel.ok("tls_set", {"mode": "all"})
        self.panel.ok("mock", {"flow_id": self.inst.flow_for("/json/small")["id"]})
        self.panel.ok("maplocal_add", {"host": "127.0.0.1", "path": "/mm", "body": "{}"})
        cp = self.suite.run(["/bin/bash", harness.RIVIS, "rules", "add", "cli1", "match=/y", "action=block"], home=self.inst.home, env=dict(self.inst.env))
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        bad = []
        for root in (os.path.join(self.inst.home, ".rivis"),):          # the CA dir is covered by FreshCa
            self.assertTrue(os.path.isdir(root), root)
            for base, dirs, files in os.walk(root):
                for d in dirs + [""]:
                    p = os.path.join(base, d)
                    if mode(p) & 0o077:
                        bad.append((p, oct(mode(p))))
                for f in files:
                    p = os.path.join(base, f)
                    if not os.path.islink(p) and mode(p) & 0o077:
                        bad.append((p, oct(mode(p))))
        self.assertEqual(bad, [], "group/world-accessible state: %s" % bad)

    def test_root_dirs_exist_with_private_modes(self):
        self.assertEqual(oct(mode(os.path.join(self.inst.home, ".rivis"))), "0o700")
        self.assertEqual(oct(mode(self.inst.state_dir)), "0o700")
        self.assertEqual(oct(mode(os.path.join(self.inst.home, ".rivis", "web-token"))), "0o600")

    def test_nothing_is_written_outside_the_state_dirs(self):
        self.fetch("/json/small")
        self.panel.ok("sess_save", {"name": "w1"})
        self.panel.ok("script_new", {"name": "w2", "lang": "js"})
        top = sorted(os.listdir(self.inst.home))
        self.assertEqual(top, [".mitmproxy", ".rivis"], top)


if __name__ == "__main__":
    unittest.main(verbosity=2)
