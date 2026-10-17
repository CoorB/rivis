"""Security regressions: loopback-only listeners, no outbound connections by Rivis itself, no system-proxy change,
private file modes, no secrets in argv, nothing written outside the state dirs."""
import json
import os
import re
import shutil
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


def _vpnapp_profile(inst):
    """A project whose own server is on a private address (the suite's upstream on 127.0.0.1, like an app whose
    servers resolve to VPN addresses through internal DNS)."""
    d = os.path.join(inst.home, ".rivis", "profiles", "vpnapp")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "project.json"), "w") as fh:
        json.dump({"id": "vpnapp", "label": "VPN app", "description": "servers on private addresses", "hosts": "localhost",
                   "record_match": ".", "throttle_match": ".", "android_packages": [], "ios_bundle_ids": []}, fh)
    shutil.copy(os.path.join(harness.REPO, "projects", "default", "rules.example.json"), d)


class ProjectServersOnPrivateAddresses(LiveCase):
    """2026-10-16, a tester's Mac: the NEO servers resolved to private VPN addresses, so the F-01 relay guard answered
    every app call with 403. The project's own declared hosts are now allowed there — by name, and only when the
    address the app connected to is what that name resolves to. No --allow-private-hosts here."""
    PROJECT = "vpnapp"
    INSTANCE_KW = {"start_args": ("--insecure",), "allow_private": False, "pre": _vpnapp_profile}

    def setUp(self):
        self.up.reset_hits()

    def test_a_project_host_on_a_private_address_is_allowed(self):
        r = self.inst.fetch("http://localhost:%d/json/small?ph=1" % self.up.http_port)
        self.assertEqual(r.status, 200)
        self.assertTrue(self.up.hits_for("/json/small"))

    def test_the_simulator_case_ip_destination_with_its_project_name_is_allowed(self):
        # local capture records the server IP as the destination; the name travels in the Host header / SNI
        status, body, _ = raw_http(self.inst.proxy_port, "GET", "http://127.0.0.1:%d/json/small?ph=2" % self.up.http_port,
                                   {"Host": "localhost:%d" % self.up.http_port, "Connection": "close"})
        self.assertEqual(status, 200, body[:120])

    def test_a_bare_private_ip_is_still_refused(self):
        r = self.inst.fetch("http://127.0.0.1:%d/json/small?ph=3" % self.up.http_port)
        self.assertEqual(r.status, 403)
        self.assertEqual(self.up.hits_for("/json/small"), [])

    def test_a_project_name_cannot_borrow_another_private_address(self):
        status, _, _ = raw_http(self.inst.proxy_port, "GET", "http://10.255.255.1:9/x",
                                {"Host": "localhost", "Connection": "close"})
        self.assertEqual(status, 403)

    def test_origin_form_relay_is_still_refused(self):
        status, _, _ = raw_http(self.inst.proxy_port, "GET", "/secret",
                                {"Host": "127.0.0.1:%d" % self.up.http_port, "Connection": "close"})
        self.assertEqual(status, 403)
        self.assertEqual(self.up.hits_for("/secret"), [])


class FreshInstallServersOnPrivateAddresses(LiveCase):
    """2026-10-16, the pilot's first install: the tester's Mac resolved the app's servers to private VPN addresses and
    every call got 403. 0.9.5 only let the ACTIVE project's declared hosts through, but a fresh install runs the
    `default` project, which declares none. Only a plain-HTTP request on the proxy port can be aimed at a private
    address by a web page (F-01, origin-form / DNS rebinding); HTTPS tunnels, simulator capture and the panel's own
    Repeat cannot, so they reach private addresses on any project."""
    INSTANCE_KW = {"start_args": ("--insecure",), "allow_private": False}

    def setUp(self):
        self.up.reset_hits()

    def test_https_to_a_name_on_a_private_address_works_on_the_default_project(self):
        r = self.inst.fetch("https://localhost:%d/json/small?fi=1" % self.up.https_port)
        self.assertEqual(r.status, 200)
        self.assertTrue(self.up.hits_for("/json/small"))

    def test_https_to_a_private_ip_works_like_simulator_capture(self):
        r = self.inst.fetch(self.up.url("/json/small?fi=2", tls=True))
        self.assertEqual(r.status, 200)

    def test_repeat_of_a_private_https_call_works(self):
        self.inst.fetch(self.up.url("/json/small?fi=3", tls=True))
        fid = self.inst.flow_for("/json/small?fi=3")["id"]
        before = len(self.up.hits_for("/json/small?fi=3"))
        self.panel.ok("retry", {"flow_id": fid, "edits": {}})
        harness.wait_for(lambda: len(self.up.hits_for("/json/small?fi=3")) > before, 10, 0.2, "repeat reached upstream")

    def test_plain_http_to_a_private_address_is_still_refused_with_the_fix_in_the_message(self):
        r = self.inst.fetch("http://localhost:%d/json/small?fi=4" % self.up.http_port)
        self.assertEqual(r.status, 403)
        self.assertEqual(self.up.hits_for("/json/small"), [])
        self.assertIn(b"--allow-private-hosts", r.body)

    def test_origin_form_relay_is_still_refused(self):
        status, _, _ = raw_http(self.inst.proxy_port, "GET", "/secret",
                                {"Host": "127.0.0.1:%d" % self.up.http_port, "Connection": "close"})
        self.assertEqual(status, 403)
        self.assertEqual(self.up.hits_for("/secret"), [])

    def test_a_page_in_the_rivis_browser_cannot_reach_a_private_https_address_cross_site(self):
        # night QA lane C1: a public page open in `rivis browser` (which trusts the Rivis CA) fetched a private HTTPS
        # address through the tunnel. Browsers mark such requests Sec-Fetch-Site: cross-site; apps never send it.
        url = "https://localhost:%d/json/small?cs=" % self.up.https_port
        r = self.inst.fetch(url + "1", headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors"})
        self.assertEqual(r.status, 403)
        self.assertEqual(self.up.hits_for("/json/small?cs=1"), [])
        self.assertEqual(self.inst.fetch(url + "2", headers={"Sec-Fetch-Site": "same-origin"}).status, 200)
        self.assertEqual(self.inst.fetch(url + "3", headers={"Sec-Fetch-Site": "none"}).status, 200)   # typed URL


class DnsRebindingPlainHttp(LiveCase):
    """Night QA A3: the guard looked the name up once to judge it and mitmproxy looked it up again to
    connect, so DNS that flips between the two (rebinding) reached a private address with plain HTTP. The checked
    address is now the one connected to."""
    INSTANCE_KW = {"start_args": ("--insecure",), "allow_private": False,
                   "extra_env": {"SHIM_PRE_ADDON": os.path.join(harness.REPO, "tests", "fakes", "dns_flip.py")}}

    def setUp(self):
        self.up.reset_hits()

    def test_a_name_that_flips_to_loopback_after_the_check_never_reaches_it(self):
        r = self.inst.fetch("http://a.rebind.rivis-test:%d/json/small?rb=1" % self.up.http_port, timeout=4)
        self.assertNotEqual(r.status, 200)
        self.assertEqual(self.up.hits_for("/json/small"), [], "the rebound address was reached")


class GuardLookups(LiveCase):
    """Night QA lane A6: the guard's DNS lookup blocked mitmproxy's event loop, so one slow name stalled every other
    call. And a lookup that failed let the request through unpinned, for mitmproxy to resolve again."""
    INSTANCE_KW = {"start_args": ("--insecure",), "allow_private": False,
                   "extra_env": {"SHIM_PRE_ADDON": os.path.join(harness.REPO, "tests", "fakes", "dns_flip.py")}}

    def setUp(self):
        self.up.reset_hits()

    def test_a_slow_lookup_does_not_stall_other_calls(self):
        import threading
        import time as _time
        t = threading.Thread(target=lambda: self.inst.fetch("http://a.slow.rivis-test:%d/x?slow=1" % self.up.http_port,
                                                            timeout=6), daemon=True)
        t.start()
        _time.sleep(0.5)                                  # the slow lookup is now in progress
        start = _time.monotonic()
        r = self.inst.fetch(self.up.url("/json/small?fast=1", tls=True))
        self.assertEqual(r.status, 200)
        self.assertLess(_time.monotonic() - start, 2.0, "an unrelated HTTPS call waited for another call's DNS lookup")
        t.join(8)

    def test_a_failed_lookup_is_answered_not_retried_by_mitmproxy(self):
        r = self.inst.fetch("http://b.nx.rivis-test:%d/json/small?nx=1" % self.up.http_port, timeout=5)
        self.assertNotEqual(r.status, 200)
        self.assertEqual(self.up.hits_for("/json/small?nx=1"), [])


class PinKeepsTheName(LiveCase):
    """Night QA lane C4: an HTTP/1.0 absolute-form request with no Host header showed (and Copy URL gave) the pinned
    IP instead of the name the app asked for."""
    INSTANCE_KW = {"start_args": ("--insecure",), "allow_private": False,
                   "extra_env": {"SHIM_PRE_ADDON": os.path.join(harness.REPO, "tests", "fakes", "dns_flip.py")}}

    def test_http10_without_host_keeps_the_name(self):
        s = socket.create_connection(("127.0.0.1", self.inst.proxy_port), timeout=3)
        try:
            s.sendall(b"GET http://c.rebind.rivis-test:%d/echo?nohost=1 HTTP/1.0\r\n\r\n" % self.up.http_port)
            try:
                s.recv(100)
            except OSError:
                pass
        finally:
            s.close()
        req = self.inst.flow_for("nohost=1")["request"]
        self.assertEqual(req.get("pretty_host"), "c.rebind.rivis-test", req)


class SecondStart(LiveCase):
    """Night QA lane B F4: the installer offers to start Rivis, then the quickstart says `rivis start --background`;
    the second start failed with 'port already taken: mitmweb … run: rivis stop'. It now says it is running, exit 0."""

    def test_a_second_start_reports_the_running_instance_and_leaves_it_alone(self):
        pids_before = group_pids(self.inst.proc.pid)
        cp = self.suite.rivis("start", "--background", "--no-open", "--no-ios", home=self.inst.home, env=dict(self.inst.env))
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("already running", cp.stdout)
        self.assertEqual(group_pids(self.inst.proc.pid), pids_before)
        self.assertEqual(self.fetch("/json/small?ss=1").status, 200)


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
    def test_web_password_is_not_visible_in_the_process_list(self):
        """FOUND-BUGS B11: `rivis start` passes --set web_password=<token> on mitmweb's command line."""
        for pid in group_pids(self.inst.proc.pid):
            args = subprocess.run(["ps", "-ww", "-o", "args=", "-p", str(pid)], capture_output=True, text=True).stdout
            self.assertNotIn(self.inst.password, args, "secret visible in argv of pid %d" % pid)

    def test_ui_command_uses_a_one_time_bootstrap_not_the_password(self):
        before = self.suite.shim_log("open.log")
        cp = self.suite.rivis("ui", home=self.inst.home, env=dict(self.inst.env))
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        opened = self.suite.shim_log("open.log")[len(before):].strip().splitlines()[-1]
        self.assertIn("/proxy/bootstrap/", opened)
        self.assertNotIn(self.inst.password, opened)
        self.assertNotIn("?token=", opened)

        import http.cookiejar
        import urllib.request
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), urllib.request.ProxyHandler({}))
        self.assertEqual(opener.open(opened, timeout=10).status, 200)
        self.assertEqual(opener.open(self.panel.base + "/proxy/api/state", timeout=10).status, 200)


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
        self.panel.ok("add", {"rule": {"name": "r", "match": "/r-only", "action": "block"}})
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
