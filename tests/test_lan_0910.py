"""Real phones and tablets on the Wi-Fi (pilot 2026-10-21: "no physical device support"), opt-in with `start --lan`.

A client that connects from this Mac's own Wi-Fi/Ethernet address is, to the proxy, exactly a phone on the network:
it is refused (with a page saying why) until it is allowed, then captured and shown with the device's name. The setup
page with the certificate opens from http://<address>:<port>/ (the QR code) and from http://rivis.setup/."""
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import Instance, LiveCase, Suite, wait_for

sys.path.insert(0, os.path.join(harness.REPO, "addons"))
import proxy_lan                  # noqa: E402
import qr                         # noqa: E402

LAN = proxy_lan.lan_addresses()
NO_LAN = "this Mac has no private Wi-Fi/Ethernet address to act as a phone from"


def curl(argv, timeout=10):
    tmp = tempfile.mkdtemp()
    out = os.path.join(tmp, "b")
    cp = subprocess.run(["curl", "-sS", "--max-time", str(timeout), "-o", out, "-w", "%{http_code}"] + argv,
                        capture_output=True, timeout=timeout + 10)
    try:
        body = open(out, "rb").read()
    except OSError:
        body = b""
    shutil.rmtree(tmp, ignore_errors=True)
    return int(cp.stdout.decode() or 0), body, cp.returncode, cp.stderr.decode("utf-8", "replace")


@unittest.skipUnless(LAN, NO_LAN)
class LanLive(LiveCase):
    INSTANCE_KW = {"start_args": ("--insecure", "--lan")}

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.ip = LAN[0]
        cls.devices = os.path.join(cls.inst.home, ".rivis", "lan-devices.json")

    def setUp(self):
        super().setUp()
        if os.path.exists(self.devices):
            os.unlink(self.devices)

    def phone(self, url, extra=()):
        """A call through the proxy's Wi-Fi address: the proxy sees it come from this Mac's LAN address."""
        return curl(["--noproxy", "", "-x", "http://%s:%d" % (self.ip, self.inst.proxy_port), "--cacert", self.suite.ca_pem]
                    + list(extra) + [url])

    def test_start_lan_listens_on_the_wifi_address_and_says_so(self):
        out = subprocess.run(["lsof", "-nP", "-a", "-p", str(self._mitmweb_pid()), "-iTCP", "-sTCP:LISTEN"],
                             capture_output=True, text=True).stdout
        self.assertIn("%s:%d" % (self.ip, self.inst.proxy_port), out)
        self.assertIn("127.0.0.1:%d" % self.inst.proxy_port, out)
        self.assertNotIn("*:%d" % self.inst.proxy_port, out, "never every interface (0.0.0.0)")
        self.assertNotIn("%s:%d" % (self.ip, self.inst.web_port), out, "the web UI stays on loopback")
        self.assertIn("LAN    phones and tablets", self.inst.log())
        lan = self.panel.state()["lan"]
        self.assertTrue(lan["on"])
        self.assertIn("%s:%d" % (self.ip, self.inst.proxy_port), lan["addresses"])
        self.assertEqual(lan["setup_urls"][0], "http://%s:%d/" % (self.ip, self.inst.proxy_port))
        self.assertTrue(lan["qr"][0].startswith("<svg"))

    def _mitmweb_pid(self):
        out = subprocess.run(["lsof", "-nP", "-t", "-iTCP:%d" % self.inst.web_port, "-sTCP:LISTEN"], capture_output=True, text=True).stdout
        return int(out.split()[0])

    def test_a_device_is_refused_until_allowed_then_captured_under_its_name(self):
        status, body, rc, err = self.phone(self.up.url("/echo?phone=1"), extra=("-A", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)"))
        self.assertEqual(status, 403)
        self.assertIn(b"not allowed yet", body)
        self.assertEqual(self.up.hits_for("/echo"), [], "a refused device's call never reaches the server")
        status, body, rc, err = self.phone(self.up.url("/echo", tls=True))
        self.assertNotEqual(rc, 0, "HTTPS (CONNECT) from a device that is not allowed is refused too")
        self.assertIn("403", err)
        pending = wait_for(lambda: self.panel.state()["lan"]["pending"], 5, 0.2, "the waiting device")
        self.assertEqual((pending[0]["ip"], pending[0]["name"]), (self.ip, "iPhone"))
        doc = self.panel.ok("lan_allow", {"ip": self.ip, "name": "QA iPhone 15"})
        self.assertEqual(doc["device"]["name"], "QA iPhone 15")
        self.assertEqual(self.panel.state()["lan"]["pending"], [])
        status, body, rc, err = self.phone(self.up.url("/echo?phone=2", tls=True))
        self.assertEqual((rc, status), (0, 200), err)
        flow = self.inst.flow_for("/echo?phone=2")
        src = wait_for(lambda: self._source(flow["client_conn"]["id"]), 5, 0.2, "the call's source")
        self.assertEqual((src["kind"], src["device"]), ("phone", "QA iPhone 15"))
        cp = self.suite.rivis("lan", "rm", self.ip, home=self.inst.home, env=self.inst.env)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        wait_for(lambda: self.phone(self.up.url("/echo?phone=3"))[0] == 403, 5, 0.2, "refused again after rm")

    def _source(self, conn_id):
        s = self.panel.state().get("sources") or {}
        key = (s.get("by_conn") or {}).get(conn_id)
        return next((r for r in s.get("list") or [] if r["key"] == key), None) if key else None

    def test_setup_page_opens_without_a_proxy_and_through_it(self):
        base = "http://%s:%d/" % (self.ip, self.inst.proxy_port)
        status, body, rc, err = curl(["--noproxy", "*", base])           # the QR code: the phone has no proxy yet
        self.assertEqual(status, 200, err)
        self.assertIn(b"Waiting for the Mac", body)
        self.assertIn(("Server <code>%s</code>, port <code>%d</code>" % (self.ip, self.inst.proxy_port)).encode(), body)
        status, pem, rc, err = curl(["--noproxy", "*", base + "rivis-ca.pem"])
        self.assertEqual(status, 200)
        with open(self.suite.ca_pem, "rb") as fh:
            self.assertEqual(pem, fh.read())
        self.assertEqual(curl(["--noproxy", "*", base + "nothing"])[0], 404)
        self.assertEqual(self.up.hits, [], "the setup page never goes upstream")
        self.panel.ok("lan_allow", {"ip": self.ip})
        status, body, rc, err = self.phone("http://rivis.setup/")
        self.assertEqual(status, 200, err)
        self.assertIn(b"This device is allowed", body)
        r = self.inst.fetch("http://rivis.setup/rivis-ca.crt")
        self.assertEqual(r.status, 200, "an emulator (loopback) can open the setup page too")
        self.assertIn(b"BEGIN CERTIFICATE", r.body)

    def test_rules_never_answer_for_a_refused_device_or_the_setup_page(self):
        self.reset_state(rules=[self.rule("everything", "respond", ".", status=299, body="mocked")])
        status, body, rc, err = self.phone(self.up.url("/echo?mock=1"))
        self.assertEqual(status, 403)
        status, body, rc, err = curl(["--noproxy", "*", "http://%s:%d/" % (self.ip, self.inst.proxy_port)])
        self.assertEqual(status, 200)
        self.assertIn(b"Set up this device", body)
        self.assertEqual(self.inst.fetch(self.up.url("/echo?mock=2")).status, 299, "the Mac's own calls still get the rule")

    def test_panel_dismiss_and_remove(self):
        self.assertEqual(self.phone(self.up.url("/echo?d=1"))[0], 403)
        wait_for(lambda: self.panel.state()["lan"]["pending"], 5, 0.2, "waiting device")
        self.panel.ok("lan_dismiss", {"ip": self.ip})
        self.assertEqual(self.panel.state()["lan"]["pending"], [], "Ignore takes it off the waiting list")
        self.panel.ok("lan_allow", {"ip": self.ip, "name": "Tab"})
        self.assertEqual(self.phone(self.up.url("/echo?d=2"))[0], 200)
        self.panel.ok("lan_rm", {"ip": self.ip})
        self.assertEqual(self.panel.state()["lan"]["devices"], [])
        self.assertEqual(self.phone(self.up.url("/echo?d=3"))[0], 403)
        code, doc, raw = self.panel.post("lan_rm", {"ip": self.ip})
        self.assertGreaterEqual(code, 400)
        self.assertIn(b"not in the list", raw)
        code, doc, raw = self.panel.post("lan_allow", {"ip": "127.0.0.1"})
        self.assertGreaterEqual(code, 400)

    def test_cli_lan_allow_list_rm(self):
        env, home = self.inst.env, self.inst.home
        self.assertIn("no devices allowed", self.suite.rivis("lan", home=home, env=env).stdout)
        cp = self.suite.rivis("lan", "allow", self.ip, "Pixel 8", home=home, env=env)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("%s" % self.ip, self.suite.rivis("lan", "list", home=home, env=env).stdout)
        wait_for(lambda: self.phone(self.up.url("/echo?cli=1"))[0] == 200, 5, 0.2, "allowed from the CLI, no restart")
        self.assertEqual(os.stat(self.devices).st_mode & 0o777, 0o600)
        self.assertNotEqual(self.suite.rivis("lan", "allow", "127.0.0.1", home=home, env=env).returncode, 0)
        self.assertNotEqual(self.suite.rivis("lan", "allow", "not-an-ip", home=home, env=env).returncode, 0)
        self.assertEqual(self.suite.rivis("lan", "rm", self.ip, home=home, env=env).returncode, 0)
        self.assertNotEqual(self.suite.rivis("lan", "rm", self.ip, home=home, env=env).returncode, 0)


@unittest.skipUnless(LAN, NO_LAN)
class LanOffByDefault(unittest.TestCase):
    def test_without_lan_nothing_listens_on_the_wifi_address(self):
        suite = Suite.get()
        inst = Instance(suite, "lanoff").start()
        try:
            with socket.socket() as s:
                s.settimeout(2)
                self.assertNotEqual(s.connect_ex((LAN[0], inst.proxy_port)), 0, "the default proxy is loopback-only")
            self.assertFalse(inst.panel.state()["lan"]["on"])
            self.assertNotIn("LAN    phones", inst.log())
        finally:
            inst.stop()


class LanUnit(unittest.TestCase):
    IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet6 fe80::1%en0 prefixlen 64 secured scopeid 0xe
\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255
\tstatus: active
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 169.254.3.4 netmask 0xffff0000
\tinet 10.1.2.3 netmask 0xffff0000
\tstatus: active
en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 172.16.9.9 netmask 0xffff0000
\tstatus: inactive
utun5: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400
\tinet 10.212.135.10 --> 10.212.135.10 netmask 0xffffffff
bridge100: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.64.1 netmask 0xffffff00 broadcast 192.168.64.255
\tstatus: active
en9: flags=8863<UP> mtu 1500
\tinet 8.8.4.4 netmask 0xffffff00
"""

    def test_only_private_wifi_and_ethernet_addresses(self):
        self.assertEqual(proxy_lan.lan_addresses(self.IFCONFIG), ["192.168.1.20", "10.1.2.3", "192.168.64.1"])

    def test_device_names_from_the_user_agent(self):
        self.assertEqual(proxy_lan.guess_name("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)"), "iPhone")
        self.assertEqual(proxy_lan.guess_name("Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/AP1A) Chrome/120"), "Android Pixel 8")
        self.assertEqual(proxy_lan.guess_name("Mozilla/5.0 (Linux; Android 10; K) Chrome/120"), "Android")
        self.assertEqual(proxy_lan.guess_name("okhttp/4.12"), "Device")
        self.assertEqual(proxy_lan.clean_name("<b>evil|</b>\n"), "bevil/b")

    def test_devices_file(self):
        path = os.path.join(Suite.get().new_home("lanfile"), "lan-devices.json")
        d = proxy_lan.Devices(path)
        d.allow("::ffff:192.168.1.5", "Tab")
        self.assertEqual(d.get("192.168.1.5")["name"], "Tab")
        d.allow("192.168.1.5", "Tab 2")                       # rename keeps one row
        self.assertEqual([r["name"] for r in proxy_lan.Devices(path).rows()], ["Tab 2"])
        for bad in ("127.0.0.1", "::1", "x"):
            with self.assertRaises(ValueError):
                d.allow(bad)
        self.assertTrue(d.remove("192.168.1.5"))
        self.assertFalse(d.remove("192.168.1.5"))


DECODER = None
if sys.platform == "darwin" and shutil.which("xcrun"):
    DECODER = """import CoreImage
import Foundation
for path in CommandLine.arguments.dropFirst() {
    let img = CIImage(contentsOf: URL(fileURLWithPath: path))!
    let det = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])!
    print(det.features(in: img).compactMap { ($0 as? CIQRCodeFeature)?.messageString }.first ?? "NONE")
}
"""


class QrCode(unittest.TestCase):
    TEXTS = ["http://192.168.17.92:8080/", "http://10.0.0.5:18480/", "A", "http://192.168.100.200:65535/setup?code=123456",
             "x" * 60, "http://" + "a" * 90 + "/", "مرحبا http://1.2.3.4:8080/"]

    def test_sizes_and_limits(self):
        self.assertEqual(len(qr.matrix("A")), 21)                 # version 1
        self.assertEqual(len(qr.matrix("x" * 106)), 41)           # version 6, the largest
        with self.assertRaises(ValueError):
            qr.matrix("x" * 107)
        self.assertIn('viewBox="0 0 33 33"', qr.svg("http://192.168.17.92:8080/"))

    @unittest.skipUnless(DECODER, "needs macOS CoreImage (swift) to read the codes back")
    def test_a_real_decoder_reads_every_code_back(self):
        tmp = tempfile.mkdtemp(dir=Suite.get().root)
        src = os.path.join(tmp, "decode.swift")
        with open(src, "w") as fh:
            fh.write(DECODER)
        exe = os.path.join(tmp, "decode")
        cp = subprocess.run(["xcrun", "swiftc", "-O", src, "-o", exe], capture_output=True, text=True, timeout=240)
        if cp.returncode != 0:
            self.skipTest("swiftc could not build the decoder: " + cp.stderr[-200:])
        paths = []
        for i, t in enumerate(self.TEXTS):
            paths.append(os.path.join(tmp, "q%d.png" % i))
            with open(paths[-1], "wb") as fh:
                fh.write(qr.png(t))
        out = subprocess.run([exe] + paths, capture_output=True, text=True, timeout=60).stdout.splitlines()
        self.assertEqual(out, self.TEXTS)


if __name__ == "__main__":
    harness.main()
