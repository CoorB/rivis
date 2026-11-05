"""DNS Spoofing: host → IP (or hostname). Listed calls keep the original URL and Host; bytes go to the spoofed
address. No system DNS change. Distinct from Map Remote, which rewrites the URL."""
import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _paths  # noqa: F401,E402
import proxy_common  # noqa: E402
import harness  # noqa: E402
from harness import LiveCase, Suite, wait_for  # noqa: E402
import test_cli  # noqa: E402


class Normalize(unittest.TestCase):
    def test_host_and_address_shapes(self):
        self.assertEqual(proxy_common.normalize_dns_host("API.Prod.Example."), "api.prod.example")
        self.assertEqual(proxy_common.normalize_dns_address("127.0.0.1"), "127.0.0.1")
        self.assertEqual(proxy_common.normalize_dns_address("::1"), "::1")
        self.assertEqual(proxy_common.normalize_dns_address("[::1]"), "::1")
        self.assertEqual(proxy_common.normalize_dns_address("Staging.Example."), "staging.example")
        for bad in ("", "http://x", "x/y", "x:8080", "*.example.test", "a b"):
            with self.assertRaises(ValueError):
                proxy_common.normalize_dns_host(bad)
        for bad in ("", "http://x", "x/y", "x:8080", "a b"):
            with self.assertRaises(ValueError):
                proxy_common.normalize_dns_address(bad)

    def test_list_last_entry_wins_and_off_is_dropped_from_map(self):
        cfg = {"dns_spoof": [
            {"host": "a.example", "address": "10.0.0.1"},
            {"host": "A.Example", "address": "10.0.0.2"},
            {"host": "b.example", "address": "10.0.0.3", "enabled": False},
        ]}
        rows = proxy_common.dns_spoof_list(cfg)
        self.assertEqual([(r["host"], r["address"]) for r in rows],
                         [("a.example", "10.0.0.2"), ("b.example", "10.0.0.3")])
        self.assertEqual(proxy_common.dns_spoof_map(cfg), {"a.example": "10.0.0.2"})


class Wire(LiveCase):
    def test_spoof_keeps_host_header_and_hits_the_local_server(self):
        host = "spoof.example.test"
        self.reset_state(dns_spoof=[{"host": host, "address": "127.0.0.1", "enabled": True}])
        url = "http://%s:%d/echo?dns-spoof=1" % (host, self.up.http_port)
        r = wait_for(lambda: (lambda x: x if x.status == 200 else None)(self.inst.fetch(url)),
                     12, 0.2, "spoofed call")
        self.assertEqual(r.status, 200, r)
        doc = r.json()
        got = [v for k, v in doc["headers"] if k.lower() == "host"]
        expect = "%s:%d" % (host, self.up.http_port)
        self.assertEqual(got, [expect], "Host header was rewritten: %r" % got)
        self.assertTrue(self.up.hits_for("/echo?dns-spoof=1"), "spoofed call never reached 127.0.0.1")
        f = self.inst.flow_for("dns-spoof=1")
        req = f.get("request") or {}
        self.assertEqual(req.get("pretty_host"), host, "listed call lost the original host: %r" % req)
        self.assertIn("dns-spoof", f.get("comment") or "")

    def test_without_a_spoof_the_unknown_host_does_not_reach_the_server(self):
        self.reset_state(dns_spoof=[])
        before = len(self.up.hits)
        url = "http://spoof.example.test:%d/echo?dns-none=1" % self.up.http_port
        r = self.inst.fetch(url, timeout=8)
        self.assertNotEqual(r.status, 200, "call reached the server with no spoof: %r" % r)
        self.assertEqual(len(self.up.hits), before)

    def test_https_spoof_keeps_host_and_hits_the_local_server(self):
        host = "spoof-tls.example.test"
        self.reset_state(dns_spoof=[{"host": host, "address": "127.0.0.1", "enabled": True}])
        url = "https://%s:%d/echo?dns-spoof-tls=1" % (host, self.up.https_port)
        r = wait_for(lambda: (lambda x: x if x.rc == 0 and x.status == 200 else None)(self.inst.fetch(url)),
                     12, 0.2, "https spoofed call")
        self.assertEqual((r.rc, r.status), (0, 200), r)
        got = [v for k, v in r.json()["headers"] if k.lower() == "host"]
        expect = "%s:%d" % (host, self.up.https_port)
        self.assertEqual(got, [expect], "Host header was rewritten: %r" % got)
        self.assertTrue(self.up.hits_for("/echo?dns-spoof-tls=1"), "https spoofed call never reached 127.0.0.1")
        f = self.inst.flow_for("dns-spoof-tls=1")
        req = f.get("request") or {}
        self.assertEqual(req.get("pretty_host"), host, "listed call lost the original host: %r" % req)
        self.assertIn("dns-spoof", f.get("comment") or "")

    def test_panel_add_and_rm_drive_the_next_call(self):
        host = "panel-spoof.example.test"
        self.inst.panel.ok("dns_add", {"host": host, "address": "127.0.0.1"})
        wait_for(lambda: any(e["host"] == host for e in self.inst.panel.state().get("dns_spoof") or []),
                 5, 0.1, "panel state lists the spoof")
        url = "http://%s:%d/echo?dns-panel=1" % (host, self.up.http_port)
        r = wait_for(lambda: (lambda x: x if x.status == 200 else None)(self.inst.fetch(url)),
                     12, 0.2, "panel spoof applied")
        self.assertEqual(r.status, 200, r)
        self.inst.panel.ok("dns_rm", {"host": host})
        wait_for(lambda: not any(e["host"] == host for e in self.inst.panel.state().get("dns_spoof") or []),
                 5, 0.1, "removed")
        before = len(self.up.hits)
        self.assertNotEqual(self.inst.fetch(url, timeout=8).status, 200)
        self.assertEqual(len(self.up.hits), before)


class HttpsPin(unittest.TestCase):
    def test_trailing_dot_host_still_pins_for_server_connect(self):
        """Map lookup strips a trailing FQDN dot; the HTTPS pin key must keep it so server_connect hits.

        Live curl cannot ask for https://host.:port (LibreSSL: invalid name syntax), so a mitmdump probe
        drives the hook pair with a hand-built flow (same idiom as the private-address guard probe)."""
        suite = harness.Suite.get()
        out = os.path.join(suite.root, "dns-spoof-pin-%d.json" % os.getpid())
        conf = os.path.join(suite.root, "dns-spoof-pin-conf")
        env = dict(os.environ,
                   DNS_SPOOF_PIN_OUT=out,
                   DNS_SPOOF_PIN_ADDONS=os.path.join(harness.REPO, "addons"))
        subprocess.run([harness.REAL_MITMDUMP, "--listen-host", "127.0.0.1", "-p", "0", "--set",
                        "confdir=" + conf, "-q",
                        "-s", os.path.join(harness.REPO, "tests", "fakes", "dns_spoof_pin_probe.py")],
                       env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
        with open(out) as fh:
            got = json.load(fh)
        self.assertTrue(got["applied"], got)
        self.assertEqual(got["address"], ["10.0.0.9", 8443], got)
        self.assertEqual(got["sni"], "spoof.example.test.", got)


class Cli(test_cli.CliBase):
    def test_add_list_rm_and_refusals(self):
        self.assertIn("dns: (none)", self.ok("dns", "list").stdout)
        self.assertIn("dns: api.prod.example → 10.0.0.5",
                      self.ok("dns", "add", "API.Prod.Example", "10.0.0.5").stdout)
        self.assertEqual(self.cfg()["dns_spoof"],
                         [{"host": "api.prod.example", "address": "10.0.0.5", "enabled": True}])
        listed = self.ok("dns", "list").stdout
        self.assertIn("api.prod.example → 10.0.0.5", listed)
        self.assertIn("dns: removed api.prod.example", self.ok("dns", "rm", "api.prod.example").stdout)
        self.assertEqual(self.cfg().get("dns_spoof") or [], [])
        self.refused("dns", "rm", "missing.example", msg="no DNS spoof")
        self.refused("dns", "add", "http://bad", "10.0.0.1", msg="host name")
        self.refused("dns", "add", "ok.example", "10.0.0.1:8080", msg="port")
        self.refused("dns", "add", "only-one-arg", msg="add HOST ADDRESS")
        self.refused("dns", "maybe", msg="list | add")

    def test_help_lists_dns(self):
        self.assertIn("dns list | add HOST ADDRESS | rm HOST", self.ok("--help").stdout)
        self.assertIn("dns", self.ok("dns", "--help").stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
