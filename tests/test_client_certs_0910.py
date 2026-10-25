"""Client certificates (mutual TLS) per host (pilot 2026-10-21: "No client certificate (mTLS) support").

A local HTTPS server that REQUIRES a client certificate signed by its own CA stands in for an mTLS gateway. Through
Rivis, a call to it fails until a client certificate is added for its host, then succeeds with that certificate;
a replaced certificate is used from the next connection (no restart), and a removed one is no longer sent."""
import base64
import json
import os
import ssl
import stat
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import LiveCase, wait_for

sys.path.insert(0, os.path.join(harness.REPO, "addons"))
import client_certs                         # noqa: E402

OPENSSL = "/usr/bin/openssl"


def sh(*argv, input=None):
    cp = subprocess.run(list(argv), capture_output=True, input=input)
    if cp.returncode != 0:
        raise AssertionError("%s failed: %s" % (argv[:3], cp.stderr.decode("utf-8", "replace")))
    return cp.stdout


class Pki:
    """A client CA, client certificates signed by it, and a server certificate for 127.0.0.1 / localhost."""

    def __init__(self, d):
        self.d = d
        p = self.p
        sh(OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", p("ca.key"), "-out", p("ca.crt"),
           "-subj", "/CN=Rivis Test Client CA", "-days", "30")
        with open(p("san.cnf"), "w") as fh:
            fh.write("subjectAltName=IP:127.0.0.1,DNS:localhost\n")
        sh(OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", p("server.key"), "-out", p("server.crt"),
           "-subj", "/CN=localhost", "-days", "30", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost")

    def p(self, name):
        return os.path.join(self.d, name)

    def client(self, cn, password="s3cret pass"):
        """(pem cert, pem key, p12 path) for a client certificate with this CN, signed by the client CA."""
        p = self.p
        sh(OPENSSL, "req", "-newkey", "rsa:2048", "-nodes", "-keyout", p(cn + ".key"), "-out", p(cn + ".csr"), "-subj", "/CN=" + cn)
        sh(OPENSSL, "x509", "-req", "-in", p(cn + ".csr"), "-CA", p("ca.crt"), "-CAkey", p("ca.key"), "-CAcreateserial",
           "-out", p(cn + ".crt"), "-days", "30")
        sh(OPENSSL, "pkcs12", "-export", "-in", p(cn + ".crt"), "-inkey", p(cn + ".key"), "-certfile", p("ca.crt"),
           "-out", p(cn + ".p12"), "-passout", "pass:" + password)
        return p(cn + ".crt"), p(cn + ".key"), p(cn + ".p12")


class _Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        peer = self.connection.getpeercert() or {}
        cn = next((v for rdn in peer.get("subject", ()) for k, v in rdn if k == "commonName"), None)
        body = json.dumps({"client_cn": cn}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class MtlsServer:
    """127.0.0.1, random port, CERT_REQUIRED against the client CA."""

    def __init__(self, pki):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(pki.p("server.crt"), pki.p("server.key"))
        ctx.load_verify_locations(pki.p("ca.crt"))
        ctx.verify_mode = ssl.CERT_REQUIRED
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
        self.httpd.daemon_threads = True
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ClientCertsLive(LiveCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.pki = Pki(cls.suite.new_home("pki"))
        cls.alice = cls.pki.client("alice")
        cls.bob = cls.pki.client("bob", password="other")
        cls.srv = MtlsServer(cls.pki)
        cls.store = cls.inst.path("client-certs")

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()
        super().tearDownClass()

    def tearDown(self):
        for host in ("127.0.0.1", "localhost"):
            client_certs.remove(self.store, host)

    def call(self, host="127.0.0.1"):
        return self.inst.fetch("https://%s:%d/who" % (host, self.srv.port), timeout=10)

    def cli(self, *args, input=None):
        env = dict(self.inst.env)
        return self.suite.rivis("tls", "client-cert", *args, home=self.inst.home, env=env, input=input)

    def test_server_that_requires_a_client_certificate_gets_the_one_added_for_its_host(self):
        r = self.call()
        self.assertNotEqual(r.status, 200, "without a client certificate the mTLS server must refuse the call")
        cp = self.cli("add", "127.0.0.1", self.alice[2], "--password-stdin", input="s3cret pass\n")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("CN=alice", cp.stdout.replace(" = ", "="))
        r = wait_for(lambda: (lambda x: x if x.status == 200 else None)(self.call()), 10, 0.3, "mTLS call with alice")
        self.assertEqual(r.json(), {"client_cn": "alice"})

    def test_a_replaced_certificate_is_used_from_the_next_connection(self):
        self.assertEqual(self.cli("add", "127.0.0.1", self.alice[0], "--key", self.alice[1]).returncode, 0)
        wait_for(lambda: self.call().status == 200, 10, 0.3, "alice")
        self.assertEqual(self.call().json(), {"client_cn": "alice"})
        cp = self.cli("add", "127.0.0.1", self.bob[2], "--password-stdin", input="other\n")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        wait_for(lambda: self.call().json() == {"client_cn": "bob"}, 10, 0.3, "bob after replacing alice")

    def test_removed_certificate_is_no_longer_sent(self):
        self.assertEqual(self.cli("add", "127.0.0.1", self.alice[2], "--password-stdin", input="s3cret pass\n").returncode, 0)
        wait_for(lambda: self.call().status == 200, 10, 0.3, "alice")
        cp = self.cli("rm", "127.0.0.1")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        wait_for(lambda: self.call().status != 200, 10, 0.3, "refused again after rm")

    def test_only_the_named_host_gets_the_certificate(self):
        self.assertEqual(self.cli("add", "localhost", self.alice[2], "--password-stdin", input="s3cret pass\n").returncode, 0)
        wait_for(lambda: self.call("localhost").status == 200, 10, 0.3, "localhost gets alice")
        self.assertNotEqual(self.call("127.0.0.1").status, 200, "127.0.0.1 has no certificate of its own")

    def test_panel_adds_lists_and_removes_a_p12(self):
        with open(self.alice[2], "rb") as fh:
            data = base64.b64encode(fh.read()).decode()
        code, doc, raw = self.panel.post("client_cert_add", {"host": "127.0.0.1", "file_b64": data, "password": "wrong"})
        self.assertGreaterEqual(code, 400)
        self.assertIn("password", raw.decode())
        code, doc, raw = self.panel.post("client_cert_add", {"host": "https://x", "file_b64": data, "password": "s3cret pass"})
        self.assertGreaterEqual(code, 400)
        self.assertIn("host name", raw.decode())
        doc = self.panel.ok("client_cert_add", {"host": "127.0.0.1", "file_b64": data, "password": "s3cret pass"})
        self.assertEqual(doc["cert"]["host"], "127.0.0.1")
        rows = self.panel.state()["client_certs"]
        self.assertEqual([(r["host"], "alice" in r["subject"]) for r in rows], [("127.0.0.1", True)])
        self.assertNotIn("PRIVATE KEY", json.dumps(self.panel.state()))
        wait_for(lambda: self.call().status == 200, 10, 0.3, "alice via panel")
        self.panel.ok("client_cert_rm", {"host": "127.0.0.1"})
        self.assertEqual(self.panel.state()["client_certs"], [])

    def test_store_is_private(self):
        self.assertEqual(self.cli("add", "127.0.0.1", self.alice[2], "--password-stdin", input="s3cret pass\n").returncode, 0)
        self.assertEqual(stat.S_IMODE(os.stat(self.store).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.store, "127.0.0.1.pem")).st_mode), 0o600)
        listing = self.cli("list")
        self.assertIn("127.0.0.1", listing.stdout)
        self.assertNotIn("PRIVATE", listing.stdout)


class ClientCertsUnit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = harness.Suite.get()
        cls.pki = Pki(cls.suite.new_home("pki-unit"))
        cls.alice = cls.pki.client("alice")
        cls.bob = cls.pki.client("bob")

    def test_hosts_are_normalized_and_bad_ones_refused(self):
        self.assertEqual(client_certs.normalize_host(" API.Example.test. "), "api.example.test")
        self.assertEqual(client_certs.normalize_host("*.Example.test"), "*.example.test")
        self.assertEqual(client_certs.normalize_host("10.0.0.7"), "10.0.0.7")
        for bad in ("https://x.test", "x.test:443", "x.test/p", "*.test", "a b", "", "*", "-x.test"):
            with self.assertRaises(client_certs.CertError, msg=bad):
                client_certs.normalize_host(bad)
        self.assertEqual(client_certs.file_name("*.example.test"), "_wildcard.example.test.pem")
        self.assertEqual(client_certs.host_of("_wildcard.example.test.pem"), "*.example.test")

    def test_exact_host_wins_then_the_longest_wildcard(self):
        hosts = ["*.example.test", "*.api.example.test", "pay.api.example.test"]
        self.assertEqual(client_certs.matching(hosts, "pay.api.example.test"), "pay.api.example.test")
        self.assertEqual(client_certs.matching(hosts, "x.api.example.test"), "*.api.example.test")
        self.assertEqual(client_certs.matching(hosts, "www.example.test"), "*.example.test")
        self.assertIsNone(client_certs.matching(hosts, "example.test"))
        self.assertIsNone(client_certs.matching(hosts, "badexample.test"))

    def test_wrong_password_and_foreign_key_are_refused(self):
        with open(self.alice[2], "rb") as fh:
            p12 = fh.read()
        with self.assertRaisesRegex(client_certs.CertError, "password"):
            client_certs.to_pem(p12, "nope")
        with open(self.alice[0], "rb") as c, open(self.bob[1], "rb") as k:
            with self.assertRaisesRegex(client_certs.CertError, "does not belong"):
                client_certs.to_pem(c.read(), key_data=k.read())
        with open(self.alice[0], "rb") as c:
            with self.assertRaisesRegex(client_certs.CertError, "no private key"):
                client_certs.to_pem(c.read())

    def test_p12_gives_leaf_first_then_chain_then_key(self):
        with open(self.alice[2], "rb") as fh:
            pem = client_certs.to_pem(fh.read(), "s3cret pass")
        self.assertEqual(pem.count("BEGIN CERTIFICATE"), 2)
        self.assertEqual(pem.count("PRIVATE KEY-----"), 2)
        self.assertNotIn("ENCRYPTED", pem)
        self.assertIn("alice", client_certs.describe(pem)["subject"])

    def test_active_directory_follows_the_store_and_fills_wildcards_on_demand(self):
        store = os.path.join(self.suite.new_home("store"), "client-certs")
        with open(self.alice[2], "rb") as fh:
            client_certs.add(store, "*.example.test", fh.read(), "s3cret pass")
        active = client_certs.Active(store)
        first = active.refresh()
        self.assertTrue(os.path.isdir(first))
        self.assertEqual(active.prepare("api.example.test"), "*.example.test")
        self.assertTrue(os.path.isfile(os.path.join(first, "api.example.test.pem")))
        self.assertIsNone(active.prepare("other.test"))
        self.assertFalse(os.path.exists(os.path.join(first, "other.test.pem")))
        with open(self.bob[2], "rb") as fh:
            client_certs.add(store, "*.example.test", fh.read(), "s3cret pass")
        second = active.refresh()
        self.assertNotEqual(first, second, "a replaced certificate needs a new path (mitmproxy caches TLS contexts by path)")
        self.assertFalse(os.path.exists(first), "the old version is cleaned up")
        client_certs.remove(store, "*.example.test")
        self.assertIsNone(active.refresh())
        self.assertEqual(client_certs.entries(store), [])


if __name__ == "__main__":
    harness.main()
