"""C3: when Rivis cannot reach the server at all — the name does not resolve, nothing listens, the connection times out or
the network is unreachable — the app's 502 page and the call's Error tab say which host and port, which address was tried,
and the likely cause in plain words, and name the hosts-file line when that is where the address came from.
(Certificate errors are test_hosts_f3.) The hosts file is a scratch file (RIVIS_HOSTS_FILE); the real one is never read."""
import os
import sys
import tempfile
import unittest
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _paths  # noqa: F401,E402
import harness                     # noqa: E402
from harness import LiveCase, wait_for   # noqa: E402

HOSTS = os.path.join(tempfile.mkdtemp(prefix="rivis-c3-"), "hosts")
with open(HOSTS, "w") as fh:
    fh.write("# scratch hosts file\n127.0.0.1\tlocalhost\n")


class ConnectionErrors(LiveCase):
    INSTANCE_KW = {"extra_env": {"RIVIS_HOSTS_FILE": HOSTS}}

    def test_cycle5_dns_failure_has_the_same_html_format_as_connection_errors(self):
        result = self.inst.fetch("http://no-such-host-rivis.invalid/cycle5-format")
        self.assertEqual(result.status, 502)
        self.assertIn("text/html", dict((k.lower(), v) for k, v in result.headers)["content-type"])
        self.assertIn(b"<html>", result.body)
        self.assertIn(b"Rivis could not reach", result.body)

    def test_cycle5_early_close_names_the_host_and_explains_the_failure(self):
        class ShortBody(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "100")
                self.end_headers()
                self.wfile.write(b"short")

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), ShortBody)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            result = self.inst.fetch("http://127.0.0.1:%d/cycle5-short" % server.server_port)
            self.assertEqual(result.status, 502)
            self.assertIn(b"Rivis", result.body)
            self.assertIn(("127.0.0.1:%d" % server.server_port).encode(), result.body)
            self.assertIn(b"before the response was complete", result.body)
            self.assertIn("before the response was complete", self.error_of("cycle5-short"))
        finally:
            server.shutdown()
            server.server_close()
            worker.join(3)

    def error_of(self, path):
        return wait_for(lambda: (self.inst.flow_for(path) or {}).get("error"), 5, 0.2, "the call's error")["msg"]

    def test_nothing_listening_names_the_address_and_the_cause(self):
        self.reset_state()
        port = harness.free_port()
        r = self.inst.fetch("http://127.0.0.1:%d/c3-refused" % port)
        body = r.body.decode()
        self.assertEqual(r.status, 502)
        self.assertIn("127.0.0.1:%d" % port, body)
        self.assertIn("nothing is listening", body.lower())
        self.assertNotIn("Errno", body.split("(")[0], "the first line is plain words, not an errno")
        self.assertIn("nothing is listening", self.error_of("/c3-refused").lower(), "the Error tab says the same")

    def test_an_address_from_the_hosts_file_is_named(self):
        self.reset_state()
        port = harness.free_port()
        r = self.inst.fetch("http://localhost:%d/c3-hosts" % port)
        body = r.body.decode()
        self.assertIn("localhost:%d" % port, body)
        self.assertIn("hosts file", body)
        self.assertIn("line 2", body)

    def test_a_name_that_does_not_resolve_says_so_plainly(self):
        self.reset_state()
        for url in ("http://no-such-host-rivis.invalid/c3-dns", "https://no-such-host-rivis.invalid/c3-dns"):
            r = self.inst.fetch(url)
            text = r.body.decode()
            if r.status != 502:                  # an HTTPS CONNECT that fails is reported by curl, not as a page
                text = self.error_of("no-such-host-rivis.invalid")
            self.assertIn("no-such-host-rivis.invalid", text, url)
            self.assertIn("does not resolve", text.lower(), url)
            self.assertIn("vpn", text.lower(), url)


class Texts(unittest.TestCase):
    def test_timeout_and_unreachable_messages(self):
        import proxy_common
        cases = {"[Errno 60] Operation timed out": "did not answer",
                 "TimeoutError: [Errno 110] Connection timed out": "did not answer",
                 "[Errno 65] No route to host": "no network route",
                 "[Errno 51] Network is unreachable": "no network route",
                 "[Errno 8] nodename nor servname provided, or not known": "does not resolve",
                 "[Errno 61] Connect call failed ('10.1.2.3', 8443)": "nothing is listening"}
        for msg, want in cases.items():
            text = proxy_common.upstream_conn_text(msg, "api.example.test", 8443)
            self.assertIn(want, text.lower(), msg)
            self.assertIn("api.example.test:8443", text, msg)
        self.assertIn("10.1.2.3", proxy_common.upstream_conn_text("[Errno 61] Connect call failed ('10.1.2.3', 8443)", "api.example.test", 8443))
        self.assertIsNone(proxy_common.upstream_conn_text("Certificate verify failed: hostname mismatch", "a", 443))
        self.assertIsNone(proxy_common.upstream_conn_text("peer closed connection", "a", 443))


if __name__ == "__main__":
    unittest.main()
