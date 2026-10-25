"""R10 traffic handling: a large body's view never stalls other calls (R10-01), an upstream `103 Early Hints` is not
taken for the final response (R10-02), an upstream certificate Rivis cannot verify gets a 502 that says why and how to
fix it (R10-04), and Copy URL / Copy as cURL keep IPv6 brackets (R10-09)."""
import json
import os
import socket
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Background, Instance, LiveCase, Suite, wait_for     # noqa: E402


class _RawServer:
    """A one-route TCP server that answers every request with fixed bytes (for answers http.server cannot send)."""

    def __init__(self, answer, family=socket.AF_INET, host="127.0.0.1"):
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.answer = answer
        self.hits = 0
        self._stop = False
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            conn.settimeout(10)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                data += chunk
            self.hits += 1
            for part in self.answer:
                conn.sendall(part)
                time.sleep(0.05)
            time.sleep(0.3)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self._stop = True
        self.sock.close()


class TrafficR10(LiveCase):
    def test_r10_01_large_body_view_does_not_stall_other_calls(self):
        big = self.fetch("/bigline?mb=60&type=json&r10big=1", timeout=120)
        self.assertEqual(big.status, 200, big)
        fid = self.inst.flow_for("r10big=1")["id"]
        for _ in range(3):                                       # warm: connections, caches
            self.fetch("/json/small?r10warm=1")
        path = "/flows/%s/response/content/auto.json" % fid
        view = Background(lambda: self.panel.get(path, 180))
        time.sleep(0.05)
        worst, n, start = 0.0, 0, time.time()
        while n < 4 or (time.time() - start < 3 and not view._out):
            t0 = time.time()
            r = self.fetch("/json/small?r10probe=%d" % n, timeout=30)
            worst = max(worst, time.time() - t0)
            self.assertEqual(r.status, 200, r)
            n += 1
        self.assertLess(worst, 1.0, "a small call took %.2f s while a 60 MB body was being viewed" % worst)
        code, raw = view.result(180)
        self.assertEqual(code, 200, raw[:200])
        doc = json.loads(raw)
        self.assertIn("showing first", doc["text"])                # clipped, with the Download / Open raw note
        self.assertTrue(doc["text"].startswith('{"data":"aaaa') or "aaaa" in doc["text"][:200], doc["text"][:200])
        # B4: truncated big JSON says truncated (size shown/limit), not "failed to parse"
        self.assertIn("truncated", doc.get("description", "").lower())
        self.assertNotIn("failed to parse", doc.get("description", "").lower())
        self.assertIn("256 KB/4.0 MB", doc.get("description", ""))

    def test_r10_01_small_bodies_view_exactly_as_before(self):
        self.fetch("/json/small?r10small=1")
        fid = self.inst.flow_for("r10small=1")["id"]
        doc = self.panel.get_json("/flows/%s/response/content/auto.json" % fid)
        self.assertIn('"alice"', doc["text"])
        self.assertNotIn("showing first", doc["text"])

    def test_r10_02_early_hints_then_200_reaches_the_client(self):
        body = b'{"after":"103"}'
        srv = _RawServer([b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\n",
                          b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s"
                          % (len(body), body)])
        self.addCleanup(srv.close)
        t0 = time.time()
        r = self.inst.fetch("http://127.0.0.1:%d/early?r10early=1" % srv.port, timeout=8)
        self.assertEqual((r.rc, r.status), (0, 200), "%r after %.1f s" % (r, time.time() - t0))
        self.assertEqual(r.body, body)
        flow = self.inst.flow_for("r10early=1")
        self.assertEqual(flow["response"]["status_code"], 200)

    def test_r10_09_copy_url_and_curl_keep_ipv6_brackets(self):
        srv = _RawServer([b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"], socket.AF_INET6, "::1")
        self.addCleanup(srv.close)
        url = "http://[::1]:%d/ok?r10v6=1" % srv.port
        self.inst.fetch(url, timeout=10)                       # any answer will do (a private host may be refused)
        fid = self.inst.flow_for("r10v6=1")["id"]
        self.assertEqual(self.panel.ok("export", {"flow_id": fid, "fmt": "url"})["text"], url)
        curl = self.panel.ok("export", {"flow_id": fid})["text"]
        self.assertIn("'%s'" % url, curl)
        self.assertNotIn("://::1", curl)


class UpstreamTlsR10(unittest.TestCase):
    """Without --insecure (what testers run): the hermetic upstream's self-signed cert is not trusted."""

    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()
        cls.up = cls.suite.upstream()
        cls.inst = Instance(cls.suite, "r10tls", start_args=("--verify-upstream",)).start()

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()

    def test_r10_04_untrusted_upstream_gets_a_502_naming_reason_and_fix(self):
        r = self.inst.fetch(self.up.url("/echo?r10tls=1", tls=True))
        self.assertEqual(r.status, 502, r)
        text = r.body.decode("utf-8", "replace")
        self.assertIn("could not verify the HTTPS certificate of 127.0.0.1", text)
        self.assertIn("self-signed", text)
        self.assertIn("tls ignore add 127.0.0.1", text)
        self.assertIn("--insecure", text)
        flow = self.inst.flow_for("r10tls=1")
        self.assertIsNone(flow.get("response"))
        self.assertIn("tls ignore add", flow["error"]["msg"])      # the Error tab says the same


if __name__ == "__main__":
    unittest.main(verbosity=2)
