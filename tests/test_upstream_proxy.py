"""A local forwarding proxy proves Rivis uses mitmproxy's upstream mode."""
import os
import sys
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(__file__))
from harness import Instance, LiveCase


class CompanyProxy(BaseHTTPRequestHandler):
    hits = None

    def do_GET(self):
        self.hits.append(self.path)
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(self.path, timeout=5) as upstream:
                body = upstream.read()
                self.send_response(upstream.status)
                for key, value in upstream.headers.items():
                    if key.lower() not in ("content-length", "transfer-encoding", "connection"):
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        except Exception as exc:
            self.send_error(502, str(exc))

    def log_message(self, *args): pass


class UpstreamProxy(LiveCase):
    @classmethod
    def make_instance(cls):
        cls.hits = []
        cls.company = ThreadingHTTPServer(("127.0.0.1", 0), CompanyProxy)
        CompanyProxy.hits = cls.hits
        cls.thread = threading.Thread(target=cls.company.serve_forever, daemon=True)
        cls.thread.start()
        cls.company_url = "http://127.0.0.1:%d" % cls.company.server_port
        return Instance(cls.suite, "company-upstream", start_args=("--upstream", cls.company_url, "--insecure"))

    @classmethod
    def tearDownClass(cls):
        try: super().tearDownClass()
        finally:
            cls.company.shutdown()
            cls.company.server_close()

    def test_calls_go_through_saved_company_proxy(self):
        response = self.fetch("/json/small")
        self.assertEqual(response.status, 200)
        self.assertTrue(any("/json/small" in hit for hit in self.hits), self.hits)
        status = self.suite.rivis("status", home=self.inst.home, env=self.inst.env)
        self.assertIn("upstream proxy: " + self.company_url, status.stdout)
        doctor = self.suite.rivis("doctor", "--no-net", home=self.inst.home, env=self.inst.env)
        self.assertIn(self.company_url, doctor.stdout)

