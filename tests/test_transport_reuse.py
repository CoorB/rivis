"""NEO transport regression: TLS 1.2 static-RSA origins must work without connection fan-out."""
import os
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Instance, Suite


class StaticRsaReuse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()
        cls.up = cls.suite.upstream(static_rsa=True, handshake_delay=0.05)
        cls.inst = Instance(cls.suite, "static-rsa-reuse").start()

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()

    def curl_many(self, count, version="--http2"):
        url = self.up.url("/json/small", tls=True)
        argv = ["curl", "-sS", "--fail", "--noproxy", "", "-x",
                "http://127.0.0.1:%d" % self.inst.proxy_port,
                "--cacert", self.suite.ca_pem, version, "--max-time", "20"]
        for _ in range(count):
            argv += ["-o", "/dev/null", "-w", "%{http_version}\n", url]
        started = time.monotonic()
        cp = subprocess.run(argv, env=self.suite.env(self.inst.home), capture_output=True, text=True, timeout=30)
        return cp, time.monotonic() - started

    def test_static_rsa_tls12_and_sequential_upstream_reuse(self):
        """NEO-PERF-01: an HTTP/2-capable client falls back to h1 and reuses one expensive upstream handshake."""
        n = 6
        cp, elapsed = self.curl_many(n)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stdout.splitlines(), ["1.1"] * n)
        self.assertEqual(len(self.up.hits_for("/json/small")), n)
        self.assertEqual(self.up.connection_count["https"], 1,
                         "%d sequential calls opened %d upstream TLS connections in %.3fs" %
                         (n, self.up.connection_count["https"], elapsed))

        flows = [f for f in self.inst.flows() if "/json/small" in ((f.get("request") or {}).get("path") or "")]
        conn_ids = {f.get("server_conn", {}).get("id") for f in flows}
        conn_ids.discard(None)
        self.assertEqual(len(flows), n)
        self.assertEqual(len(conn_ids), 1, "flows used server connections %r" % sorted(conn_ids))


if __name__ == "__main__":
    unittest.main(verbosity=2)
