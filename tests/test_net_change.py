"""Durability when the network under Rivis changes: VPN drop, DNS that recovers, an upstream that goes away and
comes back. Hermetic — no real VPN, no real emulator, no system proxy."""
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import LiveCase, wait_for

VPN_FLIP = os.path.join(harness.REPO, "tests", "fakes", "dns_vpn_flip.py")


class VpnDnsRecovers(LiveCase):
    """A name that resolved inside the VPN (private address) must not stay refused for a minute after DNS returns a
    public address — Rivis was caching the private answer in the F-01 check and the browser kept seeing 403."""
    INSTANCE_KW = {"extra_env": {"SHIM_PRE_ADDON": VPN_FLIP}}

    def test_a_private_dns_answer_is_not_kept_after_the_vpn_drops(self):
        url = "http://app.vpnflip.rivis-test:9/after-vpn"
        first = self.inst.fetch(url, timeout=5)
        self.assertEqual(first.status, 403, first)
        self.assertIn(b"10.55.1.1", first.body)
        # curl may time out waiting on the recovered public address (:9 nothing listens); the call list is the proof
        self.inst.fetch(url, timeout=3)
        flows = [f for f in self.inst.flows()
                 if "after-vpn" in ((f.get("request") or {}).get("path") or "")]
        self.assertGreaterEqual(len(flows), 2, flows)
        self.assertEqual((flows[0].get("response") or {}).get("status_code"), 403)
        self.assertEqual((flows[-1].get("request") or {}).get("host"), "1.1.1.1",
                         "second call must re-resolve and pin the public address, not the cached VPN one")
        self.assertNotEqual((flows[-1].get("response") or {}).get("status_code"), 403)


class UpstreamReturns(LiveCase):
    """An origin that refuses then listens again: the next call must succeed (no stuck pooled connection)."""

    def test_capture_resumes_when_the_upstream_listens_again(self):
        hits = []

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        url = "http://127.0.0.1:%d/up-bounce" % port
        self.assertEqual(self.inst.fetch(url).status, 200)
        srv.shutdown()
        srv.server_close()
        down = self.inst.fetch(url, timeout=5)
        self.assertEqual(down.status, 502, down)
        srv2 = HTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=srv2.serve_forever, daemon=True).start()
        self.addCleanup(srv2.shutdown)
        self.addCleanup(srv2.server_close)
        wait_for(lambda: self.inst.fetch(url, timeout=5).status == 200, 10, 0.3, "upstream answering again")


if __name__ == "__main__":
    unittest.main(verbosity=2)
