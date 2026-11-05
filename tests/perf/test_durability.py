"""All-day durability budgets: open WebSocket frames and total retained HTTP bodies stay capped.

Hermetic load through the suite upstream. Numbers are written to tests/.artifacts/durability.json.
Budgets are generous under machine load, tight enough to catch an unbounded store or an O(n²) path.
"""
import base64
import hashlib
import http.client
import json
import os
import socket
import statistics
import subprocess
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import harness
from harness import Instance, Suite, wait_for

RESULTS = {}


def rss_mb(inst):
    out = subprocess.run(["pgrep", "-g", str(inst.proc.pid)], capture_output=True, text=True).stdout.split()
    pids = sorted({inst.proc.pid} | {int(x) for x in out})
    total = 0
    for pid in pids:
        raw = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
        total += int(raw or 0)
    return total / 1024.0


def median_ms(fn, n=5):
    samples = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t) * 1000)
    return statistics.median(samples)


def through(conn, url, host):
    conn.request("GET", url, headers={"Host": host})
    r = conn.getresponse()
    r.read()
    return r.status


def ws_frame(payload):
    mask = b"\x01\x02\x03\x04"
    n = len(payload)
    if n < 126:
        hdr = bytes([0x81, 0x80 | n])
    elif n < 65536:
        hdr = bytes([0x81, 0x80 | 126, (n >> 8) & 0xff, n & 0xff])
    else:
        hdr = bytes([0x81, 0x80 | 127]) + n.to_bytes(8, "big")
    return hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


class Durability(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()
        cls.up = cls.suite.upstream()

    @classmethod
    def tearDownClass(cls):
        os.makedirs(harness.ARTIFACTS, exist_ok=True)
        with open(os.path.join(harness.ARTIFACTS, "durability.json"), "w") as fh:
            json.dump(RESULTS, fh, indent=2, sort_keys=True)
        print("\nDURABILITY %s" % json.dumps(RESULTS, sort_keys=True))

    def test_open_websocket_messages_stay_under_the_cap(self):
        # Without the per-call frame cap, messages_meta.count grows for as long as the socket stays open.
        limit = 200
        inst = Instance(self.suite, "dur-ws",
                        extra_env={"RIVIS_MAX_FLOWS": "20",
                                   "RIVIS_MAX_WS_MESSAGES": str(limit),
                                   "RIVIS_MAX_WS_MB": "64"}).start()
        hold = threading.Event()
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def server():
            srv.settimeout(120)
            try:
                conn, _ = srv.accept()
            except (socket.timeout, OSError):
                return
            req = b""
            while b"\r\n\r\n" not in req:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                req += chunk
            key = [line.split(b":", 1)[1].strip() for line in req.split(b"\r\n")
                   if line.lower().startswith(b"sec-websocket-key")][0]
            accept = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                         b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")
            conn.settimeout(0.2)
            while not hold.is_set():
                try:
                    if not conn.recv(65536):
                        break
                except socket.timeout:
                    continue
                except OSError:
                    break
            try:
                conn.close()
            except OSError:
                pass
            try:
                srv.close()
            except OSError:
                pass

        threading.Thread(target=server, daemon=True).start()
        proxy = None
        try:
            proxy = socket.create_connection(("127.0.0.1", inst.proxy_port), 10)
            proxy.sendall(("GET http://127.0.0.1:%d/ws?durws=1 HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                           "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                           "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
                           % (port, port)).encode())
            proxy.settimeout(10)
            head = b""
            while b"\r\n\r\n" not in head:
                head += proxy.recv(4096)
            self.assertIn(b" 101 ", head.split(b"\r\n")[0])
            wait_for(lambda: any("durws=1" in ((f.get("request") or {}).get("path") or "")
                                 for f in inst.flows()), 10, 0.1, "open websocket")
            base = rss_mb(inst)
            payload = b"W" * 2048
            for i in range(limit * 3):
                proxy.sendall(ws_frame(payload + ("-%d" % i).encode()))
                if i % 100 == 0:
                    time.sleep(0.02)
            time.sleep(1.5)
            ws = wait_for(lambda: next((f for f in inst.flows()
                                        if "durws=1" in ((f.get("request") or {}).get("path") or "")), None),
                          10, 0.1, "ws still listed")
            meta = (ws.get("websocket") or {}).get("messages_meta") or {}
            state = inst.panel.state()["retention"]
            rss = rss_mb(inst)
            result = {"limit": limit, "count": meta.get("count"), "contentLength": meta.get("contentLength"),
                      "ws_dropped": state.get("ws_dropped"), "rss_growth_mb": round(rss - base, 1),
                      "comment": ws.get("comment") or ""}
            RESULTS["websocket_cap"] = result
            self.assertLessEqual(int(meta.get("count") or 0), limit, result)
            self.assertGreaterEqual(int(state.get("ws_dropped") or 0), limit, result)
            self.assertIn("older messages dropped", result["comment"])
            # 3× the cap of 2 KiB frames would be ~1.2 MiB retained without the cap; growth stays small.
            self.assertLess(rss - base, 40.0, result)
        finally:
            hold.set()
            if proxy is not None:
                try:
                    proxy.close()
                except OSError:
                    pass
            inst.stop()

    def test_retained_http_bodies_stay_under_the_byte_budget(self):
        # Without the body-byte budget, twenty 1 MiB responses stay in RSS after the flow-count cap is raised.
        budget_mb = 5
        inst = Instance(self.suite, "dur-body",
                        extra_env={"RIVIS_MAX_FLOWS": "100",
                                   "RIVIS_MAX_BODY_MB": str(budget_mb)}).start()
        host = "127.0.0.1:%d" % self.up.http_port
        conn = http.client.HTTPConnection("127.0.0.1", inst.proxy_port, timeout=60)
        try:
            base = rss_mb(inst)
            for i in range(20):
                self.assertEqual(through(conn, "http://%s/big?mb=1&dur=%d" % (host, i), host), 200)
            wait_for(lambda: len(inst.flows()) >= 20, 30, 0.2, "20 large flows")
            # One more small call so retention runs again after the last big body settled.
            self.assertEqual(through(conn, "http://%s/json/small?after=1" % host, host), 200)
            wait_for(lambda: int(inst.panel.state()["retention"].get("bodies_dropped") or 0) >= 1,
                     20, 0.2, "bodies trimmed")
            state = inst.panel.state()["retention"]
            state_ms = median_ms(lambda: inst.panel.state(), 5)
            rss = rss_mb(inst)
            result = {"budget_mb": budget_mb, "flows": len(inst.flows()),
                      "bodies_dropped": state.get("bodies_dropped"),
                      "body_budget": state.get("body_budget"),
                      "rss_growth_mb": round(rss - base, 1), "state_ms": round(state_ms, 1)}
            RESULTS["body_budget"] = result
            self.assertEqual(int(state.get("body_budget") or 0), budget_mb * 1024 * 1024, result)
            self.assertGreaterEqual(int(state.get("bodies_dropped") or 0), 10, result)
            # 20 MiB of bodies with a 5 MiB keep budget must not leave ~20 MiB of growth behind.
            self.assertLess(rss - base, 80.0, result)
            self.assertLess(state_ms, 500.0, result)
        finally:
            conn.close()
            inst.stop()

    def test_panel_stays_linear_from_1k_to_5k_small_flows(self):
        inst = Instance(self.suite, "dur-scale",
                        extra_env={"RIVIS_MAX_FLOWS": "20000"}).start()
        host = "127.0.0.1:%d" % self.up.http_port
        url = "http://%s/json/small" % host
        conn = http.client.HTTPConnection("127.0.0.1", inst.proxy_port, timeout=30)
        try:
            base = rss_mb(inst)
            rows = {}
            for n in (1000, 5000):
                while len(inst.flows()) < n:
                    have = len(inst.flows())
                    for i in range(have, min(n, have + 250)):
                        through(conn, url + "?durscale=%d" % i, host)
                    wait_for(lambda: len(inst.flows()) >= min(n, have + 1), 30, 0.2, "flows growing")
                wait_for(lambda: len(inst.flows()) >= n, 60, 0.5, "%d flows" % n)
                state_ms = median_ms(lambda: inst.panel.state(), 5)
                t0 = time.perf_counter()
                inst.flows()
                flows_ms = (time.perf_counter() - t0) * 1000
                t0 = time.perf_counter()
                inst.panel.ok("viewer_summaries", {"limit": 12})
                summ_ms = (time.perf_counter() - t0) * 1000
                rss = rss_mb(inst)
                rows[n] = {"state_ms": round(state_ms, 1), "flows_ms": round(flows_ms, 1),
                           "summaries_ms": round(summ_ms, 1),
                           "rss_growth_mb": round(rss - base, 1)}
            RESULTS["small_scale"] = rows
            # 5× the calls must not cost 25× the time (guards an accidental O(n²) on the state path).
            self.assertLess(rows[5000]["state_ms"], max(250.0, rows[1000]["state_ms"] * 8), rows)
            self.assertLess(rows[5000]["flows_ms"], max(2000.0, rows[1000]["flows_ms"] * 8), rows)
            self.assertLess(rows[5000]["rss_growth_mb"], 400.0, rows)
        finally:
            conn.close()
            inst.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
