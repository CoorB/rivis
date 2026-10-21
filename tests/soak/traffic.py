"""The app: a seeded stream of NEO-like calls through the proxy for the whole run, plus the latency probe and a websocket.

Calls go out over pooled keep-alive connections from worker threads (a slow 1-3 s endpoint never delays the others),
about one in twenty through the curl binary so the Source menu has a second sender. Hosts are *.localhost names (they
resolve to 127.0.0.1 here, so a Repeat never leaves the machine) shaped like the NEO gateway hosts.
"""
import http.client
import json
import math
import os
import queue
import random
import socket
import ssl
import subprocess
import sys
import threading
import time

HOSTS = ["backbase-edge-sit.localhost", "backbase-identity-sit.localhost", "lifestyle-api-sit.localhost"]
PAUSE_PATH = "/api/soak-pause/client-api/v1/ping"        # only this path is ever paused by a breakpoint
MIX = [  # weight, path, method, extra query
    (22, "/api/arrangement-manager/client-api/v2/productsummary/context", "GET", ""),
    (18, "/api/card-manager/client-api/v2/cards", "GET", ""),
    (14, "/api/transaction-manager/client-api/v2/transactions", "GET", "rows"),
    (8, "/api/payment-order-service/client-api/v2/payment-orders", "POST", ""),
    (8, "/api/user-manager/client-api/v2/users/me", "GET", ""),
    (7, "/api/loyalty/client-api/v1/points", "GET", "slow"),
    (5, "/api/sadad/client-api/v1/bills", "GET", "slow"),
    (6, "/api/notification/client-api/v1/inbox", "GET", "error"),
    (2, "/api/statement/client-api/v1/statement.pdf", "GET", "big"),
    (10, PAUSE_PATH, "GET", ""),
]
WEIGHTS = [m[0] for m in MIX]


class Traffic:
    def __init__(self, cfg, inst, up, metrics, seed):
        self.cfg, self.inst, self.up, self.m = cfg, inst, up, metrics
        self.rng = random.Random(seed)
        self.q = queue.Queue()
        self.stop_ev = threading.Event()
        self.threads = []
        self.n = 0
        self.sent = 0
        self.paused_by_user = 0
        self.ctx = ssl.create_default_context(cafile=inst.suite.ca_pem)
        self.ctx.check_hostname = False
        self.lock = threading.Lock()
        self.probe_proc = None
        self.probe_reader = None

    # -- one call -----------------------------------------------------------------------------------------------------
    def make_call(self):
        with self.lock:
            self.n += 1
            i = self.n
        _, path, method, kind = self.rng.choices(MIX, WEIGHTS)[0]
        q = "i=%d" % i
        if kind == "rows":
            q += "&rows=%d" % self.rng.choice([20, 20, 120, 120, 600, 2500])
        elif kind == "slow":
            q += "&ms=%d" % self.rng.choice([1000, 1500, 2000, 3000])
        elif kind == "error":
            q += "&code=%d" % self.rng.choice([400, 401, 403, 404, 429, 500, 502, 503])
        elif kind == "big":
            q += "&mb=%d" % self.rng.choice([1, 2, 3])
        host = self.rng.choice(HOSTS)
        tls = self.rng.random() < 0.2
        via_curl = self.rng.random() < 0.05
        body = json.dumps({"amount": self.rng.randint(1, 5000), "to": "SA%020d" % i, "ref": "r%d" % i}).encode() if method == "POST" else None
        return {"i": i, "path": "%s?%s" % (path, q), "method": method, "host": host, "tls": tls, "curl": via_curl, "body": body, "kind": kind or "plain"}

    def execute(self, conns, call):
        t = self.m.now()
        t0 = time.perf_counter()
        status = 0
        try:
            if call["curl"]:
                url = "%s://%s:%d%s" % ("https" if call["tls"] else "http", call["host"], self.up.https_port if call["tls"] else self.up.http_port, call["path"])
                r = self.inst.fetch(url, method=call["method"], data=call["body"], timeout=40)
                status = r.status
            else:
                key = "https" if call["tls"] else "http"
                conn = conns.get(key)
                if conn is None:
                    if call["tls"]:
                        conn = http.client.HTTPSConnection("127.0.0.1", self.inst.proxy_port, timeout=40, context=self.ctx)
                        conn.set_tunnel("%s" % call["host"], self.up.https_port)
                    else:
                        conn = http.client.HTTPConnection("127.0.0.1", self.inst.proxy_port, timeout=40)
                    conns[key] = conn
                target = call["path"] if call["tls"] else "http://%s:%d%s" % (call["host"], self.up.http_port, call["path"])
                headers = {"Accept": "application/json", "User-Agent": "NEO/2.4.0 (soak)"}
                if call["body"] is not None:
                    headers["Content-Type"] = "application/json"
                conn.request(call["method"], target, body=call["body"], headers=headers)
                resp = conn.getresponse()
                resp.read()
                status = resp.status
        except Exception:                                   # noqa: BLE001 - a dropped call is data, not a crash
            conns.pop("https" if call["tls"] else "http", None)
        ms = (time.perf_counter() - t0) * 1000.0
        self.sent += 1
        self.m.add("app", (t, ms, status, call["kind"] if not call["path"].startswith(PAUSE_PATH) else "pause"))

    def worker(self):
        conns = {}
        while not self.stop_ev.is_set():
            try:
                call = self.q.get(timeout=0.3)
            except queue.Empty:
                continue
            self.execute(conns, call)
        for c in conns.values():
            try:
                c.close()
            except Exception:                               # noqa: BLE001
                pass

    # -- arrival process ----------------------------------------------------------------------------------------------
    def enqueue(self, call):
        if self.q.qsize() > 150:                            # the proxy is frozen: do not queue an unbounded backlog
            self.m.dropped += 1
        else:
            self.q.put(call)

    def scheduler(self):
        start = time.time()
        next_burst = start + self.rng.uniform(20, 50)
        while not self.stop_ev.is_set():
            now = time.time()
            rate = max(0.5, self.cfg.rate * (1 + 0.4 * math.sin(2 * math.pi * (now - start) / 90.0)))
            if now >= next_burst:
                for _ in range(self.rng.randint(12, 35)):
                    self.enqueue(self.make_call())
                    time.sleep(self.rng.uniform(0.02, 0.09))
                next_burst = time.time() + self.rng.uniform(25, 70)
                continue
            self.enqueue(self.make_call())
            self.stop_ev.wait(self.rng.expovariate(rate))

    # -- latency probe: isolated from the UI driver's Python GIL and Playwright trace processing -------------------
    def read_probes(self):
        for line in self.probe_proc.stdout:
            try:
                self.m.add("probe", tuple(json.loads(line)))
            except (ValueError, TypeError):
                pass

    def websocket_once(self):
        t = self.m.now()
        frames, ok = 0, False
        try:
            s = socket.create_connection(("127.0.0.1", self.inst.proxy_port), 10)
            s.settimeout(8)
            req = ("GET http://127.0.0.1:%d/neo/ws HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % (self.up.http_port, self.up.http_port, "dGhlIHNhbXBsZSBub25jZQ=="))
            s.sendall(req.encode())
            buf = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            ok = buf.startswith(b"HTTP/1.1 101")
            frames = buf.count(b'{"event"')
            s.close()
        except Exception:                                   # noqa: BLE001
            pass
        self.m.add("ws", (t, ok and frames > 0, frames))

    def ws_loop(self):
        while not self.stop_ev.wait(40.0):
            self.websocket_once()

    # -- lifecycle ----------------------------------------------------------------------------------------------------
    def prefill(self, n):
        done = []

        def one():
            conn = http.client.HTTPConnection("127.0.0.1", self.inst.proxy_port, timeout=60)
            while True:
                with self.lock:
                    if len(done) >= n:
                        return
                    done.append(1)
                    self.n += 1
                    i = self.n
                host = self.rng.choice(HOSTS)
                conn.request("GET", "http://%s:%d/api/card-manager/client-api/v2/cards?i=%d" % (host, self.up.http_port, i))
                conn.getresponse().read()
        ts = [threading.Thread(target=one, daemon=True) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()

    def start(self):
        for _ in range(self.cfg.workers):
            self.threads.append(threading.Thread(target=self.worker, daemon=True))
        for fn in (self.scheduler, self.ws_loop):
            self.threads.append(threading.Thread(target=fn, daemon=True))
        self.probe_proc = subprocess.Popen(
            [sys.executable, "-u", os.path.join(os.path.dirname(__file__), "prober.py"),
             str(self.up.http_port), str(self.inst.proxy_port), str(self.m.t0)],
            stdout=subprocess.PIPE, text=True)
        self.probe_reader = threading.Thread(target=self.read_probes, daemon=True)
        self.probe_reader.start()
        for t in self.threads:
            t.start()

    def stop(self):
        self.stop_ev.set()
        if self.probe_proc is not None:
            self.probe_proc.terminate()
            try:
                self.probe_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.probe_proc.kill()
                self.probe_proc.wait(timeout=5)
            self.probe_reader.join(timeout=5)
        for t in self.threads:
            t.join(timeout=45)
