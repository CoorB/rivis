"""A NEO-like fake upstream for the soak: realistic Backbase-style JSON endpoints of varied size, some slow (1-3 s),
some failing (4xx/5xx), some large, plus one websocket. It extends the suite's deterministic Upstream (so /echo, /slow,
/status/N, /big … still work) and, unlike it, records nothing per call: a 25-minute run makes thousands of them.
Everything is generated from a seeded RNG-free function of the path, so a call and its repeat see the same body.
"""
import base64
import collections
import hashlib
import json
import os
import sys
import time
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import upstream as base            # noqa: E402

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
# path -> (kind, parameters); the client side (soak.py) picks from this table with weights
ENDPOINTS = {
    "/neo/ping": "tiny, no delay: the latency probe",
    "/api/arrangement-manager/client-api/v2/productsummary/context": "mid JSON (accounts)",
    "/api/card-manager/client-api/v2/cards": "mid JSON (cards)",
    "/api/transaction-manager/client-api/v2/transactions": "large JSON, paged (rows=N)",
    "/api/payment-order-service/client-api/v2/payment-orders": "small JSON, POST",
    "/api/user-manager/client-api/v2/users/me": "small JSON",
    "/api/loyalty/client-api/v1/points": "slow (1-3 s)",
    "/api/sadad/client-api/v1/bills": "slow (1-3 s)",
    "/api/notification/client-api/v1/inbox": "4xx / 5xx at random",
    "/api/statement/client-api/v1/statement.pdf": "large body (1-3 MB)",
    "/neo/ws": "websocket",
}


def _doc(path, rows, seed):
    h = hashlib.sha256((path + str(seed)).encode()).hexdigest()
    return {"id": h[:16], "kind": path.rsplit("/", 1)[-1], "currency": "SAR",
            "items": [{"id": "%s-%d" % (h[:8], i), "amount": round(((int(h[i % 32], 16) + 1) * 37.5) % 9000, 2),
                       "label": "Row %d %s" % (i, h[(i * 3) % 40:(i * 3) % 40 + 12]), "booked": True,
                       "meta": {"channel": "mobile", "ref": h[i % 20:i % 20 + 20]}} for i in range(rows)]}


class NeoHandler(base.Handler):
    def _route(self):
        u = urlsplit(self.path)
        if not (u.path.startswith("/api/") or u.path.startswith("/neo/")):
            return base.Handler._route(self)
        data = self._body()
        self.server.owner.seen[self.path] += 1            # exact path?query: lets a test prove a Repeat reached the server
        q = parse_qs(u.query, keep_blank_values=True)
        p = u.path
        n = lambda k, d: int((q.get(k) or [d])[0])
        if p == "/neo/ping":
            return self._send(200, {"pong": True})
        if p == "/neo/ws":
            return self._websocket()
        if p.endswith("/productsummary/context"):
            return self._send(200, _doc(p, 6, n("seed", 0)))
        if p.endswith("/cards"):
            return self._send(200, _doc(p, 4, n("seed", 0)))
        if p.endswith("/transactions"):
            return self._send(200, _doc(p, min(n("rows", 120), 4000), n("seed", 0)))
        if p.endswith("/payment-orders"):
            return self._send(201 if self.command == "POST" else 200, {"id": hashlib.md5(data or b"x").hexdigest(), "state": "ACCEPTED"})
        if p.endswith("/users/me"):
            return self._send(200, {"name": "Soak User", "segment": "retail", "lang": "en"})
        if p.endswith("/points") or p.endswith("/bills"):
            time.sleep(n("ms", 1500) / 1000.0)
            return self._send(200, _doc(p, 10, n("seed", 0)))
        if p.endswith("/inbox"):
            code = n("code", 500)
            return self._send(code, {"error": {"code": "E%d" % code, "message": "synthetic %d" % code}})
        if p.endswith("/statement.pdf"):
            body = (b"%PDF-1.4\n" + hashlib.sha256(b"neo").digest() * 32768) * max(1, n("mb", 1))
            return self._send(200, body, ctype="application/pdf")
        return self._send(404, {"error": "no such path", "path": p})

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _route

    def _websocket(self):
        key = self.headers.get("Sec-WebSocket-Key")
        if not key or "websocket" not in (self.headers.get("Upgrade") or "").lower():
            return self._send(400, {"error": "websocket upgrade expected"})
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.close_connection = True
        try:
            for i in range(4):
                msg = json.dumps({"event": "balance", "n": i}).encode()
                self.wfile.write(bytes([0x81, len(msg)]) + msg)       # unmasked text frame (< 126 bytes)
                self.wfile.flush()
                time.sleep(0.4)
            self.wfile.write(b"\x88\x00")                             # close
            self.wfile.flush()
        except OSError:
            pass


class NeoUpstream(base.Upstream):
    def __init__(self, workdir):
        self.seen = collections.Counter()
        super().__init__(workdir)

    def _make(self, tls, ctx):
        s = base._Server(("127.0.0.1", 0), NeoHandler)
        s.owner, s.is_tls = self, tls
        if ctx:
            s.socket = ctx.wrap_socket(s.socket, server_side=True, do_handshake_on_connect=False)
        return s
