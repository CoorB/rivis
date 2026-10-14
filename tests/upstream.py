"""Deterministic local upstream for the Rivis test-suite (stdlib only, 127.0.0.1, random ports).

One HTTP and one HTTPS listener share the same handler. The HTTPS cert is self-signed (generated with the
openssl CLI at start, SAN = 127.0.0.1 + localhost). Every request is recorded in ``hits`` so tests can prove a
call did (or did not) reach the server.
"""
import base64
import gzip
import hashlib
import json
import os
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(payload=None, header=None, sig="c2ln"):
    h = b64u(json.dumps(header or {"alg": "HS256", "typ": "JWT"}).encode())
    p = b64u(json.dumps(payload or {"sub": "user-1", "iat": 1700000000, "exp": 4102444800}).encode())
    return "%s.%s.%s" % (h, p, sig)


JWT_FRESH = make_jwt({"sub": "alice", "iat": 1700000000, "exp": 4102444800})      # exp in 2100
JWT_EXPIRED = make_jwt({"sub": "bob", "iat": 1500000000, "exp": 1500003600})      # exp in 2017
# one gRPC frame: flag 0, length 7, protobuf {1: 150, 2: "hi"}
GRPC_BODY = b"\x00\x00\x00\x00\x07" + b"\x08\x96\x01\x12\x02hi"
SMALL_JSON = {"user": {"name": "alice", "roles": ["a", "b"]}, "items": [{"id": 1}, {"id": 2}], "flag": False}


def big_body(mb):
    block = hashlib.sha256(b"rivis").digest() * 32768      # 1 MiB
    return block * mb


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "RivisUpstream/1"

    def log_message(self, *a):
        pass

    # -- plumbing -------------------------------------------------------------------------------------
    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(n) if n else b""
        if not n and (self.headers.get("Transfer-Encoding") or "").lower() == "chunked":
            data = b""
            while True:
                size = int(self.rfile.readline().strip() or b"0", 16)
                if not size:
                    self.rfile.readline()
                    break
                data += self.rfile.read(size)
                self.rfile.readline()
        return data

    def _send(self, status, body=b"", ctype="application/json", headers=(), gz=False):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        if ctype:
            self.send_header("Content-Type", ctype)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _route(self):
        data = self._body()
        u = urlsplit(self.path)
        q = parse_qs(u.query, keep_blank_values=True)
        srv = self.server.owner
        srv.hits.append({"method": self.command, "path": self.path, "headers": [(k, v) for k, v in self.headers.items()],
                         "body": data, "tls": self.server.is_tls, "t": time.time()})
        p = u.path
        if p == "/echo":
            doc = {"method": self.command, "path": u.path, "query": q, "headers": [[k, v] for k, v in self.headers.items()],
                   "body_len": len(data), "body_sha256": hashlib.sha256(data).hexdigest(), "tls": self.server.is_tls}
            if len(data) <= 65536:
                try:
                    doc["body"] = data.decode()
                except UnicodeDecodeError:
                    doc["body_b64"] = base64.b64encode(data).decode()
            return self._send(200, doc)
        if p == "/json/small":
            return self._send(200, SMALL_JSON)
        if p == "/json/gzip":
            raw = json.dumps({"gz": True, "items": list(range(50)), "name": "zipped"}).encode()
            return self._send(200, gzip.compress(raw), headers=[("Content-Encoding", "gzip")])
        if p == "/big":
            return self._send(200, big_body(int((q.get("mb") or ["3"])[0])), ctype="application/octet-stream")
        if p == "/slow":
            time.sleep(int((q.get("ms") or ["1000"])[0]) / 1000)
            return self._send(200, {"slow": True})
        if p.startswith("/status/"):
            return self._send(int(p.split("/")[2]), {"status": int(p.split("/")[2])})
        if p == "/cookies":
            return self._send(200, {"cookies": 2}, headers=[("Set-Cookie", "a=1; Path=/"), ("Set-Cookie", "b=2; Path=/; HttpOnly")])
        if p == "/multi":
            return self._send(200, {"multi": True}, headers=[("X-Multi", "one"), ("X-Multi", "two"), ("X-Multi", "three")])
        if p == "/jwt/setcookie":
            return self._send(200, {"ok": 1}, headers=[("Set-Cookie", "session=%s; Path=/" % JWT_FRESH)])
        if p == "/jwt/body":
            return self._send(200, {"access_token": JWT_FRESH, "refresh": {"nested": [JWT_EXPIRED]}})
        if p == "/jwt/header":
            return self._send(200, {"ok": 1}, headers=[("Authorization", "Bearer " + JWT_FRESH)])
        if p == "/jwt/form":
            return self._send(200, "token=%s&x=1" % JWT_FRESH, ctype="application/x-www-form-urlencoded")
        if p == "/graphql":
            query = ""
            if self.command == "GET":
                query = (q.get("query") or [""])[0]
            else:
                try:
                    doc = json.loads(data or b"{}")
                    query = doc.get("query", "") if isinstance(doc, dict) else ""
                except ValueError:
                    pass
            if "fail" in query:
                return self._send(200, {"data": None, "errors": [{"message": "boom", "path": ["x"]}]})
            return self._send(200, {"data": {"viewer": {"id": "1", "name": "alice"}}})
        if p == "/rest":
            return self._send(200, {"rest": True, "query": q})
        if p.startswith("/grpc/"):
            return self._send(200, GRPC_BODY, ctype="application/grpc", headers=[("grpc-status", "0"), ("grpc-message", "OK")])
        if p == "/redirect":
            return self._send(302, b"", headers=[("Location", "/json/small")])
        if p == "/counter":
            srv.counter += 1
            return self._send(200, {"n": srv.counter})
        if p == "/empty":
            return self._send(200, b"", ctype="application/json")
        if p == "/text":
            return self._send(200, "not json at all", ctype="text/plain")
        if p == "/deep":
            n = int((q.get("n") or ["2000"])[0])
            return self._send(200, "[" * n + "]" * n)
        if p == "/hits":
            return self._send(200, {"n": len(srv.hits)})
        return self._send(404, {"error": "no such path", "path": p})

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _route


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


class Upstream:
    def __init__(self, workdir):
        self.hits = []
        self.counter = 0
        self.cert = os.path.join(workdir, "upstream-cert.pem")
        key = os.path.join(workdir, "upstream-key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", self.cert,
                        "-days", "2", "-subj", "/CN=rivis-test-upstream",
                        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                       check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, key)
        self.http = self._make(False, None)
        self.https = self._make(True, ctx)
        self.http_port = self.http.server_address[1]
        self.https_port = self.https.server_address[1]
        for s in (self.http, self.https):
            threading.Thread(target=s.serve_forever, daemon=True).start()

    def _make(self, tls, ctx):
        s = _Server(("127.0.0.1", 0), Handler)
        s.owner, s.is_tls = self, tls
        if ctx:        # handshake happens lazily in the handler thread, so a slow client can't block accept()
            s.socket = ctx.wrap_socket(s.socket, server_side=True, do_handshake_on_connect=False)
        return s

    def url(self, path="/", tls=False):
        return "%s://127.0.0.1:%d%s" % ("https" if tls else "http", self.https_port if tls else self.http_port, path)

    def reset_hits(self):
        del self.hits[:]

    def hits_for(self, prefix):
        return [h for h in self.hits if h["path"].startswith(prefix)]

    def close(self):
        for s in (self.http, self.https):
            try:
                s.shutdown()
                s.server_close()
            except Exception:
                pass
