"""Deterministic capture operations using the engine's actual flow store and breakpoint addon."""
import asyncio
import ast
import json
import os
import sys
import threading
import traceback

from mitmproxy import connection, ctx, http
from mitmproxy.addons.intercept import Intercept
from mitmproxy.addons.view import View

FORBIDDEN_PORTS = {8080, 8083, 9090}

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "addons"))
import proxy_panel
from proxy_retention import ProxyRetention


def flow(live=False):
    f = http.HTTPFlow(connection.Client(peername=("127.0.0.1", 1), sockname=("127.0.0.1", 2)),
                      connection.Server(address=("example.test", 80)))
    f.request = http.Request.make("GET", "http://example.test/body")
    f.response = http.Response.make(200, b"body")
    f.live = live
    return f


class Probe:
    def load(self, loader):
        View().load(loader)
        Intercept().load(loader)
        ProxyRetention().load(loader)

    async def running(self):
        errors = []
        cases = ("content",) if os.environ.get("PROBE_GROUP") == "content" else (
            "live", "read_arrival", "response_pause", "overlap", "clear", "failure", "retention")
        for name in cases:
            try:
                await self.check(name)
            except BaseException:
                errors.append(name + ": " + traceback.format_exc())
        with open(os.environ["RESTORE_RESULT"], "w") as fh:
            json.dump(errors, fh)
        ctx.master.shutdown()

    async def check(self, name):
        if name == "content":
            await self.content()
            return
        v = View()
        ctx.master.view = v
        p = proxy_panel.ProxyPanel()
        p.load_cfg = lambda: {}
        original = [flow() for _ in range(96)]
        incoming = [flow() for _ in range(96)]
        v.add(original)
        p.read_session = lambda session: incoming

        async def restore(session="saved"):
            if hasattr(p, "sess_load_async"):
                return await p.sess_load_async({"name": session, "replace": True})
            return p._act("sess_load", {"name": session, "replace": True})

        if name == "live":
            original[40].live = True
            await restore()
            assert v.get_by_id(original[40].id) is original[40], "live call removed"
            assert original[40].error is None, "live call killed"
        elif name == "read_arrival":
            started, release = threading.Event(), threading.Event()
            newcomer = flow(True)
            def read(session):
                started.set()
                assert release.wait(3), "disk read was not off-thread"
                return incoming
            p.read_session = read
            task = asyncio.create_task(restore())
            await asyncio.to_thread(started.wait, 2)
            v.add([newcomer])
            release.set()
            await task
            assert v.get_by_id(newcomer.id) is newcomer and newcomer.error is None, "arrival during read removed"
        elif name == "response_pause":
            if not hasattr(p, "sess_load_async"):
                return  # The synchronous path has no between-chunk turn.
            intercept = Intercept()
            ctx.options.update(intercept="~s", intercept_active=True)
            intercept.configure({"intercept"})
            victim = original[40]
            paused = []
            def pause():
                victim.live = True
                intercept.response(victim)
                paused.append(victim.intercepted)
            fired = False
            def removed(flow):
                nonlocal fired
                if not fired:
                    fired = True
                    asyncio.get_running_loop().call_soon(pause)
            v.sig_store_remove.connect(removed)
            await restore()
            await asyncio.sleep(0)
            assert paused == [True], "real response breakpoint did not pause"
            assert v.get_by_id(victim.id) is victim, "call paused between chunks removed"
            assert victim.intercepted, "paused call resumed during replacement"
            assert victim.error is None, "paused call killed"
            victim.resume()
        elif name == "overlap":
            second = [flow() for _ in range(96)]
            p.read_session = lambda session: incoming if session == "first" else second
            await asyncio.gather(restore("first"), restore("second"))
            assert {f.id for f in v} == {f.id for f in second}, "concurrent replaces left a mixed capture"
        elif name == "clear":
            fired = False
            def added(flow):
                nonlocal fired
                if not fired:
                    fired = True
                    asyncio.get_running_loop().call_soon(v.clear)
            v.sig_view_add.connect(added)
            try:
                await restore()
            except proxy_panel.PanelError as exc:
                assert "cancelled" in str(exc)
            await asyncio.sleep(0)
            assert not list(v), "acknowledged Clear was undone"
        elif name == "failure":
            add = v.add
            calls = 0
            def fail(flows):
                nonlocal calls
                calls += 1
                if calls == (2 if hasattr(p, "sess_load_async") else 1):
                    add(flows[:3])
                    raise OSError("injected add failure")
                return add(flows)
            v.add = fail
            try:
                await restore()
            except OSError:
                pass
            else:
                raise AssertionError("injected add failure never reached")
            assert {f.id for f in v} == {f.id for f in original}, "failed restore left a half-replaced capture"
        elif name == "retention":
            if not hasattr(p, "sess_load_async"):
                return  # Retention cannot interleave with the synchronous commit.
            retention = ProxyRetention()
            ctx.options.update(proxy_max_flows=64)
            def trim(flow):
                asyncio.get_running_loop().call_soon(retention.trim)
            v.sig_view_add.connect(trim)
            result = await restore()
            await asyncio.sleep(0)
            assert result["count"] == len(v), "restore reported planned rather than retained additions"
            assert 0 < len(v) <= 64 and retention.trimmed > 0

    async def content(self):
        from mitmproxy.tools.web import app as webapp
        from mitmproxy import tcp, udp, websocket
        from tornado.httpclient import AsyncHTTPClient
        from tornado.httpserver import HTTPServer
        from tornado.netutil import bind_sockets
        from tornado.web import Application
        source = open(proxy_panel.__file__).read()
        classes = [n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.ClassDef) and n.name == "SafeFlowContent"]
        handler = webapp.FlowContent
        if classes:
            ns = {"webapp": webapp}
            exec(compile(ast.Module(body=[classes[0]], type_ignores=[]), proxy_panel.__file__, "exec"), ns)
            handler = ns["SafeFlowContent"]
        current = [None]
        class Content(handler):
            def get_current_user(self):
                return True
            @property
            def flow(self):
                return current[0]
        app = Application([(r"/flows/(?P<flow_id>[0-9a-f-]+)/(?P<message>request|response|messages)/content.data", Content)])
        while True:
            sockets = bind_sockets(0, address="127.0.0.1")
            port = sockets[0].getsockname()[1]
            if port not in FORBIDDEN_PORTS:
                break
            for sock in sockets:
                sock.close()
        server = HTTPServer(app)
        server.add_sockets(sockets)
        client = AsyncHTTPClient()
        checks = []
        async def get(f, part, code, contains=None):
            current[0] = f
            r = await client.fetch("http://127.0.0.1:%d/flows/%s/%s/content.data" % (port, f.id, part), raise_error=False)
            checks.append((part, r.code, code))
            if contains is not None and r.code == code:
                assert contains in r.body
            return r
        try:
            absent = flow()
            absent.response = None
            await get(absent, "response", 200, b"Content is missing")
            absent.request = None
            await get(absent, "request", 200, b"Content is missing")
            streamed = flow()
            streamed.response.raw_content = None
            streamed.response.stream = True
            await get(streamed, "response", 200, b"Content is missing")
            empty = flow()
            empty.response.raw_content = b""
            r = await get(empty, "response", 200)
            assert r.body == b"" and "attachment" in r.headers["Content-Disposition"]
            ws = flow()
            ws.websocket = websocket.WebSocketData()
            await get(ws, "messages", 400)
            for cls in (tcp.TCPFlow, udp.UDPFlow):
                f = cls(empty.client_conn, empty.server_conn)
                await get(f, "messages", 400)
            assert all(got == want for _, got, want in checks), "content status mismatch: %r" % checks
        finally:
            client.close()
            server.stop()
            await server.close_all_connections()


addons = [Probe()]
