"""W5 flow retention: bounded store, oldest-first trim, protected selected/paused calls, restart safety."""
import base64
import hashlib
import os
import socket
import sys
import threading
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Background, Instance, LiveCase, Suite, wait_for


class FooterCopy(unittest.TestCase):
    def test_footer_describes_batch_trim(self):
        # R4A-02: the footer must describe the existing low-water policy.
        panel = open(os.path.join(os.path.dirname(__file__), "..", "addons", "panel.js")).read()
        self.assertIn("keeps up to ${state.retention.limit}; trims oldest in batches", panel)
        self.assertNotIn("keeps the last ${state.retention.limit}", panel)


class TrimSelectionRace(unittest.TestCase):
    def test_trim_does_not_drop_a_call_selected_after_candidates_were_chosen(self):
        # The candidate list is built from one snapshot of selection; a click that lands before view.remove
        # must still protect that call — otherwise the engineer loses the call they just opened.
        # Stub mitmproxy: the frozen app has no importable package for /usr/bin/python3.
        addons = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "addons")
        sys.path.insert(0, addons)
        m = types.ModuleType("mitmproxy")
        m.ctx = types.SimpleNamespace()
        m.http = types.SimpleNamespace(HTTPFlow=type("HTTPFlow", (), {}))
        sys.modules.update({"mitmproxy": m})
        import proxy_retention as pr
        flows = []
        for i in range(30):
            f = mock.Mock()
            f.id = "f%d" % i
            f.intercepted = False
            f.live = False
            f.response = object()
            f.error = None
            f.request = mock.Mock(timestamp_start=float(i))
            f.timestamp_start = float(i)
            flows.append(f)
        removed = []
        calls = {"n": 0}

        def selected():
            calls["n"] += 1
            # Second read (just before delete) sees the click that landed after the candidate list.
            if calls["n"] >= 2:
                return {flows[0].id}
            return set()

        view = mock.Mock()
        view._store = {f.id: f for f in flows}
        view.remove = lambda victims: removed.extend(victims)
        master = mock.Mock(view=view)
        opts = mock.Mock(proxy_max_flows=20)
        retention = pr.ProxyRetention()
        with mock.patch.object(pr, "ctx", mock.Mock(master=master, options=opts)), \
                mock.patch.object(pr.ProxyRetention, "_selected", staticmethod(selected)), \
                mock.patch.object(pr.ProxyRetention, "_completed", staticmethod(lambda f: True)):
            retention.trim()
        self.assertNotIn(flows[0], removed)
        self.assertTrue(removed)


class Retention(LiveCase):
    INSTANCE_KW = {"extra_env": {"RIVIS_MAX_FLOWS": "25"}}

    def fill(self, n, stem="fill"):
        for i in range(n):
            self.fetch("/json/small?%s=%d" % (stem, i))
        return wait_for(lambda: (lambda f: f if len(f) <= 25 else None)(self.inst.flows()),
                        10, 0.1, "flow store trimmed to 25")

    def test_oldest_completed_calls_are_dropped_and_status_reports_the_limit(self):
        first = self.fetch("/echo?oldest=1")
        self.assertEqual(first.status, 200)
        oldest = self.inst.flow_for("oldest=1")["id"]
        flows = self.fill(35)
        self.assertGreaterEqual(len(flows), 23)
        self.assertLessEqual(len(flows), 25)
        self.assertNotIn(oldest, {f["id"] for f in flows})
        state = self.panel.state()
        self.assertEqual(state["retention"]["limit"], 25)
        self.assertGreaterEqual(state["retention"]["trimmed"], 11)

    def test_batch_trim_uses_a_low_water_mark_without_exceeding_the_cap(self):
        self.fill(26, "batch")
        count = len(self.inst.flows())
        self.assertGreaterEqual(count, 23)  # 25 - floor(10%)
        self.assertLessEqual(count, 25)

    def test_selected_call_is_never_trimmed(self):
        self.fetch("/echo?selected=1")
        selected = self.inst.flow_for("selected=1")["id"]
        self.panel.ok("flow_selected", {"id": selected})
        flows = self.fill(35, "selected-fill")
        self.assertIn(selected, {f["id"] for f in flows})
        self.panel.ok("flow_selected", {"id": None})

    def test_paused_call_is_never_trimmed(self):
        self.reset_state(breakpoints=[{"name": "hold", "match": r"/echo\?paused", "request": True,
                                       "response": False, "enabled": True}])
        call = Background(self.fetch, "/echo?paused=1", timeout=20)
        paused = wait_for(lambda: self.panel.state()["paused"], 10, 0.1, "paused flow")[0]
        flows = self.fill(35, "paused-fill")
        self.assertIn(paused["id"], {f["id"] for f in flows})
        self.panel.ok("paused_abort", {"id": paused["id"]})
        self.assertNotEqual(call.result().rc, 0)

    def test_in_flight_call_is_never_trimmed(self):
        call = Background(self.fetch, "/slow?ms=2500&inflight=1", timeout=20)
        waiting = wait_for(lambda: self.inst.flow_for("inflight=1"), 10, 0.1, "in-flight call")
        flows = self.fill(35, "inflight-fill")
        self.assertIn(waiting["id"], {f["id"] for f in flows})
        self.assertEqual(call.result().status, 200)


class OpenWebsocketRetention(unittest.TestCase):
    """An open WebSocket has a 101 response, so a naive 'has response' check treats it as done and
    retention can delete it while frames are still flowing."""

    def test_open_websocket_is_never_trimmed(self):
        suite = Suite.get()
        up = suite.upstream()
        inst = Instance(suite, "retention-ws", extra_env={"RIVIS_MAX_FLOWS": "10"}).start()
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        hold = threading.Event()
        client_holder = []

        def ws_server():
            srv.settimeout(30)
            try:
                conn, _ = srv.accept()
            except (socket.timeout, OSError):
                return
            client_holder.append(conn)
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
            hold.wait(30)
            try:
                conn.close()
            except OSError:
                pass

        threading.Thread(target=ws_server, daemon=True).start()
        proxy = None
        try:
            for i in range(6):
                self.assertEqual(inst.fetch(up.url("/json/small?before=%d" % i)).status, 200)
            proxy = socket.create_connection(("127.0.0.1", inst.proxy_port), 5)
            proxy.sendall(("GET http://127.0.0.1:%d/ws?livews=1 HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                           "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                           "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
                           % (port, port)).encode())
            proxy.settimeout(5)
            head = b""
            while b"\r\n\r\n" not in head:
                head += proxy.recv(4096)
            self.assertIn(b" 101 ", head.split(b"\r\n")[0])
            ws = wait_for(lambda: next((f for f in inst.flows()
                                        if "livews=1" in ((f.get("request") or {}).get("path") or "")), None),
                          10, 0.1, "open websocket flow")
            ws_id = ws["id"]
            for i in range(30):
                self.assertEqual(inst.fetch(up.url("/json/small?after=%d" % i)).status, 200)
            flows = wait_for(lambda: (lambda f: f if len(f) <= 10 else None)(inst.flows()),
                             10, 0.1, "store at cap")
            self.assertIn(ws_id, {f["id"] for f in flows},
                          "open WebSocket was trimmed while the client socket was still connected")
            msg, mask = b"still-here", b"\x01\x02\x03\x04"
            proxy.sendall(b"\x81" + bytes([0x80 | len(msg)]) + mask +
                          bytes(b ^ mask[i % 4] for i, b in enumerate(msg)))
        finally:
            hold.set()
            if proxy is not None:
                try:
                    proxy.close()
                except OSError:
                    pass
            srv.close()
            inst.stop()


class RestartSafety(unittest.TestCase):
    def test_restart_with_the_same_state_dir_is_clean_and_keeps_the_configured_cap(self):
        suite = Suite.get()
        up = suite.upstream()
        first = Instance(suite, "retention-restart-a", extra_env={"RIVIS_MAX_FLOWS": "10"}).start()
        home = first.home
        try:
            for i in range(18):
                first.fetch(up.url("/json/small?r=%d" % i))
            wait_for(lambda: len(first.flows()) <= 10, 10, 0.1, "first instance trimmed")
        finally:
            first.stop()
        second = Instance(suite, "retention-restart-b", extra_env={"RIVIS_MAX_FLOWS": "10"})
        second.home = home
        try:
            second.start()
            self.assertEqual(second.panel.state()["retention"]["limit"], 10)
            self.assertEqual(second.fetch(up.url("/json/small?after-restart=1")).status, 200)
            self.assertLessEqual(len(second.flows()), 10)
        finally:
            second.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
