"""Bound mitmweb's in-memory flow store by dropping the oldest safe calls first.

Paused breakpoint calls, the call selected in the panel, and calls still on the wire
are never removed. The limit is a mitmproxy option so deployments can set it without
changing project data.

Open WebSockets and retained HTTP bodies are capped separately: a never-closing socket
or a day of multi-megabyte responses must not grow memory without bound after the call
count itself has plateaued.
"""
from mitmproxy import ctx, http

DEFAULT_MAX_FLOWS = 5000
DEFAULT_MAX_WS_MESSAGES = 2000
DEFAULT_MAX_WS_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_BODY_BYTES = 512 * 1024 * 1024

_WS_TAG = "websocket: older messages dropped (keeps the latest)"
_BODY_TAG = "body dropped to free memory"


class ProxyRetention:
    def __init__(self):
        self.trimmed = 0
        self.ws_dropped = 0
        self.bodies_dropped = 0

    def load(self, loader):
        loader.add_option("proxy_max_flows", int, DEFAULT_MAX_FLOWS,
                          "maximum calls retained in memory (oldest completed calls are removed first)")
        loader.add_option("proxy_max_ws_messages", int, DEFAULT_MAX_WS_MESSAGES,
                          "maximum WebSocket messages kept per open call (oldest dropped first)")
        loader.add_option("proxy_max_ws_bytes", int, DEFAULT_MAX_WS_BYTES,
                          "maximum WebSocket payload bytes kept per open call (oldest dropped first)")
        loader.add_option("proxy_max_body_bytes", int, DEFAULT_MAX_BODY_BYTES,
                          "maximum total HTTP body bytes retained across all calls (oldest completed bodies cleared first)")

    @staticmethod
    def _flows():
        view = ctx.master.view
        return list(getattr(view, "_store", {}).values()) or list(view)

    @staticmethod
    def _selected():
        selected = set()
        try:
            flow = ctx.master.view.focus.flow
            if flow is not None:
                selected.add(flow.id)
        except (AttributeError, IndexError):
            pass
        manager = getattr(ctx.master, "addons", None)
        if manager is not None:
            try:
                panel = manager.get("proxypanel")
            except (KeyError, TypeError):
                panel = None
            flow_id = getattr(panel, "selected_flow_id", None)
            if flow_id:
                selected.add(flow_id)
        return selected

    @staticmethod
    def _completed(flow):
        # Still on the wire (open WebSocket after 101, in-flight HTTP, open TCP/UDP): never treat the
        # headers/101 snapshot as done, or trim drops the call the tester is watching.
        if getattr(flow, "live", False):
            return False
        websocket = getattr(flow, "websocket", None)
        if websocket is not None and getattr(websocket, "timestamp_end", None) is None:
            return False
        if isinstance(flow, http.HTTPFlow):
            return flow.response is not None or flow.error is not None
        return True

    @staticmethod
    def _tag(flow, tag):
        comment = flow.comment or ""
        if tag in comment.split(" | "):
            return
        flow.comment = (comment + " | " if comment else "") + tag

    def trim(self):
        limit = int(ctx.options.proxy_max_flows)
        flows = self._flows()
        excess = len(flows) - limit
        if excess <= 0:
            return 0
        selected = self._selected()
        candidates = [f for f in flows if f.id not in selected and not getattr(f, "intercepted", False)
                      and self._completed(f)]
        candidates.sort(key=lambda f: (getattr(getattr(f, "request", None), "timestamp_start", None)
                                       or getattr(f, "timestamp_start", None) or 0, f.id))
        # Drop toward a 90% low-water mark (at most 500 extra) so an all-day session does not
        # sort the 5k-flow view for every single response after reaching the cap.
        batch = min(500, limit // 10)
        victims = candidates[:excess + batch]
        # Re-read selection and pause state just before delete: a click that landed after the
        # candidate list was built must still protect that call (check-then-delete is how user
        # data was lost elsewhere in this project).
        selected = self._selected()
        victims = [f for f in victims if f.id not in selected and not getattr(f, "intercepted", False)]
        if victims:
            ctx.master.view.remove(victims)
            self.trimmed += len(victims)
        return len(victims)

    def trim_bodies(self):
        """Clear request/response bodies of oldest completed calls when the retained total is over budget.

        The call rows stay in the list (headers, status, timing); only the bytes go, so a day of PDFs
        and JSON dumps cannot push RSS by gigabytes after the flow-count cap has already plateaued.
        """
        budget = int(ctx.options.proxy_max_body_bytes)
        if budget <= 0:
            return 0
        selected = self._selected()
        rows = []
        total = 0
        for f in self._flows():
            if not isinstance(f, http.HTTPFlow):
                continue
            req = f.request.raw_content if f.request is not None else None
            resp = f.response.raw_content if f.response is not None else None
            size = (len(req) if isinstance(req, (bytes, bytearray)) else 0) + \
                   (len(resp) if isinstance(resp, (bytes, bytearray)) else 0)
            if size:
                total += size
                rows.append(f)
        if total <= budget:
            return 0
        target = budget - min(budget // 10, 64 * 1024 * 1024)
        rows.sort(key=lambda f: (getattr(getattr(f, "request", None), "timestamp_start", None)
                                 or getattr(f, "timestamp_start", None) or 0, f.id))
        selected = self._selected()
        freed = 0
        dropped = 0
        for f in rows:
            if total - freed <= target:
                break
            if f.id in selected or getattr(f, "intercepted", False) or not self._completed(f):
                continue
            before = 0
            if f.request is not None and isinstance(f.request.raw_content, (bytes, bytearray)):
                before += len(f.request.raw_content)
                f.request.raw_content = None
            if f.response is not None and isinstance(f.response.raw_content, (bytes, bytearray)):
                before += len(f.response.raw_content)
                f.response.raw_content = None
            if before:
                freed += before
                dropped += 1
                f.metadata["proxy_body_dropped"] = True
                self._tag(f, _BODY_TAG)
        if dropped:
            self.bodies_dropped += dropped
            try:
                ctx.master.view.update([f for f in rows if f.metadata.get("proxy_body_dropped")])
            except Exception:
                pass
        return dropped

    def trim_websocket(self, flow):
        """Drop the oldest frames on one WebSocket once the per-call caps are exceeded."""
        ws = getattr(flow, "websocket", None)
        msgs = getattr(ws, "messages", None) if ws is not None else None
        if not msgs:
            return 0
        max_n = int(ctx.options.proxy_max_ws_messages)
        max_b = int(ctx.options.proxy_max_ws_bytes)
        if max_n <= 0 and max_b <= 0:
            return 0
        # Keep a running byte total on the flow so each new frame is O(1) under the caps, not O(n).
        newest = len(msgs[-1].content or b"")
        if "proxy_ws_bytes" in flow.metadata:
            total = int(flow.metadata["proxy_ws_bytes"]) + newest
        else:
            total = sum(len(m.content or b"") for m in msgs)
        flow.metadata["proxy_ws_bytes"] = total
        if (max_n <= 0 or len(msgs) <= max_n) and (max_b <= 0 or total <= max_b):
            return 0
        dropped = 0
        # Cap work per frame so a sudden burst cannot stall every other call on the event loop.
        for _ in range(512):
            if not msgs:
                break
            over_n = max_n > 0 and len(msgs) > max_n
            over_b = max_b > 0 and flow.metadata.get("proxy_ws_bytes", 0) > max_b
            if not over_n and not over_b:
                break
            if len(msgs) == 1 and over_b:
                # One oversized frame: drop its payload but keep the row so the Messages tab still shows a slot.
                msgs[0].content = b""
                flow.metadata["proxy_ws_bytes"] = 0
                dropped += 1
                break
            old = msgs.pop(0)
            flow.metadata["proxy_ws_bytes"] = max(0, int(flow.metadata.get("proxy_ws_bytes", 0)) - len(old.content or b""))
            dropped += 1
        if dropped:
            flow.metadata["proxy_ws_dropped"] = int(flow.metadata.get("proxy_ws_dropped", 0)) + dropped
            self.ws_dropped += dropped
            self._tag(flow, _WS_TAG)
        return dropped

    def response(self, flow):
        self.trim()
        self.trim_bodies()

    def error(self, flow):
        self.trim()
        self.trim_bodies()

    def websocket_message(self, flow):
        self.trim_websocket(flow)

    def websocket_end(self, flow):
        self.trim()
        self.trim_bodies()

    def tcp_end(self, flow):
        self.trim()

    def udp_end(self, flow):
        self.trim()


addons = [ProxyRetention()]
