"""Bound mitmweb's in-memory flow store by dropping the oldest safe calls first.

Paused breakpoint calls and the call selected in the panel are never removed. The
limit is a mitmproxy option so deployments can set it without changing project data.
"""
from mitmproxy import ctx, http

DEFAULT_MAX_FLOWS = 5000


class ProxyRetention:
    def __init__(self):
        self.trimmed = 0

    def load(self, loader):
        loader.add_option("proxy_max_flows", int, DEFAULT_MAX_FLOWS,
                          "maximum calls retained in memory (oldest completed calls are removed first)")

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
        if isinstance(flow, http.HTTPFlow):
            return flow.response is not None or flow.error is not None
        return not bool(getattr(flow, "live", False))

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
        victims = candidates[:excess]
        if victims:
            ctx.master.view.remove(victims)
            self.trimmed += len(victims)
        return len(victims)

    def response(self, flow):
        self.trim()

    def error(self, flow):
        self.trim()

    def websocket_end(self, flow):
        self.trim()

    def tcp_end(self, flow):
        self.trim()

    def udp_end(self, flow):
        self.trim()


addons = [ProxyRetention()]
