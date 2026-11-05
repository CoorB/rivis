"""
HTTP/3 (QUIC) pass-through without "mitmproxy has crashed!" on ignored UDP connections.

mitmproxy 12.2.3's ClientQuicLayer swaps to UDPLayer when tls_clienthello sets
ignore_connection (Rivis does that for hosts that refused the Rivis CA). That swap
reassigns parent.handle_event / _handle_event onto a UDPLayer still in `start`; an
outer cached handle_event then delivers OpenConnection replies, UdpStartHook replies
and further datagrams into `@expect(Start)`, which asserts and floods the log. Each
connection dies; the app falls back to TCP. The same AssertionError shows up for
NextLayer's ignore-path UDPLayer when stray events arrive before Start settles.

Upstream mitmproxy PR 8339 fixes the ClientQuicLayer swap; Rivis keeps the vendored
12.2.3 binary and applies that idea here, plus a tolerant UDPLayer.start. Loaded with
the other -s add-ons (and installed from proxy_rules on import so a hot reload keeps it).
"""
import logging

try:
    from mitmproxy import ctx
except ImportError:  # system Python unit imports: no mitmproxy
    ctx = None

_LOGGED_HOSTS = set()


def _host_label(context):
    client = getattr(context, "client", None)
    server = getattr(context, "server", None)
    for candidate in (
        getattr(client, "sni", None),
        (getattr(server, "address", None) or (None, None))[0],
        (getattr(server, "peername", None) or (None, None))[0],
    ):
        if candidate:
            return str(candidate).split("%", 1)[0]
    return "unknown"


def _log_passthrough_once(context):
    host = _host_label(context).lower()
    if host in _LOGGED_HOSTS:
        return
    _LOGGED_HOSTS.add(host)
    msg = "passing HTTP/3 to %s through unchanged" % host
    if ctx is not None:
        try:
            ctx.log.info(msg)
            return
        except Exception:
            pass
    logging.getLogger("rivis.quic").info(msg)


def install_tolerant_udp_start():
    """UDPLayer.start must not assert on stray replies / datagrams (stale parent._handle_event)."""
    try:
        from mitmproxy import flow
        from mitmproxy.proxy import commands, events
        from mitmproxy.proxy.layers import udp as udp_mod
        from mitmproxy.proxy.layers.udp import UdpErrorHook, UdpStartHook
    except ImportError:
        return False
    UDPLayer = udp_mod.UDPLayer
    if getattr(UDPLayer.start, "_rivis_quic", False):
        return True

    def start(self, event):
        current = self._handle_event
        if current is not start and getattr(current, "__func__", None) is not start:
            yield from current(event)
            return
        if not isinstance(event, events.Start):
            if isinstance(event, events.CommandCompleted):
                return
            pending = getattr(self, "_rivis_pre_start", None)
            if pending is None:
                pending = self._rivis_pre_start = []
            pending.append(event)
            return
        if self.flow:
            yield UdpStartHook(self.flow)
        if self.context.server.timestamp_start is None:
            err = yield commands.OpenConnection(self.context.server)
            if err:
                if self.flow:
                    self.flow.error = flow.Error(str(err))
                    yield UdpErrorHook(self.flow)
                yield commands.CloseConnection(self.context.client)
                self._handle_event = self.done
                return
        self._handle_event = self.relay_messages
        for queued in getattr(self, "_rivis_pre_start", ()):
            yield from self.relay_messages(queued)
        self._rivis_pre_start = []

    start._rivis_quic = True
    UDPLayer.start = start
    # Fresh instances bind _handle_event = start from the class attribute set in the class body;
    # keep the class attribute in sync so new UDPLayers use the tolerant start immediately.
    UDPLayer._handle_event = start
    return True


def install_quic_ignore_swap():
    """Intercept the broken ignore_connection swap and install PR 8339's dispatcher instead."""
    try:
        from mitmproxy.proxy import events
        from mitmproxy.proxy.layers.quic import _stream_layers as sl
    except ImportError:
        return False
    ClientQuicLayer = sl.ClientQuicLayer
    original = ClientQuicLayer.receive_handshake_data
    if getattr(original, "_rivis_quic", False):
        return True

    # parent_id -> replacement UDPLayer waiting for the broken setattr pair
    pending = {}

    def receive_handshake_data(self, data):
        real_udp = sl.UDPLayer

        def capturing_udp(context, ignore=False):
            layer = real_udp(context, ignore=ignore)
            if not ignore:
                return layer
            # ClientQuicLayer is context.layers[-1]; its parent is the layer above it.
            parent = context.layers[context.layers.index(self) - 1]
            pending[id(parent)] = (layer, context)
            parent_cls = type(parent)
            if not getattr(parent_cls, "_rivis_quic_setattr", False):
                def setattr_guard(obj, name, value, _pending=pending):
                    wait = _pending.get(id(obj))
                    if wait is not None and name == "handle_event":
                        return  # keep Layer.handle_event so NextLayer's cached ref still works
                    if wait is not None and name == "_handle_event":
                        repl, ctx_ = _pending.pop(id(obj))

                        def handle_udp_event(event, _repl=repl):
                            if isinstance(event, events.CommandCompleted):
                                return
                                yield
                            yield from _repl._handle_event(event)

                        object.__setattr__(obj, name, handle_udp_event)
                        _log_passthrough_once(ctx_)
                        return
                    object.__setattr__(obj, name, value)

                parent_cls.__setattr__ = setattr_guard
                parent_cls._rivis_quic_setattr = True
            return layer

        sl.UDPLayer = capturing_udp
        try:
            return (yield from original(self, data))
        finally:
            sl.UDPLayer = real_udp
            try:
                parent = self.context.layers[self.context.layers.index(self) - 1]
                pending.pop(id(parent), None)
            except (ValueError, IndexError, AttributeError):
                pass

    receive_handshake_data._rivis_quic = True
    receive_handshake_data._rivis_original = original
    ClientQuicLayer.receive_handshake_data = receive_handshake_data
    return True


def install():
    ok_udp = install_tolerant_udp_start()
    ok_swap = install_quic_ignore_swap()
    return bool(ok_swap or ok_udp)


class ProxyQuic:
    """Log once when NextLayer picks UDP pass-through for a connection (allow/ignore hosts)."""

    def load(self, loader):
        install()

    def configure(self, updated):
        install()

    def next_layer(self, nextlayer):
        if nextlayer.layer is None:
            return
        try:
            from mitmproxy.proxy.layers.udp import UDPLayer
        except ImportError:
            return
        if not isinstance(nextlayer.layer, UDPLayer):
            return
        client = nextlayer.context.client
        if getattr(client, "transport_protocol", None) != "udp":
            return
        addr = getattr(nextlayer.context.server, "address", None)
        port = addr[1] if addr else None
        alpn = getattr(client, "alpn", None) or getattr(client, "alpn_offers", None) or ()
        if port in (443, 8443) or b"h3" in tuple(alpn):
            _log_passthrough_once(nextlayer.context)


addons = [ProxyQuic()]

install()
