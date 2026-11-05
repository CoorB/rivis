"""mitmweb response viewer helpers: UTF-8 text view, body clipping, and the flow-list feed.

Used by proxy_panel for content views and by the /proxy/api/flows_since poll. No panel state.
"""
import re
import uuid
import zlib

# ── mitmweb's response viewer: text that is text, bodies too big to paint ───────
# R6B-03: mitmproxy's automatic view treats any body whose first bytes are mostly >0x7e as binary, so valid UTF-8
# Arabic or emoji text/plain showed as a hex dump. This view claims such bodies above Hex Dump (0.5) and below every
# format-specific view (1.0); pure ASCII is left to Raw, images to Image, real binary (control bytes) to Hex Dump.
class Utf8TextView:
    name = "Text"
    syntax_highlight = "none"

    @staticmethod
    def _text(data):
        if not data or data.isascii() or b"\x00" in data:
            return None
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        sample = text[:65536]
        ctrl = sum(1 for c in sample if c < " " and c not in "\t\n\r\f\v\x1b")
        return text if ctrl <= len(sample) // 100 else None

    def prettify(self, data, metadata):
        text = self._text(data)
        return text if text is not None else data.decode("utf-8", "replace")

    def render_priority(self, data, metadata):
        if (getattr(metadata, "content_type", None) or "").lower().startswith("image/"):
            return 0
        return 0.6 if self._text(data) is not None else 0


# R6B-07: mitmweb paints a view's text into one <pre>; a 5 MB one-line script or a 20 MB JSON string is wider than
# Chromium can lay out (33,554,430 px), so the block stayed empty. Views are clipped to their first VIEW_CLIP
# characters, with the size in the view's title and a last line saying how to get all of it (panel.js turns the
# title into Download / Open raw links).
VIEW_CLIP = 256 * 1024


def _size(n):
    return "%.1f MB" % (n / 1048576) if n >= 1048576 else "%d KB" % max(1, round(n / 1024))


# R10-01: a content view is built on the event loop that also moves every call, so rendering a 400 MB body stalled all
# traffic for 22 s (50 MB: 3 s). Only the first VIEW_SOURCE bytes of a body larger than VIEW_SOURCE_LIMIT are rendered
# (decoded incrementally when gzip/deflate), which is still far more text than VIEW_CLIP shows. Bodies up to the limit
# render exactly as before; Download / Open raw still give the whole body.
VIEW_SOURCE_LIMIT = 4 * 1024 * 1024
VIEW_SOURCE = 1024 * 1024


def body_prefix(message, limit):
    """(first `limit` decoded bytes, True when the body is longer) without decoding the rest — or None when the
    encoding cannot be decoded piecewise here (the caller decodes the whole body)."""
    raw = message.raw_content or b""
    enc = (message.headers.get("content-encoding") or "").strip().lower()
    if enc in ("", "identity", "none"):
        return raw[:limit], len(raw) > limit
    if enc in ("gzip", "x-gzip", "deflate"):
        for wbits in ((31,) if "gzip" in enc else (15, -15)):
            try:
                d = zlib.decompressobj(wbits)
                out = d.decompress(raw, limit)
                return out, bool(d.unconsumed_tail) or len(out) >= limit
            except zlib.error:
                continue
    return None


def preview_message(message):
    """A copy of message whose body is only its first VIEW_SOURCE decoded bytes, or None when it is small enough to
    render whole (or cannot be cut)."""
    raw = getattr(message, "raw_content", None)
    if not isinstance(raw, (bytes, bytearray)) or len(raw) <= VIEW_SOURCE_LIMIT or not hasattr(message, "headers"):
        return None
    cut = body_prefix(message, VIEW_SOURCE)
    if cut is None:
        return None
    preview = message.copy()
    preview.headers.pop("content-encoding", None)
    preview.raw_content = cut[0]
    return preview


def request_url(r):
    """r.pretty_url with an IPv6 host in brackets (R10-09): mitmproxy writes http://::1:8080/x, which curl and every
    URL parser reject as a bad port."""
    url = r.pretty_url
    if getattr(r, "first_line_format", "") == "authority":
        return url
    for host in (r.pretty_host, r.host):
        if host and ":" in host and not host.startswith("["):
            prefix = "%s://%s" % (r.scheme, host)
            if url.startswith(prefix):
                return "%s://[%s]%s" % (r.scheme, host, url[len(prefix):])
    return url


def clip_view(result, total=None, partial=False):
    """A mitmweb content-view reply ({text, view_name, description, …}) cut to VIEW_CLIP characters; other replies
    (a list of websocket messages, an error) unchanged. partial: the view was built from the body's start only, so it
    says so even when its text is short."""
    if not isinstance(result, dict) or not isinstance(result.get("text"), str):
        return result
    if len(result["text"]) <= VIEW_CLIP and not partial:
        return result
    text = result["text"]
    cut = text.rfind("\n", VIEW_CLIP - 4096, VIEW_CLIP) if len(text) > VIEW_CLIP else len(text)
    cut = cut if cut > 0 else min(VIEW_CLIP, len(text))
    note = "showing first %s of %s" % (_size(cut), _size(max(total or 0, len(text))))
    out = dict(result)
    out["text"] = text[:cut] + "\n\n… [%s — Download or Open raw for the whole body]" % note
    desc = result.get("description") or ""
    if partial and "failed to parse" in desc.lower():
        desc = re.sub(r"\[?failed to parse[^\]]*\]?", "[truncated (%s/%s)]" % (_size(cut), _size(VIEW_SOURCE_LIMIT)), desc, flags=re.I)
    out["description"] = ((desc + " (" + note + ")") if desc else ("(" + note + ")")).strip()
    return out


class FlowFeed:
    """F2: what changed in the flow view since a cursor, so the panel's poll with the Tools drawer open does not download the
    whole call list every second. It listens to the same signals mitmweb's own websocket does (a call added to, changed in or
    removed from the list; the list refreshed or cleared). `epoch` changes whenever the list is rebuilt (clear, filter change):
    a client holding another epoch, or a cursor older than the removals still remembered, is given the whole list."""
    MAX_REMOVED = 4096

    def __init__(self, view):
        self.view = view
        self._reset()
        view.sig_view_add.connect(self._touch)
        view.sig_view_update.connect(self._touch)
        view.sig_view_remove.connect(self._gone)
        view.sig_view_refresh.connect(self._reset)

    def _reset(self, *args, **kw):
        self.epoch = uuid.uuid4().hex[:12]
        self.seq = self.floor = 0
        self.touched = {}           # id of a call in the list -> sequence number of its last add / change
        self.removed = {}           # id of a call that left the list -> sequence number of its removal (oldest first)

    def _touch(self, flow, *args, **kw):
        self.seq += 1
        self.touched[flow.id] = self.seq
        self.removed.pop(flow.id, None)

    def _gone(self, flow, *args, **kw):
        self.seq += 1
        self.touched.pop(flow.id, None)
        self.removed[flow.id] = self.seq
        while len(self.removed) > self.MAX_REMOVED:
            self.floor = max(self.floor, self.removed.pop(next(iter(self.removed))))

    def since(self, epoch, cursor):
        """(full, flows, removed_ids) for a client at (epoch, cursor)."""
        try:
            cursor = int(cursor)
        except (TypeError, ValueError):
            cursor = -1
        if epoch != self.epoch or cursor < self.floor or cursor > self.seq:
            return True, list(self.view), []
        flows = [f for f in (self.view.get_by_id(i) for i, n in self.touched.items() if n > cursor) if f is not None]
        return False, flows, [i for i, n in self.removed.items() if n > cursor]
