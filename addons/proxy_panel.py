"""
proxy_panel — a Proxyman-style project panel inside mitmweb's own page.

Loaded by the product CLI next to proxy_rules.py. Adds, behind mitmweb's existing login:
  /proxy/panel.js      the in-page drawer (injected into mitmweb's index page)
  /proxy/api/...       JSON endpoints the drawer calls (same XSRF scheme as mitmweb's own UI)

It never changes the installed mitmproxy: it registers extra tornado routes on the running
mitmweb app. rules.json stays the single source of truth shared with the CLI; proxy_rules.py
hot-reloads it. If anything here fails it only logs a warning — capture and rules keep working.

Tested on mitmproxy 12.2.3. Re-test after any mitmproxy upgrade (already a security-review step).
"""
import json
import importlib
import math
import mimetypes
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
import zlib
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from mitmproxy import ctx, flowfilter, http
from mitmproxy.addonmanager import traverse

HERE = os.path.dirname(os.path.abspath(__file__))

# mitmweb serves a strict CSP (default-src 'self'; no 'unsafe-inline' for scripts), so the boot logic
# CANNOT be an inline <script> — it would be blocked and the skin would only apply late, after panel.js
# loads (a flash of stock mitmweb), and the ?theme=off kill switch would never run. It is therefore
# served as a same-origin external script (/proxy/boot.js), injected synchronously into <head> so it
# runs before first paint. It applies the remembered theme / density and, unless the skin is switched
# off (?theme=off or the panel toggle), parser-writes the /proxy/theme.css link (render-blocking → no
# flash). Everything is wrapped in try/catch because localStorage can throw in private windows.
THEME_BOOT = '<script src="./proxy/boot.js"></script>'
BOOT_JS = b"""(function(){var load=true;try{
var d=document.documentElement,s=window.localStorage,q=new URLSearchParams(location.search),t=q.get("theme");
if(t==="off"||t==="on")s.setItem("rivis-skin",t);else if(t==="light"||t==="dark"||t==="system")s.setItem("rivis-theme",t);
var k=s.getItem("rivis-skin")||s.getItem("proxy-restyle")||"on",m=s.getItem("rivis-theme");
if(m==="light"||m==="dark")d.setAttribute("data-theme",m);
if(s.getItem("rivis-compact")==="on")d.setAttribute("data-density","compact");
if(k==="off"){d.setAttribute("data-skin","off");load=false;}
}catch(e){}
if(load)document.write('<link rel="stylesheet" href="./proxy/theme.css" id="rivis-theme">');})();"""
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import proxy_common
importlib.reload(proxy_common)
from rules_cli import acquire_lock
from proxy_common import (ACTION_REQUIREMENTS, ACTIONS, PANEL_PROFILES, PRESETS, PRODUCT, SAFE_NAME, STATE_ROOT, atomic_json,
                          atomic_write_bytes, atomic_write_text, breakpoints, commit_temp_file,
                          confined_path, migrate_collection, migrate_rules, owned_mock_file, project_profile,
                          project_profiles, project_state, tls_config, tls_covering, tls_update,
                          throttle_shorthand, user_regex, without_hop_headers)
from proxy_codegen import TARGETS, generate
import proxy_redact
import devices
importlib.reload(devices)
from proxy_compose import ComposerStore, normalize_request, normalize_url
from curl_import import parse_curl
from proxy_rule_validation import compile_rule, explain_rules, map_remote_warning
from proxy_scripts import (decode_grpc_frames, decode_protobuf, detect_graphql, find_jwts)
import proxy_source        # helpers only (summaries, the list-filter clause); the add-on itself is loaded by the CLI
importlib.reload(proxy_source)

DEFAULT_STATE = os.path.join(STATE_ROOT, "projects", "default")
_VERSION_AT_LOAD = None
STATE_DIR = DEFAULT_STATE          # confinement base for every panel file op (F-09/B5)
COLL_DIR = os.path.join(DEFAULT_STATE, "collections")
SESS_DIR = os.path.join(DEFAULT_STATE, "sessions")
MOCK_DIR = os.path.join(DEFAULT_STATE, "mocks")
SCRIPT_DIR = os.path.join(DEFAULT_STATE, "scripts")
COMPOSE_DIR = os.path.join(DEFAULT_STATE, "composer")
# FRTMProxy's built-in traffic profiles (same numbers), then manual. latency/jitter ms, kbps, loss %
PROFILES = PANEL_PROFILES
MANUAL_KEYS = ("latency_ms", "jitter_ms", "down_kbps", "up_kbps", "loss_pct", "response_delay_ms")
SCRIPT_TEMPLATES = {
    "header": "add/replace a request header",
    "json": "rewrite a JSON response field",
    "mock": "answer locally with a mock",
    "latency": "add latency to one endpoint",
    "token": "log every token refresh",
}
# Bounds on what the signed-in panel may send. Sized for real QA work (QA-02, QA-06): a HAR of a whole user journey
# from Proxyman, Charles or a browser (thousands of calls, ~80 JSON values per call) and editing a large catalogue or
# transaction-history body at a breakpoint or in Map Local. The old 8 MiB / 2 MiB / 10 000 refused a 55-call HAR.
MAX_PANEL_REQUEST_BYTES = 64 * 1024 * 1024
MAX_PANEL_TEXT_BYTES = 32 * 1024 * 1024
MAX_PANEL_VALUES = 1000000
MAX_PANEL_DEPTH = 16
# F-03: a session HAR leaves out any single body larger than this (with a comment saying so). Redacting a 60 MB body
# took a minute of pure-Python regex that holds the interpreter lock, so even off the event loop it froze live traffic.
HAR_BODY_LIMIT = 4 * 1024 * 1024
# A binary mock (a PDF, an image) opens in the editor as text with U+FFFD for every byte that is not UTF-8. Chromium needs
# ~10 s to lay out 1 MB of that in a textarea (~110 s for 3 MB; plain ASCII takes 75 ms), blocking the whole page. Above this
# size the editor gets a read-only preview of the first bytes; status and headers stay editable and Save keeps the file's bytes.
MOCK_BINARY_PREVIEW = 16 * 1024
# panel ops whose work (disk read, HAR build, redaction) runs on a worker thread so live traffic and the panel keep flowing
OFF_LOOP_OPS = ("sess_har",)


def wildcard_regex(host, path, literal_query=False):
    """FRTMProxy-style host/path with * and ? wildcards → URL regex used by the rules engine."""
    def wc(t, star):
        return "".join(star if c == "*" else "." if c == "?" else re.escape(c) for c in t)
    host = (host or "").strip()
    path = (path or "/").strip() or "/"
    full_url = host.startswith(("http://", "https://"))
    if full_url:                             # a full URL pasted into the host box
        parsed = urlsplit(host)
        host = parsed.netloc.lower()
        path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        literal_query = bool(parsed.query)
    else:
        host = host.lower()
    if not host:
        raise PanelError("host is required")
    if not path.startswith("/"):
        path = "/" + path
    if literal_query and "?" in path:
        route, query = path.split("?", 1)
        return r"^https?://" + wc(host, r"[^/:]*") + r"(:\d+)?" + wc(route, ".*") + r"\?" + wc(query, ".*") + "$"
    return r"^https?://" + wc(host, r"[^/:]*") + r"(:\d+)?" + wc(path, ".*") + r"(\?|$)"


def http_status(value):
    """A status code a client can read: 100..599, else a clear error (0, -1 or 70000 gave the app an empty reply)."""
    text = str(value).strip()
    if not text.isdigit() or not 100 <= int(text) <= 599:
        raise PanelError("status must be a number from 100 to 599")
    return int(text)


class PanelError(ValueError):
    """A user-facing 400. A ValueError on purpose: after a hot reload the API route (registered once) still holds the
    OLD module's PanelError while the swapped-in implementation raises the NEW one; both are ValueErrors."""



HOST_NAME = re.compile(r"[A-Za-z0-9._:\[\]-]{1,253}")      # DNS names, IPv4, IPv6 (with or without brackets)

def _session_meta(doc, fallback_name):
    """Only the typed fields the panel shows: a shared or planted .meta.json must not inject markup (F-15)."""
    if not isinstance(doc, dict):
        return None
    name = doc.get("name") if isinstance(doc.get("name"), str) and SAFE_NAME.fullmatch(doc.get("name")) else fallback_name
    if not SAFE_NAME.fullmatch(name or ""):
        return None
    number = lambda v: v if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) else 0
    hosts = doc.get("hosts") if isinstance(doc.get("hosts"), list) else []
    return {"name": name, "note": doc.get("note") if isinstance(doc.get("note"), str) else "",
            "count": int(number(doc.get("count"))), "created": float(number(doc.get("created"))),
            "hosts": [h for h in hosts if isinstance(h, str)][:8]}

# ── mitmweb bundle fix ──────────────────────────────────────────────────────────
# mitmweb 12's FlowTable.onViewportUpdate stores min(scrollTop, end * rowHeight) as viewportTop but compares the
# UNclamped scrollTop against it. Whenever scrollTop is past the last rendered row (the sticky header's height, a list
# that just shrank under the retention cap, a very short list pane) the two never match, every componentDidUpdate
# calls setState again, and React aborts the page with error #185 ("mitmproxy has crashed") while the user scrolls.
# The fix compares the clamped value. Matched by shape, not minified names; if a future mitmweb changes the code the
# bundle is served unchanged and a warning is logged.
MITMWEB_PATCH_VERSION = "1"
_VIEWPORT_LOOP = re.compile(
    r"if\(this\.state\.viewportTop!==(\w+)\|\|!(\w+)\(this\.state\.vScroll,(\w+)\)\)\{"
    r"const (\w+)=Math\.min\(\1,\3\.end\*this\.props\.rowHeight\);"
    r"this\.setState\(\{vScroll:\3,viewportTop:\4\}\)\}")


def patch_mitmweb_js(source, warn=None):
    patched, n = _VIEWPORT_LOOP.subn(
        lambda m: ("{const %(t)s=Math.min(%(s)s,%(v)s.end*this.props.rowHeight);"
                   "if(this.state.viewportTop!==%(t)s||!%(eq)s(this.state.vScroll,%(v)s))"
                   "this.setState({vScroll:%(v)s,viewportTop:%(t)s})}")
        % {"s": m.group(1), "eq": m.group(2), "v": m.group(3), "t": m.group(4)}, source)
    if n != 1 and warn and "this.state.viewportTop" in source:
        warn("proxy_panel: mitmweb's flow-list code changed; the scroll-crash fix was not applied")
    return patched if n == 1 else source


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


# Pilot 2026-10-21: "I can't log in to the app while the tool is running". Rivis captures every simulator as soon as it
# starts, but only a simulator / emulator that trusts the Rivis CA can talk HTTPS through it: on any other, every HTTPS
# call failed at the handshake, the app said "Network error" and the call list showed nothing at all. Now a host the
# client refuses the certificate for passes through undecrypted for a while (the app keeps working), and the panel says
# which hosts and how to set the device up.
UNTRUSTED_REFUSED = ("does not trust", "certificate unknown", "unknown ca", "bad certificate")   # the client said no
UNTRUSTED_DROPPED = "disconnected during the handshake"      # iOS just hangs up: counts after a second time
UNTRUSTED_WINDOW = 30          # seconds in which two dropped handshakes count
UNTRUSTED_HOLD = 600           # seconds a refused host passes through before Rivis tries to decrypt it again

# seconds between checks that the emulators `android on` set up still use this proxy (tests shorten it)
ANDROID_WATCH_EVERY = float(os.environ.get("RIVIS_ANDROID_WATCH_SECONDS") or 15)


class ProxyPanel:
    def __init__(self):
        self._tls_drops = {}            # host -> monotonic times of recent dropped client handshakes
        self._untrusted = {}            # host -> (monotonic time it started passing through, wall time)
        self._device_jobs = devices.Jobs()
        self._sysproxy_stale_since = 0.0        # see _system_proxy_check
        self._sysproxy = devices.Snapshot(self._system_proxy_check, 5)       # off the event loop (review R1)
        self._devices = devices.Snapshot(self._devices_check, 2)
        self._update = devices.Snapshot(self._update_check, 6 * 3600)        # signed in-app updates (addons/updater.py)
        self._update_login = None                                            # the device-flow sign-in in progress
        self._update_installing = None
        self._browser_jobs = devices.Jobs("a browser is still starting — wait a moment")
        self.project_only = False
        self.show_dns = False
        self.focused_host = None
        self.graphql_operation = None
        self.source = None              # "<kind>|<device>|<app id>" (one app) or "<kind>|<device>|" (one device)
        self.selected_flow_id = None
        self._coll_count_cache = {}
        self._viewer_cache = {}
        self._panel_view_filter = None
        self.active_project = "default"
        self.view_project = "default"
        self.active_profile = {"id": "default", "label": "All", "hosts": "", "record_match": "."}
        self._tls_tunnels = False      # is the list filter currently showing tunnel rows?
        self._last_good_cfg = {"rules": []}
        self._rules_error = None
        self._bad_cfg = None

    def configure(self, updated):
        global STATE_DIR, COLL_DIR, SESS_DIR, MOCK_DIR, SCRIPT_DIR, COMPOSE_DIR
        if "proxy_project" in updated or "proxy_rules_file" in updated:
            base = project_state(ctx.options.proxy_project)
            STATE_DIR = base
            COLL_DIR = os.path.join(base, "collections")
            SESS_DIR = os.path.join(base, "sessions")
            MOCK_DIR = os.path.join(base, "mocks")
            SCRIPT_DIR = os.path.join(base, "scripts")
            COMPOSE_DIR = os.path.join(base, "composer")      # created on first save (0700)
            for directory in (COLL_DIR, SESS_DIR, MOCK_DIR, SCRIPT_DIR):
                os.makedirs(directory, mode=0o700, exist_ok=True)
                os.chmod(directory, 0o700)
        if "proxy_project" in updated:
            self.active_project = ctx.options.proxy_project
            self.view_project = self.active_project
            self.active_profile = project_profile(self.active_project)

    def tls_failed_client(self, data):
        conn = data.conn
        host, err = (conn.sni or "").lower(), str(conn.error or "").lower()
        if not host:
            return
        now = time.monotonic()
        if not any(x in err for x in UNTRUSTED_REFUSED):
            if UNTRUSTED_DROPPED not in err:
                return
            drops = [t for t in self._tls_drops.get(host, ()) if now - t < UNTRUSTED_WINDOW] + [now]
            self._tls_drops[host] = drops[-5:]
            if len(drops) < 2:
                return
        if host not in self._untrusted:
            self._untrusted[host] = (now, time.time())
            ctx.log.warn(f"proxy_panel: a client does not trust the {PRODUCT['name']} certificate for {host}; its HTTPS "
                         f"passes through undecrypted for {UNTRUSTED_HOLD // 60} min (set the device up: Tools → Devices)")

    def tls_clienthello(self, data):
        host = (data.client_hello.sni or "").lower()
        hit = self._untrusted.get(host)
        if hit is None:
            return
        if time.monotonic() - hit[0] < UNTRUSTED_HOLD:
            data.ignore_connection = True
        else:
            del self._untrusted[host]

    def untrusted_state(self):
        now = time.monotonic()
        return [{"host": h, "since": wall} for h, (t, wall) in sorted(self._untrusted.items(), key=lambda x: -x[1][0])
                if now - t < UNTRUSTED_HOLD]

    def load(self, loader):
        loader.add_option("proxy_bootstrap_file", str, "", "one-time browser login nonce file")

    @property
    def view_profile(self):
        return project_profile(self.view_project)

    @staticmethod
    def project_filter(profile):
        hosts = profile.get("hosts") or ""
        if not hosts:
            return ""
        # mitmproxy unescapes filter-string backslashes; double them before quoting.
        return "~d '" + hosts.replace("\\", "\\\\").replace("'", "\\'") + "'"

    # ── rules file (same format as rules_cli.py / proxy_rules.py) ────────────────
    @property
    def rules_path(self):
        try:
            return os.path.expanduser(ctx.options.proxy_rules_file)
        except Exception:
            return os.path.join(DEFAULT_STATE, "rules.json")

    def load_cfg(self):
        cfg = None
        try:
            try:
                with open(self.rules_path) as f:
                    cfg = migrate_rules(json.load(f))
            except FileNotFoundError:
                cfg = {}
            if not isinstance(cfg, dict):
                raise ValueError("top level must be an object")
            cfg.setdefault("rules", [])
            if not isinstance(cfg["rules"], list):
                raise ValueError("rules must be a list")
            for rule in cfg["rules"]:
                if not isinstance(rule, dict):
                    raise ValueError("each rule must be an object")
            throttle = str(cfg.get("throttle", "off") or "off").lower()
            shorthand = throttle_shorthand(throttle)
            if throttle not in PRESETS and shorthand is None:       # PRESETS = the panel's profiles + the CLI's lte/3g/edge/slow
                raise ValueError("unknown throttle '%s'" % throttle)
            if cfg.get("throttle_match"):
                user_regex(cfg["throttle_match"])
            tls_config(cfg)
        except (PanelError, TypeError, ValueError, re.error) as exc:
            self._rules_error = str(exc)
            self._bad_cfg = cfg
            for addon in self._addons():
                if addon.__class__.__name__ == "ProxyRules" and getattr(addon, "last_good_cfg", None):
                    self._last_good_cfg = addon.last_good_cfg
                    break
            return self._last_good_cfg
        self._last_good_cfg = cfg
        self._rules_error = None
        self._bad_cfg = None
        return cfg

    def save_cfg(self, cfg):
        if self._rules_error:
            raise PanelError("rules.json is invalid on disk: %s; fix it before changing rules" % self._rules_error)
        try:
            with open(self.rules_path) as fh:
                json.load(fh)
        except (OSError, ValueError) as exc:
            raise PanelError("rules.json is invalid on disk: %s; fix it before changing rules" % exc)
        atomic_json(self.rules_path, migrate_rules(cfg))
        # Apply now, not on the proxy's next once-a-second poll: a breakpoint set in the panel must catch the very next
        # call (on a quiet app that is the only call; seen with a real app, 2026-10-15).
        for addon in self._addons():
            if addon.__class__.__name__ == "ProxyRules":
                try:
                    addon.mtime = None
                    addon._reload(force=True)
                except Exception as e:  # noqa: BLE001 - the file is saved; the proxy still picks it up on its next poll
                    ctx.log.warn(f"panel: could not apply the rules change at once: {e}")

    @staticmethod
    def _check_input(value):
        """Bound decoded panel values as well as the HTTP body to protect every operation."""
        stack = [(value, 0)]
        seen = 0
        while stack:
            item, depth = stack.pop()
            seen += 1
            if seen > MAX_PANEL_VALUES:
                raise PanelError("request contains too many values")
            if depth > MAX_PANEL_DEPTH:
                raise PanelError("request is nested too deeply")
            if isinstance(item, str) and len(item.encode("utf-8")) > MAX_PANEL_TEXT_BYTES:
                raise PanelError("text value exceeds the %d MiB panel limit" % (MAX_PANEL_TEXT_BYTES // (1024 * 1024)))
            if isinstance(item, dict):
                stack.extend((key, depth + 1) for key in item)
                stack.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                stack.extend((child, depth + 1) for child in item)

    @staticmethod
    def find(cfg, name):
        for r in cfg["rules"]:
            if r.get("name") == name:
                return r
        raise PanelError(f"no rule named '{name}'")

    @staticmethod
    def validate(r):
        if not SAFE_NAME.fullmatch(r.get("name", "")):
            raise PanelError("name: letters, digits, . _ - only (max 64)")
        if r.get("action") not in ACTIONS:
            raise PanelError("unknown action")
        if "method" in r:
            if r["method"] is not None and not isinstance(r["method"], str):
                raise PanelError("method must be text")
            if not (r["method"] or "").strip():
                del r["method"]                     # "" / null = any method, as the engine reads it
        for k in ("match", "replace"):
            if k in r:
                try:
                    user_regex(r[k])
                except re.error as e:
                    raise PanelError(f"bad regex in {k}: {e}")
        missing = [k for k in ACTION_REQUIREMENTS[r["action"]] if k not in r]
        if missing:                       # the engine would skip it later; say so now, not after a "saved"
            raise PanelError(f"action '{r['action']}' needs: {', '.join(missing)}")
        if r["action"] in ("respond", "status") and ("status" in r or r["action"] == "status"):
            if not str(r.get("status", "")).isdigit():
                raise PanelError("status must be a number")
            if not 100 <= int(r["status"]) <= 599:
                raise PanelError("status must be 100..599")
        if r["action"] == "delay":
            try:
                ms = float(r["ms"])
            except (TypeError, ValueError):
                raise PanelError("delay ms must be a number")
            if not 0 <= ms <= 600000:
                raise PanelError("delay ms must be 0..600000")
        if r["action"] == "set_header" and not isinstance(r["header"], str):
            raise PanelError("header must be text")
        if r["action"] == "json_patch" and not (isinstance(r["set"], dict) and r["set"]):
            raise PanelError("set must be an object of path: value")
        if r["action"] == "map_remote" and not isinstance(r["with"], str):
            raise PanelError("with must be text")

    def engine_check(self, r):
        """The proxy skips a rule its loader refuses; refuse it here too, so "saved" never means "silently inert"."""
        try:
            confdir = os.path.expanduser(ctx.options.confdir)
        except (AttributeError, KeyError):
            confdir = None
        state_dir = os.path.dirname(os.path.abspath(os.path.expanduser(self.rules_path)))
        try:
            compile_rule(dict(r), state_dir, r.get("name"), confdir)
        except (KeyError, TypeError, ValueError, re.error) as e:
            raise PanelError("the proxy would skip this rule: %s" % e)

    # ── mock files: only ever <active-project>/mocks/<safe-name>.json ──────────
    @staticmethod
    def mock_text(raw):
        """How the panel editor sees a mock file: (text, binary, clipped)."""
        try:
            return raw.decode("utf-8"), False, False
        except UnicodeDecodeError:
            if len(raw) > MOCK_BINARY_PREVIEW:
                return raw[:MOCK_BINARY_PREVIEW].decode("utf-8", "replace"), True, True
            return raw.decode("utf-8", "replace"), True, False

    @staticmethod
    def mock_path(name):
        if not SAFE_NAME.fullmatch(name or ""):
            raise PanelError("bad mock name")
        return os.path.join(MOCK_DIR, name + ".json")

    @staticmethod
    def _servable_mock(r):
        """A Map Local rule worth reopening: its file is one of this project's mocks and exists."""
        f = r.get("file")
        if not isinstance(f, str) or not f:
            return False
        real = os.path.realpath(os.path.expanduser(f))
        return os.path.dirname(real) == os.path.realpath(MOCK_DIR) and os.path.isfile(real)

    # ── state for the drawer ──────────────────────────────────────────────────
    def _rules_outside(self, cfg):
        """Names of rules that read a file outside the project (allowed only because the user trusted it here)."""
        base = os.path.realpath(os.path.dirname(os.path.abspath(self.rules_path)))
        out = []
        for r in cfg.get("rules", []):
            f = isinstance(r, dict) and (r.get("file") or r.get("body_file"))
            if isinstance(f, str) and f:
                real = os.path.realpath(os.path.expanduser(f))
                if real != base and not real.startswith(base + os.sep):
                    out.append(r.get("name"))
        return out

    def state(self):
        cfg = self.load_cfg()
        tls_cfg = self._bad_cfg if self._rules_error and isinstance(self._bad_cfg, dict) and "tls" in self._bad_cfg else cfg
        tls = self.tls_state(tls_cfg)
        self._sync_view_state()
        if (tls["mode"] != "all") != self._tls_tunnels:
            self._tls_tunnels = tls["mode"] != "all"
            self._write_view_filter()      # show / hide the host-only tunnel rows of undecrypted hosts
        bps = breakpoints(cfg)
        return {
            "product": PRODUCT,
            "active_project": self.active_project,
            "view_project": self.view_project,
            "project": self.view_profile,
            "projects": project_profiles(),
            "project_state": project_state(self.active_project),
            "rules_file": self.rules_path,
            "home": os.path.expanduser("~"),          # the panel shows file paths as ~/… (shorter, and no temp-dir noise)
            "rules_error": self._rules_error,
            "rules": cfg["rules"],
            "rule_warnings": {r.get("name", "?"): w for r in cfg["rules"] if isinstance(r, dict)
                              for w in [map_remote_warning(r)] if w},
            "rules_outside": self._rules_outside(cfg),
            "throttle": cfg.get("throttle", "off"),
            "throttle_match": cfg.get("throttle_match", ""),
            "loss": cfg.get("loss", 0),
            "no_cache": bool(cfg.get("no_cache")),
            "manual": {k: (cfg.get("manual") or {}).get(k, 0) for k in MANUAL_KEYS},
            "profiles": PROFILES,
            "breakpoints": bps,
            "paused": self.paused(),
            "collections": self.collections(cfg),
            "sessions": self.sessions(),
            "skipped_rules": self.skipped_rules(),
            "rule_hits": self.rule_hits(),
            "scripts": self.scripts(cfg),
            "script_status": self.script_status(),
            "retention": self.retention_state(),
            "update": self.update_state(),
            "version": self.product_version(),
            "system_proxy": self.system_proxy_state(),
            "untrusted": self.untrusted_state(),
            "android_restored": list(getattr(ctx.master, "_rivis_android_restored", [])),
            "flow_count": len(self.all_flows()),
            "stream_large_bodies": str(ctx.options.stream_large_bodies),
            "ssl_insecure": bool(getattr(ctx.options, "ssl_insecure", False)),
            "focus_host": self.focused_host,
            "project_only": self.project_only,
            "show_dns": self.show_dns,
            "graphql_operation": self.graphql_operation,
            "source": self.source,
            "sources": proxy_source.summarize(self.all_flows(), self._listed),
            "tls": tls,
            "composer": self.composer_state(),
            "saved_filters": self.filters_list(),
            "codegen_targets": [{"id": k, "name": v} for k, v in TARGETS],
        }

    @staticmethod
    def _addons():
        manager = getattr(ctx.master, "addons", None)
        if manager is None:
            return []
        found = []
        for name in ("proxyrules", "proxycollections", "proxyscripts", "proxyretention"):
            try:
                addon = manager.get(name)
            except (KeyError, TypeError):
                addon = None
            if addon is not None:
                found.append(addon)
        try:
            nested = traverse(manager.chain)
        except (AttributeError, TypeError):
            nested = ()
        for addon in nested:
            if addon not in found:
                found.append(addon)
        return found

    @staticmethod
    def _edit_request(req, e, hdr):
        """Apply method/url/headers edits from the paused sheet / Edit & Repeat. R2A-01: the sheet sends EVERY header back,
        so an edited URL host would be undone by the stale Host header; when the URL host changed and the sheet's Host is
        still the old one (the user did not touch it), the Host follows the new URL."""
        if e.get("method"):
            req.method = e["method"].upper()
        old_host = req.headers.get("Host")
        if e.get("url") and e["url"] != req.url:
            req.url = normalize_url(e["url"])   # R7A-01: the sheet can contain a browser-style Unicode URL
        new_host = req.headers.get("Host")
        if "headers" in e:
            req.headers = hdr(e["headers"])
            if new_host != old_host and req.headers.get("Host") == old_host:
                req.headers["Host"] = new_host

    def skipped_rules(self):
        for addon in self._addons():
            if addon.__class__.__name__ == "ProxyRules":
                failed = getattr(addon, "failed_rules", {})     # R2A-02: mock files that vanished after load
                return list(getattr(addon, "skipped_rules", [])) + [
                    {"name": n, "error": "mock file unusable, requests get 502: " + e} for n, e in failed.items()]
        return []

    def rule_hits(self):
        for addon in self._addons():
            if addon.__class__.__name__ == "ProxyRules" and hasattr(addon, "hit_summary"):
                return addon.hit_summary()
        return None

    def rule_test(self, flow_id):
        """Explain, rule by rule, what the current rules would do to this call (the panel's "Test against this call")."""
        f = self.flow_any(flow_id)
        if not hasattr(f, "request"):
            raise PanelError("this row is a tunnel to a host that is not decrypted: there is no URL to test")
        cfg = self.load_cfg()
        try:
            confdir = os.path.expanduser(ctx.options.confdir)
        except (AttributeError, KeyError):
            confdir = None
        state_dir = os.path.dirname(os.path.abspath(os.path.expanduser(self.rules_path)))
        rows = explain_rules(cfg.get("rules", []), state_dir, f.request.pretty_url, f.request.method, confdir)
        return {"url": f.request.pretty_url, "method": f.request.method, "rules": rows}

    def script_status(self):
        for addon in self._addons():
            if addon.__class__.__name__ == "ProxyScripts":
                from proxy_scripts import node_missing_message
                return {"node": bool(getattr(addon, "node", None)),
                        "node_message": None if getattr(addon, "node", None) else node_missing_message(),
                        "errors": dict(getattr(addon, "last_errors", {}))}
        return {"node": False, "node_message": "Scripting add-on is not loaded", "errors": {}}

    def system_proxy_state(self):
        """The Mac's system proxy, as the iOS Simulator sees it: the last background check (at most 5 s old)."""
        if sys.platform != "darwin":
            return None
        return self._sysproxy.get()[1]

    def _system_proxy_check(self):
        """Inspect the system proxy off the event loop; clear only a previously observed Rivis/Proxyman leftover."""
        import socket
        import time
        now = time.time()
        stale_since = self._sysproxy_stale_since
        info = None
        try:
            txt = subprocess.run(["scutil", "--proxy"], capture_output=True, text=True, timeout=3).stdout
            kv = dict(re.findall(r"^\s*(\w+)\s*:\s*(\S+)", txt, re.M))
            for pre in ("HTTPS", "HTTP"):
                if kv.get(pre + "Enable") == "1":
                    host, port = kv.get(pre + "Proxy", ""), kv.get(pre + "Port", "")
                    owner, ours = "", False
                    if port.isdigit() and host in ("127.0.0.1", "localhost"):
                        rows = subprocess.run(["lsof", "-nP", "-iTCP:%s" % port, "-sTCP:LISTEN"], capture_output=True,
                                              text=True, timeout=3).stdout.splitlines()[1:]
                        if rows:
                            owner, ours = rows[0].split()[0], rows[0].split()[1] == str(os.getpid())
                        try:
                            with socket.create_connection(("127.0.0.1", int(port)), timeout=0.5):
                                owner = owner or "another local listener"
                        except OSError:
                            pass
                    info = {"host": host, "port": port, "owner": owner, "ours": ours,
                            "stale": host in ("127.0.0.1", "localhost", "::1") and not owner}
                    break
        except (OSError, subprocess.SubprocessError, IndexError):
            info = None
        if info and info["stale"]:
            if stale_since and now - stale_since >= 4:          # not a proxy app in the middle of quitting
                try:
                    reset = subprocess.run([devices.CLI, "net-reset", "--auto"], capture_output=True, text=True, timeout=30)
                    if reset.returncode == 0 and "fixed:" in reset.stdout:
                        info = dict(info, fixed=True)
                except (OSError, subprocess.SubprocessError):
                    pass
                stale_since = 0.0
            elif not stale_since:
                stale_since = now
        else:
            stale_since = 0.0
        self._sysproxy_stale_since = stale_since
        return info

    # ── in-app updates: everything slow (network, Keychain) runs off the event loop ─────────────────────────────────
    @staticmethod
    def _updater(*args, timeout=90):
        try:
            r = subprocess.run(["/usr/bin/python3", "-I", os.path.join(HERE, "updater.py"), *args],
                               capture_output=True, text=True, timeout=timeout)
            return r.returncode, json.loads(r.stdout or "{}")
        except (OSError, subprocess.SubprocessError, ValueError) as e:
            return 1, {"error": "update check failed: %s" % e}

    def _update_check(self):
        rc, st = self._updater("status")
        out = dict(st if rc == 0 else {}, available=None, error=None if rc == 0 else st.get("error"))
        if rc == 0 and st.get("configured") and st.get("signed_in") and st.get("installed"):
            rc, j = self._updater("check")
            if rc == 0:
                out["available"] = j.get("available")
            else:
                out["error"] = j.get("error")
                out["signed_in"] = self._updater("status")[1].get("signed_in", False)   # a revoked sign-in is forgotten
        return out

    def _update_login_flow(self):
        import time
        rc, j = self._updater("login-start", timeout=30)
        if rc != 0:
            self._update_login = {"status": "error", "error": j.get("error")}
            return
        self._update_login = {"status": "waiting", "user_code": j["user_code"], "uri": j["verification_uri"],
                              "expires_at": j["expires_at"]}
        interval = int(j.get("interval", 5))
        while time.time() < j["expires_at"]:
            time.sleep(interval)
            rc, r = self._updater("login-poll", j["device_code"], timeout=30)
            if rc != 0:
                self._update_login = {"status": "error", "error": r.get("error")}
                return
            if r.get("result") == "ok":
                self._update_login = {"status": "ok"}
                self._update.invalidate()
                return
            if r.get("result") == "slow_down":
                interval += 5
        self._update_login = {"status": "error", "error": "the code expired — sign in again"}

    def update_state(self):
        have, snap = self._update.get()
        out = dict(snap if have and snap else {"pending": True})
        login = self._update_login
        out["login"] = {k: v for k, v in login.items() if k != "device_code"} if login else None
        out["installing"] = self._update_installing
        return out

    @staticmethod
    def product_version():
        """The version this proxy process STARTED with: an update swaps the files before it restarts the proxy, and the
        page must reload only once the new version is actually running."""
        global _VERSION_AT_LOAD
        if _VERSION_AT_LOAD is None:
            _VERSION_AT_LOAD = ""
            for p in (os.path.join(os.path.dirname(HERE), "VERSION"), os.path.join(os.path.dirname(HERE), "install", "VERSION")):
                try:
                    _VERSION_AT_LOAD = open(p).read().strip()
                    break
                except OSError:
                    continue
        return _VERSION_AT_LOAD

    def retention_state(self):
        for addon in self._addons():
            if addon.__class__.__name__ == "ProxyRetention":
                return {"limit": int(ctx.options.proxy_max_flows), "trimmed": int(getattr(addon, "trimmed", 0))}
        return {"limit": 5000, "trimmed": 0}

    @staticmethod
    def _bp_hits(bp, f, phase):
        """Does breakpoint bp hold call f at phase ("request" / "response")?"""
        if bp.get("enabled") is False or not bp.get(phase) or (bp.get("method") and bp["method"] != f.request.method):
            return False
        try:
            return bool(user_regex(bp.get("match") or ".").search(f.request.pretty_url))
        except re.error:
            return False

    def release_held(self, cfg, changed):
        """A breakpoint that was deleted or switched off lets go of the calls it is holding (unless another still holds them)."""
        hits = self._bp_hits
        flows = []
        for f in self.all_flows():
            if not getattr(f, "intercepted", False) or not getattr(f, "request", None):
                continue
            phase = "response" if f.response else "request"
            if any(hits(b, f, phase) for b in changed) and not any(hits(b, f, phase) for b in cfg.get("breakpoints") or []):
                f.comment = (f.comment + " | " if f.comment else "") + "breakpoint removed: sent unchanged"
                f.resume()
                flows.append(f)
        if flows:
            ctx.master.view.update(flows)
        return len(flows)

    @staticmethod
    def script_syntax(filename, content):
        """Compile without running: a Python or JavaScript syntax error as one line, or None."""
        if filename.endswith(".py"):
            try:
                compile(content, filename, "exec")
            except SyntaxError as e:
                return f"line {e.lineno}: {e.msg}"
            except ValueError as e:
                return str(e)
            return None
        from proxy_scripts import find_node
        node = find_node()
        if not node:
            return None
        check = ('let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{new (require("vm").Script)'
                 '("\\"use strict\\";\\n"+s,{filename:"script.js"})}catch(e){const m=/:(\\d+)/.exec(String(e.stack||""));'
                 'console.log((m?"line "+(m[1]-1)+": ":"")+e.message)}})')
        try:
            p = subprocess.run([node, "-e", check], input=content, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return p.stdout.strip() or None

    def clear_script_error(self, filename):
        for addon in self._addons():
            if addon.__class__.__name__ == "ProxyScripts":
                getattr(addon, "last_errors", {}).pop(filename, None)

    @staticmethod
    def scripts(cfg):
        out = []
        for item in cfg.get("scripts") or []:
            if not isinstance(item, dict):
                continue
            x = dict(item)
            filename = x.get("file", "")
            x["exists"] = False
            if os.path.basename(filename) == filename:
                try:   # a symlink out of the project counts as missing, and script_get refuses it (B5)
                    x["exists"] = os.path.isfile(confined_path(STATE_DIR, os.path.join(SCRIPT_DIR, filename), "script"))
                except (TypeError, ValueError):
                    pass
            out.append(x)
        return sorted(out, key=lambda x: x.get("file", "").lower())

    @staticmethod
    def _script_path(filename):
        if os.path.basename(filename or "") != filename or not SAFE_NAME.fullmatch(os.path.splitext(filename)[0] or "") \
                or not filename.endswith((".py", ".js")):
            raise PanelError("bad script filename")
        try:   # a symlink planted in scripts/ must not read or write outside the project (B5)
            return confined_path(STATE_DIR, os.path.join(SCRIPT_DIR, filename), "script")
        except ValueError as e:
            raise PanelError(str(e))

    @staticmethod
    def script_template(lang, kind):
        if lang not in ("py", "js") or kind not in SCRIPT_TEMPLATES:
            raise PanelError("unknown script language or template")
        if lang == "py":
            return {
                "header": 'def on_request(context, url, request):\n    request["headers"]["X-QA"] = "enabled"\n    return request\n',
                "json": 'def on_response(context, url, request, response):\n    if isinstance(response["body"], dict):\n        response["body"]["featureEnabled"] = True\n        return response\n',
                "mock": 'def on_request(context, url, request):\n    return mock(200, {"message": "local response"}, {"Content-Type": "application/json"})\n',
                "latency": 'async def on_request(context, url, request):\n    await sleep(500)\n',
                "token": 'def on_response(context, url, request, response):\n    if "token" in url.lower():\n        log("token refresh", response["statusCode"])\n',
            }[kind]
        return {
            "header": 'async function onRequest(context, url, request) {\n  request.headers["X-QA"] = "enabled";\n  return request;\n}\n',
            "json": 'async function onResponse(context, url, request, response) {\n  if (response.body && typeof response.body === "object") {\n    response.body.featureEnabled = true;\n    return response;\n  }\n}\n',
            "mock": 'async function onRequest(context, url, request) {\n  return mock(200, {message: "local response"}, {"Content-Type": "application/json"});\n}\n',
            "latency": 'async function onRequest(context, url, request) {\n  await sleep(500);\n}\n',
            "token": 'async function onResponse(context, url, request, response) {\n  if (url.toLowerCase().includes("token")) log("token refresh", response.statusCode);\n}\n',
        }[kind]

    @staticmethod
    def _headers(message):
        return list(message.headers.items(multi=True)) if message is not None else []

    @staticmethod
    def _content(message, limit=None):
        if message is None:
            return b""
        if limit:
            cut = body_prefix(message, limit)          # R10-01: a 400 MB body is not decoded to read its first MB
            if cut is not None:
                return cut[0]
        try:
            content = message.get_content(strict=False) or b""
        except Exception:
            content = message.raw_content or b""
        return content[:limit] if limit else content

    def _flow_viewer(self, f, body_limit=None):
        req, resp = f.request, f.response
        req_type = req.headers.get("content-type", "")
        resp_type = resp.headers.get("content-type", "") if resp else ""
        req_content = self._content(req, body_limit)
        resp_content = self._content(resp, body_limit)
        tokens = find_jwts(self._headers(req), req_content, req_type, url=req.pretty_url)
        if resp:
            tokens += find_jwts(self._headers(resp), resp_content, resp_type)
        distinct = []
        for token in tokens:
            if not any(x["token"] == token["token"] for x in distinct):
                distinct.append(token)
        try:
            gql = detect_graphql(req.method, req.pretty_url, req_content, req_type)
        except Exception:
            gql = []
        gql_response = None
        if gql and resp:
            try:
                doc = json.loads(resp_content.decode("utf-8"))
                if isinstance(doc, dict):
                    gql_response = {"data": doc.get("data"), "errors": doc.get("errors") or []}
                elif isinstance(doc, list):
                    gql_response = {"data": [x.get("data") for x in doc if isinstance(x, dict)],
                                    "errors": [e for x in doc if isinstance(x, dict) for e in (x.get("errors") or [])],
                                    "batch": doc}
                else:
                    gql_response = {"invalid_json": True}
            except Exception:
                gql_response = {"invalid_json": True}
        ctype = (req_type + ";" + resp_type).lower()
        grpc = None
        if "application/grpc" in ctype or "application/x-protobuf" in ctype:
            parts = [x for x in req.path.split("?", 1)[0].split("/") if x]
            grpc = {"service": parts[-2] if len(parts) >= 2 else "", "method": parts[-1] if parts else "",
                    "status": None, "message": None, "request": None, "response": None,
                    "content_type": "grpc" if "application/grpc" in ctype else "protobuf",
                    "decoder": "schema-less field numbers (same representation as mitmproxy's built-in protobuf/gRPC view)"}
            trailers = getattr(resp, "trailers", None) if resp else None
            source = trailers or (resp.headers if resp else {})
            grpc["status"] = source.get("grpc-status") if source is not None else None
            grpc["message"] = source.get("grpc-message") if source is not None else None
            try:
                grpc["request"] = decode_grpc_frames(req_content) if "application/grpc" in req_type.lower() else decode_protobuf(req_content)
            except Exception as exc: grpc["request_error"] = str(exc)
            if resp:
                try:
                    grpc["response"] = decode_grpc_frames(resp_content) if "application/grpc" in resp_type.lower() else decode_protobuf(resp_content)
                except Exception as exc: grpc["response_error"] = str(exc)
        return {"id": f.id, "tokens": distinct, "graphql": gql, "graphql_response": gql_response, "grpc": grpc}

    def response(self, flow):
        """Mark GraphQL 200-with-errors cheaply so the list can show ERR before its drawer is opened."""
        if not flow.response:
            return
        request_body = flow.request.raw_content or b""
        response_body = flow.response.raw_content or b""
        if len(request_body) > 256 * 1024 or len(response_body) > 512 * 1024:
            return
        try:
            operations = detect_graphql(flow.request.method, flow.request.pretty_url, request_body,
                                        flow.request.headers.get("content-type", ""))
            if not operations:
                return
            doc = json.loads(response_body.decode("utf-8"))
            errors = (doc.get("errors") if isinstance(doc, dict) else
                      [error for item in doc if isinstance(item, dict) for error in (item.get("errors") or [])]
                      if isinstance(doc, list) else [])
            if errors:
                flow.metadata["proxy_graphql_error"] = True
                if "graphql:error" not in (flow.comment or "").split(" | "):
                    flow.comment = (flow.comment + " | " if flow.comment else "") + "graphql:error"
        except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
            return

    @staticmethod
    def _flow_revision(f):
        req, resp = f.request, f.response
        return (id(req.raw_content), len(req.raw_content or b""), req.method, req.pretty_url,
                tuple(req.headers.fields),
                id(resp.raw_content) if resp else None, len((resp.raw_content or b"")) if resp else 0,
                resp.status_code if resp else None, tuple(resp.headers.fields) if resp else ())

    def viewer_summaries(self, work_limit=12):
        """Incrementally build session summaries only when the open panel asks."""
        flows = [f for f in self.all_flows() if isinstance(f, http.HTTPFlow)]
        live_ids = {f.id for f in flows}
        self._viewer_cache = {flow_id: value for flow_id, value in self._viewer_cache.items()
                              if flow_id in live_ids}
        computed = 0
        for f in flows:
            revision = self._flow_revision(f)
            cached = self._viewer_cache.get(f.id)
            if cached and cached[0] == revision:
                continue
            if computed >= max(1, min(int(work_limit or 12), 50)):
                continue
            try:
                view = self._flow_viewer(f, 1024 * 1024)
            except Exception:
                view = {"id": f.id, "tokens": [], "graphql": [], "graphql_response": None, "grpc": None}
            self._viewer_cache[f.id] = (revision, view, f.request.method, f.request.pretty_url)
            computed += 1
        tokens, token_keys, ops = [], set(), {}
        graphql_error_ids = [f.id for f in flows if f.metadata.get("proxy_graphql_error")]
        for f in flows:
            cached = self._viewer_cache.get(f.id)
            if not cached:
                continue
            view, method, url = cached[1], cached[2], cached[3]
            for token in view["tokens"]:
                payload = token.get("payload") or {}
                key = (str(payload.get("sub", "")), str(payload.get("iat", "")))
                if key == ("", ""): key = (token["token"], "")
                if key not in token_keys:
                    token_keys.add(key)
                    tokens.append({"sub": payload.get("sub"), "iat": payload.get("iat"), "exp": payload.get("exp"),
                                   "alg": token.get("alg"), "kid": token.get("kid"), "flow_id": f.id,
                                   "method": method, "url": url})
            has_errors = bool((view.get("graphql_response") or {}).get("errors"))
            if has_errors and f.id not in graphql_error_ids: graphql_error_ids.append(f.id)
            for op in view["graphql"]:
                item = ops.setdefault(op["name"], {"name": op["name"], "type": op["type"], "count": 0, "flow_ids": [], "errors": 0})
                item["count"] += 1; item["flow_ids"].append(f.id); item["errors"] += int(has_errors)
        return {"tokens": tokens, "graphql_ops": sorted(ops.values(), key=lambda x: x["name"]),
                "graphql_error_ids": graphql_error_ids,
                "complete": len(self._viewer_cache) == len(flows), "computed": computed,
                "cached": len(self._viewer_cache), "total": len(flows)}

    def flush_collection(self, name=None, forget=False):
        for addon in self._addons():
            if addon.__class__.__name__ == "ProxyCollections":
                addon.flush_recording(name, forget=forget)
                return

    def refresh_collections(self, deleted=None, restored=None):
        for addon in self._addons():
            if addon.__class__.__name__ == "ProxyCollections":
                addon.checked = 0.0
                if deleted:
                    addon.deleted.add(deleted)
                if restored:
                    addon.deleted.discard(restored)
                return

    def collections(self, cfg):
        c = cfg.get("collections") or {}
        items = []
        if os.path.isdir(COLL_DIR):
            for fn in sorted(os.listdir(COLL_DIR)):
                if fn.endswith(".json") and not fn.startswith("."):
                    name = fn[:-5]
                    path = os.path.join(COLL_DIR, fn)
                    try:
                        confined_path(STATE_DIR, path)
                    except ValueError:
                        continue      # symlink out of the project: never read, never listed (B5)
                    try:
                        st = os.stat(path)
                        key = (path, st.st_mtime_ns, st.st_size)
                        cached = self._coll_count_cache.get(key)
                        if cached is None:
                            with open(path) as fh:
                                doc = migrate_collection(json.load(fh))
                            cached = (len(doc.get("entries", [])), doc.get("created"))
                            self._coll_count_cache = {k: v for k, v in self._coll_count_cache.items() if k[0] != path}
                            self._coll_count_cache[key] = cached
                        items.append({"name": name, "count": cached[0], "created": cached[1],
                                      "replay": name in (c.get("replay") or [])})
                    except (OSError, ValueError):
                        items.append({"name": name, "count": 0, "broken": True, "replay": False})
        return {"items": items, "recording": c.get("recording"), "strict": bool(c.get("strict")),
                "record_match": c.get("record_match") or self.active_profile.get("record_match") or "."}

    @staticmethod
    def sessions():
        out = []
        if os.path.isdir(SESS_DIR):
            for fn in sorted(os.listdir(SESS_DIR)):
                if fn.endswith(".meta.json"):
                    try:
                        path = confined_path(STATE_DIR, os.path.join(SESS_DIR, fn))   # B5
                        with open(path) as fh:
                            meta = _session_meta(json.load(fh), fn[:-len(".meta.json")])
                        if meta:
                            out.append(meta)
                    except (OSError, ValueError, TypeError):
                        pass
        return sorted(out, key=lambda m: m["created"], reverse=True)

    def read_session(self, name):
        """The saved flows of a session; a damaged (e.g. truncated) file is a clear 400 naming it, not a 500 (QA-10)."""
        from mitmproxy import exceptions, io as mio
        fpath, _ = self.sess_paths(name)
        try:
            with open(fpath, "rb") as fh:
                return list(mio.FlowReader(fh).stream())
        except exceptions.FlowReadException as e:
            raise PanelError("session '%s' is damaged and cannot be read (%s). Delete it, or keep the file %s aside."
                             % (name, e, fpath))

    @staticmethod
    def sess_paths(name):
        if not SAFE_NAME.fullmatch(name or ""):
            raise PanelError("session name: letters, digits, . _ - only (max 64)")
        try:   # a symlink planted in sessions/ must not read outside the project (B5)
            return (confined_path(STATE_DIR, os.path.join(SESS_DIR, name + ".flows"), "session"),
                    confined_path(STATE_DIR, os.path.join(SESS_DIR, name + ".meta.json"), "session"))
        except ValueError as e:
            raise PanelError(str(e))

    @staticmethod
    def coll_file(name):
        if not SAFE_NAME.fullmatch(name or ""):
            raise PanelError("collection name: letters, digits, . _ - only (max 64)")
        try:   # a symlink planted in collections/ must not read outside the project (B5)
            return confined_path(STATE_DIR, os.path.join(COLL_DIR, name + ".json"), "collection")
        except ValueError as e:
            raise PanelError(str(e))

    def view_filter(self):
        if self.show_dns:
            base = ""
        else:
            pf = self.project_filter(self.view_profile)
            http_part = "( ~http | ~tcp )" if self._tls_tunnels else "~http"
            base = f"{http_part} & ({pf})" if self.project_only and pf else http_part
        if self.focused_host:
            h = "~d '^" + re.escape(self.focused_host).replace("\\", "\\\\").replace("'", "\\'") + "$'"
            base = f"{base} & {h}" if base else h
        if self.graphql_operation:
            q = re.escape(self.graphql_operation).replace("\\", "\\\\").replace("'", "\\'")
            g = f"( ~u '{q}' | ~bq '{q}' )"
            base = f"{base} & {g}" if base else g
        if self.source:
            s = proxy_source.filter_clause(self.source)
            base = f"{base} & {s}" if base else s
        return base

    def _listed(self, f):
        """Could the list show this call without the source limit? (DNS / UDP / TCP rows only in the matching views;
        R8C-06: under Show → <project> only, only the project's calls, so the Source menu never counts hidden calls.)"""
        if not (isinstance(f, http.HTTPFlow) or self.show_dns or (self._tls_tunnels and getattr(f, "type", "") == "tcp")):
            return False
        pf = self.project_filter(self.view_profile) if self.project_only else ""
        if not pf:
            return True
        cached = getattr(self, "_listed_pf", (None, None))
        if cached[0] != pf:
            try:
                cached = (pf, flowfilter.parse(pf))
            except Exception:
                cached = (pf, None)
            self._listed_pf = cached
        return cached[1] is None or bool(cached[1](f))

    @staticmethod
    def source_from_filter(text):
        """The source selection inside a view filter (the inverse of proxy_source.filter_clause), or None."""
        if "!~meta '^rivis_source_key: '" in (text or ""):
            return proxy_source.UNKNOWN["key"]          # R8C-03: the Unknown choice (never stamped, or stamped unknown)
        m = re.search(r"~meta '\^rivis_source_key: ((?:[^'\\]|\\.)*)'", text or "")
        if not m:
            return None
        body = m.group(1).replace("\\'", "'").replace("\\\\", "\\")
        whole = body.endswith("$") and not body.endswith("\\$")
        sel = re.sub(r"\\(.)", r"\1", body[:-1] if whole else body)
        return sel if whole or sel.endswith("|") else None

    def _sync_view_state(self):
        """Reflect edits made in mitmweb's filter box without writing the option."""
        current = ctx.options.view_filter or ""
        if current == self._panel_view_filter:
            return
        pf = self.project_filter(self.view_profile)
        self.project_only = bool(pf and pf in current)
        self.show_dns = "~http" not in current
        match = re.search(r"~d '\^(.+)\$'", current)
        if match:
            escaped = match.group(1).replace("\\\\", "\\")
            self.focused_host = re.sub(r"\\(.)", r"\1", escaped)
        else:
            self.focused_host = None
        self.source = self.source_from_filter(current)

    def _write_view_filter(self):
        self._panel_view_filter = self.view_filter()
        ctx.options.update(view_filter=self._panel_view_filter)

    # Pilot 2026-10-21: "the project-only view reset to all traffic after a restart". The choice made in the panel is kept
    # per project and applied again at the next start; start's own --all / --project-only still win.
    def _view_file(self):
        return os.path.join(project_state(self.active_project), "view.json")

    def _filters_file(self):
        return os.path.join(project_state(self.active_project), "filters.json")

    def filters_list(self):
        try:
            with open(self._filters_file()) as fh:
                rows = json.load(fh)
        except FileNotFoundError:
            return []
        if not isinstance(rows, list) or len(rows) > 30 or any(not isinstance(row, dict) or
                not isinstance(row.get("name"), str) or not isinstance(row.get("filter"), str) for row in rows):
            raise PanelError("filters.json is invalid")
        return rows

    def _save_filters(self, rows):
        atomic_json(self._filters_file(), rows)

    def _save_view_choice(self):
        try:
            atomic_json(self._view_file(), {"project_only": bool(self.project_only and self.view_project == self.active_project)})
        except (OSError, ValueError) as e:
            ctx.log.warn(f"proxy_panel: could not keep the view choice ({e})")

    def _restore_view_choice(self, vf):
        if vf != "~http" or self.project_only:       # --all, --project-only or a filter of its own: that was asked for
            return
        try:
            with open(self._view_file()) as fh:
                saved = json.load(fh)
        except (OSError, ValueError):
            return
        if isinstance(saved, dict) and saved.get("project_only") is True and self.project_filter(self.view_profile):
            self.project_only = True
            self._write_view_filter()

    # ── paused (intercepted) calls ─────────────────────────────────────────────
    @staticmethod
    def all_flows():
        v = ctx.master.view
        return list(getattr(v, "_store", {}).values()) or list(v)

    def flows_since(self, epoch, cursor):
        """The call list as the panel's poll needs it: only what is new or changed since (epoch, cursor), the ids that left
        the list, and a new cursor; the whole list when the client has none or the proxy cannot serve its cursor."""
        from mitmproxy.tools.web.app import flow_to_json
        view = ctx.master.view
        feed = getattr(view, "_rivis_feed", None)
        if feed is None:
            feed = view._rivis_feed = FlowFeed(view)
        full, flows, removed = feed.since(epoch, cursor)
        return {"epoch": feed.epoch, "cursor": feed.seq, "full": full, "removed": removed,
                "flows": [flow_to_json(f) for f in flows]}

    def paused(self):
        out = []
        for f in self.all_flows():
            if getattr(f, "intercepted", False) and isinstance(f, http.HTTPFlow):
                out.append({"id": f.id, "phase": "response" if f.response else "request",
                            "method": f.request.method, "url": f.request.pretty_url,
                            "status": f.response.status_code if f.response else None})
        return out

    @staticmethod
    def _text(msg):
        raw = msg.get_content(strict=False) or b""
        try:
            return raw.decode("utf-8"), True
        except UnicodeDecodeError:
            return f"<{len(raw)} bytes of binary content — not editable here>", False

    def flow(self, flow_id):
        f = ctx.master.view.get_by_id(flow_id)
        if not isinstance(f, http.HTTPFlow):
            raise PanelError("that call is no longer in the list")
        return f

    @staticmethod
    def flow_any(flow_id):
        f = ctx.master.view.get_by_id(flow_id)
        if f is None:
            raise PanelError("that call is no longer in the list")
        return f

    @staticmethod
    def flow_regex(f):
        """This call's endpoint, matched against pretty_url: scheme, exact host and port, path; query ignored.
        Review R6: the pattern was unanchored, so it also matched otherapi.example.test and any URL carrying this one
        in its query string (…?next=https://api.example.test/accounts), and every port of the host.
        pretty_url leaves out a default port (443/80), so that one is optional; any other port must be the same."""
        req = f.request
        scheme = req.scheme if req.scheme in ("http", "https") else "https"
        default = {"http": 80, "https": 443}[scheme]
        port = "(?::%d)?" % default if req.port == default else ":%d" % req.port
        return ("^" + scheme + "://" + re.escape(req.pretty_host) + port + re.escape(req.path.split("?")[0]) + r"(\?|$)")

    @staticmethod
    def flow_regex_before_r6(f):
        """The unanchored form saved by earlier versions: a click on the same call still finds (and updates) it."""
        return re.escape(f.request.pretty_host) + r"(:\d+)?" + re.escape(f.request.path.split("?")[0]) + r"(\?|$)"

    @staticmethod
    def default_name(f, prefix):
        seg = [s for s in f.request.path.split("?")[0].split("/") if s] or ["root"]
        base = re.sub(r"[^A-Za-z0-9._-]", "-", seg[-1])[:40]
        return f"{prefix}-{f.request.method.lower()}-{base}"

    def unique(self, cfg, name):
        names = {r.get("name") for r in cfg["rules"]}
        n, i = name, 2
        while n in names:
            n, i = f"{name}-{i}", i + 1
        return n

    # ── TLS decryption list (allow_hosts / ignore_hosts) ─────────────────────────
    @staticmethod
    def tls_state(cfg):
        try:
            out = tls_config(cfg)
            out["error"] = None
        except ValueError as e:
            out = {"mode": "all", "allow": [], "ignore": [], "error": str(e)}
        out["note"] = ("Applies to new connections after the next rules poll; allow a few seconds — no restart. Connections that are "
                       "already open keep their earlier decision; reopen the app or its screen. "
                       "Hosts that are not decrypted still show up as a host-only row, but their URLs, headers and bodies "
                       "stay hidden, and rules, Map Local, breakpoints, scripts and network conditions cannot touch them. "
                       "Those rows keep their bytes in memory for the whole session.")
        return out

    @staticmethod
    def _flow_host(f):
        if isinstance(f, http.HTTPFlow):
            return f.request.pretty_host
        server = getattr(f, "server_conn", None)
        sni = getattr(getattr(f, "client_conn", None), "sni", None) or getattr(server, "sni", None)
        address = getattr(server, "address", None)
        host = sni or (address[0] if address else "")
        port = address[1] if address and len(address) > 1 else None
        if host and port and not str(host).endswith(":" + str(port)):
            return "%s:%s" % (host, port)
        return host

    def tls_host(self, cfg, host, decrypt):
        """'Decrypt this host' / 'Don't decrypt this host' without losing the rest of the list."""
        host = str(host or "").strip().lower()
        if not host:
            raise PanelError("no host")
        tls = tls_config(cfg)
        if decrypt:
            blocked = tls_covering(tls, host, "ignore") if tls["mode"] == "ignore" else []
            if blocked and any(x != host for x in blocked):
                raise PanelError("%s is on the leave-alone list through %s — edit it in Network → HTTPS decryption"
                                 % (host, ", ".join(x for x in blocked if x != host)))
            if tls["mode"] == "all":
                return "%s is already decrypted — every host is" % host
            tls_update(cfg, remove=[("ignore", host)], add=[("allow", host)] if tls["mode"] == "allow" else [])
            return "Decrypting %s from now on (new connections)" % host
        # don't decrypt: in 'all' mode switch to 'ignore' so every other host stays decrypted
        if tls["mode"] == "allow":
            tls_update(cfg, remove=[("allow", host)])
            covering = tls_covering(tls_config(cfg), host, "allow")
            if covering:
                raise PanelError("%s is on the decrypt list through %s — edit it in Network → HTTPS decryption"
                                 % (host, ", ".join(covering)))
        else:
            tls_update(cfg, mode="ignore", add=[("ignore", host)])
        return "Stopped decrypting %s (new connections)" % host

    # ── composer (new request from scratch), saved requests, variables ──────────
    @staticmethod
    def composer():
        return ComposerStore(COMPOSE_DIR)

    def composer_state(self):
        store = self.composer()
        try:
            return {"names": store.list(), "vars": store.variables(), "error": None}
        except (OSError, ValueError) as e:
            return {"names": [], "vars": {}, "error": str(e)}

    DROP_ON_COMPOSE = frozenset(("content-length", "connection", "keep-alive", "proxy-connection",
                                 "transfer-encoding", "te", "trailer", "upgrade"))

    def _flow_request(self, f):
        """A call as plain data for code generation: decoded body, matching headers."""
        r = f.request
        raw = r.raw_content or b""
        body = self._content(r)
        headers = [(k, v) for k, v in r.headers.items(multi=True)]
        if body != raw:     # body was decoded for us — the Content-Encoding header no longer applies
            headers = [(k, v) for k, v in headers if k.lower() != "content-encoding"]
        return {"method": r.method, "url": request_url(r), "headers": headers, "body": body}

    def _compose_spec(self, f):
        """Prefill the Compose tab from a captured call."""
        r = f.request
        parts = urlsplit(r.pretty_url)
        query = [[k, v, True] for k, v in parse_qsl(parts.query, keep_blank_values=True)]
        base = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))
        headers = [[k, v, True] for k, v in r.headers.items(multi=True)
                   if not k.startswith(":") and k.lower() not in self.DROP_ON_COMPOSE]
        if r.raw_content and self._content(r) != r.raw_content:
            headers = [h for h in headers if h[0].lower() != "content-encoding"]
        text, ok = self._text(r)
        ctype = (r.headers.get("content-type") or "").lower()
        mode, body, form, note = "none", "", [], ""
        if r.raw_content and not ok:
            note = "The original body is binary and was not copied."
        elif r.raw_content:
            if "json" in ctype or text.lstrip().startswith(("{", "[")):
                try:
                    json.loads(text)      # R3A-02: validate for the JSON editor, but keep signed request bytes intact
                    body, mode = text, "json"
                except (ValueError, RecursionError):
                    body, mode = text, "raw"
            elif "x-www-form-urlencoded" in ctype:
                form, mode = [[k, v, True] for k, v in parse_qsl(text, keep_blank_values=True)], "form"
            else:
                body, mode = text, "raw"
        return {"method": r.method, "url": r.pretty_url if not query else base + "?" + parts.query,
                "query": query, "headers": headers, "body_mode": mode, "body": body, "form": form, "note": note}

    @staticmethod
    def _clean_spec(spec):
        if not isinstance(spec, dict):
            raise PanelError("request must be an object")
        out = {k: spec[k] for k in ("method", "url", "query", "headers", "body_mode", "body", "form") if k in spec}
        for key in ("query", "headers", "form"):
            rows = out.get(key)
            if rows is not None and not (isinstance(rows, list) and all(
                    isinstance(x, (list, tuple)) and len(x) >= 2 for x in rows)):
                raise PanelError("%s must be a list of [name, value] rows" % key)
        return out

    def compose_send(self, spec, overrides=None):
        import time
        import uuid
        from mitmproxy import connection
        from mitmproxy import http as mhttp
        variables = dict(self.composer().variables())
        variables.update({str(k): str(v) for k, v in (overrides or {}).items()})
        req = normalize_request(self._clean_spec(spec), variables)
        r = mhttp.Request.make(req["method"], req["url"], b"", [])
        headers = [(k, v) for k, v in req["headers"] if k.lower() not in ("content-length", "host")]
        host_header = next((v for k, v in req["headers"] if k.lower() == "host"), None)
        r.headers = mhttp.Headers([(str(k).encode("ascii"), str(v).encode("utf-8"))
                                   for k, v in [("Host", host_header or urlsplit(req["url"]).netloc)] + headers])
        if req["body"]:
            r.content = req["body"]        # also sets Content-Length
        client = connection.Client(peername=("127.0.0.1", 0), sockname=("127.0.0.1", 0),
                                   timestamp_start=time.time())
        server = connection.Server(address=(r.host, r.port))
        nf = mhttp.HTTPFlow(client, server)
        nf.id = str(uuid.uuid4())
        nf.request = r
        nf.metadata["proxy_composed"] = True
        nf.comment = "composed"
        ctx.master.view.add([nf])
        ctx.master.commands.call("replay.client", [nf])
        return {"id": nf.id, "method": req["method"], "url": req["url"]}

    def latest_token(self, host):
        host = str(host or "").strip().lower()
        flows = [f for f in self.all_flows() if isinstance(f, http.HTTPFlow) and f.request.pretty_host.lower() == host]
        flows.sort(key=lambda f: f.request.timestamp_start or 0, reverse=True)
        for f in flows:
            value = f.request.headers.get("authorization") or ""
            if value[:7].lower() != "bearer ":
                continue
            found = find_jwts([("authorization", value)])
            if found:
                payload = found[0].get("payload") or {}
                return {"token": value[7:].strip(), "sub": payload.get("sub"), "exp": payload.get("exp"),
                        "flow_id": f.id}
        raise PanelError("no Authorization: Bearer JWT seen for %s yet" % host)

    # ── devices (Proxyman's Certificate → Simulator / Emulator menu) ───────────
    def _proxy_port(self):
        for mode in ctx.options.mode or []:
            m = re.match(r"^regular@(?:[^:]+:)?(\d+)$", mode)
            if m:
                return int(m.group(1))
        return ctx.options.listen_port or 8080

    def devices_state(self):
        """The last background device check (never waits for adb/xcrun: review R1). pending = no answer yet."""
        job = self._device_jobs.summary()
        if job and job["ended"] and job["ended"] > self._devices.at:
            self._devices.invalidate()                     # a setup just finished: look again
        have, snap = self._devices.get()
        # browsers: plain file checks, and the browser job's output: both live, never from the snapshot
        return dict(snap if have else {"pending": True}, job=job, browsers=devices.browsers(),
                    browser_job=self._browser_jobs.summary())

    def _devices_check(self):
        want = devices.ca_sha256(os.path.join(os.path.expanduser(ctx.options.confdir), "mitmproxy-ca-cert.pem"))
        pins = os.path.join(HERE, "android", "magisk.pins")
        version = ""
        try:
            version = next((l.split("=", 1)[1].strip() for l in open(pins) if l.startswith("MAGISK_VERSION=")), "")
        except OSError:
            pass
        magisk = os.environ.get("RIVIS_MAGISK_DIR") or os.path.join(os.path.dirname(os.path.dirname(HERE)), "magisk-" + version)
        adb = devices.adb_path()
        ios, ios_error = devices.ios_status(want)
        return {"ios": ios, "ios_error": ios_error,
                "android": devices.android_devices(adb, want, STATE_ROOT, self._proxy_port()),
                "magisk": bool(version) and os.path.isdir(magisk)}

    # ── actions ───────────────────────────────────────────────────────────────
    def act(self, op, a):
        lock = acquire_lock(self.rules_path)
        try:
            return self._act(op, a)
        finally:
            if lock is not None:
                lock.close()

    def _act(self, op, a):
        if not isinstance(a, dict):
            raise PanelError("request body must be a JSON object")
        self._check_input(a)
        if op == "flow_selected":
            flow_id = a.get("id")
            if flow_id is not None:
                self.flow_any(flow_id)
            self.selected_flow_id = flow_id
            for addon in self._addons():
                if addon.__class__.__name__ == "ProxyRetention":
                    addon.trim()
                    break
            return {"id": flow_id}
        if op == "devices":
            return self.devices_state()
        if op == "rule_test":
            return self.rule_test(a.get("flow_id"))
        if op == "device_job":
            return {"job": self._device_jobs.summary()}
        if op == "update_check":
            self._update.invalidate()
            return {"update": self.update_state()}
        if op == "update_login_start":
            import threading
            if not (self._update_login and self._update_login.get("status") == "waiting"):
                self._update_login = {"status": "starting"}
                threading.Thread(target=self._update_login_flow, daemon=True).start()
            return {"update": self.update_state()}
        if op == "update_logout":
            import threading
            def _out():
                self._updater("logout", timeout=30)
                self._update_login = None
                self._update.invalidate()
            threading.Thread(target=_out, daemon=True).start()
            return {}
        if op == "update_install":
            import time
            have, snap = self._update.get()
            avail = (snap or {}).get("available") if have else None
            if not avail:
                raise PanelError("no update to install — check again")
            if not (snap or {}).get("installed"):
                raise PanelError("this copy runs from a source checkout — update it with git")
            log = os.path.join(STATE_ROOT, "updates", "update.log")
            os.makedirs(os.path.dirname(log), mode=0o700, exist_ok=True)
            with open(log, "w") as fh:              # downloads + verifies, then hands over to the detached installer
                subprocess.Popen([devices.CLI, "update", "install", "--yes"], stdout=fh, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, start_new_session=True)
            self._update_installing = {"version": avail["version"], "since": time.time()}
            return {"update": self.update_state()}
        if op == "browser_open":   # a background job: the CLI asks this proxy for its options (and must never block it)
            try:
                argv = devices.browser_argv(a.get("browser"), str(a.get("url") or ""))
                env = devices.browser_env(self._proxy_port(), ctx.options.web_port)
                return {"id": self._browser_jobs.start(argv, a.get("browser"), env=env)}
            except (ValueError, RuntimeError) as e:
                raise PanelError(str(e))
        if op == "untrusted_retry":     # "Decrypt again": the device has been set up since
            self._untrusted.clear()
            self._tls_drops.clear()
            return {}
        if op == "device_setup":
            self._untrusted.clear()     # the device is being set up: decrypt again from its next connection
            self._tls_drops.clear()
            try:
                argv = devices.setup_argv(a.get("platform"), str(a.get("target") or ""), bool(a.get("consent")))
                label = "%s %s" % ({"ios": "iOS", "android": "Android"}[a["platform"]], a.get("name") or a.get("target"))
                return {"id": self._device_jobs.start(argv, label, a["platform"], str(a.get("target") or ""))}
            except (ValueError, KeyError, RuntimeError) as e:
                raise PanelError(str(e))
        cfg = self.load_cfg()
        if op == "viewer":
            return self._flow_viewer(self.flow(a["flow_id"]), VIEW_SOURCE_LIMIT)
        elif op == "viewer_summaries":
            return {"viewers": self.viewer_summaries(a.get("limit", 12))}
        elif op == "script_new":
            name, lang = (a.get("name") or "").strip(), a.get("lang")
            if not SAFE_NAME.fullmatch(name) or lang not in ("py", "js"):
                raise PanelError("script name: letters, digits, . _ - only; language py or js")
            filename = name + "." + lang
            scripts = cfg.setdefault("scripts", [])
            if any(x.get("file") == filename or x.get("name") == name for x in scripts if isinstance(x, dict)):
                raise PanelError("that script already exists")
            match = a.get("match") or "."
            user_regex(match)
            method = (a.get("method") or "").upper() or None
            source = self.script_template(lang, a.get("template") or "header")
            path = self._script_path(filename)
            os.makedirs(SCRIPT_DIR, mode=0o700, exist_ok=True)
            atomic_write_text(path, source)
            scripts.append({"name": name, "file": filename, "lang": lang, "enabled": True,
                            "match": match, "method": method})
            self.save_cfg(cfg)
            return {"file": filename}
        elif op == "script_get":
            filename = a["file"]; path = self._script_path(filename)
            item = next((x for x in cfg.get("scripts", []) if x.get("file") == filename), None)
            if item is None: raise PanelError("no such script")
            with open(path, encoding="utf-8") as fh: content = fh.read()
            return {"script": item, "content": content, "file": path, "templates": SCRIPT_TEMPLATES}
        elif op == "script_put":
            filename = a["file"]; path = self._script_path(filename)
            item = next((x for x in cfg.get("scripts", []) if x.get("file") == filename), None)
            if item is None: raise PanelError("no such script")
            match = a.get("match") or "."; user_regex(match)
            method = (a.get("method") or "").upper() or None
            atomic_write_text(path, a.get("content") or "")
            item.update(match=match, method=method)
            self.save_cfg(cfg)
            self.clear_script_error(filename)
            problem = self.script_syntax(filename, a.get("content") or "")
            if problem:                  # saved anyway (never lose the user's edit), but flagged now, not on the next call
                for addon in self._addons():
                    if addon.__class__.__name__ == "ProxyScripts":
                        addon._error(filename, "syntax", SyntaxError(problem))
                return {"syntax_error": problem}
        elif op == "script_toggle":
            item = next((x for x in cfg.get("scripts", []) if x.get("file") == a.get("file")), None)
            if item is None: raise PanelError("no such script")
            item["enabled"] = bool(a.get("enabled")); self.save_cfg(cfg)
        elif op == "script_delete":
            filename = a["file"]; path = self._script_path(filename)
            before = len(cfg.get("scripts", []))
            cfg["scripts"] = [x for x in cfg.get("scripts", []) if x.get("file") != filename]
            if len(cfg["scripts"]) == before: raise PanelError("no such script")
            if os.path.exists(path): os.unlink(path)
            self.save_cfg(cfg)
        elif op == "graphql_filter":
            self.graphql_operation = a.get("name") or None
            self._write_view_filter()
        elif op == "source":           # Source chooser: one app, one device ("<kind>|<device>|"), or everything (None)
            sel = a.get("source") or None
            if sel is not None and not (isinstance(sel, str) and len(sel) <= 400 and sel.count("|") >= 2
                                        and not re.search(r"[\x00-\x1f\x7f]", sel)):
                raise PanelError("source: a device or app from the Source menu")   # it becomes part of a filter
            self.source = sel
            self._write_view_filter()
        elif op == "toggle":
            r = self.find(cfg, a["name"])
            r["enabled"] = bool(a["enabled"])
            if r["enabled"]:
                r.pop("draft", None)                 # switched on by hand: no longer a discardable draft
            self.save_cfg(cfg)
        elif op == "delete":
            r = self.find(cfg, a["name"])
            cfg["rules"].remove(r)
            mock = owned_mock_file(r, cfg["rules"], MOCK_DIR, self.rules_path)
            if mock:
                os.remove(mock)              # before the save: whoever sees the rule gone never finds its mock still on disk
            self.save_cfg(cfg)
            if r.get("action") == "map_local" and isinstance(r.get("file"), str) and not mock and os.path.isfile(os.path.expanduser(r["file"])):
                return {"message": "mock file kept: " + r["file"]}
        elif op == "add":
            r = dict(a["rule"])
            if "file" in r or "body_file" in r:
                raise PanelError("file-backed rules are created with Map Local in the panel, or with the product CLI")
            r.setdefault("enabled", True)
            self.validate(r)
            if not str(r.get("match", "")).strip():     # an omitted match used to mean "every call": too easy to break everything
                raise PanelError("match is required (a regex on the URL; '.' means every call)")
            if any(x.get("name") == r["name"] for x in cfg["rules"]):
                raise PanelError("a rule with that name exists")
            self.engine_check(r)
            cfg["rules"].append(r)
            self.save_cfg(cfg)
        elif op == "maplocal_folder_add":
            name = str(a.get("name") or "").strip()
            base = str(a.get("base") or "").strip()
            folder = os.path.abspath(os.path.expanduser(str(a.get("folder") or "").strip()))
            if not SAFE_NAME.fullmatch(name):
                raise PanelError("name must use letters, numbers, dots, dashes or underscores")
            if any(r.get("name") == name for r in cfg["rules"]):
                raise PanelError("a rule with that name exists")
            if not os.path.isdir(folder):
                raise PanelError("folder not found: " + folder)
            r = {"name": name, "enabled": True, "action": "map_local", "file": folder, "base": base,
                 "match": "^" + re.escape(base) + ".*$"}
            self.engine_check(r)
            cfg["rules"].append(r)
            self.save_cfg(cfg)
        elif op == "proxyman_import":
            from proxyman_import import import_proxyman
            try:
                summary = import_proxyman(self.rules_path)
            except (OSError, ValueError) as exc:
                raise PanelError("Proxyman import: %s" % exc)
            return {"summary": summary}
        elif op == "update":        # Rules tab: edit one rule in place (same name, action and list position; its files stay)
            old = self.find(cfg, a["name"])
            new = dict(a["rule"])
            if "file" in new or "body_file" in new:
                raise PanelError("a rule's file is changed with Map Local in the panel, or with the product CLI")
            if a["name"] in self._rules_outside(cfg):
                raise PanelError("this rule reads a file outside the project: edit it in your own editor")
            merged = {k: v for k, v in old.items() if k not in a.get("keys", ())}
            merged.update(new, name=old["name"], action=old["action"])
            merged.pop("draft", None)                # saved by hand: no longer a discardable draft
            self.validate(merged)
            if not str(merged.get("match", "")).strip():
                raise PanelError("match is required (a regex on the URL; '.' means every call)")
            self.engine_check(merged)
            old.clear()
            old.update(merged)
            self.save_cfg(cfg)
        elif op == "mock":          # Map Local from the selected call
            f = self.flow(a["flow_id"])
            for r in cfg["rules"]:   # first matching mock wins: reopen it instead of creating a dead duplicate
                try:
                    matches = re.search(r.get("match") or r"(?!x)x", f.request.pretty_url)
                except re.error:
                    matches = False
                if r.get("action") == "map_local" and matches and r.get("method") in (None, "", f.request.method):
                    if not self._servable_mock(r):   # an example/template rule whose file is missing or outside
                        continue                     # the project would be switched on and serve nothing
                    if r.get("draft"):               # an unsaved draft stays off until it is saved
                        return {"name": r["name"], "draft": True}
                    r["enabled"] = True
                    self.save_cfg(cfg)
                    return {"name": r["name"], "existing": True}
            name = self.unique(cfg, a.get("name") or self.default_name(f, "mock"))
            path = self.mock_path(name)
            os.makedirs(MOCK_DIR, exist_ok=True)
            # Rules may have been reset while their mock files remain. Do not overwrite one:
            # a fresh draft needs its own file so its creation can be recorded and discarded.
            base, suffix = name, 2
            names = {r.get("name") for r in cfg["rules"]}
            while name in names or os.path.lexists(path):
                tail = f"-{suffix}"
                name = base[:64 - len(tail)].rstrip(".") + tail
                path = self.mock_path(name)
                suffix += 1
            # a call that never got an answer (server down, unreachable) is mocked from an empty JSON template
            body = (f.response.get_content(strict=False) or b"") if f.response else b"{}\n"
            try:   # pretty-print JSON so it is easy to edit
                body = (json.dumps(json.loads(body), indent=2, ensure_ascii=False) + "\n").encode()
            except (ValueError, RecursionError):
                pass
            atomic_write_bytes(path, body)
            # From the panel the new mock is a draft until its first Save, as in Proxyman: opening the editor and going
            # Back used to leave an active mock answering the next calls (overnight QA r1 B-03). The API default and
            # `rivis mock` stay "on at once".
            draft = a.get("draft") is True
            r = {"name": name, "enabled": not draft, "match": self.flow_regex(f), "method": f.request.method,
                 "action": "map_local", "file": path,
                 "status": f.response.status_code if f.response else 200,
                 "note": f"from {f.request.method} {f.request.pretty_url[:120]}"}
            r["rivis_created_mock"] = os.path.realpath(path)
            if draft:
                r["draft"] = True
            if f.response:
                unsafe = {"content-length", "transfer-encoding", "content-encoding"}
                r["headers"] = without_hop_headers([k, v] for k, v in f.response.headers.items(multi=True)
                                                   if k.lower() not in unsafe)
            cfg["rules"].append(r)
            self.save_cfg(cfg)
            return {"name": name, "draft": draft}
        elif op == "quick":         # force status / block / delay on the selected call's endpoint
            f = self.flow(a["flow_id"])
            kind = a["kind"]
            r = {"enabled": True, "match": self.flow_regex(f), "method": f.request.method}
            if kind == "status":
                r.update(action="respond", status=http_status(a["status"]),
                         body={"message": f"forced {a['status']} by {PRODUCT['name']}"})
            elif kind == "block":
                r.update(action="block")
            elif kind == "delay":
                r.update(action="delay", ms=int(a["ms"]))
            else:
                raise PanelError("unknown quick action")
            same = {r["match"], self.flow_regex_before_r6(f)}
            for x in cfg["rules"]:   # same quick action on the same endpoint: update it, don't stack copies
                if x.get("match") in same and x.get("method") == r["method"] and x.get("action") == r["action"]:
                    x.update(r)
                    cfg["rules"].remove(x)
                    cfg["rules"].insert(0, x)  # request-local actions are first-match-wins
                    self.save_cfg(cfg)
                    return {"name": x["name"]}
            r["name"] = self.unique(cfg, self.default_name(f, kind if kind != "status" else f"s{a['status']}"))
            self.validate(r)
            cfg["rules"].insert(0, r)          # override older Map Local/respond rules on this endpoint
            self.save_cfg(cfg)
            return {"name": r["name"]}
        elif op == "bp_add":            # from the selected call, or host/path/method like FRTMProxy
            if a.get("flow_id"):
                f = self.flow(a["flow_id"])
                match, method = self.flow_regex(f), f.request.method
                same = {match, self.flow_regex_before_r6(f)}
                label = f.request.pretty_host + f.request.path.split("?")[0]
            elif a.get("match"):          # Rules tab: a regex on the URL, as in rules.json
                match = a["match"]
                try:
                    user_regex(match)
                except re.error as e:
                    raise PanelError(f"bad regex in match: {e}")
                same = {match}
                method = (a.get("method") or "").upper() or None
                label = match
            else:
                match = wildcard_regex(a.get("host"), a.get("path"))
                same = {match}
                method = (a.get("method") or "").upper() or None
                label = (a.get("host") or "") + (a.get("path") or "/")
            if not (a.get("request") or a.get("response")):
                raise PanelError("pick Request, Response or both")
            bps = breakpoints(cfg, migrate=True)
            for b in bps:                 # same endpoint+method: update phases instead of stacking copies
                if b.get("match") in same and b.get("method") == method:
                    b.update(match=match, request=bool(a.get("request")), response=bool(a.get("response")), enabled=True)
                    self.save_cfg(cfg)
                    return {"name": b["name"]}
            names = {b.get("name") for b in bps}
            segs = [x for x in label.split("/") if x and "*" not in x and "?" not in x]
            base = re.sub(r"[^A-Za-z0-9._-]", "-", (segs[-1] if segs else label))[:30].strip("-") or "bp"
            name, i = base, 2
            while name in names:
                name, i = f"{base}-{i}", i + 1
            bps.append({"name": name, "label": label, "match": match, "method": method,
                        "request": bool(a.get("request")), "response": bool(a.get("response")), "enabled": True})
            self.save_cfg(cfg)
            return {"name": name}
        elif op == "bp_update":
            for b in cfg.get("breakpoints") or []:
                if b.get("name") == a["name"]:
                    before = dict(b)
                    for k in ("enabled", "request", "response"):
                        if k in a:
                            b[k] = bool(a[k])
                    if "match" in a:             # Rules tab: edit what the breakpoint catches
                        if not str(a["match"]).strip():
                            raise PanelError("match is required (a regex on the URL)")
                        try:
                            user_regex(a["match"])
                        except re.error as e:
                            raise PanelError(f"bad regex in match: {e}")
                        b["match"], b["label"] = a["match"], a["match"]
                    if "method" in a:
                        b["method"] = (a["method"] or "").upper() or None
                    resumed = self.release_held(cfg, [before])     # before the save: the reload it triggers would free them uncounted
                    self.save_cfg(cfg)
                    return {"resumed": resumed}
            else:
                if a["name"] == "legacy":
                    cfg.pop("breakpoint", None)
                    self.save_cfg(cfg)
                else:
                    raise PanelError("no such breakpoint")
        elif op == "bp_delete":
            if a.get("name") == "legacy":
                cfg.pop("breakpoint", None)
            gone = [b for b in cfg.get("breakpoints") or [] if b.get("name") == a.get("name")]
            cfg["breakpoints"] = [b for b in cfg.get("breakpoints") or [] if b.get("name") != a.get("name")]
            resumed = self.release_held(cfg, gone)
            self.save_cfg(cfg)
            return {"resumed": resumed}
        elif op == "paused_get":
            f = self.flow(a["id"])
            if not f.intercepted:
                raise PanelError("that call is not paused any more")
            body, ok = self._text(f.request)
            out = {"id": f.id, "phase": "response" if f.response else "request",
                   "method": f.request.method, "url": f.request.pretty_url,
                   "req_headers": [[k, v] for k, v in f.request.headers.items(multi=True)],
                   "req_body": body, "req_body_editable": ok,
                   # pilot 2026-10-21: people typed the new RESPONSE into the request sheet; it says whether the response pauses next
                   "response_next": not f.response and any(self._bp_hits(b, f, "response") for b in breakpoints(cfg))}
            if f.response:
                rb, rok = self._text(f.response)
                out.update(status=f.response.status_code,
                           resp_headers=[[k, v] for k, v in f.response.headers.items(multi=True)],
                           resp_body=rb, resp_body_editable=rok)
            return out
        elif op == "paused_resume_all":             # the paused sheet's way out of a busy breakpoint
            flows = [f for f in self.all_flows() if getattr(f, "intercepted", False)]
            for f in flows:
                f.comment = (f.comment + " | " if f.comment else "") + "breakpoint: skipped (sent unchanged)"
                f.resume()
            ctx.master.view.update(flows)
            return {"resumed": len(flows)}
        elif op in ("paused_continue", "paused_skip", "paused_abort"):
            from mitmproxy import http as mhttp
            f = self.flow(a["id"])
            if not f.intercepted:
                raise PanelError("that call is not paused any more")
            if op == "paused_abort":
                # kill() clears intercepted without waking wait_for_resume(); signal first so an
                # intercepted client replay does not wedge mitmproxy's replay worker.
                f.resume()
                f.kill()
            else:
                if op == "paused_continue":
                    e = a.get("edits") or {}
                    msg = f.response or f.request
                    before = (getattr(msg, "status_code", None), f.request.method, f.request.url,
                              tuple(msg.headers.fields), msg.raw_content or b"")
                    hdr = lambda rows: mhttp.Headers([(str(k).encode(), str(v).encode()) for k, v in rows if str(k).strip()])
                    if f.response:
                        if "status" in e:
                            f.response.status_code = http_status(e["status"])
                        if "headers" in e:
                            f.response.headers = hdr(e["headers"])
                        if e.get("body") is not None and e["body"] != (f.response.get_text(strict=False) or ""):
                            f.response.text = e["body"]
                    else:
                        self._edit_request(f.request, e, hdr)
                        if e.get("body") is not None and e["body"] != (f.request.get_text(strict=False) or ""):
                            f.request.text = e["body"]
                    after = (getattr(msg, "status_code", None), f.request.method, f.request.url,
                             tuple(msg.headers.fields), msg.raw_content or b"")
                    # the sheet always sends every field back: only say "edited" when something really changed (L1)
                    tag = "edited at breakpoint" if after != before else "breakpoint: continued unchanged"
                else:
                    tag = "breakpoint: skipped (sent unchanged)"
                f.comment = (f.comment + " | " if f.comment else "") + tag
                f.resume()
            ctx.master.view.update([f])
        elif op == "nocache":            # Proxyman "No Caching": a project switch, hot-reloaded by proxy_rules
            cfg["no_cache"] = bool(a.get("on"))
            self.save_cfg(cfg)
        elif op == "profile":
            current = cfg.get("throttle", "off")
            pid = a.get("id", current)
            # a CLI preset (`rivis throttle 3g`, `500ms`) is not in the panel's list, but editing only its URL scope
            # sends it back as the current profile: keep it, and its loss, as they are
            keep_cli = pid == current and pid not in {p["id"] for p in PROFILES} and (
                pid in PRESETS or throttle_shorthand(pid) is not None)
            if pid not in {p["id"] for p in PROFILES} and not keep_cli:
                raise PanelError("unknown profile")
            cfg["throttle"] = pid
            if not keep_cli:
                cfg["loss"] = 0              # the profile's own loss applies
            if pid == "manual":
                m = cfg.setdefault("manual", {})
                for k in MANUAL_KEYS:
                    if k in (a.get("manual") or {}):
                        v = float(a["manual"][k])
                        cap = 100 if k == "loss_pct" else 120000 if k in (
                            "latency_ms", "jitter_ms", "response_delay_ms") else 1000000
                        if not math.isfinite(v) or v < 0 or v > cap:
                            raise PanelError(f"{k.replace('_pct', ' %').replace('_ms', ' (ms)').replace('_', ' ')} must be 0..{cap:,}")
                        m[k] = v
            if "match" in a:
                scope = str(a["match"] or "").strip()      # a pasted "  /echo \n" must not silently match nothing
                if scope:
                    try:
                        user_regex(scope)
                    except re.error as e:
                        raise PanelError(f"the URL scope is a regex: {e}")
                cfg["throttle_match"] = scope
            self.save_cfg(cfg)
        elif op == "maplocal_add":       # manual Map Local rule: host/path wildcards, like FRTMProxy "Add Rule"
            requested_name = (a.get("name") or "").strip()
            base_name = requested_name or re.sub(r"[^A-Za-z0-9._-]", "-",
                        "mock-" + ((a.get("path") or "/").strip("/").split("/")[-1] or a.get("host", "x")))[:60]
            method = (a.get("method") or "").upper() or None
            match = wildcard_regex(a.get("host"), a.get("path"), bool(a.get("literal_query")))
            for existing in cfg["rules"]:
                if (existing.get("action") == "map_local" and existing.get("match") == match
                        and existing.get("method") == method):
                    existing["enabled"] = True
                    self.save_cfg(cfg)
                    return {"name": existing["name"], "existing": True}
            if requested_name and any(r.get("name") == requested_name for r in cfg["rules"]):
                raise PanelError("a rule with that name exists")
            name = self.unique(cfg, base_name)
            os.makedirs(MOCK_DIR, exist_ok=True)
            path = self.mock_path(name)
            created_mock = not os.path.exists(path)
            atomic_write_text(path, a.get("body") or "{}\n")
            r = {"name": name, "enabled": True, "match": match,
                 "action": "map_local", "file": path,
                 "status": http_status(200 if a.get("status") in (None, "") else a["status"]),
                 # R4B-03: browser module/style MIME checks use the URL extension, not the generated mock filename.
                 "headers": {"Content-Type": mimetypes.guess_type(urlsplit(a.get("path") or a.get("host") or "/").path)[0] or "application/json"},
                 "note": f"manual: {a.get('host')}{a.get('path') or '/'}"}
            if created_mock:
                r["rivis_created_mock"] = os.path.realpath(path)
            if method:
                r["method"] = method
            self.validate(r)
            cfg["rules"].append(r)
            self.save_cfg(cfg)
            return {"name": name}
        elif op == "view":
            if a.get("project") is not None:
                project_profile(a["project"])  # validate before changing the view
                self.view_project = a["project"]
            self.project_only = bool(a.get("project_only"))
            if not self.project_only:
                # R9-02: "All traffic" kept the last project as the view, so the header, status bar and empty state
                # went on saying "NEO" until a restart. Showing everything is the started project's view again.
                self.view_project = self.active_project
            self.show_dns = bool(a.get("show_dns"))
            self._write_view_filter()
            self._save_view_choice()
        elif op == "filter_check":     # the list filter is evaluated here: an invalid one closes mitmweb's websocket, so the panel asks first
            text = str(a.get("filter") or "").strip()
            if not text:                   # empty = no filter, which is always valid
                return {"ok": True}
            try:
                flowfilter.parse(text)
            except ValueError as e:
                return {"ok": False, "error": str(e).replace("Invalid filter expression: ", "")[:200]}
            return {"ok": True}
        elif op == "filters_list":
            return {"filters": self.filters_list()}
        elif op == "filters_save":
            name, value, old = a.get("name"), a.get("filter"), a.get("old")
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9 ._-]{1,40}", name) or name != name.strip():
                raise PanelError("filter name: 1–40 letters, digits, spaces or . _ -")
            rows = self.filters_list()
            if old is not None and old not in [row["name"] for row in rows]:
                raise PanelError("saved filter not found")
            if any(row["name"] == name and row["name"] != old for row in rows):
                raise PanelError("filter name already exists")
            if old is None:
                if len(rows) >= 30:
                    raise PanelError("maximum 30 saved filters")
                if not isinstance(value, str) or not value.strip():
                    raise PanelError("filter is empty")
                try:
                    flowfilter.parse(value)
                except ValueError as e:
                    raise PanelError("invalid filter: %s" % e)
                rows.append({"name": name, "filter": value.strip()})
            else:
                for row in rows:
                    if row["name"] == old:
                        row["name"] = name
            self._save_filters(rows)
            return {"filters": rows}
        elif op == "filters_delete":
            rows = self.filters_list()
            remaining = [row for row in rows if row["name"] != a.get("name")]
            if len(remaining) == len(rows):
                raise PanelError("saved filter not found")
            self._save_filters(remaining)
            return {"filters": remaining}
        elif op == "filters_order":
            rows = self.filters_list()
            names = a.get("names")
            if not isinstance(names, list) or len(names) != len(rows) or set(names) != set(row["name"] for row in rows):
                raise PanelError("filter order must contain each saved filter once")
            by_name = {row["name"]: row for row in rows}
            rows = [by_name[name] for name in names]
            self._save_filters(rows)
            return {"filters": rows}
        elif op == "compose_from_curl":
            return parse_curl(a.get("command"))
        elif op == "focus_host":       # "show only this host" / clear it
            host = a.get("host") or None
            if host is not None and not (isinstance(host, str) and HOST_NAME.fullmatch(host)):
                raise PanelError("host: a hostname or IP address")   # F-16: it becomes part of a filter expression
            self.focused_host = host
            self._write_view_filter()
        elif op == "export":           # Copy URL / Copy cURL
            f = self.flow(a["flow_id"])
            if a.get("fmt") == "url":
                url = request_url(f.request)
                return {"text": proxy_redact.url(url) if a.get("mask", True) is not False else url}
            # mask secrets unless the panel explicitly unticked "Mask secrets" (bank policy: no shared tokens)
            return {"text": generate(self._flow_request(f), "curl", a.get("mask", True) is not False)}
        elif op == "retry":            # Edit & Retry: copy the call, apply edits, send it again
            import uuid
            from mitmproxy import http as mhttp
            f = self.flow(a["flow_id"])
            nf = f.copy()
            nf.id = str(uuid.uuid4())
            nf.response = None
            nf.error = None
            e = a.get("edits") or {}
            self._edit_request(nf.request, e, lambda rows: mhttp.Headers(
                [(str(k).encode(), str(v).encode()) for k, v in rows if str(k).strip()]))
            if e.get("body") is not None and e["body"] != (f.request.get_text(strict=False) or ""):
                nf.request.text = e["body"]
            same = (nf.request.method, nf.request.url, tuple(nf.request.headers.fields), nf.request.raw_content or b"") == \
                (f.request.method, f.request.url, tuple(f.request.headers.fields), f.request.raw_content or b"")
            # a plain Repeat (or an Edit & Retry left untouched) is a repeat, not an edit (L2 / MQ-19)
            nf.comment = ("repeat of " if same else "edit & retry of ") + f.request.method + " " + f.request.path[:60]
            ctx.master.view.add([nf])
            ctx.master.commands.call("replay.client", [nf])
            return {"id": nf.id}
        elif op == "retry_get":        # request fields for the Edit & Retry editor
            f = self.flow(a["flow_id"])
            body, ok = self._text(f.request)
            return {"id": f.id, "method": f.request.method, "url": f.request.pretty_url,
                    "req_headers": [[k, v] for k, v in f.request.headers.items(multi=True)],
                    "req_body": body, "req_body_editable": ok}
        elif op == "codegen":          # Copy as … (cURL, Python, fetch, Swift, …)
            mask = a.get("mask", True) is not False
            if a.get("flow_id"):
                request = self._flow_request(self.flow(a["flow_id"]))
            else:
                request = normalize_request(self._clean_spec(a.get("spec")), self.composer().variables())
            return {"text": generate(request, a.get("target") or "curl", mask), "masked": mask}
        elif op == "compose_get":      # "Compose from this call"
            return {"spec": self._compose_spec(self.flow(a["flow_id"]))}
        elif op == "compose_send":
            spec = a.get("spec")
            if spec is None and a.get("name"):
                spec = self.composer().load(a["name"])
            try:
                return self.compose_send(spec, a.get("vars"))
            except (PanelError, ValueError, OSError):
                raise
            except Exception as e:   # flow construction depends on mitmproxy internals — report, don't 500
                raise PanelError("cannot send: %s: %s" % (type(e).__name__, e))
        elif op == "flow_result":      # R2A-03: mitmweb 12.2.3 answers GET /flows/<id> with 405, so the CLI asks here
            f = self.flow(a["id"])
            return {"status": f.response.status_code if f.response else None,
                    "error": (f.error.msg if f.error else None)}
        elif op == "compose_save":
            self.composer().save(a.get("name"), self._clean_spec(a.get("spec")), overwrite=a.get("overwrite") is True)
            return {"name": a["name"]}
        elif op == "compose_load":
            return {"spec": self.composer().load(a.get("name"))}
        elif op == "compose_rename":
            self.composer().rename(a.get("old"), a.get("new"))
        elif op == "compose_delete":
            self.composer().delete(a.get("name"))
        elif op == "compose_vars":
            self.composer().save_variables(a.get("vars"))
        elif op == "compose_token":
            return self.latest_token(a.get("host"))
        elif op == "tls_set":          # mode and/or whole lists
            current = tls_config(cfg)
            cfg["tls"] = tls_config({"tls": {"mode": a.get("mode", current["mode"]),
                                             "allow": a.get("allow", current["allow"]),
                                             "ignore": a.get("ignore", current["ignore"])}})
            self.save_cfg(cfg)
        elif op == "tls_update":       # one list mutation; preserve concurrent CLI changes
            which, action = a.get("list"), a.get("action")
            if which not in ("allow", "ignore"):
                raise PanelError("list must be allow or ignore")
            if action not in ("add", "remove"):
                raise PanelError("action must be add or remove")
            pattern = str(a.get("pattern") or "").strip().lower()
            tls_update(cfg, **{action: [(which, pattern)]})
            self.save_cfg(cfg)
        elif op == "tls_host":         # quick action on the This-call tab
            host = a.get("host") or self._flow_host(self.flow_any(a["flow_id"]))
            message = self.tls_host(cfg, host, bool(a.get("decrypt")))
            self.save_cfg(cfg)
            return {"message": message, "host": host}
        elif op == "diff":             # Compare two calls
            return self.diff(self.flow(a["a"]), self.flow(a["b"]))
        # ── sessions: save / reload the whole capture (stays on this workstation) ──
        elif op == "sess_save":
            import time as _t
            from mitmproxy import io as mio
            name = (a.get("name") or "").strip()
            fpath, mpath = self.sess_paths(name)
            if (os.path.exists(fpath) or os.path.exists(mpath)) and a.get("overwrite") is not True:
                raise PanelError("a session named '%s' already exists" % name)
            # Keep the same call types as the list: TLS "all" hides tunnel rows, and the
            # normal view hides DNS/UDP. Otherwise the saved count disagrees with the list
            # and with HAR (which can export HTTP calls only).
            flows = [f for f in self.all_flows() if not getattr(f, "intercepted", False) and
                     (self.show_dns or isinstance(f, http.HTTPFlow) or
                      (self._tls_tunnels and getattr(f, "type", "") == "tcp"))]
            if a.get("visible_only"):
                search = a.get("search_filter", "")
                if not isinstance(search, str):
                    raise PanelError("current filter must be text")
                view = ctx.options.view_filter or ""
                try:
                    if search:
                        flowfilter.parse(search)
                    flows = [f for f in flows if (not view or flowfilter.match(view, f)) and
                             (not search or flowfilter.match(search, f))]
                except ValueError as exc:
                    raise PanelError("current filter is invalid: %s" % exc)
                # R7A-05: iterating ctx.master.view ignored the browser's Search filter, including a zero-result
                # search; saving that view disclosed hidden calls in the session and its HAR.
                if not flows:
                    raise PanelError("no calls match the current filter; nothing was saved")
            os.makedirs(SESS_DIR, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=SESS_DIR, prefix=".sess-")
            with os.fdopen(fd, "wb") as fh:
                w = mio.FlowWriter(fh)
                for f in flows:
                    w.add(f)
                fh.flush()
                os.fsync(fh.fileno())
            commit_temp_file(tmp, fpath)
            meta = {"name": name, "note": a.get("note") or "", "created": _t.time(), "count": len(flows),
                    "hosts": sorted({f.request.pretty_host for f in flows if isinstance(f, http.HTTPFlow)})[:8]}
            atomic_json(mpath, meta)
            return {"count": len(flows)}
        elif op == "sess_load":
            flows = self.read_session(a["name"])
            if a.get("replace"):
                # keep calls paused at a breakpoint: view.clear() dropped them too, the sheet closed and the app's
                # call hung until its own timeout with nothing left to Continue (QA-03)
                view = ctx.master.view
                gone = [f for f in list(view) if not getattr(f, "intercepted", False)]
                if gone:
                    view.remove(gone)
            known = {f.id for f in self.all_flows()}
            new = [f for f in flows if f.id not in known]
            ctx.master.view.add(new)
            return {"count": len(new)}
        elif op == "sess_note":
            _, mpath = self.sess_paths(a["name"])
            with open(mpath) as fh:
                meta = json.load(fh)
            meta["note"] = a.get("note") or ""
            atomic_json(mpath, meta)
        elif op == "sess_delete":
            for pth in self.sess_paths(a["name"]):
                if os.path.exists(pth):
                    os.remove(pth)
        elif op == "sess_har":
            return self.sess_har(a)
        # ── collections ──
        elif op == "coll_record":
            name = (a.get("name") or "").strip()
            self.coll_file(name)
            c = cfg.setdefault("collections", {})
            self.flush_collection(c.get("recording"), forget=True)
            c["recording"] = name
            if a.get("record_match") is not None:
                user_regex(a["record_match"] or ".")
                c["record_match"] = a["record_match"]
            if name in (c.get("replay") or []):        # never replay into the collection being recorded
                c["replay"] = [x for x in c["replay"] if x != name]
            self.save_cfg(cfg)
            self.refresh_collections(restored=name)
        elif op == "coll_stop":
            self.flush_collection(cfg.setdefault("collections", {}).get("recording"), forget=True)
            cfg.setdefault("collections", {})["recording"] = None
            self.save_cfg(cfg)
            self.refresh_collections()
        elif op == "coll_replay":
            c = cfg.setdefault("collections", {})
            rp = [x for x in (c.get("replay") or []) if x != a["name"]]
            if a.get("enabled"):
                self.coll_file(a["name"])
                if c.get("recording") == a["name"]:
                    raise PanelError("stop recording this collection before replaying it")
                rp.append(a["name"])
            c["replay"] = rp
            self.save_cfg(cfg)
        elif op == "coll_strict":
            cfg.setdefault("collections", {})["strict"] = bool(a.get("strict"))
            self.save_cfg(cfg)
        elif op == "coll_match":
            pattern = a.get("record_match") or "."
            user_regex(pattern)
            cfg.setdefault("collections", {})["record_match"] = pattern  # R3A-04: imported HARs need an editable strict scope
            self.save_cfg(cfg)
        elif op == "coll_delete":
            path = self.coll_file(a["name"])
            self.flush_collection(a["name"], forget=True)
            c = cfg.setdefault("collections", {})
            c["replay"] = [x for x in (c.get("replay") or []) if x != a["name"]]
            if c.get("recording") == a["name"]:
                c["recording"] = None
            self.save_cfg(cfg)
            self.refresh_collections(deleted=a["name"])
            if os.path.exists(path):
                os.remove(path)
        elif op == "coll_entries":
            self.flush_collection(a["name"])
            with open(self.coll_file(a["name"])) as fh:
                doc = migrate_collection(json.load(fh))
            return {"entries": [{"i": i, "method": e["method"], "host": e["host"], "path": e["path"],
                                 "query": e.get("query", ""), "status": e["status"]}
                                for i, e in enumerate(doc.get("entries", []))]}
        elif op == "coll_entry_delete":
            path = self.coll_file(a["name"])
            self.flush_collection(a["name"], forget=True)
            with open(path) as fh:
                doc = migrate_collection(json.load(fh))
            doc["entries"] = [e for i, e in enumerate(doc.get("entries", [])) if i != int(a["i"])]
            self._write_coll(doc)
        elif op == "coll_export":      # HAR, downloaded by the browser to this workstation only
            self.flush_collection(a["name"])
            with open(self.coll_file(a["name"])) as fh:
                doc = migrate_collection(json.load(fh))
            return self._har_reply(self.to_har(doc), a)
        elif op == "coll_import":
            # review R5: a name already in use silently replaced that recording. Refused unless overwrite is set, and
            # the old one stays untouched until the new HAR has parsed (the write itself is atomic)
            name = (a.get("name") or "").strip()
            path = self.coll_file(name)
            if os.path.exists(path) and a.get("overwrite") is not True:
                raise PanelError("a collection named '%s' already exists" % name)
            har = a.get("har") or {}
            skipped = []
            entries = self.from_har(har, skipped)
            if not entries:
                raise PanelError("no usable entries in that HAR")
            self.flush_collection(name, forget=True)
            self._write_coll({"name": name, "created": __import__("time").time(), "entries": entries})
            return {"count": len(entries), "skipped": skipped[:20], "skipped_count": len(skipped)}
        elif op == "mockfile_get":
            r = self.find(cfg, a["name"])
            if r.get("action") != "map_local":
                raise PanelError("not a Map Local rule")
            path = os.path.realpath(os.path.expanduser(r["file"]))
            if os.path.dirname(path) != os.path.realpath(MOCK_DIR):
                raise PanelError("only mocks in the active project's state directory can be opened in the panel")
            with open(path, "rb") as fh:
                raw = fh.read()
                headers = r.get("headers") or {}
                header_rows = list(headers.items()) if isinstance(headers, dict) else headers
                text, binary, clipped = self.mock_text(raw)   # binary: an image, protobuf…, shown as text; Save keeps the bytes unless edited
                return {"content": text, "status": r.get("status", 200), "binary": binary, "clipped": clipped,
                        "draft": r.get("draft") is True,
                        "size": len(raw),
                        "headers": [[k, v] for k, v in header_rows],
                        "match": r.get("match"), "method": r.get("method"),
                        "file": path, "editable": os.path.dirname(path) == os.path.realpath(MOCK_DIR)}
        elif op == "mockfile_put":
            r = self.find(cfg, a["name"])
            if r.get("action") != "map_local":
                raise PanelError("not a Map Local rule")
            path = os.path.realpath(os.path.expanduser(r["file"]))
            if os.path.dirname(path) != os.path.realpath(MOCK_DIR):
                raise PanelError("only files in the active project's state directory can be edited here")
            self.mock_path(os.path.basename(path)[:-5])   # name check
            # R6B-09: the panel leaves "content" out when the body is unchanged (re-sending 20 MB on every Save froze
            # it); then only status / headers / on change and the file is not even read.
            if "content" in a:
                if not isinstance(a["content"], str):
                    raise PanelError("content must be text")
                with open(path, "rb") as fh:
                    raw = fh.read()
                # a binary mock comes back from the editor as its replacement-character text: writing that turned every
                # non-UTF-8 byte into U+FFFD (QA-08). Unchanged text = keep the file's bytes, change only status/headers.
                text, _binary, clipped = self.mock_text(raw)
                if a["content"] != text:
                    if clipped:
                        raise PanelError("this body is binary and larger than %d KB: the panel shows only a preview and cannot replace the file "
                                         "(status and headers can still be saved)" % (MOCK_BINARY_PREVIEW // 1024))
                    atomic_write_text(path, a["content"])
            if str(a.get("status", "")).strip():
                r["status"] = http_status(a["status"])
            if isinstance(a.get("headers"), list):
                r["headers"] = [[str(k), str(v)] for k, v in a["headers"] if str(k).strip()]
            if r.pop("draft", None):
                r["enabled"] = True          # the first Save turns a new Map Local on
            self.save_cfg(cfg)
        else:
            raise PanelError(f"unknown op {op}")
        return {}

    def _write_coll(self, doc):
        os.makedirs(COLL_DIR, exist_ok=True)
        atomic_json(self.coll_file(doc["name"]), migrate_collection(doc))

    def sess_har(self, a):
        """A saved session as a HAR. Runs on a worker thread when asked from the panel (F-03): it only reads the
        session file and touches no shared state."""
        # Review R4: this went through the reduced collection format: no request headers or body, no port, zero
        # timings, and calls without a response were dropped. A session is a capture of evidence, so it is
        # exported from the complete saved flows by mitmproxy's own HAR writer (request headers and body, real
        # port and timings, failed calls with their error), then redacted like every HAR unless secrets are asked for.
        from mitmproxy.addons.savehar import SaveHar
        flows = [f for f in self.read_session(a["name"]) if isinstance(f, http.HTTPFlow)]
        har = SaveHar().make_har(flows)
        self._cap_har_bodies(har)
        entries = har.get("log", {}).get("entries", [])
        if len(entries) == len(flows):    # HAR allows custom fields with a leading "_": which device / app sent it
            for e, f in zip(entries, flows):
                src = f.metadata.get("rivis_source")
                if isinstance(src, dict):
                    e["_rivisSource"] = {k: src.get(k, "") for k in ("kind", "device", "app", "id")}
        return self._har_reply(har, a)

    @staticmethod
    def _cap_har_bodies(har, limit=HAR_BODY_LIMIT):
        """F-03: drop request/response bodies over `limit` bytes from a HAR (in place), leaving the size and a
        comment, so building and redacting a session with big downloads stays short. Smaller bodies are unchanged."""
        for e in (har.get("log") or {}).get("entries") or []:
            for part, key in ((e.get("request") or {}, "postData"), (e.get("response") or {}, "content")):
                body = part.get(key)
                text = body.get("text") if isinstance(body, dict) else None
                if text and (len(text) * 3 // 4 if body.get("encoding") == "base64" else len(text)) > limit:
                    body["text"] = ""
                    body.pop("encoding", None)
                    body["comment"] = ("Body left out: larger than the %d MiB HAR export limit (%s bytes). The saved "
                                       "session still holds it." % (limit // (1024 * 1024), body.get("size", "?")))
        return har

    @staticmethod
    def _har_reply(har, a):
        """HAR for the browser to download: secrets redacted unless the user ticked "Include secrets" (F-08)."""
        secrets_in = a.get("include_secrets") is True
        return {"har": har if secrets_in else proxy_redact.har(har), "redacted": not secrets_in,
                "filename": a["name"] + ".har"}

    @staticmethod
    def to_har(doc):
        import datetime
        out = []
        for e in doc.get("entries", []):
            text = e.get("text")
            content = {"size": len(text or ""), "mimeType": next((v for k, v in e["headers"] if k.lower() == "content-type"), ""),
                       **({"text": text} if text is not None else {"text": e.get("b64", ""), "encoding": "base64"})}
            q = ("?" + e["query"]) if e.get("query") else ""
            out.append({
                "startedDateTime": datetime.datetime.fromtimestamp(e.get("recorded_at", 0), datetime.timezone.utc).isoformat(),
                "time": 0,
                "request": {"method": e["method"], "url": f"{e.get('scheme', 'https')}://{e['host']}{e['path']}{q}",
                            "httpVersion": "HTTP/1.1", "headers": [], "queryString": [], "cookies": [], "headersSize": -1, "bodySize": -1,
                            # collections keep only a fingerprint of the request body (not the body): carry it, so an
                            # exported collection imported elsewhere still replays each POST by its body
                            **({"_rivisRequestBodyHash": e["req_body"]} if e.get("req_body") else {})},
                "response": {"status": e["status"], "statusText": "", "httpVersion": "HTTP/1.1",
                             "headers": [{"name": k, "value": v} for k, v in e["headers"]], "cookies": [],
                             "content": content, "redirectURL": "", "headersSize": -1, "bodySize": -1},
                "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0}})
        return {"log": {"version": "1.2", "creator": {"name": PRODUCT["name"], "version": "1"}, "entries": out}}

    @staticmethod
    def from_har(har, skipped=None):
        import base64
        import time as _t
        from urllib.parse import parse_qsl, urlencode, urlsplit
        from proxy_collections import body_hash
        out = []
        for e in ((har or {}).get("log") or {}).get("entries", [])[:10000]:
            try:
                req, resp = e["request"], e["response"]
                u = urlsplit(req["url"])
                c = resp.get("content") or {}
                # R2A-05: keep the request body (hashed like a live recording) so calls differing only by body replay apart
                post = req.get("postData") or {}
                if post.get("text") is not None:
                    raw = base64.b64decode(post["text"]) if post.get("encoding") == "base64" else str(post["text"]).encode("utf-8")
                elif post.get("params"):
                    raw = urlencode([(p["name"], p.get("value", "")) for p in post["params"]]).encode("utf-8")
                else:
                    raw = None
                hashed = req.get("_rivisRequestBodyHash")
                if raw is None and isinstance(hashed, str) and re.fullmatch(r"[0-9a-f]{16}", hashed):
                    req_body = hashed                     # a Rivis collection export: the body's fingerprint, not the body
                else:
                    req_body = body_hash(raw or b"")
                ent = {"method": req["method"].upper(), "scheme": u.scheme or "https", "host": u.hostname or "",
                       "path": u.path or "/",
                       "query": urlencode(sorted(parse_qsl(u.query, keep_blank_values=True))),
                       "req_body": req_body, "status": int(resp["status"]),
                       "headers": [[h["name"], h["value"]] for h in resp.get("headers", [])
                                   if h["name"].lower() not in ("content-encoding", "content-length", "transfer-encoding", "connection")
                                   and not h["name"].startswith(":")],
                       "recorded_at": _t.time()}
                if c.get("encoding") == "base64":
                    ent["b64"] = c.get("text", "")
                    base64.b64decode(ent["b64"])
                else:
                    ent["text"] = c.get("text", "")
                if not ent["host"] or ent["status"] <= 0:
                    why = "failed call (status 0)"
                elif ent["status"] == 101:
                    why = "WebSocket upgrade (101 cannot be replayed)"
                else:
                    out.append(ent)
                    continue
                if skipped is not None:       # R2A-10: say what was left out instead of dropping it silently
                    skipped.append("%s %s: %s" % (ent["method"], ent["path"][:60], why))
            except (KeyError, ValueError, TypeError):
                continue
        return out

    @staticmethod
    def diff(fa, fb):
        def flat(o, p="$", out=None):
            out = {} if out is None else out
            if isinstance(o, dict):
                if not o:
                    out[p] = "{}"
                for k, v in o.items():
                    flat(v, f"{p}.{k}", out)
            elif isinstance(o, list):
                if not o:
                    out[p] = "[]"
                for i, v in enumerate(o):
                    flat(v, f"{p}[{i}]", out)
            else:
                out[p] = json.dumps(o, ensure_ascii=False)
            return out

        def body_rows(ma, mb):
            ra = (ma.get_content(strict=False) or b"") if ma else b""
            rb = (mb.get_content(strict=False) or b"") if mb else b""
            try:
                da, db = flat(json.loads(ra or b"null")), flat(json.loads(rb or b"null"))
                rows = []
                for k in sorted(set(da) | set(db)):
                    if da.get(k) != db.get(k):
                        rows.append([k, da.get(k, "—"), db.get(k, "—")])
                return "json", rows[:500]
            except (ValueError, RecursionError):
                import difflib
                ta, tb = ra.decode("utf-8", "replace").splitlines(), rb.decode("utf-8", "replace").splitlines()
                rows = [[l[:1], l[1:][:300], ""] for l in difflib.unified_diff(ta, tb, lineterm="", n=0)
                        if l[:1] in "+-" and not l.startswith(("+++", "---"))]
                return "text", rows[:500]

        def hdr_rows(ha, hb):
            def keyed(h):
                seen, out = {}, {}
                for k, v in (h.items(multi=True) if h is not None else []):
                    k = k.lower()
                    seen[k] = seen.get(k, 0) + 1
                    out[k if seen[k] == 1 else f"{k}[{seen[k]}]"] = v
                return out
            a, b = keyed(ha), keyed(hb)
            return [[k, a.get(k, "—"), b.get(k, "—")] for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]

        ra, rb = fa.response, fb.response
        sa, sb = body_rows(fa.request, fb.request), body_rows(ra, rb)
        return {
            "a": {"method": fa.request.method, "url": fa.request.pretty_url, "status": ra.status_code if ra else None},
            "b": {"method": fb.request.method, "url": fb.request.pretty_url, "status": rb.status_code if rb else None},
            "req_headers": hdr_rows(fa.request.headers, fb.request.headers),
            "resp_headers": hdr_rows(ra.headers if ra else None, rb.headers if rb else None),
            "req_body": {"kind": sa[0], "rows": sa[1]},
            "resp_body": {"kind": sb[0], "rows": sb[1]},
        }

    # ── wiring into mitmweb ───────────────────────────────────────────────────
    @staticmethod
    def _show_start_time_column():
        """The list opens newest first (panel.js sorts "Start time" descending), and mitmweb can only sort by a column
        it shows. Set here, not in the launchers, so it also reaches an instance already running when this reloads."""
        cols = list(getattr(ctx.options, "web_columns", None) or [])    # mitmweb-only option
        if cols and "timestamp" not in cols:
            ctx.options.update(web_columns=cols + ["timestamp"])

    def running(self):
        try:
            self.active_project = ctx.options.proxy_project
            self.view_project = self.active_project
            self.active_profile = project_profile(self.active_project)
            vf = ctx.options.view_filter or ""
            self.show_dns = vf == "" or vf.startswith("~d '")
            pf = self.project_filter(self.view_profile)
            self.project_only = bool(pf and pf in vf)
            m = re.search(r"~d '\^([^']*)\$'", vf)
            self.focused_host = m.group(1).replace("\\", "") if m else None
            self.source = self.source_from_filter(vf)        # a hot reload keeps the chosen device / app
            self._start_android_watch()
            self._restore_view_choice(vf)
            self._register()
            self._show_start_time_column()
            from mitmproxy import contentviews
            contentviews.add(Utf8TextView())        # by name: a hot reload replaces it
        except Exception as e:   # never take mitmweb down
            ctx.log.warn(f"proxy_panel: not available ({type(e).__name__}: {e})")

    def _start_android_watch(self):
        import asyncio
        old = getattr(ctx.master, "_rivis_android_watch", None)
        if old is not None:
            old.cancel()                 # a hot reload: one watch, on the new code
        ctx.master._rivis_android_watch = asyncio.get_running_loop().create_task(self._android_watch())

    async def _android_watch(self):
        """Put the proxy back on an emulator `android on` set up when it comes back without one (cold boot, an older
        Quick Boot snapshot, a wipe). adb runs off the event loop: a slow emulator must not stall the proxy."""
        import asyncio
        while True:
            await asyncio.sleep(ANDROID_WATCH_EVERY)
            try:
                restored = await asyncio.to_thread(devices.restore_android_proxy, devices.adb_path(), STATE_ROOT,
                                                   self._proxy_port())
            except Exception as e:       # never take the proxy down over an emulator
                ctx.log.warn(f"proxy_panel: emulator proxy check failed ({type(e).__name__}: {e})")
                continue
            try:
                for serial, avd in restored:
                    ctx.log.info(f"proxy_panel: {serial} ({avd}) had lost its proxy setting; set it back to this proxy")
                    # on the master, not on self: a hot reload swaps the panel instance
                    ctx.master._rivis_android_restored = (list(getattr(ctx.master, "_rivis_android_restored", []))
                                                          + [{"serial": serial, "avd": avd, "at": time.time()}])[-5:]
                    self._devices.invalidate()
            except Exception as e:       # a reporting error must not end the watch
                ctx.log.warn(f"proxy_panel: emulator proxy report failed ({type(e).__name__}: {e})")

    def _register(self):
        app = getattr(ctx.master, "app", None)
        if app is None:
            return   # mitmdump / mitmproxy console: no web UI
        app._proxy_panel_impl = self          # hot reload: routes stay, implementation swaps
        if getattr(app, "_proxy_panel_routes", False):
            return
        from mitmproxy.tools.web import app as webapp

        def impl(h):
            return h.application._proxy_panel_impl

        def allowed_hosts():
            names = {"127.0.0.1", "localhost", "[::1]", (ctx.options.web_host or "127.0.0.1").lower()}
            return names | {f"{n}:{ctx.options.web_port}" for n in names}

        def allowed_origins():
            return {f"http://{h}" for h in allowed_hosts() if ":" in h.rsplit("]", 1)[-1]}

        class ProxyIndex(webapp.IndexHandler):
            # F-19: mitmweb's ?token= login would set a ~13-month cookie; keep the login to this browser session.
            def set_signed_cookie(self, name, value, expires_days=None, **kw):
                kw.pop("expires", None)
                kw.setdefault("httponly", True)
                kw.setdefault("samesite", "Strict")
                return super().set_signed_cookie(name, value, expires_days=None, **kw)

            set_secure_cookie = set_signed_cookie

            def finish(self, chunk=None):
                if chunk is not None:
                    s = chunk.decode() if isinstance(chunk, bytes) else chunk
                    if "</head>" in s and "proxy/boot.js" not in s:
                        s = s.replace("</head>", THEME_BOOT + "</head>", 1)
                    s = re.sub(r'(src="\./static/index-[\w-]+\.js)"', r'\1?rivis=%s"' % MITMWEB_PATCH_VERSION, s, count=1)
                    if "</body>" in s and "proxy/panel.js" not in s:
                        s = s.replace("</body>", '<script src="./proxy/panel.js"></script></body>')
                    chunk = s
                return super().finish(chunk)

        class PanelJS(webapp.RequestHandler):
            def get(self):
                with open(os.path.join(HERE, "panel.js"), "rb") as fh:
                    self.set_header("Content-Type", "application/javascript")
                    self.set_header("Cache-Control", "no-store")
                    self.write(fh.read())

        class MitmwebIndexJS(webapp.RequestHandler):
            """mitmweb's own bundle with patch_mitmweb_js applied (see there). no-store, and the index page asks for it
            with ?rivis=N, so a browser never keeps running a cached unpatched copy."""

            def get(self, name):
                path = os.path.join(os.path.dirname(webapp.__file__), "static", name)
                try:
                    with open(path, encoding="utf-8") as fh:
                        source = fh.read()
                except OSError:
                    raise tornado.web.HTTPError(404)
                self.set_header("Content-Type", "application/javascript")
                self.set_header("Cache-Control", "no-store")
                self.write(patch_mitmweb_js(source, ctx.log.warn))

        class ClippedContentView(webapp.FlowContentView):
            """mitmweb's own view endpoint, with clip_view applied (R6B-07)."""

            def message_to_json(self, view_name, message, flow, *args, **kw):
                raw = getattr(message, "raw_content", None)
                preview = preview_message(message)          # R10-01: never render a huge body on the event loop
                result = super().message_to_json(view_name, preview or message, flow, *args, **kw)
                # R6-06: panel-side protobuf decoding needs the complete built-in view; ordinary UI views stay clipped.
                if self.get_query_argument("full", "") == "1" and preview is None:
                    return result
                return clip_view(result, len(raw) if isinstance(raw, (bytes, bytearray)) else None, preview is not None)

        class MitmwebExport(webapp.RequestHandler):
            """mitmweb's own toolbar menu Export ▾ (Copy as cURL / HTTPie / raw) copied tokens and cookies in clear text,
            next to our masked Copy as. Same masking here; unmasked copies stay a deliberate choice in Copy as."""

            def post(self):
                try:
                    fmt, ref = (json.loads(self.request.body or b"{}").get("arguments") or [None, None])[:2]
                    flow = impl(self).flow(str(ref or "").lstrip("@"))
                    if fmt in ("curl", "httpie"):
                        text = generate(impl(self)._flow_request(flow), fmt, True)
                    elif fmt in ("raw_request", "raw_response", "raw"):
                        from mitmproxy.addons import export as mexport
                        raw = getattr(mexport, fmt)(flow)
                        text = proxy_redact.raw_text(raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw))
                    else:
                        raise ValueError("unknown export format %r" % fmt)
                    self.write({"value": text})
                except (PanelError, ValueError, KeyError, TypeError) as e:
                    self.write({"error": str(e)})

        class SafeDumpFlows(webapp.DumpFlows):
            """R9-05: mitmweb's File → Open (POST /flows/dump) clears the list before it parses the file, so a broken
            HAR wiped every captured call and answered a bare 500. Parse the whole file first; if it cannot be read,
            answer 400 with a readable reason and leave the current calls alone. A readable file goes to the stock
            handler unchanged. F1: when calls are already captured, the file is added to them (see below) unless the
            request says mode=replace."""

            async def post(self):
                from io import BytesIO
                from mitmproxy import io as mio
                files = self.request.files
                data = next(iter(files.values()))[0].body if files else self.request.body
                name = next(iter(files.values()))[0].get("filename", "") if files else ""
                problem = None
                try:
                    count = sum(1 for _ in mio.FlowReader(BytesIO(data)).stream())
                    if not count:
                        problem = "it contains no calls"
                except Exception as e:      # noqa: BLE001 - any reader failure means "cannot open this file"
                    problem = str(e).strip().splitlines()[0][:200] if str(e).strip() else type(e).__name__
                if problem:
                    looks_har = data.lstrip()[:1] == b"{" or str(name).lower().endswith(".har")
                    kind = "Not a valid HAR (JSON) file" if looks_har else "Not a HAR or mitmproxy flow file"
                    self.set_status(400)
                    self.set_header("Content-Type", "text/plain; charset=utf-8")
                    self.finish("Could not open %s: %s (%s). Your current calls were kept."
                                % (name or "the file", kind, problem))
                    return
                existing = len(getattr(self.view, "_store", None) or ())
                if existing == 0 or self.get_query_argument("mode", "") == "replace":
                    return await super().post()      # nothing to lose, or the panel's dialog asked for a replacement
                # F1: File → Open replaced the whole live capture without asking. Without an explicit mode=replace the
                # file's calls are added next to the captured ones, marked as imported, with fresh ids (a dump of this
                # very capture would otherwise collide with itself).
                label = "imported from %s" % (os.path.basename(str(name)) or "a file")
                added = 0
                for f in mio.FlowReader(BytesIO(data)).stream():
                    f.id = str(uuid.uuid4())
                    f.comment = (f.comment + " | " if f.comment else "") + label
                    f.marked = ":large_blue_circle:"
                    await self.master.load_flow(f)
                    added += 1
                self.set_header("Content-Type", "application/json")
                self.finish(json.dumps({"added": added, "kept": existing}))

        class ThemeCSS(webapp.RequestHandler):
            def get(self):
                with open(os.path.join(HERE, "theme.css"), "rb") as fh:
                    self.set_header("Content-Type", "text/css; charset=utf-8")
                    self.set_header("Cache-Control", "no-store")
                    self.write(fh.read())

        class BootJS(webapp.RequestHandler):
            # Pre-paint boot: served as a same-origin script because the page CSP blocks inline <script>.
            def get(self):
                self.set_header("Content-Type", "application/javascript")
                self.set_header("Cache-Control", "no-store")
                self.write(BOOT_JS)

        import tornado.web

        class Bootstrap(tornado.web.RequestHandler):
            """Exchange a one-time, non-password URL nonce for mitmweb's signed session cookie.
            A plain tornado handler on purpose: every webapp.RequestHandler subclass is wrapped with mitmweb's
            _require_auth, which would demand the very login this endpoint grants."""

            def get(self, nonce):
                expected_host = {"127.0.0.1", "localhost", f"127.0.0.1:{ctx.options.web_port}",
                                 f"localhost:{ctx.options.web_port}"}
                if self.request.headers.get("Host", "") not in expected_host:
                    self.set_status(403); return
                path = os.path.expanduser(ctx.options.proxy_bootstrap_file or "")
                try:
                    with open(path) as fh:
                        expected = fh.read().strip()
                except OSError:
                    expected = ""
                if not expected or not secrets.compare_digest(nonce, expected):
                    self.set_status(403); return
                try:
                    os.remove(path)
                except OSError:
                    self.set_status(403); return
                self.set_header("Cache-Control", "no-store")
                self.set_header("Referrer-Policy", "no-referrer")
                self.set_secure_cookie(f"mitmproxy-auth-{ctx.options.web_port}", "y", expires_days=None,
                                       httponly=True, samesite="Strict")
                self.redirect("/")

        class Api(webapp.RequestHandler):
            def _refuse_cross_site(self):
                """F-04: SameSite=Strict is per site, not per port, so a page on another 127.0.0.1 port could plant the
                xsrf cookie. Require what a browser only sends for our own page: a JSON body, the XSRF header (never
                the ?_xsrf= form, which needs no CORS preflight), and our own Origin / same-origin fetch metadata."""
                h = self.request.headers
                if "_xsrf" in self.request.query_arguments or "_xsrf" in self.request.body_arguments:
                    return "the _xsrf parameter form is not accepted"
                if not h.get("X-XSRFToken"):
                    return "missing X-XSRFToken header"
                if (h.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
                    return "Content-Type must be application/json"
                origin = h.get("Origin")
                if origin is not None and origin not in allowed_origins():
                    return "cross-origin request"
                if h.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
                    return "cross-site request"
                return None

            async def _test_hold(self, op):
                """Test-only: RIVIS_TEST_PANEL_DELAY_FILE names a JSON file {"<op>": seconds}; that op then answers late
                (the event loop stays free), to reproduce a proxy that does not answer. Inert unless the variable is set."""
                path = os.environ.get("RIVIS_TEST_PANEL_DELAY_FILE")
                if not path:
                    return
                try:
                    with open(path) as fh:
                        wait = float(json.load(fh).get(op, 0))
                except (OSError, ValueError, AttributeError):
                    return
                if wait > 0:
                    import asyncio
                    await asyncio.sleep(wait)

            async def get(self, op):
                if op not in ("state", "flows_since"):
                    raise webapp.APIError(404, "unknown")
                await self._test_hold(op)
                self.set_header("Content-Type", "application/json")
                if op == "flows_since":
                    self.write(json.dumps(impl(self).flows_since(self.get_query_argument("epoch", ""),
                                                                 self.get_query_argument("cursor", ""))))
                    return
                self.write(json.dumps(impl(self).state()))

            def prepare(self):
                # before mitmweb's own prepare, whose fetch-metadata refusal surfaces as a 500
                if self.request.method not in ("GET", "HEAD", "OPTIONS"):
                    raw_length = self.request.headers.get("Content-Length")
                    try:
                        declared = int(raw_length) if raw_length is not None else len(self.request.body or b"")
                    except ValueError:
                        raise tornado.web.HTTPError(400, "invalid Content-Length")
                    if declared > MAX_PANEL_REQUEST_BYTES or len(self.request.body or b"") > MAX_PANEL_REQUEST_BYTES:
                        raise tornado.web.HTTPError(413, "panel request exceeds the %d MiB limit"
                                                    % (MAX_PANEL_REQUEST_BYTES // (1024 * 1024)))
                    refused = self._refuse_cross_site()
                    if refused:
                        raise tornado.web.HTTPError(403, refused)
                return super().prepare()

            async def post(self, op):
                self.set_header("Content-Type", "application/json")
                await self._test_hold(op)
                try:
                    a = json.loads(self.request.body or b"{}")
                    if op in OFF_LOOP_OPS:   # F-03: slow reads/exports must not stall the proxy's event loop
                        import asyncio
                        if not isinstance(a, dict):
                            raise PanelError("request body must be a JSON object")
                        impl(self)._check_input(a)
                        out = await asyncio.get_running_loop().run_in_executor(None, getattr(impl(self), op), a) or {}
                    else:
                        out = impl(self).act(op, a) or {}
                    out["state"] = impl(self).state()
                    self.write(json.dumps(out))
                except (PanelError, AttributeError, KeyError, TypeError, ValueError, OSError, re.error) as e:
                    self.set_status(400)
                    self.write(json.dumps({"error": str(e)}))
                except Exception as e:   # a bug: say so in the UI, and leave the traceback in the log for the bug report
                    import traceback
                    ctx.log.error("panel %s failed: %s\n%s" % (op, e, traceback.format_exc()[-4000:]))
                    self.set_status(500)
                    self.write(json.dumps({"error": "%s failed (%s) — details are in the log; `%s bug-report` collects them"
                                                    % (op, type(e).__name__, PRODUCT["cli"])}))

        # B2 (DNS rebinding): a page on evil.example that re-resolves to 127.0.0.1 is same-origin to itself, so the
        # browser sends Host: evil.example. Every UI request (mitmweb's own routes, the websocket and ours) must name
        # this listener by a loopback name.
        original_find_handler = app.find_handler

        def find_handler(request, **kw):
            if (request.host or "").lower() not in allowed_hosts():
                return app.get_handler_delegate(request, tornado.web.ErrorHandler, {"status_code": 403})
            return original_find_handler(request, **kw)

        app.find_handler = find_handler

        app.add_handlers(r".*", [
            (r"/", ProxyIndex),
            (r"/proxy/panel\.js", PanelJS),
            (r"/proxy/theme\.css", ThemeCSS),
            (r"/commands/export", MitmwebExport),
            (r"/flows/dump", SafeDumpFlows),
            (r"/flows/(?P<flow_id>[0-9a-f\-]+)/(?P<message>request|response|messages)/content/(?P<content_view>[0-9a-zA-Z\-\_%]+)(?:\.json)?",
             ClippedContentView),
            (r"/static/(index-[A-Za-z0-9_-]+\.js)", MitmwebIndexJS),
            (r"/proxy/boot\.js", BootJS),
            (r"/proxy/bootstrap/([0-9a-f]{32})", Bootstrap),
            (r"/proxy/api/([a-z_]+)", Api),
        ])
        app._proxy_panel_routes = True
        ctx.log.info(f"proxy_panel: {PRODUCT['name']} project panel available in the mitmweb UI")


addons = [ProxyPanel()]
