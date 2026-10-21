"""
proxy_rules — Proxyman-style rules for mitmproxy, driven by one JSON file.

Loaded by the product CLI (mitmweb -s proxy_rules.py). The rules file is re-read
whenever it changes, so CLI rule changes (or editing the file) take
effect on the next request — no proxy restart, rules survive restarts.

File: the active project's rules.json (option `proxy_rules_file`):

{
  "throttle": "off",            # off | lte | 3g | edge | slow | "<latency_ms>ms[/<kbps>kbps]"
  "throttle_match": ".",  # regex on URL; only matching calls are throttled ("" = all)
  "loss": 0,                     # % of matching calls dropped (connection killed)
  "no_cache": false,             # No Caching: strip conditional request headers, force no-store responses
  "rules": [
    {"name": "...", "enabled": true, "match": "<regex on full URL>", "method": "GET",
     "action": "<one of below>", ...action fields}
  ]
}

Actions
  respond     status, body | body_file, headers{}   answer locally, never hits the server
  map_local   file, [status], [headers{} or [[name,value],...]]  serve a local file
  status      status, [body | body_file]             let the call go through, then rewrite the status
  json_patch  set{ "a.b[0].c": value, ... }          edit fields in the real JSON response
  delay       ms                                     hold the request before sending it
  set_header  side request|response, header, value   (value null = remove)
  map_remote  replace (regex), with                  rewrite the URL before it is sent
  block                                              kill the connection (app sees a network error)

`file` / `body_file` must live inside the project's state directory (the directory holding
this rules file; symlinks are resolved, so a link inside the project cannot point out of it).
A rule pointing anywhere else is skipped at load time with an error — the panel shows it as
disabled and the proxy keeps running. This stops a shared rules file from serving arbitrary
local files (security finding F-09).

Every rule that fires appends "rule:<name>" to the flow comment, so the UI shows what changed a call.

Hit counts: every enabled rule counts the calls it changed and the calls it matched but left unchanged (a map_remote
whose replace finds nothing, a json_patch on a non-JSON response), with the number of calls seen since the rule was
switched on or last edited. Applied hits are written when the response finishes; other call totals are polled, so
`rules list` and the panel can say "ON but never matched" instead of leaving a tester with an inert rule.
"""
import asyncio
import importlib
import json
import math
import mimetypes
import os
import random
import re
import socket
import sys
import time
import ipaddress

from mitmproxy import ctx, flowfilter, http
from mitmproxy.net.http import status_codes

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import proxy_common
importlib.reload(proxy_common)
from proxy_common import (PRODUCT, PROFILE_VALUES, atomic_json, STATE_ROOT, breakpoints, project_profile,
                          migrate_rules, remote_url_problem, throttle_shorthand, tls_config, tls_options, user_regex)
import proxy_rule_validation
importlib.reload(proxy_rule_validation)      # mitmproxy reloads this add-on in place: the validator must see the new proxy_common too
from proxy_rule_validation import compile_rule, rule_fingerprint

DNS_TIMEOUT = 10        # seconds for the private-address guard's own lookup

# Traffic profiles: latency ms, jitter ms, down kbps, up kbps, loss %, extra response delay ms.
# The first four named ones are FRTMProxy's built-ins, same numbers, so teams see the same thing.
PROFILES = PROFILE_VALUES
DEFAULT_FILE = os.path.join(STATE_ROOT, "projects", "default", "rules.json")
_UNSET = object()


def _parse_throttle(spec, manual=None):
    """→ (latency, jitter, down_kbps, up_kbps, loss_pct, delay_ms) or None"""
    spec = (spec or "off").strip().lower()
    if spec in ("", "off", "none"):
        return None
    if spec in PROFILES:
        return PROFILES[spec]
    if spec == "manual":
        m = manual or {}
        values = (float(m.get("latency_ms", 0)), float(m.get("jitter_ms", 0)), float(m.get("down_kbps", 0)),
                  float(m.get("up_kbps", 0)), float(m.get("loss_pct", 0)), float(m.get("response_delay_ms", 0)))
        return tuple(0 if not math.isfinite(v) or v < 0 else v for v in values)
    shorthand = throttle_shorthand(spec)
    if shorthand is not None:
        return shorthand[0], 0, shorthand[1], 0, 0, 0
    raise ValueError(f"unknown throttle '{spec}' ({'|'.join(['off', *PROFILES, 'manual'])}|<ms>ms[/<kbps>kbps])")


def _bp_filter(bps):
    """breakpoints list → one mitmproxy intercept filter (OR of each active breakpoint)."""
    parts = []
    for b in bps:
        if not b.get("enabled", True) or not b.get("match") or not (b.get("request") or b.get("response")):
            continue
        # mitmproxy's filter parser un-escapes backslashes inside quotes, so double them
        # (and escape the quote) — otherwise "a\.b" reaches the regex engine as "a.b"
        # and "(\?|$)" as the invalid "(?|$)".
        q = b["match"].replace("\\", "\\\\").replace("'", "\\'")
        f = "~u '" + q + "'"
        if b.get("method"):
            f += " & ~m '^" + re.escape(b["method"].upper()) + "$'"
        if b.get("request") and not b.get("response"):
            f += " & ~q"
        elif b.get("response") and not b.get("request"):
            f += " & ~s"
        if b.get("response"):
            # R4B-01: a streamed SSE body has no editable response snapshot, so do not pause its delivery.
            f += " & ( ~q | !~hs '(?i)content-type: *text/event-stream' )" if b.get("request") else " & !~hs '(?i)content-type: *text/event-stream'"
        # Calls Rivis answers itself (Map Local / respond, tagged "mock:") are paused by proxy_rules, never by
        # mitmweb's Intercept: mitmweb 12.2.3 never sends a locally answered response it has intercepted.
        f += " & !~comment '(^| )mock:'"
        # spaces inside the brackets matter: mitmproxy's parser rejects "~s)" but accepts "~s )"
        parts.append("( " + f + " )")
    return " | ".join(parts)


def _local_bps(bps):
    """Active breakpoints as (url regex, METHOD or None, request?, response?) for calls Rivis answers itself."""
    out = []
    for b in bps:
        if b.get("enabled", True) and b.get("match") and (b.get("request") or b.get("response")):
            try:
                out.append((re.compile(b["match"]), (b.get("method") or "").upper() or None,
                            bool(b.get("request")), bool(b.get("response"))))
            except re.error:
                continue
    return out


def _set_path(doc, path, value):
    """a.b[0].c = value  (creates nothing; a missing path is reported, not invented)"""
    parts = re.findall(r"[^.\[\]]+|\[\d+\]", path)
    cur = doc
    for i, p in enumerate(parts):
        key = int(p[1:-1]) if p.startswith("[") else p
        last = i == len(parts) - 1
        if isinstance(key, int):
            if not isinstance(cur, list) or key >= len(cur):
                raise KeyError(path)
        elif not isinstance(cur, dict) or (key not in cur and not last):
            raise KeyError(path)
        if last:
            cur[key] = value
        else:
            cur = cur[key]


def _tag(flow, text):
    flow.comment = (flow.comment + " | " if flow.comment else "") + text


def _tag_rule(flow, rule, suffix="", modified=True):
    if modified:
        flow.metadata["proxy_modified"] = True
    kind = "mock" if rule.get("action") in ("respond", "map_local") else "rule"
    _tag(flow, f"{kind}:{rule['name']}{suffix}")


_CONDITIONAL_HEADERS = ("If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since", "If-Range")


def _no_cache_request(flow):
    """No Caching, request side: the server cannot answer 304 to a request that carries no validators."""
    for name in _CONDITIONAL_HEADERS:
        flow.request.headers.pop(name, None)
    flow.request.headers["Cache-Control"] = "no-cache"
    flow.request.headers["Pragma"] = "no-cache"
    flow.metadata["proxy_no_cache"] = True
    _tag(flow, "no-cache")


def _no_cache_response(flow):
    """No Caching, response side: the app must not store this answer nor revalidate it later."""
    h = flow.response.headers
    h["Cache-Control"] = "no-store, no-cache, must-revalidate"
    h["Pragma"] = "no-cache"
    h["Expires"] = "0"
    h.pop("ETag", None)
    h.pop("Last-Modified", None)
    if not flow.metadata.get("proxy_no_cache"):
        flow.metadata["proxy_no_cache"] = True
        _tag(flow, "no-cache")


def _confdir():
    try:
        return ctx.options.confdir
    except (AttributeError, KeyError):
        return None


def _no_body_for(resp):
    """R7B-01: 204 and 304 never carry a body. Sending the old body with its Content-Length after the status line
    says 204/304 leaves those bytes on a keep-alive connection, where the client reads them as the next response."""
    if resp.status_code in (204, 304):
        resp.content = b""
        for k in ("content-length", "transfer-encoding", "content-encoding"):
            resp.headers.pop(k, None)


def _compile_rule(source, state_dir, fallback_name=None):
    # R5A-02: CLI and proxy must reach the same skip decision.
    return compile_rule(source, state_dir, fallback_name, _confdir())


# ── R10-02: HTTP/1 interim (1xx) responses ─────────────────────────────────────────────────────────────────────────
# Mitmproxy 12.2.3's HTTP/1 client takes the first status line it reads as the final response. An upstream that sends
# `103 Early Hints` (or an unsolicited `100 Continue`) before its real answer therefore had the 103 delivered to the
# app as the whole response, and the client then waited for ever. The interim heads are informational only (RFC 9110
# 15.2), so they are dropped here and the real response is read and passed on as usual. 101 is a real switch and is
# left alone. The wrap is installed once per process: a hot reload re-runs this module and must not wrap the wrapper.
_INTERIM_HEAD = re.compile(rb"HTTP/1\.[01] (1(?!01)\d\d)\b")


def _install_interim_drop():
    try:
        import logging
        from mitmproxy.proxy import commands as _commands, events as _events
        from mitmproxy.proxy.layers.http import _http1
        original = _http1.Http1Client.read_headers
    except (ImportError, AttributeError):
        return False
    if getattr(original, "_rivis_interim", False):
        return True

    def read_headers(self, event):
        if isinstance(event, _events.DataReceived) and getattr(self, "request", None) is not None:
            while True:
                raw = bytes(self.buf)
                m = _INTERIM_HEAD.match(raw)
                if not m or (b"\r\n\r\n" not in raw and b"\n\n" not in raw):
                    break                                  # a final head, or an interim one not complete yet
                if self.buf.maybe_extract_lines() is None:
                    break
                yield _commands.Log("dropped an interim %s response from %s" % (
                    m.group(1).decode(), getattr(self.conn, "address", "?")), logging.DEBUG)
        yield from original(self, event)

    read_headers._rivis_interim = True
    _http1.Http1Client.read_headers = read_headers
    return True


# ── R10-04: upstream TLS failures answer with the reason and the fix ───────────────────────────────────────────────
# Mitmproxy answers a failed upstream handshake with a bare "502 … Certificate verify failed: …" page. The error hook
# (which runs just before that page is built) stores a full explanation under the original message; the wrapped
# format_error swaps it in. The table lives on mitmproxy's module so a hot reload keeps feeding the installed wrap.
def _error_texts():
    try:
        from mitmproxy.proxy.layers.http import _base
    except ImportError:
        return {}
    table = getattr(_base, "_rivis_error_text", None)
    if table is None:
        table = _base._rivis_error_text = {}
    return table


def _install_error_text():
    try:
        from mitmproxy.proxy.layers.http import _base
    except ImportError:
        return False
    import html as _html
    import importlib as _importlib
    original = _base.format_error

    def format_error(status_code, message):
        text = _error_texts().pop(message, None)
        if text is None:
            return original(status_code, message)
        reason = status_codes.RESPONSES.get(status_code, "Unknown")
        return ("<html>\n<head><title>%d %s</title></head>\n<body>\n<h1>%d %s</h1>\n"
                "<pre style=\"white-space: pre-wrap\">%s</pre>\n</body>\n</html>"
                % (status_code, reason, status_code, reason, _html.escape(text))).encode("utf-8", "replace")

    format_error._rivis_error_text = True
    installed = False
    for name in ("_http1", "_http2", "_http3"):
        try:
            mod = _importlib.import_module("mitmproxy.proxy.layers.http." + name)
        except ImportError:
            continue
        if getattr(getattr(mod, "format_error", None), "_rivis_error_text", False):
            installed = True
            continue
        if hasattr(mod, "format_error"):
            mod.format_error = format_error
            installed = True
    return installed


_TLS_REASONS = (
    ("unable to get local issuer certificate",
     "The server did not send a chain this proxy can check. Usually the server leaves out its intermediate "
     "certificate (an incomplete chain): browsers and phones download a missing intermediate themselves, Rivis does "
     "not. Less often, your network inspects HTTPS with a root certificate this Mac does not trust."),
    ("certificate has expired", "The server's certificate has expired."),
    ("self-signed certificate", "The server uses a self-signed certificate that nothing trusts."),
    ("self signed certificate", "The server uses a self-signed certificate that nothing trusts."),
    ("hostname mismatch", "The server's certificate is for a different host name."),
    ("ip address mismatch", "The server's certificate does not cover this IP address."),
)


def upstream_tls_text(message, host, cli="rivis"):
    """The explanation for a failed upstream certificate check, or None for any other error."""
    if not isinstance(message, str) or not message.startswith("Certificate verify failed"):
        return None
    detail = message.split(":", 1)[1].strip() if ":" in message else message
    why = next((text for key, text in _TLS_REASONS if key in detail.lower()),
               "The server's certificate could not be verified.")
    return ("Rivis could not verify the HTTPS certificate of %(host)s (%(detail)s).\n%(why)s\n\n"
            "The app was answered 502 by Rivis; the server was not asked.\n\n"
            "To fix it:\n"
            "  - Pass this host through without decrypting it (its calls are then not captured or changed):\n"
            "      %(cli)s tls ignore add %(host)s   and   %(cli)s tls mode ignore\n"
            "  - A dev or test server you trust: start with   %(cli)s start --insecure   (no upstream certificate"
            " checks).\n"
            "  - Your company inspects HTTPS: install IT's root certificate in Keychain Access, or start with"
            " RIVIS_EXTRA_TRUST=/path/root.pem.\n" % {"host": host, "detail": detail, "why": why, "cli": cli})


_install_interim_drop()
_install_error_text()


class ProxyRules:
    def __init__(self):
        self.path = DEFAULT_FILE
        self.mtime = None
        self.checked = 0.0
        self.rules = []
        self.throttle = None        # (latency, jitter, down, up, loss, delay) or None
        self.throttle_re = None
        self.loss = 0
        self.no_cache = False       # No Caching (Proxyman tool): every decrypted call fetches fresh content
        self.skipped_rules = []
        self.failed_rules = {}      # R2A-02: rules whose file could not be read at request time {name: error}
        self.last_good_cfg = {"rules": []}
        self._bp_filter = _UNSET
        self._held_bps = []         # the breakpoints of the last rules load, to release calls paused by a removed one
        self._intercept_set = _UNSET
        self.tls = tls_config({})
        self._tls_set = _UNSET
        self.private_hosts_re = None
        self.project_hosts_re = None
        self._address_cache = {}
        self._https_pins = {}
        self.hits = {}              # name → {fp, count, noop, noop_reason, last, since, seen_at_since}
        self._parked_hits = {}      # (name, fp) → hit entry of a rule that is switched off (R9-01)
        self.calls_seen = 0
        self._hits_dirty = False
        self._hits_unflushed = False
        self._hits_written = 0.0
        self._hits_lock = None      # asyncio.Lock, made on the proxy loop: one hit-file write in flight at a time
        self._hits_tasks = set()

    def load(self, loader):
        loader.add_option("proxy_rules_file", str, DEFAULT_FILE, "project rules file (JSON, hot-reloaded)")
        loader.add_option("proxy_project", str, "default", "active project profile ID")
        loader.add_option("proxy_private_hosts", str, "", "explicit regex allow-list for private upstream hosts")

    def running(self):
        # Poll once a second even with no traffic, so CLI breakpoints
        # is armed BEFORE the next call arrives (mitmweb's intercept runs ahead of us)
        async def poll():
            while True:
                await asyncio.sleep(1)
                self._reload()
                await self._flush_hits()
        self._poller = asyncio.get_running_loop().create_task(poll())

    def configure(self, updated):
        if "proxy_rules_file" in updated:
            self.path = os.path.expanduser(ctx.options.proxy_rules_file)
            self.mtime = None
            self._reload(force=True)
        if "proxy_private_hosts" in updated:
            self.private_hosts_re = re.compile(ctx.options.proxy_private_hosts) if ctx.options.proxy_private_hosts else None
        if "proxy_project" in updated:
            # the project's own servers may live on private VPN addresses (internal DNS): its declared host domains are
            # allowed there, matched as whole domains — "x.neo.sa" yes, "neo.sa.attacker.com" no
            self.project_hosts_re = None
            try:
                hosts = (project_profile(ctx.options.proxy_project).get("hosts") or "").strip()
                if hosts:
                    self.project_hosts_re = re.compile(r"(?:[a-z0-9-]+\.)*(?:%s)" % hosts, re.I)
            except (ValueError, OSError, re.error):
                self.project_hosts_re = None

    # ── file handling ────────────────────────────────────────────
    def _reload(self, force=False):
        now = time.monotonic()
        if not force and now - self.checked < 1.0:      # stat at most once a second
            return
        self.checked = now
        try:
            mtime = os.stat(self.path).st_mtime
        except FileNotFoundError:
            if self.rules or self.throttle:
                ctx.log.warn(f"proxy_rules: {self.path} gone — all rules off")
            self._set_breakpoints(None)
            self._release_held([])
            self._set_tls({})
            self.rules, self.throttle, self.loss, self.mtime = [], None, 0, None
            self.no_cache = False
            self.skipped_rules = []
            self.failed_rules.clear()      # R3A-01: no removed rule may remain in doctor/panel state
            return
        if mtime == self.mtime:
            return
        try:
            with open(self.path) as f:
                cfg = migrate_rules(json.load(f))
            if not isinstance(cfg, dict):
                raise ValueError("top level must be an object")
            if not isinstance(cfg.get("rules", []), list):
                raise ValueError("rules must be a list")
            if cfg.get("rules") and all(not isinstance(r, dict) for r in cfg["rules"]):
                raise ValueError("rules must contain objects")
            rules = []
            skipped = []
            state_dir = os.path.dirname(os.path.abspath(os.path.expanduser(self.path)))
            for index, source in enumerate(cfg.get("rules", [])):
                if isinstance(source, dict) and not source.get("enabled", True):
                    continue
                name = source.get("name") if isinstance(source, dict) else None
                name = name or f"rule #{index + 1}"
                try:
                    rules.append(_compile_rule(source, state_dir, name))
                except (KeyError, TypeError, ValueError, re.error) as e:
                    skipped.append({"name": name, "error": str(e)})
                    ctx.log.warn(f"proxy_rules: skipping rule '{name}': {e}")
            # breakpoints drive mitmweb's own Intercept (paused calls → edit → Continue)
            bp_filter = _bp_filter(breakpoints(cfg))
            self._local_breakpoints = _local_bps(breakpoints(cfg))
            throttle = _parse_throttle(cfg.get("throttle"), cfg.get("manual"))
            tre = cfg.get("throttle_match", "")
            throttle_re = user_regex(tre) if tre else None
            # explicit loss wins; otherwise the profile's own loss
            loss = float(cfg.get("loss", 0) or 0) or (throttle[4] if throttle else 0)
            tls = tls_config(cfg)
            self._set_breakpoints(bp_filter or None)
            self._release_held(breakpoints(cfg))
            self._set_tls(cfg)
            self.rules, self.throttle = rules, throttle
            self.failed_rules = {n: e for n, e in self.failed_rules.items() if n in {r["name"] for r in rules}}  # R3A-01
            self.throttle_re, self.loss = throttle_re, loss
            self.no_cache = bool(cfg.get("no_cache"))
            self.tls = tls
            self.skipped_rules = skipped
            self._sync_hits(cfg.get("rules", []))
            self.last_good_cfg = cfg
            self.mtime = mtime
            names = ", ".join(r.get("name", "?") for r in rules) or "none"
            ctx.log.info(f"proxy_rules: loaded {self.path} — active rules: {names}; "
                         f"throttle: {cfg.get('throttle', 'off')}; loss: {self.loss}%; TLS: {tls['mode']}"
                         + ("; no caching: on" if self.no_cache else ""))
        except Exception as e:   # keep the previous good rules on a bad edit
            ctx.log.warn(f"proxy_rules: cannot load {self.path}: {e} — keeping previous rules")
            self.mtime = mtime

    def _release_held(self, bps):
        """Calls paused by a breakpoint that this load removed or switched off are sent on unchanged — whoever edited
        the rules (CLI, panel, by hand), the app must not stay frozen. A call another breakpoint still holds stays paused."""
        old, self._held_bps = self._held_bps, [b for b in bps if isinstance(b, dict)]
        def hits(group, f, phase):
            for b in group:
                if b.get("enabled", True) is False or not b.get(phase) or not b.get("match") \
                        or (b.get("method") and b["method"].upper() != f.request.method):
                    continue
                try:
                    if user_regex(b["match"]).search(f.request.pretty_url):
                        return True
                except re.error:
                    continue
            return False
        if not old:
            return
        try:
            view = ctx.master.view
            flows = list(getattr(view, "_store", {}).values()) or list(view)
        except Exception:      # no flow view (unit tests, startup): nothing can be paused yet
            return
        freed = []
        for f in flows:
            if not getattr(f, "intercepted", False) or not getattr(f, "request", None):
                continue
            phase = "response" if f.response else "request"
            if hits(old, f, phase) and not hits(self._held_bps, f, phase):
                f.comment = (f.comment + " | " if f.comment else "") + "breakpoint removed: sent unchanged"
                f.resume()
                freed.append(f)
        if freed:
            ctx.master.view.update(freed)

    def _abandon_paused(self, client):
        """A call paused at a breakpoint whose client has gone (the app timed out, `curl -m`) can never be answered: end
        it as abandoned instead of leaving it "paused" for good. Killed, not resumed, so nothing is sent upstream."""
        try:
            view = ctx.master.view
            flows = list(getattr(view, "_store", {}).values()) or list(view)
        except Exception:      # no flow view (unit tests, startup): nothing can be paused yet
            return
        freed = []
        for f in flows:
            if getattr(f, "intercepted", False) and getattr(f, "client_conn", None) is not None \
                    and f.client_conn.id == client.id:
                f.comment = (f.comment + " | " if f.comment else "") + "client gave up while paused: not sent"
                f.kill()
                if f.intercepted:
                    f.resume()
                freed.append(f)
        if freed:
            ctx.master.view.update(freed)

    def _set_tls(self, cfg):
        """Apply allow/ignore to NEW connections. mitmproxy's next_layer reads ctx.options per
        connection, so no restart is needed; connections already open keep their earlier decision."""
        allow, ignore = tls_options(cfg)
        desired = (tuple(allow), tuple(ignore))
        if desired == self._tls_set:
            return
        ctx.options.update(allow_hosts=allow, ignore_hosts=ignore)
        try:   # undecrypted hosts stay visible as host-only tunnel rows
            ctx.options.update(show_ignored_hosts=bool(allow or ignore))
        except Exception as e:
            ctx.log.warn(f"proxy_rules: cannot show tunnel rows ({e})")
        self._tls_set = desired
        ctx.log.info("proxy_rules: TLS host policy updated — new connections use it (no proxy restart)")

    def _set_breakpoints(self, desired):
        """Only replace the intercept filter while it is still owned by proxy_rules."""
        current = ctx.options.intercept or None
        previous = self._intercept_set
        if desired == self._bp_filter and (previous is _UNSET or current == previous):
            return
        if previous is _UNSET and desired is not None and current == desired:
            self._bp_filter = desired
            self._intercept_set = desired
            return
        if previous is _UNSET and current is not None:
            ctx.log.warn("proxy_rules: mitmweb intercept already has a UI/config filter — leaving it alone")
            return
        if previous is not _UNSET and current is not None and current != previous:
            ctx.log.warn("proxy_rules: mitmweb intercept was changed in the UI — leaving it alone")
            return
        if previous is _UNSET and desired is None:
            self._bp_filter = desired
            return
        if current != desired:
            ctx.options.update(intercept=desired)
        self._bp_filter = desired
        self._intercept_set = desired
        ctx.log.info(f"proxy_rules: breakpoints {'set: ' + desired if desired else 'off'}")

    async def _pause_local(self, flow, phase):
        """Pause a call Rivis answers itself at a matching breakpoint (phase 'request': before the local answer,
        'response': after it, so the mock can be edited). Returns False when it was aborted while paused."""
        current = ctx.options.intercept or None
        if flow.intercepted or self._intercept_set is _UNSET or current is None or current != self._intercept_set:
            return True                                        # we do not own breakpoints right now
        url, method = flow.request.pretty_url, flow.request.method.upper()
        if any(rx.search(url) and (m is None or m == method) and (req if phase == "request" else resp)
               for rx, m, req, resp in getattr(self, "_local_breakpoints", [])):
            flow.intercept()
            await flow.wait_for_resume()
        return flow.error is None

    # ── hit counts ───────────────────────────────────────────────
    @property
    def hits_path(self):
        return os.path.join(os.path.dirname(os.path.abspath(os.path.expanduser(self.path))), "rule-hits.json")

    PARKED_HITS_MAX = 200

    def _sync_hits(self, sources):
        # R9-01: a rule that is only switched off keeps its count (parked by fingerprint) so switching it back on
        # resumes it; an edit changes the fingerprint and so still restarts the count.
        now, keep = time.time(), {}
        parked = self._parked_hits
        for index, source in enumerate(sources):
            if not isinstance(source, dict):
                continue
            name = source.get("name") or f"rule #{index + 1}"
            fp = rule_fingerprint(source)
            if not source.get("enabled", True):
                old = self.hits.get(name)
                if old and old.get("fp") == fp:
                    parked.pop((name, fp), None)
                    parked[(name, fp)] = old
                continue
            old = self.hits.get(name)
            if not (old and old.get("fp") == fp):
                old = parked.pop((name, fp), None)
            keep[name] = old if old and old.get("fp") == fp else {
                "fp": fp, "count": 0, "noop": 0, "noop_reason": None, "last": None, "since": now, "seen_at_since": self.calls_seen}
        while len(parked) > self.PARKED_HITS_MAX:
            parked.pop(next(iter(parked)))
        if keep.keys() != self.hits.keys() or any(keep[n] is not self.hits.get(n) for n in keep):
            self._hits_dirty = True
        self.hits = keep

    def _record(self, rule, changed=True, reason=None):
        h = self.hits.get(rule["name"])
        if h is None:
            return
        h["last"] = time.time()
        if changed:
            h["count"] += 1
        else:
            h["noop"] += 1
            h["noop_reason"] = reason
        self._hits_dirty = True
        self._hits_unflushed = True

    def _fired(self, flow, rule, suffix="", modified=True):
        _tag_rule(flow, rule, suffix, modified)
        self._record(rule)

    def hit_summary(self):
        return {"calls_seen": self.calls_seen, "rules": {n: {k: v for k, v in h.items() if k != "fp"} | {"calls_since": self.calls_seen - h["seen_at_since"]}
                                                          for n, h in self.hits.items()}}

    def _hits_doc(self):
        return {"written": time.time(), "pid": os.getpid(), "rules_file": self.path,
                **self.hit_summary(), "fingerprints": {n: h["fp"] for n, h in self.hits.items()}}

    # Hit counts are diagnostic: written atomically (a reader never sees half a file) but without fsync, and on the
    # proxy loop only the snapshot is taken — the file write runs in a worker thread, so a busy rule never stalls
    # other connections (review 0.9.7 #3: two fsyncs per rule-firing call ran on the event loop).
    def _write_hits(self, force=False):
        """Synchronous write; only for shutdown, where there is no loop left to hand the write to."""
        if not self._hits_dirty or (not force and time.monotonic() - self._hits_written < 0.5):   # R8D-07: was 2 s
            return
        try:
            atomic_json(self.hits_path, self._hits_doc(), durable=False)
            self._hits_dirty = False
            self._hits_unflushed = False
        except OSError as e:
            ctx.log.debug(f"proxy_rules: cannot write {self.hits_path}: {e}")
        self._hits_written = time.monotonic()

    async def _flush_hits(self, force=False):
        if self._hits_lock is None:
            self._hits_lock = asyncio.Lock()
        async with self._hits_lock:
            # a caller queued behind another write finds its hit already written: nothing left to do
            if not self._hits_dirty or (not force and time.monotonic() - self._hits_written < 0.5):   # R8D-07: was 2 s
                return
            doc = self._hits_doc()
            self._hits_dirty = False
            self._hits_unflushed = False
            try:
                await asyncio.get_running_loop().run_in_executor(None, lambda: atomic_json(self.hits_path, doc, durable=False))
            except OSError as e:
                self._hits_dirty = True
                ctx.log.debug(f"proxy_rules: cannot write {self.hits_path}: {e}")
            self._hits_written = time.monotonic()

    def _flush_hits_soon(self):
        """From a synchronous hook: write the hit file off the loop without waiting for it."""
        try:
            task = asyncio.get_running_loop().create_task(self._flush_hits(force=True))
        except RuntimeError:                      # no running loop (unit use): the poller or done() writes it
            return
        self._hits_tasks.add(task)
        task.add_done_callback(self._hits_tasks.discard)

    def done(self):
        self._write_hits(force=True)

    def _intercept_replay(self, flow):
        """mitmproxy's Intercept addon skips client replays; apply our owned filter to them."""
        if flow.is_replay != "request" or flow.intercepted:
            return
        current = ctx.options.intercept or None
        if not ctx.options.intercept_active or self._intercept_set is _UNSET \
                or current is None or current != self._intercept_set:
            return
        if flowfilter.match(current, flow):
            flow.intercept()

    def _matching(self, flow, actions):
        url, method = flow.request.pretty_url, flow.request.method.upper()
        for r in self.rules:
            if r.get("action") in actions and r["_re"].search(url) and r.get("_method") in (None, method):
                yield r

    def _throttled(self, flow):
        return self.throttle and (self.throttle_re is None or self.throttle_re.search(flow.request.pretty_url))

    async def requestheaders(self, flow: http.HTTPFlow):
        """Keep the loopback listener from becoming a relay into local/VPN networks.

        The threat (F-01) is a web page aiming the proxy port at a private address: an origin-form request, or DNS
        rebinding, sent straight to 127.0.0.1:PORT. Mitmproxy 12.2.3 normalizes absolute-form to origin-form before
        addon hooks, so for plain HTTP on the proxy port the boundary is enforced on the resolved destination. A page
        can also fetch through an HTTPS tunnel that trusts this CA; with --insecure, a rebound server's certificate is
        not checked, so all page-started requests need the same boundary. Simulator capture and the panel's own
        Repeat/Compose may reach private addresses: on a VPN the app's servers often resolve to them.
        """
        # R7B-02: the rules file is re-read here, at the first hook of every call and before mitmweb's own intercept
        # step: a 1 s stat throttle let the first calls after `rules add` / `breakpoint` slip through unblocked or
        # unpaused while the CLI already said ON. One stat per call costs microseconds.
        self._reload(force=True)
        host = flow.request.host
        plain = self._page_reachable(flow)
        insecure_page = getattr(ctx.options, "ssl_insecure", False) and self._insecure_page(flow)
        if not host or self._trusted_name(host) or not (plain or self._cross_site_page(flow) or insecure_page):
            return
        addresses = await self._resolve(host, flow.request.port)
        if addresses is None:
            # answer it here: letting mitmproxy look the name up again would reopen the rebinding window (a name that
            # fails once, then resolves to a private address)
            flow.response = http.Response.make(502, ("Rivis could not resolve %s.\n" % host).encode(),
                                               {"Content-Type": "text/plain"})
            return
        unsafe = []
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global:
                unsafe.append(address)
        if unsafe and await self._named_project_server(flow, host):
            return
        if unsafe:
            ctx.log.warn(f"proxy_rules: refused private upstream {host} -> {', '.join(sorted(unsafe))}; "
                         "use --allow-private-hosts for an intentional local test service")
            flow.response = http.Response.make(
                403, ("Private upstream destinations are blocked by Rivis for plain-HTTP proxy requests and for"
                      " web-page requests through the proxy (%s -> %s).\n"
                      "Apps' HTTPS calls are not affected. If this is your app's server, add its domain to your project, or"
                      " start Rivis with --allow-private-hosts 'REGEX' (for example '%s').\n"
                      % (host, ", ".join(sorted(unsafe)), re.escape(host))).encode(),
                {"Content-Type": "text/plain"})
            return
        if plain:
            self._pin(flow, addresses)
        elif insecure_page and flow.request.scheme == "https":
            # Pin HTTPS at connect time: changing request.host to the IP drops the hostname needed for upstream SNI.
            now = time.monotonic()
            self._https_pins = {key: value for key, value in self._https_pins.items() if now - value[0] < 60}
            key = (flow.client_conn.id, host.lower(), flow.request.port)
            self._https_pins[key] = (now, addresses)

    def server_connect(self, data):
        name, port = data.server.address
        try:
            ipaddress.ip_address(name.strip("[]"))
            return
        except ValueError:
            pass
        key = (data.client.id, name.lower(), port)
        entry = self._https_pins.get(key)
        if not entry:
            return
        if time.monotonic() - entry[0] >= 60:
            del self._https_pins[key]
            return
        data.server.address = (sorted(entry[1], key=lambda a: (":" in a, a))[0], port)
        if not data.server.sni:
            data.server.sni = name

    def client_disconnected(self, client):
        self._abandon_paused(client)
        self._https_pins = {key: value for key, value in self._https_pins.items() if key[0] != client.id}

    @staticmethod
    def _pin(flow, addresses):
        """Connect to the address that was checked. Otherwise mitmproxy looks the name up again to connect, and DNS
        that changes in between (rebinding) reaches a private address after all. The Host header keeps the name."""
        try:
            ipaddress.ip_address(flow.request.host.strip("[]"))
            return                                            # already an address
        except ValueError:
            pass
        host_header, name, port = flow.request.host_header, flow.request.host, flow.request.port
        if host_header is None:                               # HTTP/1.0 without Host: keep the name the app asked for
            default = {"http": 80, "https": 443}.get(flow.request.scheme)
            host_header = name if port == default else "%s:%d" % (name, port)
        flow.request.host = sorted(addresses, key=lambda a: (":" in a, a))[0]
        flow.request.host_header = host_header

    @staticmethod
    def _cross_site_page(flow):
        """A browser request started by a page of another site (e.g. in `rivis browser`, which trusts the Rivis CA).
        Through a proxy the browser cannot apply its own private-network protection, so Rivis does. Apps never send
        Sec-Fetch-Site; a typed URL is "none", a web app's own calls are "same-origin"/"same-site"."""
        if flow.is_replay or getattr(getattr(flow.client_conn, "proxy_mode", None), "type_name", "regular") == "local":
            return False          # Simulator capture: an app's web view (3DS, sign-in pages) reaches VPN hosts directly anyway
        return flow.request.headers.get("sec-fetch-site", "").strip().lower() == "cross-site"

    @staticmethod
    def _insecure_page(flow):
        """With upstream certificate checks off, a page's own HTTPS calls can also rebind to a private address.
        A typed URL has "none" and apps omit the header; neither is a page-started fetch."""
        if flow.is_replay or getattr(getattr(flow.client_conn, "proxy_mode", None), "type_name", "regular") == "local":
            return False
        return flow.request.headers.get("sec-fetch-site", "").strip().lower() in ("same-origin", "same-site", "cross-site")

    @staticmethod
    def _page_reachable(flow):
        """Could a web page have produced this request? Only a plain-HTTP request on the regular proxy listener."""
        if flow.is_replay:                                    # Repeat / Compose from the signed-in panel
            return False
        if flow.client_conn.tls_established:                  # CONNECT + TLS with the Rivis CA: never a page's fetch
            return False
        mode = getattr(flow.client_conn, "proxy_mode", None)
        return getattr(mode, "type_name", "regular") == "regular"   # local (simulator) capture is not a listener

    def _trusted_name(self, name):
        """A hostname (never an IP literal) the user or the project allows on private addresses."""
        if not name:
            return False
        try:
            ipaddress.ip_address(name.strip("[]"))
            literal = True
        except ValueError:
            literal = False
        if self.private_hosts_re and self.private_hosts_re.fullmatch(name):
            return True                                   # explicit --allow-private-hosts (may name an IP on purpose)
        return not literal and bool(self.project_hosts_re and self.project_hosts_re.fullmatch(name.rstrip(".")))

    async def _resolve(self, host, port):
        """Addresses for host, without blocking the proxy: a slow resolver must not stall every other call (A6)."""
        now = time.monotonic()
        cached = self._address_cache.get(host)
        if cached and now - cached[0] < 60:
            return cached[1]
        try:
            rows = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM),
                                          DNS_TIMEOUT)
        except (OSError, asyncio.TimeoutError):
            return None
        addresses = {row[4][0] for row in rows}
        self._address_cache[host] = (now, addresses)
        return addresses

    async def _named_project_server(self, flow, ip):
        """Simulator capture records the server's IP as the destination; its name is in the Host header / TLS SNI.
        Allowed only when that name is trusted AND really resolves to the address the app connected to — so no call
        to some other internal machine can borrow a project name."""
        try:
            ipaddress.ip_address(ip.strip("[]"))
        except ValueError:
            return False                                      # a hostname destination was judged by _trusted_name
        names = {flow.request.pretty_host, getattr(flow.client_conn, "sni", None)} - {None, "", ip}
        for name in names:
            if self._trusted_name(name):
                resolved = await self._resolve(name, flow.request.port)
                if resolved and ip.strip("[]") in resolved:
                    return True
        return False

    @staticmethod
    def _body(r):
        if r.get("body_file"):
            with open(os.path.expanduser(r["body_file"]), "rb") as f:
                return f.read()
        b = r.get("body", "")
        return (json.dumps(b) if isinstance(b, (dict, list)) else str(b)).encode()

    # ── request side ─────────────────────────────────────────────
    async def request(self, flow: http.HTTPFlow):
        self._reload()
        self.calls_seen += 1
        if self.hits:
            self._hits_dirty = True        # "ON but never matched" depends on calls seen, not only on hits
        answers_locally = any(True for _ in self._matching(flow, {"respond", "map_local"}))
        if not answers_locally:
            self._intercept_replay(flow)                       # Repeat: mitmweb's Intercept skips client replays
        elif not await self._pause_local(flow, "request"):
            return                                             # aborted at the breakpoint
        if self.loss and (self.throttle_re is None or self.throttle_re.search(flow.request.pretty_url)) \
                and random.random() * 100 < self.loss:
            _tag(flow, f"loss {self.loss:g}%")
            flow.kill()
            return
        for r in self._matching(flow, {"block"}):
            self._fired(flow, r, modified=False)
            self._flush_hits_soon()                      # a killed call has no response hook
            flow.kill()
            return
        for r in self._matching(flow, {"map_remote"}):
            new = r["_replace"].sub(r["with"], flow.request.pretty_url)
            if new != flow.request.pretty_url:
                bad = remote_url_problem(new)
                if bad:      # R2A-11: not a traceback and not a silent pass-through to the original server
                    _tag(flow, f"rule:{r['name']} FAILED: {bad}")
                    ctx.log.warn(f"proxy_rules: {r['name']}: map_remote result {bad}")
                    flow.response = http.Response.make(502, f"Rivis: rule '{r['name']}' (map_remote) produced an unusable URL: {bad}".encode(),
                                                       {"Content-Type": "text/plain; charset=utf-8"})
                    flow.metadata["proxy_local"] = True
                    return
                flow.request.url = new
                self._fired(flow, r, modified=False)
            else:
                self._record(r, changed=False, reason=f"matched, but replace={r['replace']!r} changed nothing in the URL "
                                                       f"(replace is the URL pattern, with is the replacement)")
        if self.no_cache and not answers_locally:
            _no_cache_request(flow)
        for r in self._matching(flow, {"set_header"}):
            if r.get("side", "request") == "request":
                if r.get("value") is None:
                    flow.request.headers.pop(r["header"], None)
                else:
                    flow.request.headers[r["header"]] = str(r["value"])
                self._fired(flow, r, modified=False)
        for r in self._matching(flow, {"delay"}):
            self._fired(flow, r, f" +{r.get('ms', 0)}ms", modified=False)
            await asyncio.sleep(r.get("ms", 0) / 1000)
        if self._throttled(flow):
            lat, jit, _down, up, _l, _d = self.throttle
            # one latency sample per call (± jitter), half before the request, half after the response
            sample = max(0.0, lat + random.uniform(-jit, jit))
            flow.metadata["proxy_latency"] = sample
            size = len(flow.request.raw_content or b"")
            await asyncio.sleep(sample / 2000 + ((size * 8 / 1000) / up if up else 0))
        for r in self._matching(flow, {"respond", "map_local"}):
            try:
                if r["action"] == "map_local":
                    path = os.path.expanduser(r["file"])
                    with open(path, "rb") as f:
                        body = f.read()
                    ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
                else:
                    body = self._body(r)
                    ctype = "application/json"
                headers = [list(pair) for pair in (r.get("headers") or [])]
                if not any(k.lower() == "content-type" for k, _v in headers):
                    headers.insert(0, ["Content-Type", ctype])
                origin = flow.request.headers.get("Origin")
                if origin and not any(k.lower() == "access-control-allow-origin" for k, _v in headers):
                    # R4B-02: a local answer never reaches the API that normally supplies its CORS policy.
                    headers.append(["Access-Control-Allow-Origin", origin])
                    for pair in headers:
                        if pair[0].lower() == "access-control-allow-credentials":
                            pair[1] = "true"
                            break
                    else:
                        headers.append(["Access-Control-Allow-Credentials", "true"])
                    for pair in headers:
                        if pair[0].lower() == "vary":
                            if "origin" not in [v.strip().lower() for v in pair[1].split(",")]:
                                pair[1] += ", Origin"
                            break
                    else:
                        headers.append(["Vary", "Origin"])
                headers = http.Headers([(k.encode("ascii"), v.encode("utf-8")) for k, v in headers])
                flow.response = http.Response.make(int(r.get("status", 200)), body, headers)
                _no_body_for(flow.response)
                flow.metadata["proxy_local"] = True     # answered locally: collections must not record it
                self._fired(flow, r, modified=False)
                self.failed_rules.pop(r["name"], None)
            except Exception as e:
                # R2A-02: a mock that cannot be served must never fall through to the REAL server (a mocked payment call
                # would reach the backend); answer 502 naming the rule and file, and flag it for rules list/panel/doctor
                what = r.get("file") or r.get("body_file") or "its body"
                msg = f"Rivis: rule '{r['name']}' ({r['action']}) cannot be served: {what}: {e}"
                self.failed_rules[r["name"]] = f"{what}: {e}"
                _tag(flow, f"rule:{r['name']} FAILED: {e}")
                ctx.log.warn(f"proxy_rules: {msg}")
                flow.response = http.Response.make(502, msg.encode("utf-8", "replace"),
                                                   {"Content-Type": "text/plain; charset=utf-8"})
                flow.metadata["proxy_local"] = True
            break
        if answers_locally and flow.response is not None:
            await self._pause_local(flow, "response")          # the mock can still be edited before the app gets it

    # ── response side ────────────────────────────────────────────
    def responseheaders(self, flow: http.HTTPFlow):
        if self.no_cache and not flow.metadata.get("proxy_local"):
            _no_cache_response(flow)       # here, not in response: streamed bodies send their headers right after
        if (flow.response.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower() == "text/event-stream":
            # R4B-01: the body may never finish, so buffering it would hide every event from the client.
            flow.response.stream = True
            flow.metadata["proxy_sse_stream"] = True

    async def response(self, flow: http.HTTPFlow):
        if flow.metadata.get("proxy_sse_stream"):
            return                         # R4B-01: streamed bytes are unavailable for response edits.
        if flow.response.stream:
            # R10-01: a body over stream_large_bodies went straight to the app and was not kept, so there is nothing
            # left to edit, and the status line has already been sent.
            _tag(flow, "large body streamed, not kept")
            return
        self._reload()
        self._intercept_replay(flow)
        for r in self._matching(flow, {"status"}):
            flow.response.status_code = int(r["status"])
            flow.response.reason = status_codes.RESPONSES.get(flow.response.status_code, "")   # not "503 OK"
            if r.get("body") is not None or r.get("body_file"):
                flow.response.content = self._body(r)
            _no_body_for(flow.response)
            self._fired(flow, r)
        for r in self._matching(flow, {"json_patch"}):
            try:
                raw = flow.response.get_text()
                if not raw:
                    raise ValueError("response is empty")
                doc = json.loads(raw)
                missing = []
                for path, value in r.get("set", {}).items():
                    try:
                        _set_path(doc, path, value)
                    except KeyError:
                        missing.append(path)
                flow.response.text = json.dumps(doc)
                self._fired(flow, r, f" (missing: {', '.join(missing)})" if missing else "")
            except (TypeError, ValueError) as e:
                _tag_rule(flow, r, " skipped: response is not JSON", modified=False)
                self._record(r, changed=False, reason="matched, but the response was not JSON")
                ctx.log.warn(f"proxy_rules: {r['name']}: json_patch left response unchanged: {e}")
        for r in self._matching(flow, {"set_header"}):
            if r.get("side") == "response":
                if r.get("value") is None:
                    flow.response.headers.pop(r["header"], None)
                else:
                    flow.response.headers[r["header"]] = str(r["value"])
                self._fired(flow, r)
        if self._throttled(flow):
            lat, _j, down, _u, _l, delay = self.throttle
            sample = flow.metadata.get("proxy_latency", lat)
            size = len(flow.response.raw_content or b"")
            wait = sample / 2000 + delay / 1000 + ((size * 8 / 1000) / down if down else 0)
            _tag(flow, f"throttle +{int(wait * 1000)}ms")
            await asyncio.sleep(wait)
        if self._hits_unflushed:
            await self._flush_hits(force=True)           # `rules list` after the response must see applied rules

    def error(self, flow: http.HTTPFlow):
        msg = flow.error.msg if flow.error else None
        text = upstream_tls_text(msg, flow.request.pretty_host if flow.request else "?", PRODUCT["cli"])
        if text:
            table = _error_texts()
            if len(table) > 256:              # never grows: an entry is taken back as soon as its 502 page is built
                table.clear()
            table[msg] = text
            flow.error.msg = text             # the Error tab says the same as the app's 502 page
        if self._hits_unflushed:
            self._flush_hits_soon()                      # request-side rule on an upstream failure


addons = [ProxyRules()]
