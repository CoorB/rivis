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
from proxy_common import (ACTION_REQUIREMENTS, ACTIONS, PROFILE_VALUES, STATE_ROOT, breakpoints, project_profile,
                          migrate_rules, rule_file_path, tls_config, tls_options, user_regex)

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
    m = re.fullmatch(r"(\d+)ms(?:/(\d+)kbps)?", spec)
    if m:
        return int(m.group(1)), 0, int(m.group(2) or 0), 0, 0, 0
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


def _confdir():
    try:
        return ctx.options.confdir
    except (AttributeError, KeyError):
        return None


def _compile_rule(source, state_dir, fallback_name=None):
    if not isinstance(source, dict):
        raise TypeError("rule must be an object")
    rule = dict(source)
    rule["name"] = rule.get("name") or fallback_name or "unnamed"
    action = rule.get("action")
    if action not in ACTIONS:
        raise ValueError(f"unknown action '{action}'")
    missing = [key for key in ACTION_REQUIREMENTS[action] if key not in rule]
    if missing:
        raise ValueError(f"action '{action}' needs: {', '.join(missing)}")
    rule["_re"] = user_regex(rule.get("match", "."))
    if rule.get("method") is not None and not isinstance(rule["method"], str):
        raise TypeError("method must be text")
    if action == "map_remote":
        rule["_replace"] = user_regex(rule["replace"])
        if not isinstance(rule["with"], str):
            raise TypeError("map_remote with must be text")
    elif action == "respond":
        int(rule.get("status", 200))
        if rule.get("body_file"):
            rule["body_file"] = rule_file_path(state_dir, rule["body_file"], "body_file", (_confdir(),))
    elif action == "status":
        int(rule["status"])
        if rule.get("body_file"):
            rule["body_file"] = rule_file_path(state_dir, rule["body_file"], "body_file", (_confdir(),))
    elif action == "delay":
        rule["ms"] = float(rule["ms"])
        if rule["ms"] < 0:
            raise ValueError("delay ms must not be negative")
    elif action == "json_patch":
        if not isinstance(rule["set"], dict) or not all(isinstance(k, str) for k in rule["set"]):
            raise TypeError("json_patch set must be an object with text paths")
    elif action == "set_header":
        if not isinstance(rule["header"], str):
            raise TypeError("set_header header must be text")
        if rule.get("side", "request") not in ("request", "response"):
            raise ValueError("set_header side must be request or response")
    elif action == "map_local":
        if not isinstance(rule["file"], str):
            raise TypeError("map_local file must be text")
        # A shared rules file must not turn the proxy into a reader for arbitrary
        # local files: confine to the project state dir (symlinks resolved) unless the
        # user trusted that file on this machine, or skip the rule with this error.
        rule["file"] = rule_file_path(state_dir, rule["file"], "map_local file", (_confdir(),))
    if "headers" in rule:
        headers = rule["headers"]
        if isinstance(headers, dict):
            rule["headers"] = [[str(k), str(v)] for k, v in headers.items()]
        elif isinstance(headers, list) and all(isinstance(x, (list, tuple)) and len(x) == 2 for x in headers):
            rule["headers"] = [[str(k), str(v)] for k, v in headers]
        else:
            raise TypeError("headers must be an object or name/value pairs")
    return rule


class ProxyRules:
    def __init__(self):
        self.path = DEFAULT_FILE
        self.mtime = None
        self.checked = 0.0
        self.rules = []
        self.throttle = None        # (latency, jitter, down, up, loss, delay) or None
        self.throttle_re = None
        self.loss = 0
        self.skipped_rules = []
        self.last_good_cfg = {"rules": []}
        self._bp_filter = _UNSET
        self._intercept_set = _UNSET
        self.tls = tls_config({})
        self._tls_set = _UNSET
        self.private_hosts_re = None
        self.project_hosts_re = None
        self._address_cache = {}

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
            self._set_tls({})
            self.rules, self.throttle, self.loss, self.mtime = [], None, 0, None
            self.skipped_rules = []
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
            self._set_tls(cfg)
            self.rules, self.throttle = rules, throttle
            self.throttle_re, self.loss = throttle_re, loss
            self.tls = tls
            self.skipped_rules = skipped
            self.last_good_cfg = cfg
            self.mtime = mtime
            names = ", ".join(r.get("name", "?") for r in rules) or "none"
            ctx.log.info(f"proxy_rules: loaded {self.path} — active rules: {names}; "
                         f"throttle: {cfg.get('throttle', 'off')}; loss: {self.loss}%; TLS: {tls['mode']}")
        except Exception as e:   # keep the previous good rules on a bad edit
            ctx.log.warn(f"proxy_rules: cannot load {self.path}: {e} — keeping previous rules")
            self.mtime = mtime

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
        url, method = flow.request.pretty_url, flow.request.method
        for r in self.rules:
            if r.get("action") in actions and r["_re"].search(url) \
                    and r.get("method", method).upper() == method:
                yield r

    def _throttled(self, flow):
        return self.throttle and (self.throttle_re is None or self.throttle_re.search(flow.request.pretty_url))

    def requestheaders(self, flow: http.HTTPFlow):
        """Keep the loopback listener from becoming a relay into local/VPN networks.

        Mitmproxy 12.2.3 normalizes absolute-form to origin-form before addon hooks, so
        the original request-target form cannot be distinguished here.  Enforcing the
        security boundary on the resolved destination closes both the origin-form and
        DNS-rebinding variants. Private test services require an explicit allow-list.
        """
        host = flow.request.host
        if not host or self._trusted_name(host):
            return
        addresses = self._resolve(host, flow.request.port)
        if addresses is None:
            return  # mitmproxy reports the normal DNS error; no destination was reached
        unsafe = []
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global:
                unsafe.append(address)
        if unsafe and self._named_project_server(flow, host):
            return
        if unsafe:
            ctx.log.warn(f"proxy_rules: refused private upstream {host} -> {', '.join(sorted(unsafe))}; "
                         "use --allow-private-hosts for an intentional local test service")
            flow.response = http.Response.make(403, b"Private upstream destinations are blocked by Rivis.\n",
                                               {"Content-Type": "text/plain"})

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

    def _resolve(self, host, port):
        now = time.monotonic()
        cached = self._address_cache.get(host)
        if cached and now - cached[0] < 60:
            return cached[1]
        try:
            addresses = {row[4][0] for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
        except OSError:
            return None
        self._address_cache[host] = (now, addresses)
        return addresses

    def _named_project_server(self, flow, ip):
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
                resolved = self._resolve(name, flow.request.port)
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
            _tag_rule(flow, r, modified=False)
            flow.kill()
            return
        for r in self._matching(flow, {"map_remote"}):
            new = r["_replace"].sub(r["with"], flow.request.pretty_url)
            if new != flow.request.pretty_url:
                flow.request.url = new
                _tag_rule(flow, r, modified=False)
        for r in self._matching(flow, {"set_header"}):
            if r.get("side", "request") == "request":
                if r.get("value") is None:
                    flow.request.headers.pop(r["header"], None)
                else:
                    flow.request.headers[r["header"]] = str(r["value"])
                _tag_rule(flow, r, modified=False)
        for r in self._matching(flow, {"delay"}):
            _tag_rule(flow, r, f" +{r.get('ms', 0)}ms", modified=False)
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
                headers = list(r.get("headers") or [])
                if not any(k.lower() == "content-type" for k, _v in headers):
                    headers.insert(0, ["Content-Type", ctype])
                headers = http.Headers([(k.encode("ascii"), v.encode("utf-8")) for k, v in headers])
                flow.response = http.Response.make(int(r.get("status", 200)), body, headers)
                flow.metadata["proxy_local"] = True     # answered locally: collections must not record it
                _tag_rule(flow, r, modified=False)
            except Exception as e:
                _tag(flow, f"rule:{r['name']} FAILED: {e}")
                ctx.log.warn(f"proxy_rules: {r['name']}: {e}")
            break
        if answers_locally and flow.response is not None:
            await self._pause_local(flow, "response")          # the mock can still be edited before the app gets it

    # ── response side ────────────────────────────────────────────
    async def response(self, flow: http.HTTPFlow):
        self._reload()
        self._intercept_replay(flow)
        for r in self._matching(flow, {"status"}):
            flow.response.status_code = int(r["status"])
            flow.response.reason = status_codes.RESPONSES.get(flow.response.status_code, "")   # not "503 OK"
            if r.get("body") is not None or r.get("body_file"):
                flow.response.content = self._body(r)
            _tag_rule(flow, r)
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
                _tag_rule(flow, r, f" (missing: {', '.join(missing)})" if missing else "")
            except (TypeError, ValueError) as e:
                _tag_rule(flow, r, " skipped: response is not JSON", modified=False)
                ctx.log.warn(f"proxy_rules: {r['name']}: json_patch left response unchanged: {e}")
        for r in self._matching(flow, {"set_header"}):
            if r.get("side") == "response":
                if r.get("value") is None:
                    flow.response.headers.pop(r["header"], None)
                else:
                    flow.response.headers[r["header"]] = str(r["value"])
                _tag_rule(flow, r)
        if self._throttled(flow):
            lat, _j, down, _u, _l, delay = self.throttle
            sample = flow.metadata.get("proxy_latency", lat)
            size = len(flow.response.raw_content or b"")
            wait = sample / 2000 + delay / 1000 + ((size * 8 / 1000) / down if down else 0)
            _tag(flow, f"throttle +{int(wait * 1000)}ms")
            await asyncio.sleep(wait)


addons = [ProxyRules()]
