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
import os
import re
import secrets
import subprocess
import sys
import tempfile
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from mitmproxy import ctx, http
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
from proxy_common import (ACTION_REQUIREMENTS, ACTIONS, PANEL_PROFILES, PRODUCT, SAFE_NAME, STATE_ROOT, atomic_json,
                          atomic_write_bytes, atomic_write_text, breakpoints, commit_temp_file,
                          confined_path, migrate_collection, migrate_rules, project_profile,
                          project_profiles, project_state, tls_config, tls_covering, tls_update,
                          user_regex)
from proxy_codegen import TARGETS, generate
import proxy_redact
import devices
importlib.reload(devices)
from proxy_compose import ComposerStore, normalize_request
from proxy_scripts import (decode_grpc_frames, decode_protobuf, detect_graphql, find_jwts)

DEFAULT_STATE = os.path.join(STATE_ROOT, "projects", "default")
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
MAX_PANEL_REQUEST_BYTES = 8 * 1024 * 1024
MAX_PANEL_TEXT_BYTES = 2 * 1024 * 1024
MAX_PANEL_VALUES = 10000
MAX_PANEL_DEPTH = 16


def wildcard_regex(host, path):
    """FRTMProxy-style host/path with * and ? wildcards → URL regex used by the rules engine."""
    def wc(t, star):
        return "".join(star if c == "*" else "." if c == "?" else re.escape(c) for c in t)
    host = (host or "").strip().lower()
    path = (path or "/").strip() or "/"
    full_url = host.startswith(("http://", "https://"))
    if full_url:                             # a full URL pasted into the host box
        parsed = urlsplit(host)
        host = parsed.netloc
        path = parsed.path or path
    if not host:
        raise PanelError("host is required")
    if full_url:
        path = path.split("?", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
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


class ProxyPanel:
    def __init__(self):
        self._device_jobs = devices.Jobs()
        self.project_only = False
        self.show_dns = False
        self.focused_host = None
        self.graphql_operation = None
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
            if throttle not in {p["id"] for p in PROFILES} and not re.fullmatch(r"\d+ms(/\d+kbps)?", throttle):
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
        atomic_json(self.rules_path, migrate_rules(cfg))
        # Apply now, not on the proxy's next once-a-second poll: a breakpoint set in the panel must catch the very next
        # call (on a quiet app that is the only call; seen with the NEO app, 2026-10-15).
        for addon in self._addons():
            if addon.__class__.__name__ == "ProxyRules":
                try:
                    addon.mtime = None
                    addon._reload(force=True)
                except Exception as e:  # noqa: BLE001 - the file is saved; the proxy still picks it up within a second
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
                raise PanelError("text value exceeds the 2 MiB panel limit")
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

    # ── mock files: only ever <active-project>/mocks/<safe-name>.json ──────────
    @staticmethod
    def mock_path(name):
        if not SAFE_NAME.fullmatch(name or ""):
            raise PanelError("bad mock name")
        return os.path.join(MOCK_DIR, name + ".json")

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
            "rules_outside": self._rules_outside(cfg),
            "throttle": cfg.get("throttle", "off"),
            "throttle_match": cfg.get("throttle_match", ""),
            "loss": cfg.get("loss", 0),
            "manual": {k: (cfg.get("manual") or {}).get(k, 0) for k in MANUAL_KEYS},
            "profiles": PROFILES,
            "breakpoints": bps,
            "paused": self.paused(),
            "collections": self.collections(cfg),
            "sessions": self.sessions(),
            "skipped_rules": self.skipped_rules(),
            "scripts": self.scripts(cfg),
            "script_status": self.script_status(),
            "retention": self.retention_state(),
            "focus_host": self.focused_host,
            "project_only": self.project_only,
            "show_dns": self.show_dns,
            "graphql_operation": self.graphql_operation,
            "tls": tls,
            "composer": self.composer_state(),
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

    def skipped_rules(self):
        for addon in self._addons():
            if addon.__class__.__name__ == "ProxyRules":
                return list(getattr(addon, "skipped_rules", []))
        return []

    def script_status(self):
        for addon in self._addons():
            if addon.__class__.__name__ == "ProxyScripts":
                return {"node": bool(getattr(addon, "node", None)),
                        "node_message": None if getattr(addon, "node", None) else "Node.js not installed — JS scripts disabled",
                        "errors": dict(getattr(addon, "last_errors", {}))}
        return {"node": False, "node_message": "Scripting add-on is not loaded", "errors": {}}

    def retention_state(self):
        for addon in self._addons():
            if addon.__class__.__name__ == "ProxyRetention":
                return {"limit": int(ctx.options.proxy_max_flows), "trimmed": int(getattr(addon, "trimmed", 0))}
        return {"limit": 5000, "trimmed": 0}

    def release_held(self, cfg, changed):
        """A breakpoint that was deleted or switched off lets go of the calls it is holding (unless another still holds them)."""
        def hits(bp, f, phase):
            if bp.get("enabled") is False or not bp.get(phase) or (bp.get("method") and bp["method"] != f.request.method):
                return False
            try:
                return bool(user_regex(bp.get("match") or ".").search(f.request.pretty_url))
            except re.error:
                return False
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
        return base

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

    def _write_view_filter(self):
        self._panel_view_filter = self.view_filter()
        ctx.options.update(view_filter=self._panel_view_filter)

    # ── paused (intercepted) calls ─────────────────────────────────────────────
    @staticmethod
    def all_flows():
        v = ctx.master.view
        return list(getattr(v, "_store", {}).values()) or list(v)

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
        # host + path, query string ignored, anchored on the path end
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
        out["note"] = ("Applies to new connections within a second — no restart. Connections that are "
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
        if sni:
            return sni
        address = getattr(server, "address", None)
        return address[0] if address else ""

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
        return {"method": r.method, "url": r.pretty_url, "headers": headers, "body": body}

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
                    body, mode = json.dumps(json.loads(text), indent=2, ensure_ascii=False), "json"
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
        want = devices.ca_sha256(os.path.join(os.path.expanduser(ctx.options.confdir), "mitmproxy-ca-cert.pem"))
        pins = os.path.join(HERE, "android", "magisk.pins")
        version = ""
        try:
            version = next((l.split("=", 1)[1].strip() for l in open(pins) if l.startswith("MAGISK_VERSION=")), "")
        except OSError:
            pass
        magisk = os.environ.get("RIVIS_MAGISK_DIR") or os.path.join(os.path.dirname(os.path.dirname(HERE)), "magisk-" + version)
        adb = devices.adb_path()
        return {"ios": devices.ios_devices(want),
                "android": devices.android_devices(adb, want, STATE_ROOT, self._proxy_port()),
                "magisk": bool(version) and os.path.isdir(magisk), "job": self._device_jobs.summary()}

    # ── actions ───────────────────────────────────────────────────────────────
    def act(self, op, a):
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
        if op == "device_job":
            return {"job": self._device_jobs.summary()}
        if op == "device_setup":
            try:
                argv = devices.setup_argv(a.get("platform"), str(a.get("target") or ""), bool(a.get("consent")))
                label = "%s %s" % ({"ios": "iOS", "android": "Android"}[a["platform"]], a.get("name") or a.get("target"))
                return {"id": self._device_jobs.start(argv, label)}
            except (ValueError, KeyError, RuntimeError) as e:
                raise PanelError(str(e))
        cfg = self.load_cfg()
        if op == "viewer":
            return self._flow_viewer(self.flow(a["flow_id"]))
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
        elif op == "toggle":
            self.find(cfg, a["name"])["enabled"] = bool(a["enabled"])
            self.save_cfg(cfg)
        elif op == "delete":
            r = self.find(cfg, a["name"])
            cfg["rules"].remove(r)
            self.save_cfg(cfg)
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
            cfg["rules"].append(r)
            self.save_cfg(cfg)
        elif op == "mock":          # Map Local from the selected call
            f = self.flow(a["flow_id"])
            match = self.flow_regex(f)
            for r in cfg["rules"]:   # one mock per endpoint: reopen it instead of duplicating
                if r.get("action") == "map_local" and r.get("match") == match and r.get("method") == f.request.method:
                    r["enabled"] = True
                    self.save_cfg(cfg)
                    return {"name": r["name"], "existing": True}
            name = self.unique(cfg, a.get("name") or self.default_name(f, "mock"))
            path = self.mock_path(name)
            os.makedirs(MOCK_DIR, exist_ok=True)
            # a call that never got an answer (server down, unreachable) is mocked from an empty JSON template
            body = (f.response.get_content(strict=False) or b"") if f.response else b"{}\n"
            try:   # pretty-print JSON so it is easy to edit
                body = (json.dumps(json.loads(body), indent=2, ensure_ascii=False) + "\n").encode()
            except (ValueError, RecursionError):
                pass
            atomic_write_bytes(path, body)
            r = {"name": name, "enabled": True, "match": self.flow_regex(f), "method": f.request.method,
                 "action": "map_local", "file": path, "status": f.response.status_code if f.response else 200,
                 "note": f"from {f.request.method} {f.request.pretty_url[:120]}"}
            cfg["rules"].append(r)
            self.save_cfg(cfg)
            return {"name": name}
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
            for x in cfg["rules"]:   # same quick action on the same endpoint: update it, don't stack copies
                if x.get("match") == r["match"] and x.get("method") == r["method"] and x.get("action") == r["action"]:
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
                label = f.request.pretty_host + f.request.path.split("?")[0]
            else:
                match = wildcard_regex(a.get("host"), a.get("path"))
                method = (a.get("method") or "").upper() or None
                label = (a.get("host") or "") + (a.get("path") or "/")
            if not (a.get("request") or a.get("response")):
                raise PanelError("pick Request, Response or both")
            bps = breakpoints(cfg, migrate=True)
            for b in bps:                 # same endpoint+method: update phases instead of stacking copies
                if b.get("match") == match and b.get("method") == method:
                    b.update(request=bool(a.get("request")), response=bool(a.get("response")), enabled=True)
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
                    self.save_cfg(cfg)
                    return {"resumed": self.release_held(cfg, [before])}
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
            self.save_cfg(cfg)
            return {"resumed": self.release_held(cfg, gone)}
        elif op == "paused_get":
            f = self.flow(a["id"])
            if not f.intercepted:
                raise PanelError("that call is not paused any more")
            body, ok = self._text(f.request)
            out = {"id": f.id, "phase": "response" if f.response else "request",
                   "method": f.request.method, "url": f.request.pretty_url,
                   "req_headers": [[k, v] for k, v in f.request.headers.items(multi=True)],
                   "req_body": body, "req_body_editable": ok}
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
                    hdr = lambda rows: mhttp.Headers([(str(k).encode(), str(v).encode()) for k, v in rows if str(k).strip()])
                    if f.response:
                        if "status" in e:
                            f.response.status_code = http_status(e["status"])
                        if "headers" in e:
                            f.response.headers = hdr(e["headers"])
                        if e.get("body") is not None:
                            f.response.text = e["body"]
                    else:
                        if e.get("method"):
                            f.request.method = e["method"].upper()
                        if e.get("url"):
                            f.request.url = e["url"]
                        if "headers" in e:
                            f.request.headers = hdr(e["headers"])
                        if e.get("body") is not None:
                            f.request.text = e["body"]
                    tag = "edited at breakpoint"
                else:
                    tag = "breakpoint: skipped (sent unchanged)"
                f.comment = (f.comment + " | " if f.comment else "") + tag
                f.resume()
            ctx.master.view.update([f])
        elif op == "profile":
            pid = a.get("id", "off")
            if pid not in {p["id"] for p in PROFILES}:
                raise PanelError("unknown profile")
            cfg["throttle"] = pid
            cfg["loss"] = 0                  # the profile's own loss applies
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
            name = (a.get("name") or "").strip() or re.sub(r"[^A-Za-z0-9._-]", "-",
                    "mock-" + ((a.get("path") or "/").strip("/").split("/")[-1] or a.get("host", "x")))[:60]
            name = self.unique(cfg, name)
            os.makedirs(MOCK_DIR, exist_ok=True)
            path = self.mock_path(name)
            atomic_write_text(path, a.get("body") or "{}\n")
            r = {"name": name, "enabled": True, "match": wildcard_regex(a.get("host"), a.get("path")),
                 "action": "map_local", "file": path, "status": http_status(200 if a.get("status") in (None, "") else a["status"]),
                 "headers": {"Content-Type": "application/json"},
                 "note": f"manual: {a.get('host')}{a.get('path') or '/'}"}
            if a.get("method"):
                r["method"] = a["method"].upper()
            self.validate(r)
            cfg["rules"].append(r)
            self.save_cfg(cfg)
            return {"name": name}
        elif op == "view":
            if a.get("project") is not None:
                project_profile(a["project"])  # validate before changing the view
                self.view_project = a["project"]
            self.project_only = bool(a.get("project_only"))
            self.show_dns = bool(a.get("show_dns"))
            self._write_view_filter()
        elif op == "filter_check":     # the list filter is evaluated here: an invalid one closes mitmweb's websocket, so the panel asks first
            from mitmproxy import flowfilter
            text = str(a.get("filter") or "").strip()
            if not text:                   # empty = no filter, which is always valid
                return {"ok": True}
            try:
                flowfilter.parse(text)
            except ValueError as e:
                return {"ok": False, "error": str(e).replace("Invalid filter expression: ", "")[:200]}
            return {"ok": True}
        elif op == "focus_host":       # "show only this host" / clear it
            host = a.get("host") or None
            if host is not None and not (isinstance(host, str) and HOST_NAME.fullmatch(host)):
                raise PanelError("host: a hostname or IP address")   # F-16: it becomes part of a filter expression
            self.focused_host = host
            self._write_view_filter()
        elif op == "export":           # Copy URL / Copy cURL
            f = self.flow(a["flow_id"])
            if a.get("fmt") == "url":
                return {"text": f.request.pretty_url}
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
            if e.get("method"):
                nf.request.method = e["method"].upper()
            if e.get("url"):
                nf.request.url = e["url"]
            if "headers" in e:
                nf.request.headers = mhttp.Headers([(str(k).encode(), str(v).encode()) for k, v in e["headers"] if str(k).strip()])
            if e.get("body") is not None:
                nf.request.text = e["body"]
            nf.comment = "edit & retry of " + f.request.method + " " + f.request.path[:60]
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
            flows = [f for f in self.all_flows() if not getattr(f, "intercepted", False)]
            if a.get("visible_only"):
                vis = {f.id for f in ctx.master.view}
                flows = [f for f in flows if f.id in vis]
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
            from mitmproxy import io as mio
            fpath, _ = self.sess_paths(a["name"])
            with open(fpath, "rb") as fh:
                flows = list(mio.FlowReader(fh).stream())
            if a.get("replace"):
                ctx.master.view.clear()
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
            from mitmproxy import io as mio
            fpath, _ = self.sess_paths(a["name"])
            with open(fpath, "rb") as fh:
                flows = [f for f in mio.FlowReader(fh).stream() if isinstance(f, http.HTTPFlow) and f.response]
            entries = []
            for f in flows:
                raw = f.response.get_content(strict=False) or b""
                try:
                    body = {"text": raw.decode("utf-8")}
                except UnicodeDecodeError:
                    import base64
                    body = {"b64": base64.b64encode(raw).decode()}
                entries.append({"method": f.request.method, "scheme": f.request.scheme, "host": f.request.pretty_host,
                                "path": f.request.path.split("?")[0],
                                "query": f.request.path.split("?", 1)[1] if "?" in f.request.path else "",
                                "status": f.response.status_code,
                                "headers": [[k, v] for k, v in f.response.headers.items(multi=True)],
                                "recorded_at": f.request.timestamp_start, **body})
            return self._har_reply(self.to_har({"entries": entries}), a)
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
            name = (a.get("name") or "").strip()
            self.coll_file(name)
            self.flush_collection(name, forget=True)
            har = a.get("har") or {}
            entries = self.from_har(har)
            if not entries:
                raise PanelError("no usable entries in that HAR")
            self._write_coll({"name": name, "created": __import__("time").time(), "entries": entries})
            return {"count": len(entries)}
        elif op == "mockfile_get":
            r = self.find(cfg, a["name"])
            if r.get("action") != "map_local":
                raise PanelError("not a Map Local rule")
            path = os.path.realpath(os.path.expanduser(r["file"]))
            if os.path.dirname(path) != os.path.realpath(MOCK_DIR):
                raise PanelError("only mocks in the active project's state directory can be opened in the panel")
            with open(path, "rb") as fh:
                return {"content": fh.read().decode("utf-8", "replace"), "status": r.get("status", 200),
                        "headers": [[k, v] for k, v in (r.get("headers") or {}).items()],
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
            atomic_write_text(path, a["content"])
            if str(a.get("status", "")).strip():
                r["status"] = http_status(a["status"])
            if isinstance(a.get("headers"), list):
                r["headers"] = {str(k): str(v) for k, v in a["headers"] if str(k).strip()}
            self.save_cfg(cfg)
        else:
            raise PanelError(f"unknown op {op}")
        return {}

    def _write_coll(self, doc):
        os.makedirs(COLL_DIR, exist_ok=True)
        atomic_json(self.coll_file(doc["name"]), migrate_collection(doc))

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
                            "httpVersion": "HTTP/1.1", "headers": [], "queryString": [], "cookies": [], "headersSize": -1, "bodySize": -1},
                "response": {"status": e["status"], "statusText": "", "httpVersion": "HTTP/1.1",
                             "headers": [{"name": k, "value": v} for k, v in e["headers"]], "cookies": [],
                             "content": content, "redirectURL": "", "headersSize": -1, "bodySize": -1},
                "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0}})
        return {"log": {"version": "1.2", "creator": {"name": PRODUCT["name"], "version": "1"}, "entries": out}}

    @staticmethod
    def from_har(har):
        import base64
        import time as _t
        from urllib.parse import parse_qsl, urlencode, urlsplit
        out = []
        for e in ((har or {}).get("log") or {}).get("entries", [])[:10000]:
            try:
                req, resp = e["request"], e["response"]
                u = urlsplit(req["url"])
                c = resp.get("content") or {}
                ent = {"method": req["method"].upper(), "scheme": u.scheme or "https", "host": u.hostname or "",
                       "path": u.path or "/",
                       "query": urlencode(sorted(parse_qsl(u.query, keep_blank_values=True))),
                       "req_body": "", "status": int(resp["status"]),
                       "headers": [[h["name"], h["value"]] for h in resp.get("headers", [])
                                   if h["name"].lower() not in ("content-encoding", "content-length", "transfer-encoding", "connection")
                                   and not h["name"].startswith(":")],
                       "recorded_at": _t.time()}
                if c.get("encoding") == "base64":
                    ent["b64"] = c.get("text", "")
                    base64.b64decode(ent["b64"])
                else:
                    ent["text"] = c.get("text", "")
                if ent["host"] and ent["status"] > 0:
                    out.append(ent)
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
            self._register()
            self._show_start_time_column()
        except Exception as e:   # never take mitmweb down
            ctx.log.warn(f"proxy_panel: not available ({type(e).__name__}: {e})")

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

            def get(self, op):
                if op != "state":
                    raise webapp.APIError(404, "unknown")
                self.set_header("Content-Type", "application/json")
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
                        raise tornado.web.HTTPError(413, "panel request exceeds the 8 MiB limit")
                    refused = self._refuse_cross_site()
                    if refused:
                        raise tornado.web.HTTPError(403, refused)
                return super().prepare()

            def post(self, op):
                self.set_header("Content-Type", "application/json")
                try:
                    a = json.loads(self.request.body or b"{}")
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
            (r"/static/(index-[A-Za-z0-9_-]+\.js)", MitmwebIndexJS),
            (r"/proxy/boot\.js", BootJS),
            (r"/proxy/bootstrap/([0-9a-f]{32})", Bootstrap),
            (r"/proxy/api/([a-z_]+)", Api),
        ])
        app._proxy_panel_routes = True
        ctx.log.info(f"proxy_panel: {PRODUCT['name']} project panel available in the mitmweb UI")


addons = [ProxyPanel()]
