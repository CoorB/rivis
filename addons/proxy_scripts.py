"""Per-project Python/JavaScript scripting and protocol viewer helpers.

Rules run first because the CLI loads proxy_rules.py before this add-on.  Enabled
scripts then run in filename order.  Script metadata is stored in rules.json's
``scripts`` array; source files live in the sibling ``scripts`` directory.
"""
import asyncio
import base64
import copy
import importlib.util
import inspect
import json
import os
import re
import shutil
import struct
import sys
import time
import glob
import traceback
from datetime import datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

try:
    from mitmproxy import ctx, http
except ImportError:  # Pure helpers are intentionally importable by static tests.
    ctx = None
    http = None

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from proxy_common import PRODUCT, SAFE_NAME, STATE_ROOT, confined_path, project_state

JWT_RE = re.compile(r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)(?![A-Za-z0-9_-])")
GRAPHQL_OP_RE = re.compile(
    r"\A(?:\s|#[^\n]*(?:\n|$))*(?:(query|mutation|subscription|fragment)\b\s*"
    r"(?:([_A-Za-z][_0-9A-Za-z]*))?|(?P<selection>\{))"
)
MAX_VIEWER_BODY = 1024 * 1024
NODE_PIPE_LIMIT = 64 * 1024 * 1024
NO_HOOK = object()
NODE_OUTER_TIMEOUT = 30.0
PYTHON_TIMEOUT = 2.0
DEFAULT_RULES = os.path.join(STATE_ROOT, "projects", "default", "rules.json")
NODE_CANDIDATES = (
    "/opt/homebrew/bin/node", "/usr/local/bin/node", "/usr/bin/node",
    os.path.expanduser("~/.nvm/versions/node/current/bin/node"),
    r"C:\Program Files\nodejs\node.exe", r"C:\Program Files (x86)\nodejs\node.exe",
)


def _b64json(segment):
    raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JWT segment is not an object")
    return value


def decode_jwt(token, now=None):
    """Decode (never verify) a compact JWT for the panel."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a three-segment JWT")
    header, payload = _b64json(parts[0]), _b64json(parts[1])
    now = time.time() if now is None else now
    times = {}
    for key in ("exp", "iat", "nbf"):
        value = payload.get(key)
        if isinstance(value, (int, float)):
            try:
                local = datetime.fromtimestamp(value).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
            except (OSError, OverflowError, ValueError):
                local = "invalid timestamp"
            item = {"epoch": value, "local": local}
            if key == "exp":
                delta = value - now
                mins = max(0, int(abs(delta) // 60))
                item["relative"] = (f"expires in {mins} min" if delta >= 0 else f"expired {mins} min ago")
                item["expired"] = delta < 0
            times[key] = item
    return {"token": token, "header": header, "payload": payload, "times": times,
            "alg": header.get("alg"), "kid": header.get("kid"), "signature": "not verified"}


def _walk_strings(value, where, out):
    """Iteratively scan nested JSON so hostile depth cannot exhaust Python's stack."""
    pending = [(where, value)]
    visited = 0
    while pending and visited < 100000:
        current_where, current = pending.pop()
        visited += 1
        if isinstance(current, str):
            for match in JWT_RE.finditer(current):
                out.append((current_where, match.group(1)))
        elif isinstance(current, dict):
            pending.extend((f"{current_where}.{key}", child) for key, child in reversed(list(current.items())))
        elif isinstance(current, list):
            pending.extend((f"{current_where}[{index}]", child)
                           for index, child in reversed(list(enumerate(current))))


def find_jwts(headers=None, body=None, content_type="", cookies=None, url=None):
    """Find distinct decodable JWTs in headers, URL queries and JSON/form values."""
    try:
        found = []
        pairs = headers.items() if hasattr(headers, "items") else (headers or [])
        for key, value in pairs:
            lk = str(key).lower()
            if lk in ("authorization", "cookie", "set-cookie"):
                values = value if isinstance(value, list) else [value]
                for header_value in values:
                    _walk_strings(str(header_value), "header:" + lk, found)
        if cookies:
            _walk_strings(cookies, "cookies", found)
        if url:
            for key, value in parse_qsl(urlsplit(str(url)).query, keep_blank_values=True):
                _walk_strings(value, f"query.{key}", found)
        if body:
            raw = body[:MAX_VIEWER_BODY] if isinstance(body, bytes) else str(body)[:MAX_VIEWER_BODY]
            text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
            stripped = text.lstrip()
            try:
                if "json" in str(content_type).lower() or stripped.startswith(("{", "[")):
                    parsed = json.loads(text)
                else:
                    parsed = [{key: value} for key, value in parse_qsl(text, keep_blank_values=True)]
                _walk_strings(parsed, "body", found)
            except Exception:
                pass
        out, seen = [], set()
        for where, token in found:
            if token in seen:
                continue
            try:
                item = decode_jwt(token)
            except Exception:
                continue
            item["where"] = where
            out.append(item)
            seen.add(token)
        return out
    except Exception:
        return []


def _graphql_item(doc, explicit_graphql=False):
    if not isinstance(doc, dict) or not isinstance(doc.get("query"), str):
        return None
    query = doc["query"]
    match = GRAPHQL_OP_RE.match(query)
    if not match and not explicit_graphql:
        return None
    op_type = match.group(1) if match and match.group(1) else "query"
    op_name = doc.get("operationName") or (match.group(2) if match else None) or "(anonymous)"
    return {"type": op_type, "name": op_name, "query": query, "variables": doc.get("variables")}


def detect_graphql(method, url, body=None, content_type=""):
    """Return GraphQL operations from a GET query or POST JSON document/batch."""
    try:
        docs = []
        ctype = str(content_type).lower()
        explicit = "application/graphql" in ctype
        if str(method).upper() == "GET":
            query_params = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
            query = query_params.get("query")
            if query is not None:
                docs = [{"query": query, "operationName": query_params.get("operationName")}]
        elif str(method).upper() == "POST" and explicit:
            text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body or "")
            docs = [{"query": text}]
        elif str(method).upper() == "POST" and ("json" in ctype or not ctype):
            text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body or "")
            doc = json.loads(text[:MAX_VIEWER_BODY])
            docs = doc if isinstance(doc, list) else [doc]
        return [item for item in (_graphql_item(doc, explicit) for doc in docs) if item]
    except Exception:
        return []


def _varint(data, pos):
    value = shift = 0
    while pos < len(data) and shift < 70:
        byte = data[pos]; pos += 1
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
    raise ValueError("invalid varint")


def decode_protobuf(data, depth=0):
    """Small schema-less protobuf decoder, matching mitmproxy's field-number view."""
    rows, pos = [], 0
    while pos < len(data) and len(rows) < 500:
        key, pos = _varint(data, pos)
        field, wire = key >> 3, key & 7
        if not field:
            raise ValueError("field number 0")
        if wire == 0:
            value, pos = _varint(data, pos)
        elif wire == 1:
            if pos + 8 > len(data): raise ValueError("truncated fixed64")
            value = {"fixed64": struct.unpack("<Q", data[pos:pos + 8])[0]}; pos += 8
        elif wire == 5:
            if pos + 4 > len(data): raise ValueError("truncated fixed32")
            value = {"fixed32": struct.unpack("<I", data[pos:pos + 4])[0]}; pos += 4
        elif wire == 2:
            size, pos = _varint(data, pos)
            if pos + size > len(data): raise ValueError("truncated bytes")
            raw, pos = data[pos:pos + size], pos + size
            try:
                text = raw.decode("utf-8")
                value = text if all(c.isprintable() or c in "\r\n\t" for c in text) else None
            except UnicodeDecodeError:
                value = None
            if value is None and depth < 4 and raw:
                try: value = {"message": decode_protobuf(raw, depth + 1)}
                except ValueError: value = {"base64": base64.b64encode(raw).decode()}
            elif value is None:
                value = {"base64": base64.b64encode(raw).decode()}
        else:
            raise ValueError(f"unsupported wire type {wire}")
        rows.append({"field": field, "wire": wire, "value": value})
    return rows


def decode_grpc_frames(data):
    rows, pos = [], 0
    while pos < len(data):
        if pos + 5 > len(data): raise ValueError("truncated gRPC frame")
        compressed, size = data[pos], int.from_bytes(data[pos + 1:pos + 5], "big"); pos += 5
        raw, pos = data[pos:pos + size], pos + size
        if len(raw) != size: raise ValueError("truncated gRPC message")
        rows.append({"compressed": bool(compressed), "size": size,
                     "fields": None if compressed else decode_protobuf(raw),
                     "note": "compressed message (not decoded)" if compressed else None})
    return rows


def load_script_files(script_dir, cfg):
    """Validate metadata and return enabled script descriptors in filename order."""
    out = []
    for item in cfg.get("scripts", []):
        if not isinstance(item, dict) or not item.get("enabled", True):
            continue
        filename = item.get("file", "")
        if os.path.basename(filename) != filename or not filename.endswith((".py", ".js")):
            continue
        path = os.path.join(script_dir, filename)
        if not os.path.isfile(path):
            continue
        try:   # a symlink planted in scripts/ must not run code from outside the project (B5)
            path = confined_path(os.path.dirname(os.path.abspath(script_dir)), path, "script")
        except ValueError as e:
            if ctx:
                ctx.log.warn(f"proxy_scripts: skipping '{filename}': {e}")
            continue
        copy_item = dict(item); copy_item["path"] = path
        copy_item["name"] = copy_item.get("name") or os.path.splitext(filename)[0]
        out.append(copy_item)
    return sorted(out, key=lambda x: x["file"].lower())


def find_node():
    prefix = str(PRODUCT.get("env_prefix", "RIVIS"))
    override = os.environ.get(prefix + "_NODE")
    candidates = ([override] if override else []) + [shutil.which("node")] + list(NODE_CANDIDATES)
    candidates += sorted(glob.glob(os.path.expanduser("~/.nvm/versions/node/*/bin/node")), reverse=True)
    if os.environ.get("NVM_HOME"):
        candidates.append(os.path.join(os.environ["NVM_HOME"], "node.exe"))
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


class ScriptContext(dict):
    __getattr__ = dict.get
    def __setattr__(self, key, value): self[key] = value


class ScriptFailure(Exception):
    def __init__(self, message, short_traceback=""):
        super().__init__(message)
        self.short_traceback = short_traceback


def _capture_user_call(fn, args):
    """Run user code without allowing SystemExit/KeyboardInterrupt out of its worker."""
    try:
        return True, fn(*args), ""
    except BaseException as exc:  # User scripts may call sys.exit().
        return False, exc, "".join(traceback.format_exception(type(exc), exc, exc.__traceback__, limit=8))


async def _capture_user_awaitable(awaitable):
    """Async equivalent that contains SystemExit inside the task that runs user code."""
    try:
        return True, await awaitable, ""
    except BaseException as exc:
        return False, exc, "".join(traceback.format_exception(type(exc), exc, exc.__traceback__, limit=8))


def _header_values(headers):
    """Represent headers as an ordered dict whose duplicate values remain ordered."""
    out, names = {}, {}
    try:
        pairs = headers.items(multi=True)
    except TypeError:
        pairs = headers.items()
    for key, value in pairs:
        key, value = str(key), str(value)
        lower = key.lower()
        actual = names.setdefault(lower, key)
        if actual not in out:
            out[actual] = value
        elif isinstance(out[actual], list):
            out[actual].append(value)
        else:
            out[actual] = [out[actual], value]
    return out


def _normalised_headers(headers):
    out = {}
    if not isinstance(headers, dict):
        return out
    for key, value in headers.items():
        values = value if isinstance(value, list) else [value]
        out[str(key).lower()] = (str(key), [str(x) for x in values])
    return out


class ProxyScripts:
    def __init__(self):
        self.rules_path = DEFAULT_RULES
        self.project = "default"
        self.script_dir = os.path.join(os.path.dirname(DEFAULT_RULES), "scripts")
        self.checked = self.mtime = 0
        self.scripts = []
        self.modules = {}
        self.contexts = {}
        self.last_errors = {}
        self.node = find_node()
        self.proc = None
        self.reader_task = None
        self.seq = 0
        self.node_generation = 0
        self.node_pending = {}
        self.node_write_locks = {}
        self.node_stderr_tasks = {}
        self.node_start_lock = asyncio.Lock()
        self.reload_lock = asyncio.Lock()
        self.script_locks = {}

    def configure(self, updated):
        if "proxy_rules_file" in updated or "proxy_project" in updated:
            self.rules_path = os.path.expanduser(ctx.options.proxy_rules_file)
            self.project = ctx.options.proxy_project
            self.script_dir = os.path.join(project_state(self.project), "scripts")
            os.makedirs(self.script_dir, mode=0o700, exist_ok=True)
            self.mtime = 0

    def _error(self, filename, phase, exc, short_traceback=""):
        message = str(exc) if isinstance(exc, ScriptFailure) else f"{type(exc).__name__}: {exc}"
        record = {"time": datetime.now().astimezone().isoformat(timespec="seconds"),
                  "message": message, "traceback": (short_traceback or "")[-4000:], "phase": phase}
        self.last_errors[filename] = record
        return record

    @staticmethod
    def _helpers(item):
        async def sleep(ms):
            await asyncio.sleep(float(ms) / 1000)

        def log(*args):
            ctx.log.info(f"script:{item['name']}: " + " ".join(map(str, args)))

        def mock(status=200, body="", headers=None):
            return {"__proxy_mock__": True, "statusCode": status, "body": body, "headers": headers or {}}

        return {"log": log, "sleep": sleep, "mock": mock}

    @staticmethod
    def _load_python(item):
        namespace = {"__file__": item["path"],
                     "__name__": "proxy_user_" + re.sub(r"\W", "_", item["name"])}
        # Installed before exec: a script's own definitions deliberately win.
        for name, helper in ProxyScripts._helpers(item).items():
            namespace.setdefault(name, helper)
        with open(item["path"], encoding="utf-8") as fh:
            code = fh.read()
        return _capture_user_call(exec, (compile(code, item["path"], "exec"), namespace)), namespace

    async def _reload(self, force=False):
        async with self.reload_lock:
            await self._reload_locked(force)

    async def _reload_locked(self, force=False):
        now = time.monotonic()
        if not force and now - self.checked < 1: return
        self.checked = now
        try:
            rule_mtime = os.stat(self.rules_path).st_mtime_ns
            file_mtime = tuple(sorted((f, os.stat(os.path.join(self.script_dir, f)).st_mtime_ns)
                                      for f in os.listdir(self.script_dir) if f.endswith((".py", ".js"))))
            stamp = (rule_mtime, file_mtime)
            if stamp == self.mtime: return
            with open(self.rules_path) as fh: cfg = json.load(fh)
            candidates = load_script_files(self.script_dir, cfg)
            scripts, modules = [], {}
            for item in candidates:
                try:
                    if item["file"].endswith(".py"):
                        try:
                            outcome, namespace = await asyncio.wait_for(
                                asyncio.to_thread(self._load_python, item), PYTHON_TIMEOUT)
                        except asyncio.TimeoutError as exc:
                            raise ScriptFailure(
                                "top-level execution timed out after 2 s (the worker thread cannot be killed)") from exc
                        ok, value, short_traceback = outcome
                        if not ok:
                            raise ScriptFailure(f"{type(value).__name__}: {value}", short_traceback)
                        modules[item["file"]] = namespace
                    else:
                        with open(item["path"], encoding="utf-8") as fh: item["code"] = fh.read()
                    item["_re"] = re.compile(item.get("match") or ".")
                    scripts.append(item)
                    self.last_errors.pop(item["file"], None)
                except BaseException as exc:
                    if isinstance(exc, asyncio.CancelledError):
                        raise
                    short_tb = getattr(exc, "short_traceback", "")
                    record = self._error(item["file"], "load", exc, short_tb)
                    ctx.log.warn(f"proxy_scripts: {item['file']}: load: {record['message']}")
            self.scripts, self.modules, self.mtime = scripts, modules, stamp
            live = {x["file"] for x in candidates}
            self.contexts = {k: v for k, v in self.contexts.items() if k in live}
            self.script_locks = {k: v for k, v in self.script_locks.items() if k in live}
            self.last_errors = {k: v for k, v in self.last_errors.items() if k in live}
            ctx.log.info("proxy_scripts: loaded " + (", ".join(x["file"] for x in scripts) or "no enabled scripts"))
        except Exception as exc:
            ctx.log.warn(f"proxy_scripts: reload failed: {exc} — keeping previous scripts")

    @staticmethod
    def _message(msg, response=False):
        try:
            raw = msg.get_content(strict=False) or b""
        except Exception:
            raw = msg.raw_content or b""
        ctype = msg.headers.get("content-type", "")
        binary = False
        if "json" in ctype.lower():
            try: body = json.loads(raw.decode("utf-8"))
            except Exception: body = raw.decode("utf-8", "replace")
        else:
            try: body = raw.decode("utf-8")
            except UnicodeDecodeError: body, binary = base64.b64encode(raw).decode(), True
        value = {"headers": _header_values(msg.headers), "body": body, "body_is_base64": binary}
        if response: value["statusCode"] = msg.status_code
        return value

    def _request(self, flow):
        p = urlsplit(flow.request.pretty_url)
        value = self._message(flow.request)
        value.update(method=flow.request.method, url=flow.request.pretty_url, scheme=p.scheme,
                     host=p.hostname or "", port=p.port or (443 if p.scheme == "https" else 80),
                     path=p.path, queries=dict(parse_qsl(p.query, keep_blank_values=True)))
        return value

    @staticmethod
    def _apply(msg, value, response=False):
        if not isinstance(value, dict): return False
        status = int(value["statusCode"]) if response and value.get("statusCode") is not None else None
        new_headers = _normalised_headers(value.get("headers")) if isinstance(value.get("headers"), dict) else None
        try:
            decoded_before = msg.get_content(strict=False) or b""
        except Exception:
            decoded_before = msg.raw_content or b""
        content = None
        if "body" in value:
            body = value["body"]
            if value.get("body_is_base64"):
                candidate = base64.b64decode(body, validate=True)
                if candidate != decoded_before: content = candidate
            elif isinstance(body, (dict, list)):
                try:
                    semantically_same = json.loads(decoded_before.decode("utf-8")) == body
                except Exception:
                    semantically_same = False
                if not semantically_same:
                    content = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            else:
                candidate = str(body).encode()
                if candidate != decoded_before: content = candidate
        before = (getattr(msg, "method", None), getattr(msg, "url", None), getattr(msg, "status_code", None),
                  list(msg.headers.items(multi=True)), msg.raw_content)
        if not response:
            if value.get("method"): msg.method = str(value["method"]).upper()
            original_url = msg.url
            if value.get("url") and str(value["url"]) != original_url:
                msg.url = str(value["url"])
            else:
                parsed = urlsplit(original_url)
                original = {"scheme": parsed.scheme, "host": parsed.hostname or "",
                            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                            "path": parsed.path, "queries": dict(parse_qsl(parsed.query, keep_blank_values=True))}
                if any(key in value and value[key] != original[key] for key in original):
                    scheme = str(value.get("scheme", original["scheme"]))
                    host = str(value.get("host", original["host"]))
                    port = int(value.get("port", original["port"]))
                    default = 443 if scheme == "https" else 80
                    netloc = host if port == default else f"{host}:{port}"
                    query = urlencode(value.get("queries", original["queries"]), doseq=True)
                    msg.url = urlunsplit((scheme, netloc, str(value.get("path", original["path"])), query, parsed.fragment))
        else:
            if status is not None: msg.status_code = status
        if new_headers is not None:
            old_headers = _normalised_headers(_header_values(msg.headers))
            for lower, (old_name, old_values) in list(old_headers.items()):
                if lower not in new_headers:
                    del msg.headers[old_name]
            for lower, (new_name, new_values) in new_headers.items():
                old = old_headers.get(lower)
                if old is None or old[1] != new_values or old[0] != new_name:
                    msg.headers.set_all(new_name, new_values)
        if content is not None:
            msg.set_content(content)
            if isinstance(value["body"], (dict, list)) and "content-type" not in msg.headers:
                msg.headers["content-type"] = "application/json"
        after = (getattr(msg, "method", None), getattr(msg, "url", None), getattr(msg, "status_code", None),
                 list(msg.headers.items(multi=True)), msg.raw_content)
        return before != after

    @staticmethod
    def _tag(flow, item, response=False):
        label = "script:" + item["name"]
        if label not in (flow.comment or ""):
            flow.comment = (flow.comment + " | " if flow.comment else "") + label
        if response: flow.metadata["proxy_modified"] = True

    async def _python(self, item, hook, context, url, request, response=None):
        ns = self.modules[item["file"]]
        fn = ns.get(hook) or ns.get("onRequest" if hook == "on_request" else "onResponse")
        if not fn: return NO_HOOK
        args = (context, url, request) if response is None else (context, url, request, response)
        if inspect.iscoroutinefunction(fn):
            ok, value, short_traceback = await asyncio.wait_for(
                _capture_user_awaitable(fn(*args)), PYTHON_TIMEOUT)
            if not ok:
                raise ScriptFailure(f"{type(value).__name__}: {value}", short_traceback)
            result = value
        else:
            try:
                ok, value, short_traceback = await asyncio.wait_for(
                    asyncio.to_thread(_capture_user_call, fn, args), PYTHON_TIMEOUT)
            except asyncio.TimeoutError as exc:
                raise ScriptFailure(
                    "timed out after 2 s (the worker thread cannot be killed; its result is ignored)") from exc
            if not ok:
                raise ScriptFailure(f"{type(value).__name__}: {value}", short_traceback)
            result = value
            if inspect.isawaitable(result):
                ok, value, short_traceback = await asyncio.wait_for(
                    _capture_user_awaitable(result), PYTHON_TIMEOUT)
                if not ok:
                    raise ScriptFailure(f"{type(value).__name__}: {value}", short_traceback)
                result = value
        return result

    async def _start_node(self):
        async with self.node_start_lock:
            if self.proc and self.proc.returncode is None:
                return self.node_generation
            if not self.node:
                return 0
            self.node_generation += 1
            generation = self.node_generation
            proc = await asyncio.create_subprocess_exec(
                self.node, os.path.join(HERE, "js_host.mjs"),
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, limit=NODE_PIPE_LIMIT)
            pending = {}
            self.proc = proc
            self.node_pending[generation] = pending
            self.node_write_locks[generation] = asyncio.Lock()
            self.reader_task = asyncio.create_task(self._read_node(proc, pending, generation))
            self.node_stderr_tasks[generation] = asyncio.create_task(self._drain_node_stderr(proc, generation))
            return generation

    async def _drain_node_stderr(self, proc, generation):
        try:
            while True:
                line = await proc.stderr.readline()
                if not line:
                    return
                ctx.log.warn(f"proxy_scripts: JavaScript host: {line.decode('utf-8', 'replace').rstrip()}")
        except Exception as exc:
            if proc.returncode is None:
                ctx.log.warn(f"proxy_scripts: JavaScript stderr reader stopped: {exc}")

    async def _read_node(self, proc, pending, generation):
        response_id = None
        try:
            while True:
                try:
                    line = await proc.stdout.readline()
                except ValueError as exc:
                    call = pending.get(response_id)
                    if call and not call["future"].done():
                        call["future"].set_exception(
                            RuntimeError(f"JavaScript response exceeded the {NODE_PIPE_LIMIT // (1024 * 1024)} MiB limit"))
                    response_id = None
                    ctx.log.warn(f"proxy_scripts: discarded an over-limit JavaScript response: {exc}")
                    continue
                if not line: break
                msg = json.loads(line)
                call = pending.get(msg.get("id"))
                if not call:
                    continue
                if msg.get("started"):
                    call["started"].set()
                    continue
                if msg.get("responding"):
                    response_id = msg.get("id")
                    continue
                future = call["future"]
                if not future.done(): future.set_result(msg)
                response_id = None
        except Exception as exc:
            ctx.log.warn(f"proxy_scripts: JavaScript host stopped: {exc}")
        finally:
            if proc.returncode is None:
                proc.kill()
                try: await proc.wait()
                except Exception: pass
            for call in pending.values():
                future = call["future"]
                if not future.done(): future.set_exception(RuntimeError("JavaScript host stopped"))
            pending.clear()
            self.node_pending.pop(generation, None)
            self.node_write_locks.pop(generation, None)
            stderr_task = self.node_stderr_tasks.pop(generation, None)
            if stderr_task and stderr_task is not asyncio.current_task():
                stderr_task.cancel()
            if self.proc is proc:
                self.proc = None

    async def _kill_node(self, proc):
        if proc and proc.returncode is None:
            proc.kill()
            try:
                await asyncio.wait_for(proc.wait(), 2)
            except Exception:
                pass

    async def _javascript(self, item, hook, context, url, request, response=None):
        script_lock = self.script_locks.setdefault(item["file"], asyncio.Lock())
        async with script_lock:
            generation = await self._start_node()
            if not generation:
                raise RuntimeError("Node.js not installed — JS scripts disabled")
            proc = self.proc
            pending = self.node_pending[generation]
            write_lock = self.node_write_locks[generation]
            self.seq += 1; request_id = self.seq
            payload = {"id": request_id, "name": item["file"], "code": item["code"], "hook": hook,
                       "context": context, "url": url, "request": request, "response": response}
            loop = asyncio.get_running_loop()
            call = {"future": loop.create_future(), "started": asyncio.Event()}
            pending[request_id] = call

            async def exchange():
                async with write_lock:
                    proc.stdin.write((json.dumps(payload, separators=(",", ":")) + "\n").encode())
                    await proc.stdin.drain()
                await call["started"].wait()
                return await call["future"]

            try:
                msg = await asyncio.wait_for(exchange(), NODE_OUTER_TIMEOUT)
            except asyncio.TimeoutError as exc:
                await self._kill_node(proc)
                raise RuntimeError("JavaScript host was unresponsive for 30 s and was restarted") from exc
            finally:
                pending.pop(request_id, None)
        for line in msg.get("logs", []): ctx.log.info(f"script:{item['name']}: {line}")
        if msg.get("error"):
            lines = str(msg["error"]).splitlines()
            raise ScriptFailure(lines[0] if lines else "JavaScript error", "\n".join(lines[:12]))
        if not msg.get("invoked", True):
            return NO_HOOK
        context.clear(); context.update(msg.get("context") or {})
        return msg.get("result")

    async def _run(self, flow, hook):
        await self._reload()
        response_side = hook == "on_response"
        if response_side and flow.metadata.get("proxy_local"):
            return
        request = self._request(flow)
        response = self._message(flow.response, True) if response_side and flow.response else None
        for item in self.scripts:
            if not response_side and flow.response:
                break
            if not item["_re"].search(flow.request.pretty_url): continue
            if item.get("method") and item["method"].upper() != flow.request.method: continue
            context = self.contexts.setdefault(item["file"], ScriptContext())
            context.update(flow_id=flow.id, project=self.project)
            call_context = ScriptContext(copy.deepcopy(context))
            call_request = copy.deepcopy(request)
            call_response = copy.deepcopy(response)
            started = time.perf_counter()
            try:
                if item["file"].endswith(".py"):
                    result = await self._python(item, hook, call_context, flow.request.pretty_url,
                                                call_request, call_response)
                else:
                    result = await self._javascript(item, hook, call_context, flow.request.pretty_url,
                                                    call_request, call_response)
                if result is NO_HOOK:
                    continue
                context.clear(); context.update(call_context)
                self.last_errors.pop(item["file"], None)
                if result is None: continue
                if not response_side and isinstance(result, dict) and result.get("__proxy_mock__"):
                    header_map = _normalised_headers(result.get("headers") or {})
                    body = result.get("body", "")
                    if isinstance(body, (dict, list)):
                        body = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                        if "content-type" not in header_map:
                            header_map["content-type"] = ("content-type", ["application/json"])
                    elif not isinstance(body, bytes): body = str(body).encode()
                    headers = {name: ", ".join(values) for name, values in header_map.values()}
                    flow.response = http.Response.make(int(result.get("statusCode", 200)), body, headers)
                    flow.metadata["proxy_local"] = True; self._tag(flow, item); break
                target = flow.response if response_side else flow.request
                backup = target.copy()
                try:
                    changed = self._apply(target, result, response_side)
                except Exception:
                    if response_side: flow.response = backup
                    else: flow.request = backup
                    raise
                if changed:
                    self._tag(flow, item, response_side)
                    request = self._request(flow)
                    response = self._message(flow.response, True) if response_side and flow.response else None
            except BaseException as exc:
                if isinstance(exc, asyncio.CancelledError):
                    raise
                short_tb = getattr(exc, "short_traceback", "") or "".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__, limit=8))
                record = self._error(item["file"], hook, exc, short_tb)
                ctx.log.warn(f"proxy_scripts: {item['name']} {hook}: {record['message']}; flow unchanged")
            finally:
                elapsed = (time.perf_counter() - started) * 1000
                if elapsed > 200: ctx.log.warn(f"proxy_scripts: {item['name']} {hook} took {elapsed:.0f} ms (>200 ms)")

    async def request(self, flow): await self._run(flow, "on_request")
    async def response(self, flow): await self._run(flow, "on_response")


addons = [ProxyScripts()] if ctx is not None else []
