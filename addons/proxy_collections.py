"""
proxy_collections — record a journey once, replay it as mocks (FRTMProxy "Collections").

State lives in the rules file under "collections" (shared with the panel and CLI):
  {"recording": "<name>" | null, "record_match": "<url regex>", "replay": ["<name>", ...], "strict": false}
Each collection is stored under the active project's state directory and never leaves the workstation
(no Git sync — the IT approval forbids pushing recordings anywhere).

Recording: every completed call whose URL matches record_match is appended with its real response.
Calls answered by a local rule are not recorded (they are not real).
Replay: a call is matched on method + host + path + canonical query; if several recordings share
that key, the one with the same request body wins, and repeated identical calls are served in the
order they were recorded (sticking on the last) — FRTMProxy always serves the first.
Strict mode: a matching call absent from every enabled collection gets 404 instead of reaching the server.
"""
import base64
import asyncio
import hashlib
import importlib
import json
import os
import re
import time
import sys
from urllib.parse import parse_qsl, urlencode

from mitmproxy import ctx, http

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import proxy_common
importlib.reload(proxy_common)
from proxy_common import (SAFE_NAME, STATE_ROOT, atomic_json, confined_path, migrate_collection,
                          migrate_rules, project_profile, project_state, user_regex)

DEFAULT_RECORD = "."
COLL_DIR = os.path.join(STATE_ROOT, "projects", "default", "collections")
SKIP_HEADERS = {"content-encoding", "content-length", "transfer-encoding", "connection"}


def canon_query(q):
    return urlencode(sorted(parse_qsl(q or "", keep_blank_values=True)))


def body_hash(raw):
    raw = raw or b""
    try:   # JSON bodies compare by content, not key order / whitespace
        raw = json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":")).encode()
    except (ValueError, RecursionError):
        pass
    return hashlib.sha256(raw).hexdigest()[:16]


def coll_path(name):
    if not SAFE_NAME.fullmatch(name or ""):
        raise ValueError("bad collection name")
    # confine to the project state dir: a symlink planted in collections/ must not
    # read (replay) or replace (record) a file outside the project (B5)
    return confined_path(os.path.dirname(COLL_DIR), os.path.join(COLL_DIR, name + ".json"), "collection")


def load_coll(name):
    with open(coll_path(name)) as f:
        return migrate_collection(json.load(f))


def save_coll(doc):
    os.makedirs(COLL_DIR, mode=0o700, exist_ok=True)
    os.chmod(COLL_DIR, 0o700)
    atomic_json(coll_path(doc["name"]), migrate_collection(doc))


def entry_from_flow(f):
    raw = f.response.get_content(strict=False) or b""
    try:
        body = {"text": raw.decode("utf-8")}
    except UnicodeDecodeError:
        body = {"b64": base64.b64encode(raw).decode()}
    return {
        "method": f.request.method, "scheme": f.request.scheme, "host": f.request.pretty_host,
        "path": f.request.path.split("?")[0], "query": canon_query(f.request.path.split("?", 1)[1] if "?" in f.request.path else ""),
        "req_body": body_hash(f.request.get_content(strict=False)),
        "status": f.response.status_code,
        "headers": [[k, v] for k, v in f.response.headers.items(multi=True) if k.lower() not in SKIP_HEADERS],
        **body, "recorded_at": time.time(),
    }


class ProxyCollections:
    def __init__(self):
        self.mtime = None
        self.checked = 0.0
        self.cfg = {}
        self.index = {}       # key → [(collection, entry)]
        self.cursor = {}      # key → next position
        self.coll_mtimes = {}
        self.recording_docs = {}
        self.dirty = set()
        self.deleted = set()
        self.flush_handle = None
        self.default_record = DEFAULT_RECORD

    def done(self):
        self.flush_recording()

    def configure(self, updated):
        global COLL_DIR
        if "proxy_project" in updated or "proxy_rules_file" in updated:
            COLL_DIR = os.path.join(project_state(ctx.options.proxy_project), "collections")
            self.default_record = project_profile(ctx.options.proxy_project).get("record_match") or DEFAULT_RECORD

    def flush_recording(self, name=None, forget=False):
        names = [name] if name else list(self.dirty)
        for item in names:
            if item in self.deleted:     # deleted in the panel: never write it back
                self.dirty.discard(item)
                self.recording_docs.pop(item, None)
                continue
            if item not in self.dirty:
                if forget:
                    self.recording_docs.pop(item, None)
                continue
            try:
                save_coll(self.recording_docs[item])
                self.dirty.discard(item)
            except Exception as e:
                ctx.log.warn(f"proxy_collections: could not flush '{item}': {e}")
            else:
                if forget:
                    # A later debounce callback must never recreate a collection
                    # that the panel has deleted or replaced.
                    self.recording_docs.pop(item, None)
        if not self.dirty and self.flush_handle:
            self.flush_handle.cancel()
            self.flush_handle = None

    def _schedule_flush(self):
        if self.flush_handle is None:
            self.flush_handle = asyncio.get_running_loop().call_later(0.5, self._flush_due)

    def _flush_due(self):
        self.flush_handle = None
        self.flush_recording()

    def _recording_doc(self, name):
        if name not in self.recording_docs:
            try:
                self.recording_docs[name] = load_coll(name)
            except FileNotFoundError:
                self.recording_docs[name] = {"name": name, "created": time.time(), "entries": []}
        return self.recording_docs[name]

    def _rules_path(self):
        try:
            return os.path.expanduser(ctx.options.proxy_rules_file)
        except Exception:
            return os.path.join(STATE_ROOT, "projects", "default", "rules.json")

    def _reload(self):
        now = time.monotonic()
        if now - self.checked < 1.0:
            return
        self.checked = now
        try:
            with open(self._rules_path()) as f:
                cfg = migrate_rules(json.load(f)).get("collections") or {}
        except (OSError, ValueError):
            return
        old_recording = self.cfg.get("recording")
        if old_recording and old_recording != cfg.get("recording"):
            self.flush_recording(old_recording, forget=True)
        replay = list(cfg.get("replay") or [])
        mt = {}
        for n in replay:
            try:
                mt[n] = os.stat(coll_path(n)).st_mtime
            except (OSError, ValueError):
                pass
        if cfg != self.cfg or mt != self.coll_mtimes:
            self.cfg, self.coll_mtimes = cfg, mt
            self.index, self.cursor = {}, {}
            for n in replay:
                try:
                    for e in load_coll(n)["entries"]:
                        k = (e["method"], e["host"], e["path"], e.get("query", ""))
                        self.index.setdefault(k, []).append((n, e))
                except (OSError, ValueError, KeyError) as e:
                    ctx.log.warn(f"proxy_collections: cannot load '{n}': {e}")
            if replay:
                ctx.log.info(f"proxy_collections: replaying {', '.join(replay)} ({sum(len(v) for v in self.index.values())} calls)")

    def request(self, flow: http.HTTPFlow):
        self._reload()
        if flow.response or not self.index and not self.cfg.get("strict"):
            return
        r = flow.request
        k = (r.method, r.pretty_host, r.path.split("?")[0], canon_query(r.path.split("?", 1)[1] if "?" in r.path else ""))
        cands = self.index.get(k)
        if cands:
            bh = body_hash(r.get_content(strict=False))
            same = [c for c in cands if c[1].get("req_body") == bh] or cands
            ck = k + (bh,)
            i = self.cursor.get(ck, 0)
            name, e = same[min(i, len(same) - 1)]
            self.cursor[ck] = i + 1
            body = base64.b64decode(e["b64"]) if "b64" in e else e.get("text", "").encode()
            flow.response = http.Response.make(e["status"], body, [(h.encode(), v.encode()) for h, v in e["headers"]])
            flow.metadata["proxy_local"] = True
            pos = f" {min(i, len(same) - 1) + 1}/{len(same)}" if len(same) > 1 else ""
            flow.comment = (flow.comment + " | " if flow.comment else "") + f"collection:{name}{pos}"
        elif self.cfg.get("strict") and self._record_matches(r.pretty_url):
            flow.response = http.Response.make(404, json.dumps({"error": "not in the replayed collection (strict mode)"}),
                                               {"Content-Type": "application/json"})
            flow.metadata["proxy_local"] = True
            flow.comment = (flow.comment + " | " if flow.comment else "") + "collection: strict miss"

    def _record_matches(self, url):
        pattern = self.cfg.get("record_match") or self.default_record
        if getattr(self, "_record_src", None) != pattern:
            try:
                self._record_re = user_regex(pattern)
            except re.error as e:      # an unsafe or broken pattern records / strict-misses nothing (F-05)
                ctx.log.warn(f"proxy_collections: record_match refused: {e}")
                self._record_re = None
            self._record_src = pattern
        return bool(self._record_re and self._record_re.search(url))

    def response(self, flow: http.HTTPFlow):
        self._reload()
        name = self.cfg.get("recording")
        # proxy_rules is loaded before this add-on, so its response hook marks rewrites first.
        if not name or name in self.deleted or flow.metadata.get("proxy_local") \
                or flow.metadata.get("proxy_modified") or not flow.response:
            return
        if not self._record_matches(flow.request.pretty_url):
            return
        try:
            doc = self._recording_doc(name)
            doc["entries"].append(entry_from_flow(flow))
            self.dirty.add(name)
            self._schedule_flush()
            flow.comment = (flow.comment + " | " if flow.comment else "") + f"recorded → {name}"
        except Exception as e:
            ctx.log.warn(f"proxy_collections: could not record into '{name}': {e}")


addons = [ProxyCollections()]
