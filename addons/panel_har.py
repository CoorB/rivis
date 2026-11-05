"""HAR import/export helpers for the panel (collection ↔ HAR, session HAR body cap and redaction).

Used by ProxyPanel.to_har / from_har / sess_har. No panel state; PRODUCT name only for the HAR creator field.
"""
import re

import proxy_redact
from proxy_common import PRODUCT

# F-03: a session HAR leaves out any single body larger than this (with a comment saying so). Redacting a 60 MB body
# took a minute of pure-Python regex that holds the interpreter lock, so even off the event loop it froze live traffic.
HAR_BODY_LIMIT = 4 * 1024 * 1024

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

def _har_reply(har, a):
    """HAR for the browser to download: secrets redacted unless the user ticked "Include secrets" (F-08)."""
    secrets_in = a.get("include_secrets") is True
    return {"har": har if secrets_in else proxy_redact.har(har), "redacted": not secrets_in,
            "filename": a["name"] + ".har"}

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
                   "headers": [[str(h["name"]), "" if h.get("value") is None else str(h["value"])]
                               for h in resp.get("headers", [])
                               if str(h.get("name") or "").lower() not in ("content-encoding", "content-length", "transfer-encoding", "connection")
                               and not str(h.get("name") or "").startswith(":")],
                   "recorded_at": _t.time()}
            # HAR exporters sometimes write "text": null for an empty body, and null header values. .get("text", "")
            # still returns None when the key is present, and replay then crashed on None.encode().
            text = c.get("text")
            if text is None:
                text = ""
            elif not isinstance(text, str):
                text = str(text)
            if c.get("encoding") == "base64":
                ent["b64"] = text
                base64.b64decode(ent["b64"])
            else:
                ent["text"] = text
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
