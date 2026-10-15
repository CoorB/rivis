"""Secret redaction for files that leave Rivis (HAR exports).

A HAR lands in the browser's Downloads folder and from there in tickets and chats, so by default it must not carry
credentials (security finding F-08). Redaction is on unless the caller explicitly asks for secrets.

What becomes ``<redacted>``:
- header values whose name is a credential (Authorization, Cookie, Set-Cookie, API keys, CSRF/session/auth tokens);
- query parameters and JSON/form fields whose key looks like a secret (password, otp, pin, token, secret, …);
- anything shaped like a JWT, wherever it appears in a text body.
Structure (keys, status codes, non-secret values) is kept, so a redacted HAR still imports and replays.
"""

import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "<redacted>"

SECRET_HEADERS = frozenset((
    "authorization", "proxy-authorization", "cookie", "set-cookie", "set-cookie2",
    "x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token", "x-refresh-token", "x-id-token",
    "x-csrf-token", "x-xsrf-token", "x-session-id", "x-session-token", "x-amz-security-token",
))
_SECRET_HEADER_PART = re.compile(r"token|secret|session|api[-_]?key|auth", re.I)
# field names: whole-word-ish match so "pinned"/"opinion"/"spine" are not caught but "pin", "user_pin", "newPin" are
_SECRET_KEY = re.compile(
    r"(^|[_\-.])(pass(word|wd|code)?|pwd|otp|pin|cvv|cvc|secret|token|session(id)?|cookie|authorization|"
    r"api[_\-]?key|private[_\-]?key|client[_\-]?secret|credentials?)($|[_\-.])"
    r"|(password|passcode|otp|pin|secret|token|apikey|apiKey|sessionid|sessionId)$"
    r"|^(access|refresh|id|auth|bearer)[_\-]?token", re.I)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")


def secret_header(name):
    lower = (name or "").lower()
    return lower in SECRET_HEADERS or bool(_SECRET_HEADER_PART.search(lower))


def secret_key(key):
    return isinstance(key, str) and bool(_SECRET_KEY.search(key))


def _value(obj):
    """Redact secret-named fields and JWT-shaped strings inside parsed JSON."""
    if isinstance(obj, dict):
        return {k: (REDACTED if secret_key(k) and v not in (None, "") and not isinstance(v, (dict, list)) else _value(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [_value(v) for v in obj]
    if isinstance(obj, str):
        return _JWT.sub(REDACTED, obj)
    return obj


def text(body, mime=""):
    """Redact a text body: JSON by structure, form-encoded by field name, anything else by JWT shape."""
    if not body:
        return body
    stripped = body.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            return json.dumps(_value(json.loads(body)), ensure_ascii=False)
        except (ValueError, RecursionError):   # not JSON, or nested too deep to walk: redact it as text
            pass
    if "x-www-form-urlencoded" in (mime or "").lower():
        return query(body)
    return _JWT.sub(REDACTED, body)


def query(qs):
    if not qs:
        return qs
    pairs = parse_qsl(qs, keep_blank_values=True)
    if not pairs:
        return _JWT.sub(REDACTED, qs)
    return urlencode([(k, REDACTED if secret_key(k) and v else _JWT.sub(REDACTED, v)) for k, v in pairs])


def url(u):
    parts = urlsplit(u)
    netloc = parts.netloc.rsplit("@", 1)[-1] if "@" in parts.netloc else parts.netloc   # user:pass@host
    return urlunsplit((parts.scheme, netloc, _JWT.sub(REDACTED, parts.path), query(parts.query), ""))


def _headers(rows):
    return [{**h, "value": REDACTED if secret_header(h.get("name")) else _JWT.sub(REDACTED, h.get("value") or "")}
            for h in rows or []]


def har(doc):
    """Return a redacted copy of a HAR 1.2 document (the input is not modified)."""
    doc = json.loads(json.dumps(doc))
    for e in (doc.get("log") or {}).get("entries") or []:
        req, resp = e.get("request") or {}, e.get("response") or {}
        if "url" in req:
            req["url"] = url(req["url"])
        for part in (req, resp):
            part["headers"] = _headers(part.get("headers"))
            part["cookies"] = [{**c, "value": REDACTED} for c in part.get("cookies") or []]
        req["queryString"] = [{**q, "value": REDACTED if secret_key(q.get("name")) else q.get("value")}
                              for q in req.get("queryString") or []]
        post = req.get("postData")
        if post and post.get("text"):
            post["text"] = text(post["text"], post.get("mimeType", ""))
        content = resp.get("content") or {}
        if content.get("text") and content.get("encoding") != "base64":
            content["text"] = text(content["text"], content.get("mimeType", ""))
            content["size"] = len(content["text"])
    doc.setdefault("log", {})["comment"] = "Secrets redacted by Rivis (credential headers, cookies, secret fields, JWTs)."
    return doc
