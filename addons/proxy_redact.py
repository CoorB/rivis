"""Secret redaction for files that leave Rivis (HAR exports).

A HAR lands in the browser's Downloads folder and from there in tickets and chats, so by default it must not carry
credentials (security finding F-08). Redaction is on unless the caller explicitly asks for secrets.

What becomes ``<redacted>``:
- header values whose name is a credential (Authorization, Cookie, Set-Cookie, API keys, CSRF/session/auth tokens);
- query parameters and JSON/form fields whose key looks like a secret (password, otp, pin, token, secret, …);
- anything shaped like a JWT, wherever it appears in a text body.
Structure (keys, status codes, non-secret values) is kept, so a redacted HAR still imports and replays.
"""

import base64
import binascii
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
_SECRET_HEADER_FIELD = re.compile(r"(^|[-_])(otp|pin|pass(word|code)?|pwd|cvv|cvc|csrf|xsrf|mfa)([-_]|$)", re.I)
# field names: whole-word-ish match so "pinned"/"opinion"/"spine" are not caught but "pin", "user_pin", "newPin" are
_SECRET_KEY = re.compile(
    r"(^|[_\-.])(pass(word|wd|code)?|pwd|otp|pin|cvv|cvc|secret|token|session(id)?|cookie|authorization|"
    r"api[_\-]?key|private[_\-]?key|client[_\-]?secret|credentials?)($|[_\-.])"
    r"|(password|passcode|otp|pin|secret|token|apikey|apiKey|sessionid|sessionId)$"
    r"|^(access|refresh|id|auth|bearer)[_\-]?token", re.I)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_EXTRA_SECRET_KEY = re.compile(
    r"^(password|passcode|otp|pin|cvv|cvc|secret)(_|\d|$)|^(auth_?code|code_verifier|mfa_?code)$", re.I)
_BEARER = re.compile(r"\b(Bearer)[ \t]+(?!<redacted>)[A-Za-z0-9._~+/=-]{6,}", re.I)
# Opening tags and multipart field headers are found with linear patterns; the value is then located with str.find,
# only for secret-named fields and within a bounded window. A backreferenced (.*?)</key> pattern scanned to the end of
# the body for every tag: 278 s on a 1 MB HTML page.
_XML_OPEN = re.compile(r"<(?P<key>[A-Za-z_][\w:.-]{0,63})\b[^<>]{0,512}>")
_MULTIPART_NAME = re.compile(r"\bname=[\"'](?P<key>[A-Za-z_][\w.-]{0,63})[\"']", re.I)
_SCAN_WINDOW = 65536
_ASSIGN_VALUE = re.compile(
    r"(?P<key>[A-Za-z_][\w.-]{0,63})(?P<sep>\s*=\s*)(?P<quote>[\"']?)(?P<value>[^&\s<>\"']+)(?P=quote)")
_JSON_VALUE = re.compile(
    r"(?P<prefix>[\"'](?P<key>[A-Za-z_][\w.-]{0,63})[\"']\s*:\s*[\"'])(?P<value>.*?)(?P<suffix>[\"'])")
_HTML_INPUT = re.compile(r"<input\b[^>]*>", re.I)
_HTML_NAME = re.compile(r"\bname\s*=\s*([\"'])(.*?)\1", re.I)
_HTML_VALUE = re.compile(r"(\bvalue\s*=\s*)([\"'])(.*?)\2", re.I)


def secret_header(name):
    lower = (name or "").lower()
    return lower in SECRET_HEADERS or bool(_SECRET_HEADER_PART.search(lower) or _SECRET_HEADER_FIELD.search(lower))


def secret_key(key):
    if not isinstance(key, str):
        return False
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).replace("-", "_").replace(".", "_")
    return bool(_SECRET_KEY.search(key) or _EXTRA_SECRET_KEY.search(normalized))


def _value(obj, depth=0):
    """Redact secret-named fields and JWT-shaped strings inside parsed JSON (and JSON nested in strings)."""
    if isinstance(obj, dict):
        name = obj.get("name")
        if isinstance(name, str) and (secret_header(name) or secret_key(name)) and "value" in obj:
            obj = dict(obj)
            if obj["value"] not in (None, ""):
                obj["value"] = REDACTED
        return {k: (REDACTED if secret_key(k) and v not in (None, "") else _value(v, depth))
                for k, v in obj.items()}
    if isinstance(obj, list):
        if len(obj) == 2 and isinstance(obj[0], str) and (secret_header(obj[0]) or secret_key(obj[0])):
            return [obj[0], REDACTED if obj[1] not in (None, "") else obj[1]]
        return [_value(v, depth) for v in obj]
    if isinstance(obj, str):
        stripped = obj.strip()
        if depth < 4 and stripped[:1] in ("{", "[") and len(stripped) <= 2_000_000:
            try:   # JSON sent as a string inside JSON (echoed bodies, wrapped payloads): redact it by field name too
                return json.dumps(_value(json.loads(stripped), depth + 1), ensure_ascii=False)
            except (ValueError, RecursionError):
                pass
        if "=" in stripped and ("&" in stripped or secret_key(stripped.split("=", 1)[0])):
            pairs = parse_qsl(stripped, keep_blank_values=True)
            if pairs and any(secret_key(k) for k, _ in pairs):
                return query(stripped)
        return _loose(obj)
    return obj


def _spans(body, starts, end_of):
    """Rebuild body with each (value_start, value_end) span replaced by REDACTED; spans are in order, non-overlapping."""
    out, last = [], 0
    for start in starts:
        if start < last:
            continue
        end = end_of(start)
        if end is None or end <= start:
            continue
        out.append(body[last:start]); out.append(REDACTED); last = end
    out.append(body[last:])
    return "".join(out)


def _xml(body):
    """<password>…</password> → <password><redacted></password>, for secret-named elements only."""
    if "<" not in body:
        return body
    found = []
    for m in _XML_OPEN.finditer(body):
        if not secret_key(m.group("key")) or m.group(0).endswith("/>"):
            continue
        close = body.find("</" + m.group("key"), m.end(), m.end() + _SCAN_WINDOW)
        if close > m.end() and "<" not in body[m.end():close]:
            found.append((m.end(), close))
    ends = dict(found)
    return _spans(body, [a for a, _ in found], ends.get)


def _multipart(body):
    """Content-Disposition: form-data; name="otp" → its part body becomes REDACTED."""
    if "--" not in body or "name=" not in body:
        return body
    found = []
    for m in _MULTIPART_NAME.finditer(body):
        if not secret_key(m.group("key")):
            continue
        blank = body.find("\n\n", m.end(), m.end() + 4096)
        crlf = body.find("\r\n\r\n", m.end(), m.end() + 4096)
        cands = [(x, 2) for x in (blank,) if x >= 0] + [(x, 4) for x in (crlf,) if x >= 0]
        if not cands:
            continue
        start = min(x + n for x, n in cands)
        end = body.find("\n--", start, start + _SCAN_WINDOW)
        if end < 0:
            continue
        if end > start and body[end - 1] == "\r":
            end -= 1
        if end > start:
            found.append((start, end))
    ends = dict(found)
    return _spans(body, [a for a, _ in found], ends.get)


def _loose(body):
    """Best-effort masking for non-JSON text (XML, multipart, JSONP, plain assignments, opaque Bearer tokens)."""

    def assigned(m):
        in_query = m.start() > 0 and m.string[m.start() - 1] in "?&"         # ?code= / &code= : an OAuth code in a URL
        secret = secret_key(m.group("key")) or (in_query and m.group("key").lower() == "code")
        value = REDACTED if secret and m.group("value") else m.group("value")
        return m.group("key") + m.group("sep") + m.group("quote") + value + m.group("quote")

    def json_value(m):
        value = REDACTED if secret_key(m.group("key")) and m.group("value") else m.group("value")
        return m.group("prefix") + value + m.group("suffix")


    def html_input(m):
        tag = m.group(0)
        name = _HTML_NAME.search(tag)
        if not name or not secret_key(name.group(2)):
            return tag
        return _HTML_VALUE.sub(lambda v: v.group(1) + v.group(2) + REDACTED + v.group(2), tag)

    body = _multipart(body)
    body = _HTML_INPUT.sub(html_input, body)
    body = _xml(body)
    body = _JSON_VALUE.sub(json_value, body)
    body = _ASSIGN_VALUE.sub(assigned, body)
    body = _BEARER.sub(lambda m: m.group(1) + " " + REDACTED, body)
    return _JWT.sub(REDACTED, body)


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
    return _loose(body)


def query(qs):
    if not qs:
        return qs
    pairs = parse_qsl(qs, keep_blank_values=True)
    if not pairs:
        return _JWT.sub(REDACTED, qs)
    # an OAuth authorization "code" is a credential in a URL or form; in a JSON body "code" is usually an error code
    return urlencode([(k, REDACTED if (secret_key(k) or k.lower() == "code") and v else _JWT.sub(REDACTED, v)) for k, v in pairs])


def url(u):
    parts = urlsplit(u)
    netloc = parts.netloc.rsplit("@", 1)[-1] if "@" in parts.netloc else parts.netloc   # user:pass@host
    return urlunsplit((parts.scheme, netloc, _JWT.sub(REDACTED, parts.path), query(parts.query), ""))


def _headers(rows):
    out = []
    for h in rows or []:
        name, value = h.get("name"), h.get("value") or ""
        if secret_header(name):
            value = REDACTED
        elif (name or "").lower() in ("location", "content-location"):
            value = url(value)
        else:
            value = _loose(value)
        out.append({**h, "value": value})
    return out


def _base64_text(value, mime):
    """Decode/redact/re-encode HAR base64 content, preserving the original bytes when nothing can be masked."""
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return value
    charset = re.search(r"charset\s*=\s*[\"']?([A-Za-z0-9._-]+)", mime or "", re.I)
    encodings = ([charset.group(1)] if charset else []) + ["utf-8", "latin-1"]
    for encoding in encodings:
        try:
            decoded = raw.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
        masked = text(decoded, mime)
        if masked != decoded:
            try:
                return base64.b64encode(masked.encode(encoding)).decode("ascii")
            except (LookupError, UnicodeEncodeError):
                continue
    return value


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
        if content.get("text"):
            if content.get("encoding") == "base64":
                content["text"] = _base64_text(content["text"], content.get("mimeType", ""))
            else:
                content["text"] = text(content["text"], content.get("mimeType", ""))
            content["size"] = len(content["text"])
    doc.setdefault("log", {})["comment"] = "Secrets redacted by Rivis (credential headers, cookies, secret fields, JWTs)."
    return doc


_HEADER_LINE = re.compile(r"^([A-Za-z0-9!#$%&'*+.^_`|~-]+):[ \t]*(.*)$")


def raw_text(raw):
    """Redact raw HTTP text (request and/or response): secret header lines, then JWT-shaped values anywhere."""
    out, in_head, ctype = [], True, ""
    for line in raw.splitlines(keepends=True):
        bare = line.rstrip("\r\n")
        if not bare:
            in_head = False
        m = _HEADER_LINE.match(bare)
        if m and (in_head or secret_header(m.group(1))):
            in_head = True                                    # the response head of a combined request + response
            if m.group(1).lower() == "content-type":
                ctype = m.group(2)
            if secret_header(m.group(1)):
                line = "%s: %s%s" % (m.group(1), REDACTED, line[len(bare):])
        elif not in_head and bare.lstrip()[:1] in ("{", "["):
            line = text(bare, ctype) + line[len(bare):]       # a JSON body line: redact by field name too
        out.append(line)
    return _loose("".join(out))
