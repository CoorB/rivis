"""Request snippet generation. Pure stdlib; safe to import outside mitmproxy."""
import base64
import json
import pprint
import re
import shlex
from urllib.parse import unquote

import proxy_redact

TARGETS = (
    ("curl", "cURL"), ("httpie", "HTTPie"), ("wget", "wget"),
    ("python", "Python requests"), ("fetch", "JavaScript fetch"),
    ("axios", "Node axios"), ("swift", "Swift URLSession"),
    ("kotlin", "Kotlin OkHttp"), ("java", "Java HttpClient"),
    ("go", "Go net/http"), ("powershell", "PowerShell Invoke-RestMethod"),
    ("postman", "Postman collection (v2.1)"),
)
TARGET_IDS = frozenset(x[0] for x in TARGETS)
DROP_HEADERS = frozenset(("connection", "content-length", "keep-alive", "proxy-authenticate", "proxy-connection",  # R7A-04: proxy-only, not for direct replay
                          "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"))
SECRET_HEADERS = frozenset(("authorization", "cookie"))


def _quoted(value):
    return json.dumps(str(value), ensure_ascii=False).replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def _swift(value):
    # Swift writes unicode escapes as \u{XXXX}; JSON's \uXXXX is a compile error there.
    text = _quoted(value).replace("\\/", "/")
    return re.sub(r"(\\\\)|\\u([0-9a-fA-F]{4})",
                  lambda m: m.group(1) or "\\u{%s}" % m.group(2), text)


def _kotlin_str(value):
    return _quoted(value).replace("$", "\\$")      # Kotlin interpolates $name inside "..."


def _powershell(value):
    # PowerShell also treats the typographic single quotes as quote characters
    return "'" + "".join(c + c if c in "'\u2018\u2019\u201a\u201b" else c for c in str(value)) + "'"


def _headers(rows, mask):
    out = []
    for key, value in rows or []:
        key, value = str(key), str(value)
        lower = key.lower()
        if key.startswith(":") or lower in DROP_HEADERS:
            continue
        if mask and (lower in SECRET_HEADERS or proxy_redact.secret_header(lower)):
            value = "<redacted>"
        out.append((key, value))
    return out


def _group_headers(rows):
    grouped, spelling = {}, {}
    for key, value in rows:
        lower = key.lower()
        spelling.setdefault(lower, key)
        grouped.setdefault(lower, []).append(value)
    result = []
    for lower, values in grouped.items():
        separator = "; " if lower == "cookie" else ", "
        result.append((spelling[lower], separator.join(values)))
    return result


def _body_info(request):
    raw = request.get("body") or b""
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not isinstance(raw, bytes):
        raw = bytes(raw)
    ctype = next((v for k, v in request.get("headers") or [] if str(k).lower() == "content-type"), "").lower()
    try:
        text = raw.decode("utf-8")
        binary = False
    except UnicodeDecodeError:
        text, binary = "", True
    native = None
    if not binary and raw and ("json" in ctype or text.lstrip().startswith(("{", "["))):
        try:
            native = json.loads(text)
        except (ValueError, RecursionError):
            pass
    return raw, text, binary, native


def _shell_prefix(binary, raw):
    if not binary:
        return "", ""
    encoded = base64.b64encode(raw).decode("ascii")
    return "# Binary body: base64-decoded before sending.\nprintf '%s' %s | base64 -d | " % ("%s", shlex.quote(encoded)), "@-"


def _curl(method, url, headers, raw, text, binary):
    prefix, body_ref = _shell_prefix(binary, raw)
    parts = ["curl -X " + shlex.quote(method)]
    for key, value in headers:
        parts.append("-H " + shlex.quote(key + ": " + value))
    if raw:
        parts.append("--data-binary " + (body_ref if binary else shlex.quote(text)))
    parts.append(shlex.quote(url))
    return prefix + " \\\n  ".join(parts)


def _httpie(method, url, headers, raw, text, binary):
    prefix, _ = _shell_prefix(binary, raw)
    # --raw sends the body byte for byte (a here-string would append a newline); a binary body
    # arrives on stdin from the base64 pipe above
    options = "" if binary else (" --raw " + shlex.quote(text) if raw else " --ignore-stdin")
    parts = ["http" + options + " " + shlex.quote(method) + " " + shlex.quote(url)]
    parts += [shlex.quote(key + (":" + value if value else ";")) for key, value in headers]
    return prefix + " \\\n  ".join(parts)


def _wget(method, url, headers, raw, text, binary):
    lines = []
    body_arg = []
    if binary:
        encoded = base64.b64encode(raw).decode("ascii")
        lines = ["# Binary body: decoded into a temporary file.", "body_file=$(mktemp)",
                 "printf '%%s' %s | base64 -d > \"$body_file\"" % shlex.quote(encoded)]
        body_arg = ['--body-file="$body_file"']
    elif raw:
        body_arg = ["--body-data=" + shlex.quote(text)]
    parts = ["wget --method=" + shlex.quote(method)]
    parts += ["--header=" + shlex.quote(key + ": " + value) for key, value in headers]
    parts += body_arg + ["-O - " + shlex.quote(url)]
    lines.append(" \\\n  ".join(parts))
    if binary:
        lines.append('rm -f "$body_file"')
    return "\n".join(lines)


def _python(method, url, headers, raw, text, binary, native):
    grouped = dict(_group_headers(headers))
    imports = ["import requests"]
    body = ""
    if raw:
        if binary:
            imports.insert(0, "import base64")
            body = ",\n    data=base64.b64decode(%s)  # binary body" % repr(base64.b64encode(raw).decode("ascii"))
        elif native is not None:
            body = ",\n    json=" + pprint.pformat(native, width=88, sort_dicts=False)
        else:
            body = ",\n    data=" + repr(text)
    header_literal = ("{\n" + "".join("        %r: %r,\n" % kv for kv in grouped.items()) + "    }") if grouped else "{}"
    return "%s\n\nresponse = requests.request(\n    %r,\n    %r,\n    headers=%s%s,\n)\nresponse.raise_for_status()\nprint(response.text)" % (
        "\n".join(imports), method, url, header_literal, body)


def _javascript(method, url, headers, raw, text, binary, native, axios=False):
    grouped = dict(_group_headers(headers))
    if binary:
        encoded = base64.b64encode(raw).decode("ascii")
        data = ("Buffer.from(%s, \"base64\") // binary body" % _quoted(encoded)) if axios else (
            "Uint8Array.from(atob(%s), c => c.charCodeAt(0)) // binary body" % _quoted(encoded))
    elif native is not None:
        literal = json.dumps(native, indent=2, ensure_ascii=False)
        data = literal if axios else "JSON.stringify(" + literal + ")"
    else:
        data = _quoted(text)
    headers_js = json.dumps(grouped, indent=2, ensure_ascii=False)
    if axios:
        fields = ["  method: %s" % _quoted(method), "  url: %s" % _quoted(url), "  headers: " + headers_js.replace("\n", "\n  ")]
        if raw: fields.append("  data: " + data.replace("\n", "\n  "))
        return "import axios from \"axios\";\n\nconst response = await axios({\n%s\n});\nconsole.log(response.data);" % ",\n".join(fields)
    fields = ["  method: %s" % _quoted(method), "  headers: " + headers_js.replace("\n", "\n  ")]
    if raw: fields.append("  body: " + data.replace("\n", "\n  "))
    return "const response = await fetch(%s, {\n%s\n});\nif (!response.ok) throw new Error(`HTTP ${response.status}`);\nconsole.log(await response.text());" % (
        _quoted(url), ",\n".join(fields))


def _swift_code(method, url, headers, raw, text, binary):
    lines = ["import Foundation", "", "var request = URLRequest(url: URL(string: %s)!)" % _swift(url),
             "request.httpMethod = %s" % _swift(method)]
    for key, value in headers:
        lines.append("request.addValue(%s, forHTTPHeaderField: %s)" % (_swift(value), _swift(key)))
    if raw:
        if binary:
            lines.append("request.httpBody = Data(base64Encoded: %s)! // binary body" % _swift(base64.b64encode(raw).decode("ascii")))
        else:
            lines.append("request.httpBody = %s.data(using: .utf8)" % _swift(text))
    lines += ["", "let (data, response) = try await URLSession.shared.data(for: request)",
              "print(String(decoding: data, as: UTF8.self))"]
    return "\n".join(lines)


def _kotlin(method, url, headers, raw, text, binary):
    if binary:
        body = "Base64.getDecoder().decode(%s).toRequestBody(null) // binary body" % _kotlin_str(base64.b64encode(raw).decode("ascii"))
    else:
        body = "%s.toRequestBody(null)" % _kotlin_str(text)
    lines = ["import java.util.Base64", "import okhttp3.MediaType.Companion.toMediaTypeOrNull",
             "import okhttp3.OkHttpClient", "import okhttp3.Request", "import okhttp3.RequestBody.Companion.toRequestBody", "",
             "val builder = Request.Builder().url(%s)" % _kotlin_str(url)]
    for key, value in headers:
        lines.append("builder.addHeader(%s, %s)" % (_kotlin_str(key), _kotlin_str(value)))
    body_expr = body if raw else "null"
    lines += ["val request = builder.method(%s, %s).build()" % (_kotlin_str(method), body_expr),
              "OkHttpClient().newCall(request).execute().use { response ->",
              "    check(response.isSuccessful) { \"HTTP ${response.code}\" }", "    println(response.body?.string())", "}"]
    return "\n".join(lines)


def _java(method, url, headers, raw, text, binary):
    lines = ["import java.net.URI;", "import java.net.http.HttpClient;", "import java.net.http.HttpRequest;",
             "import java.net.http.HttpResponse;", "import java.util.Base64;", "",
             "var builder = HttpRequest.newBuilder(URI.create(%s));" % _quoted(url)]
    for key, value in headers:
        lines.append("builder.header(%s, %s);" % (_quoted(key), _quoted(value)))
    if not raw:
        publisher = "HttpRequest.BodyPublishers.noBody()"
    elif binary:
        publisher = "HttpRequest.BodyPublishers.ofByteArray(Base64.getDecoder().decode(%s)) /* binary body */" % _quoted(base64.b64encode(raw).decode("ascii"))
    else:
        publisher = "HttpRequest.BodyPublishers.ofString(%s)" % _quoted(text)
    lines += ["var request = builder.method(%s, %s).build();" % (_quoted(method), publisher),
              "var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());",
              "System.out.println(response.body());"]
    return "\n".join(lines)


def _go(method, url, headers, raw, text, binary):
    imports = ['"fmt"', '"io"', '"net/http"']
    if raw:
        imports.append('"strings"')
    if binary:
        imports.append('"encoding/base64"')
        body_lines = ["bodyBytes, _ := base64.StdEncoding.DecodeString(%s) // binary body" % _quoted(base64.b64encode(raw).decode("ascii")),
                      "body := strings.NewReader(string(bodyBytes))"]
    else:
        body_lines = ["body := strings.NewReader(%s)" % _quoted(text)]
    lines = ["package main", "", "import (", *("\t" + x for x in sorted(imports)), ")", "", "func main() {"]
    if raw: lines += ["\t" + x for x in body_lines]
    lines.append("\treq, err := http.NewRequest(%s, %s, %s)" % (_quoted(method), _quoted(url), "body" if raw else "nil"))
    lines.append("\tif err != nil { panic(err) }")
    for key, value in headers:
        lines.append("\treq.Header.Add(%s, %s)" % (_quoted(key), _quoted(value)))
    lines += ["\tresp, err := http.DefaultClient.Do(req)", "\tif err != nil { panic(err) }", "\tdefer resp.Body.Close()",
              "\tdata, _ := io.ReadAll(resp.Body)", "\tfmt.Println(string(data))", "}"]
    return "\n".join(lines)


def _ps(method, url, headers, raw, text, binary):
    grouped = _group_headers(headers)
    h = "@{" + "; ".join(_powershell(k) + " = " + _powershell(v) for k, v in grouped) + "}"
    lines = ["$headers = " + h]
    body_arg = ""
    if raw:
        if binary:
            lines.append("$body = [Convert]::FromBase64String(%s) # binary body" % _powershell(base64.b64encode(raw).decode("ascii")))
        else:
            lines.append("$body = %s" % _powershell(text))
        body_arg = " -Body $body"
    lines.append("Invoke-RestMethod -Method %s -Uri %s -Headers $headers%s" % (
        _powershell(method), _powershell(url), body_arg))
    return "\n".join(lines)


def _postman(method, url, headers, raw, text, binary):
    item = {"name": "%s %s" % (method, url), "request": {"method": method,
            "header": [{"key": k, "value": v, "type": "text"} for k, v in headers], "url": url}}
    if raw:
        if binary:
            item["request"]["description"] = "Binary request body is base64 below; decode it before sending."
            item["request"]["body"] = {"mode": "raw", "raw": base64.b64encode(raw).decode("ascii")}
        else:
            item["request"]["body"] = {"mode": "raw", "raw": text}
    collection = {"info": {"name": "Copied call", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
                  "item": [item]}
    return json.dumps(collection, indent=2, ensure_ascii=False)


_QUERY_PAIR = re.compile(r"(^|&)([^=&]*)=([^&]*)")


def _mask_url(url):
    """Hide credentials in a URL without re-encoding the rest (user:pass@, secret query values, JWTs)."""
    scheme, sep, rest = url.partition("://")
    if sep:
        authority, slash, tail = rest.partition("/")
        url = scheme + sep + authority.rsplit("@", 1)[-1] + slash + tail
    base, q, query = url.partition("?")
    if q:
        query, hsh, frag = query.partition("#")
        query = _QUERY_PAIR.sub(lambda m: m.group(1) + m.group(2) + "=" + (
            proxy_redact.REDACTED if proxy_redact.secret_key(unquote(m.group(2))) and m.group(3) else m.group(3)), query)
        url = base + q + query + hsh + frag
    return proxy_redact._JWT.sub(proxy_redact.REDACTED, url)


def _mask_body(request, headers):
    body = request.get("body")
    if not body:
        return request
    try:
        text = body.decode("utf-8") if isinstance(body, (bytes, bytearray)) else str(body)
    except UnicodeDecodeError:
        return request
    ctype = next((v for k, v in headers if k.lower() == "content-type"), "")
    masked = proxy_redact.text(text, ctype)
    if masked == text:
        return request
    try:      # JSON is re-serialised by the redactor; keep the original bytes when nothing secret was in it
        if json.loads(masked) == json.loads(text):
            return request
    except (ValueError, RecursionError):
        pass
    return {**request, "body": masked.encode("utf-8")}


def generate(request, target="curl", mask_secrets=True):
    """Generate one ready-to-run representation from a normalized request mapping.

    mask_secrets (default on): credential headers, cookies, secret query/body fields and JWTs become <redacted>
    (F-11), using the same rules as HAR export redaction."""
    if target not in TARGET_IDS:
        raise ValueError("unknown code-generation target '%s'" % target)
    method, url = str(request.get("method") or "GET").upper(), str(request.get("url") or "")
    headers = _headers(request.get("headers") or [], bool(mask_secrets))
    if mask_secrets:
        url = _mask_url(url)
        request = _mask_body(request, headers)
    raw, text, binary, native = _body_info({**request, "headers": headers})
    if target == "curl": return _curl(method, url, headers, raw, text, binary)
    if target == "httpie": return _httpie(method, url, headers, raw, text, binary)
    if target == "wget": return _wget(method, url, headers, raw, text, binary)
    if target == "python": return _python(method, url, headers, raw, text, binary, native)
    if target == "fetch": return _javascript(method, url, headers, raw, text, binary, native)
    if target == "axios": return _javascript(method, url, headers, raw, text, binary, native, True)
    if target == "swift": return _swift_code(method, url, headers, raw, text, binary)
    if target == "kotlin": return _kotlin(method, url, headers, raw, text, binary)
    if target == "java": return _java(method, url, headers, raw, text, binary)
    if target == "go": return _go(method, url, headers, raw, text, binary)
    if target == "powershell": return _ps(method, url, headers, raw, text, binary)
    return _postman(method, url, headers, raw, text, binary)
