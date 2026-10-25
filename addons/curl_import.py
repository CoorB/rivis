"""Parse a copied cURL command into a Compose request without executing it."""
import base64
import re
import shlex
from urllib.parse import quote, urlsplit, urlunsplit


_ANSI_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "'": "'", '"': '"', "0": "\0", "a": "\a", "b": "\b",
                 "e": "\x1b", "E": "\x1b", "f": "\f", "v": "\v", "?": "?"}


def _ansi_c_quotes(command):
    """Chrome's "Copy as cURL" writes bodies as bash $'...' strings (\\' and \\n inside), which shlex does not know: turn each
    one into an ordinary single-quoted word with its escapes decoded."""
    out, i = [], 0
    while i < len(command):
        if command.startswith("$'", i) and (i == 0 or command[i - 1] in " \t="):
            j, text = i + 2, []
            while j < len(command) and command[j] != "'":
                if command[j] == "\\" and j + 1 < len(command):
                    nxt = command[j + 1]
                    m = re.match(r"x([0-9a-fA-F]{1,2})|u([0-9a-fA-F]{4})", command[j + 1:])
                    if m:
                        text.append(chr(int(m.group(1) or m.group(2), 16)))
                        j += 1 + len(m.group(0))
                        continue
                    text.append(_ANSI_ESCAPES.get(nxt, "\\" + nxt))
                    j += 2
                    continue
                text.append(command[j])
                j += 1
            if j >= len(command):
                raise ValueError("Invalid cURL quoting: no closing quote after $'")
            out.append("'" + "".join(text).replace("'", "'\"'\"'") + "'")
            i = j + 1
            continue
        out.append(command[i])
        i += 1
    return "".join(out)


def parse_curl(command):
    if not isinstance(command, str) or not command.strip():
        raise ValueError("Paste a cURL command")
    # DevTools and Postman split long shell commands with backslash-newline.
    command = re.sub(r"\\\r?\n[ \t]*", "", command.strip())
    command = _ansi_c_quotes(command)
    try:
        args = shlex.split(command)
    except ValueError as exc:
        raise ValueError("Invalid cURL quoting: %s" % exc)
    if not args or args[0].lower() not in ("curl", "curl.exe"):
        raise ValueError("Command must start with curl")
    method, explicit, get_data, url = "GET", False, False, None
    headers, data, ignored = [], [], []
    values = ("-X", "--request", "-H", "--header", "-d", "--data", "--data-raw", "--data-binary",
              "--data-urlencode", "-u", "--user", "-b", "--cookie", "--url")
    i = 1
    while i < len(args):
        token = args[i]
        key, eq, attached = token.partition("=") if token.startswith("--") else (token, "", "")
        if not eq and token.startswith(("-X", "-H", "-d", "-u", "-b")) and len(token) > 2:
            key, attached, eq = token[:2], token[2:], "="
        if key in values:
            if not eq:
                i += 1
                if i >= len(args):
                    raise ValueError("Missing value for %s" % key)
                attached = args[i]
            if key in ("-X", "--request"):
                method, explicit = attached.upper(), True
            elif key in ("-H", "--header"):
                name, sep, value = attached.partition(":")
                if not sep or not name.strip():
                    raise ValueError("Header must contain a name and colon")
                headers.append([name.strip(), value.lstrip(), True])
            elif key in ("-u", "--user"):
                secret = base64.b64encode(attached.encode("utf-8")).decode("ascii")
                headers.append(["Authorization", "Basic " + secret, True])
            elif key in ("-b", "--cookie"):
                headers.append(["Cookie", attached, True])
            elif key == "--url":
                url = attached
            else:
                if key == "--data-urlencode":
                    name, sep, value = attached.partition("=")
                    attached = name + "=" + quote(value, safe="") if sep else quote(attached, safe="")
                data.append(attached)
        elif token in ("-G", "--get"):
            get_data = True
        elif token in ("--compressed", "-k", "--insecure"):
            if token in ("-k", "--insecure"):
                ignored.append(token + " (TLS verification setting is not imported)")
        elif token.startswith("-"):
            ignored.append(token)
        elif re.match(r"^https?://", token, re.I):
            url = token
        else:
            ignored.append(token)
        i += 1
    if not url or not re.match(r"^https?://", url, re.I):
        raise ValueError("cURL needs an http:// or https:// URL")
    body = "&".join(data)
    if get_data and data:
        parts = urlsplit(url)
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query + ("&" if parts.query else "") + body, parts.fragment))
        body = ""
    if not explicit:
        method = "GET" if get_data else "POST" if data else "GET"
    spec = {"method": method, "url": url, "headers": headers, "body_mode": "raw" if body else "none", "body": body}
    return {"spec": spec, "ignored": ignored}
