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


def _windows_args(command):
    """Chrome/Edge "Copy as cURL (cmd)": every argument is wrapped in ^"...^", special characters carry a ^ (cmd.exe's
    escape), lines continue with ' ^', and a newline inside a value is ^ followed by two line breaks. Undo cmd.exe's layer,
    then split the way a Windows program reads its command line (\\" is a quote, backslashes count only before a quote)."""
    text, i, quoted = [], 0, False
    while i < len(command):
        c = command[i]
        if c == "^" and not quoted:
            nl = re.match(r"\r?\n", command[i + 1:])
            if nl:
                j = i + 1 + len(nl.group(0))
                nl2 = re.match(r"\r?\n", command[j:])
                if nl2:                                   # ^ + two line breaks: a newline inside the value
                    text.append("\n")
                    i = j + len(nl2.group(0))
                else:                                     # ' ^' at the end of a line: the command continues
                    text.append(" ")
                    i = j
                continue
            if i + 1 < len(command):
                text.append(command[i + 1])
                i += 2
                continue
        if c == '"':
            quoted = not quoted
        text.append(c)
        i += 1
    line, args, cur, has, i, quoted = "".join(text), [], [], False, 0, False
    chrome = '^"' in command
    while i < len(line):
        c = line[i]
        if c == "\\":
            n = len(re.match(r"\\+", line[i:]).group(0))
            if i + n < len(line) and line[i + n] == '"':
                cur.append("\\" * (n // 2))
                if n % 2:
                    cur.append('"')
                    i += n + 1
                else:
                    i += n
                has = True
                continue
            cur.append("\\" * (n // 2 if chrome and n % 2 == 0 else n))   # DevTools doubled every backslash first
            i += n
            has = True
            continue
        if c == '"':
            if quoted and line[i + 1:i + 2] == '"':          # "" inside quotes: a literal quote
                cur.append('"')
                i += 2
                continue
            quoted, has = not quoted, True
            i += 1
            continue
        if c in " \t\r\n" and not quoted:
            if has:
                args.append("".join(cur))
                cur, has = [], False
            i += 1
            continue
        cur.append(c)
        has = True
        i += 1
    if quoted:
        raise ValueError("Invalid cURL quoting: no closing quote")
    if has:
        args.append("".join(cur))
    return args


def parse_curl(command):
    if not isinstance(command, str) or not command.strip():
        raise ValueError("Paste a cURL command")
    command = command.strip()
    if '^"' in command or re.search(r" \^\r?\n", command):     # Windows "Copy as cURL (cmd)"
        args = _windows_args(command)
    else:
        # DevTools and Postman split long shell commands with backslash-newline.
        command = _ansi_c_quotes(re.sub(r"\\\r?\n[ \t]*", "", command))
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
    url = re.sub(r"\\([\[\]{}])", r"\1", url)       # DevTools escapes curl's URL globbing characters: \[ \] \{ \}
    from urllib.parse import urlsplit as _urlsplit
    parsed = _urlsplit(url)
    if not parsed.netloc or not parsed.hostname:
        raise ValueError("cURL needs a URL with a host name")
    body = "&".join(data)
    if get_data and data:
        parts = urlsplit(url)
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query + ("&" if parts.query else "") + body, parts.fragment))
        body = ""
    if not explicit:
        method = "GET" if get_data else "POST" if data else "GET"
    spec = {"method": method, "url": url, "headers": headers, "body_mode": "raw" if body else "none", "body": body}
    return {"spec": spec, "ignored": ignored}
