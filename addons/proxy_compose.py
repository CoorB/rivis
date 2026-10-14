"""Pure request-composer storage and normalization helpers (stdlib only)."""
import json
import os
import re
import tempfile
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from proxy_common import SAFE_NAME, confined_path

VAR_RE = re.compile(r"{{\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*}}")
METHOD_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}$")
HEADER_NAME_RE = METHOD_RE


def _rows(value):
    if not isinstance(value, list):
        raise ValueError("table rows must be a list")
    out = []
    for row in value:
        if not isinstance(row, (list, tuple)) or len(row) < 2:
            raise ValueError("table rows must contain name and value")
        if len(row) < 3 or row[2] is not False:
            out.append((str(row[0]), str(row[1])))
    return out


def substitute(text, variables):
    def repl(match):
        name = match.group(1)
        if name not in variables:
            raise ValueError("composer variable '%s' is not defined" % name)
        return str(variables[name])
    return VAR_RE.sub(repl, str(text))


def normalize_request(spec, variables=None):
    """Validate a saved/draft request and return method/url/header pairs/body bytes."""
    if not isinstance(spec, dict):
        raise ValueError("request must be an object")
    variables = variables or {}
    method = substitute(spec.get("method") or "GET", variables).upper()
    if not METHOD_RE.fullmatch(method):
        raise ValueError("invalid HTTP method")
    raw_url = substitute(spec.get("url") or "", variables)
    parsed = urlsplit(raw_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL must be an absolute http:// or https:// URL")
    query_source = spec.get("query")
    if query_source is None:
        query = parse_qsl(parsed.query, keep_blank_values=True)
    else:
        query = [(substitute(k, variables), substitute(v, variables)) for k, v in _rows(query_source)]
    url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(query, doseq=True), ""))   # a #fragment is never sent
    headers = []
    for key, value in _rows(spec.get("headers") or []):
        key, value = substitute(key, variables), substitute(value, variables)
        if not key.strip():
            continue
        if not HEADER_NAME_RE.fullmatch(key):
            raise ValueError("invalid HTTP header name")
        if any(ord(char) < 0x20 and char != "\t" for char in value) or "\x7f" in value:
            raise ValueError("invalid control character in HTTP header value")
        headers.append((key, value))
    supplied_body = substitute(spec.get("body") or "", variables)
    explicit_mode = "body_mode" in spec and spec.get("body_mode") not in (None, "")
    mode = str(spec.get("body_mode") or "none").lower()
    inferred_form = None
    if not explicit_mode and supplied_body:
        content_type = next((v.lower() for k, v in headers if k.lower() == "content-type"), "")
        if "application/x-www-form-urlencoded" in content_type:
            mode, inferred_form = "form", parse_qsl(supplied_body, keep_blank_values=True)
        elif "json" in content_type:
            mode = "json"
        else:
            try:
                json.loads(supplied_body)
                mode = "json"
            except ValueError:
                mode = "raw"
    if mode not in ("none", "json", "form", "raw"):
        raise ValueError("body mode must be none, json, form or raw")
    body = b""
    if mode == "json":
        text = supplied_body
        try:
            value = json.loads(text)
        except ValueError as exc:
            raise ValueError("JSON body is invalid: %s" % exc)
        body = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        if not any(k.lower() == "content-type" for k, _ in headers):
            headers.append(("Content-Type", "application/json"))
    elif mode == "form":
        form = inferred_form if inferred_form is not None else [
            (substitute(k, variables), substitute(v, variables)) for k, v in _rows(spec.get("form") or [])]
        body = urlencode(form, doseq=True).encode("utf-8")
        if not any(k.lower() == "content-type" for k, _ in headers):
            headers.append(("Content-Type", "application/x-www-form-urlencoded"))
    elif mode == "raw":
        body = supplied_body.encode("utf-8")
    return {"method": method, "url": url, "headers": headers, "body": body, "body_mode": mode}


class ComposerStore:
    def __init__(self, directory):
        self.directory = os.path.abspath(os.path.expanduser(directory))

    def _ensure(self):
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        os.chmod(self.directory, 0o700)

    def _path(self, name):
        if not SAFE_NAME.fullmatch(str(name or "")) or name == "vars":
            raise ValueError("name: letters, digits, . _ - only (max 64); 'vars' is reserved")
        path = os.path.abspath(os.path.join(self.directory, name + ".json"))
        if os.path.dirname(path) != self.directory:
            raise ValueError("bad composer name")
        # confine to the project state dir (the composer dir's parent): a symlink
        # planted in composer/ must not read or write outside the project (B5)
        return confined_path(os.path.dirname(self.directory), path, "saved request")

    def _vars_path(self):
        return confined_path(os.path.dirname(self.directory),
                             os.path.join(self.directory, "vars.json"), "composer variables")

    def _write(self, path, value):
        self._ensure()
        fd, tmp = tempfile.mkstemp(dir=self.directory, prefix=".composer-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(value, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
            os.chmod(path, 0o600)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def list(self):
        if not os.path.isdir(self.directory):
            return []
        return sorted(x[:-5] for x in os.listdir(self.directory)
                      if x.endswith(".json") and x != "vars.json" and SAFE_NAME.fullmatch(x[:-5]))

    def load(self, name):
        with open(self._path(name), encoding="utf-8") as fh:
            value = json.load(fh)
        if not isinstance(value, dict):
            raise ValueError("saved request is not an object")
        return value

    def save(self, name, value):
        if not isinstance(value, dict):
            raise ValueError("request must be an object")
        self._write(self._path(name), value)

    def rename(self, old, new):
        source, target = self._path(old), self._path(new)
        if os.path.exists(target):
            raise ValueError("a saved request named '%s' already exists" % new)
        os.replace(source, target)
        os.chmod(target, 0o600)

    def delete(self, name):
        os.unlink(self._path(name))

    def variables(self):
        path = self._vars_path()
        try:
            with open(path, encoding="utf-8") as fh:
                value = json.load(fh)
        except FileNotFoundError:
            return {}
        if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
            raise ValueError("composer/vars.json must be an object of string values")
        return value

    def save_variables(self, value):
        if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
            raise ValueError("variables must be an object of string values")
        for key in value:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", key):
                raise ValueError("invalid variable name '%s'" % key)
        self._write(self._vars_path(), value)
