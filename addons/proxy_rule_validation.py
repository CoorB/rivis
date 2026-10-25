"""Shared per-rule load check for the proxy and CLI (R5A-02)."""
import re
import os
from urllib.parse import urlsplit

from proxy_common import ACTION_REQUIREMENTS, ACTIONS, rule_file_path, user_regex

_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def map_remote_warning(rule):
    """Warn when a simple match example cannot be changed by replace; regexes in general need a real URL."""
    if rule.get("action") != "map_remote":
        return None
    match, replace = rule.get("match", "."), rule.get("replace")
    if not isinstance(match, str) or not isinstance(replace, str):
        return None
    # R7A-02: a reversed rule (match=/remote, replace=https://new.host/echo) was ON but inert. A simple path has a
    # concrete example; skip complex regexes rather than guessing a URL that may not match them.
    if not re.fullmatch(r"/[A-Za-z0-9/_?&=.%+-]+", match):
        return None
    # B6: if replace is a full-URL pattern targeting a specific host/scheme and matches the path in match,
    # the rule works for that host; testing against example.test produces a false warning.
    try:
        if "://" in replace and user_regex(match).search(replace):
            return None
    except re.error:
        pass
    example = "https://example.test" + match
    try:
        if user_regex(match).search(example) and not user_regex(replace).search(example):
            return "replace=%r does not match example URL %s for match=%r; this rule may never rewrite a URL (replace is the URL pattern, with is the replacement)" % (replace, example, match)
    except re.error:
        pass
    return None


def _final_status(value):
    """R7B-01: a rule answers the call, so 1xx (interim, the client keeps waiting) cannot be its final status."""
    code = int(value)
    if not 200 <= code <= 599:
        raise ValueError("status %s: use a final status from 200 to 599 (1xx are interim answers)" % value)
    return code


def compile_rule(source, state_dir, fallback_name=None, confdir=None):
    if not isinstance(source, dict):
        raise TypeError("rule must be an object")
    rule = dict(source)
    rule["name"] = rule.get("name") or fallback_name or "unnamed"
    action = rule.get("action")
    if action not in ACTIONS:
        raise ValueError(f"unknown action '{action}'")
    missing = [key for key in ACTION_REQUIREMENTS[action] if key not in rule]
    if missing:
        raise ValueError(f"action '{action}' needs: {', '.join(missing)}")
    rule["_re"] = user_regex(rule.get("match", "."))
    if rule.get("method") is not None and not isinstance(rule["method"], str):
        raise TypeError("method must be text")
    # "" or null means any method, as for breakpoints and scripts (`rules add … method=$M` with M unset wrote "",
    # which never matched; null crashed every other rule of the call)
    rule["_method"] = (rule.get("method") or "").strip().upper() or None
    if action == "map_remote":
        rule["_replace"] = user_regex(rule["replace"])
        if not isinstance(rule["with"], str):
            raise TypeError("map_remote with must be text")
    elif action == "respond":
        _final_status(rule.get("status", 200))
        if rule.get("body_file"):
            rule["body_file"] = rule_file_path(state_dir, rule["body_file"], "body_file", (confdir,))
    elif action == "status":
        _final_status(rule["status"])
        if rule.get("body_file"):
            rule["body_file"] = rule_file_path(state_dir, rule["body_file"], "body_file", (confdir,))
    elif action == "delay":
        rule["ms"] = float(rule["ms"])
        if not 0 <= rule["ms"] <= 600000:        # also refuses inf / nan: a matching call would never complete
            raise ValueError("delay ms must be 0..600000")
    elif action == "json_patch":
        if not isinstance(rule["set"], dict) or not all(isinstance(k, str) for k in rule["set"]):
            raise TypeError("json_patch set must be an object with text paths")
    elif action == "set_header":
        if not isinstance(rule["header"], str):
            raise TypeError("set_header header must be text")
        # R7B-04: an invalid name made the server answer 400 to every matching call; a CR/LF in the value split it into
        # an extra header line on the wire
        if not _TOKEN.fullmatch(rule["header"]):
            raise ValueError("set_header header '%s' is not a valid header name (letters, digits and !#$%%&'*+.^_`|~-)" % rule["header"])
        if rule.get("value") is not None and re.search(r"[\r\n\x00]", str(rule["value"])):
            raise ValueError("set_header value must be one line (no line breaks)")
        if rule.get("side", "request") not in ("request", "response"):
            raise ValueError("set_header side must be request or response")
    elif action == "map_local":
        if not isinstance(rule["file"], str):
            raise TypeError("map_local file must be text")
        # A shared rules file must not turn the proxy into a reader for arbitrary
        # local files: confine to the project state dir (symlinks resolved) unless the
        # user trusted that file on this machine, or skip the rule with this error.
        rule["file"] = rule_file_path(state_dir, rule["file"], "map_local file", (confdir,))
        if "variants" in rule:
            variants = rule["variants"]
            if not isinstance(variants, list) or not variants:
                raise ValueError("map_local variants must be a nonempty list")
            names = set()
            checked = []
            for variant in variants:
                if not isinstance(variant, dict) or not isinstance(variant.get("name"), str) or not variant["name"].strip():
                    raise ValueError("map_local variant needs a name")
                if variant["name"] in names:
                    raise ValueError("map_local variant names must be unique")
                names.add(variant["name"])
                if not isinstance(variant.get("file"), str):
                    raise TypeError("map_local variant file must be text")
                item = dict(variant)
                item["file"] = rule_file_path(state_dir, item["file"], "map_local variant file", (confdir,))
                if os.path.isdir(item["file"]):
                    raise ValueError("map_local variant file must not be a folder")
                if "status" in item:
                    item["status"] = _final_status(item["status"])
                if "headers" in item:
                    headers = item["headers"]
                    if isinstance(headers, dict):
                        item["headers"] = [[str(k), str(v)] for k, v in headers.items()]
                    elif isinstance(headers, list) and all(isinstance(x, (list, tuple)) and len(x) == 2 for x in headers):
                        item["headers"] = [[str(k), str(v)] for k, v in headers]
                    else:
                        raise TypeError("map_local variant headers must be an object or name/value pairs")
                checked.append(item)
            if rule.get("active") not in names:
                raise ValueError("map_local active variant must name a variant")
            if rule.get("base"):
                raise ValueError("map_local folders cannot have variants")
            rule["variants"] = checked
        if rule.get("base") is not None or os.path.isdir(rule["file"]):
            base = rule.get("base")
            parsed = urlsplit(base) if isinstance(base, str) else None
            if not parsed or parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.query or parsed.fragment:
                raise ValueError("map_local folder needs base=http(s)://host/path/")
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ValueError("map_local folder base port must be 1..65535")
            if parsed.netloc.count(":") == 1 and not parsed.netloc.startswith("["):
                _, possible = parsed.netloc.rsplit(":", 1)
                if possible.isdigit() and not 1 <= int(possible) <= 65535:
                    raise ValueError("map_local folder base port must be 1..65535")
            if not base.endswith("/"):
                raise ValueError("map_local folder base must end with /")
            if not os.path.isdir(rule["file"]):
                raise ValueError("map_local folder not found: %s" % rule["file"])
    if "headers" in rule:
        headers = rule["headers"]
        if isinstance(headers, dict):
            rule["headers"] = [[str(k), str(v)] for k, v in headers.items()]
        elif isinstance(headers, list) and all(isinstance(x, (list, tuple)) and len(x) == 2 for x in headers):
            rule["headers"] = [[str(k), str(v)] for k, v in headers]
        else:
            raise TypeError("headers must be an object or name/value pairs")
    return rule



_ACTION_LABEL = {"respond": "answers locally", "map_local": "Map Local", "status": "forces a status", "json_patch": "edits JSON fields",
                 "delay": "adds a delay", "set_header": "sets a header", "map_remote": "rewrites the URL", "block": "blocks the call"}


def rule_fingerprint(source):
    """Identity of a rule's behaviour: hit counts restart when the rule is edited (not when it is only toggled)."""
    import hashlib
    import json
    if not isinstance(source, dict):
        return ""
    core = {k: v for k, v in source.items() if k not in ("enabled", "note", "draft")}
    return hashlib.sha1(json.dumps(core, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:12]


def explain_rules(sources, state_dir, url, method="GET", confdir=None):
    """Would each rule fire on this call, and what would it do? Mirrors proxy_rules' matching order: the first matching
    Map Local / respond answers the call, so later mocks and server-side rules never see it. Returns one dict per rule:
    {name, action, enabled, fires, effect | reason}."""
    method = (method or "GET").upper()
    out, answered_by, blocked_by = [], None, None
    for index, source in enumerate(sources or []):
        name = (source.get("name") if isinstance(source, dict) else None) or "rule #%d" % (index + 1)
        row = {"name": name, "action": source.get("action") if isinstance(source, dict) else None,
               "enabled": bool(source.get("enabled", True)) if isinstance(source, dict) else False, "fires": False}
        out.append(row)
        if not row["enabled"]:
            row["reason"] = "switched off"
            continue
        try:
            rule = compile_rule(source, state_dir, name, confdir)
        except (KeyError, TypeError, ValueError, re.error) as e:
            row["reason"] = "skipped by the proxy: %s" % e
            continue
        if not rule["_re"].search(url):
            row["reason"] = "match=%r does not match this URL" % rule.get("match", ".")
            continue
        if rule["_method"] not in (None, method):
            row["reason"] = "only for %s; this call is %s" % (rule["_method"], method)
            continue
        action = rule["action"]
        if blocked_by:
            row["reason"] = "matches, but rule '%s' blocks the call first" % blocked_by
            continue
        if action in ("respond", "map_local"):
            if answered_by:
                row["reason"] = "matches, but '%s' already answers this call (only the first matching mock is used)" % answered_by
                continue
            answered_by = name
            row["fires"] = True
            what = rule.get("file") or rule.get("body_file") or "its body"
            row["effect"] = "answered locally with %s from %s; the server is not called" % (rule.get("status", 200), what)
            continue
        if answered_by and action in ("status", "json_patch") or answered_by and action == "set_header" and rule.get("side") == "response":
            row["reason"] = "matches, but '%s' answers this call locally, so there is no server response to change" % answered_by
            continue
        if action == "map_remote":
            new = rule["_replace"].sub(rule["with"], url)
            if new == url:
                row["reason"] = ("matches, but replace=%r changes nothing in this URL — replace is the URL pattern, "
                                 "with is the replacement" % rule["replace"])
                row["inert"] = True
                continue
            row["fires"], row["effect"] = True, "sent to %s instead" % new
            continue
        row["fires"] = True
        if action == "block":
            blocked_by = name
            row["effect"] = "connection killed (the app sees a network error)"
        elif action == "status":
            row["effect"] = "the server's status becomes %s" % rule["status"]
        elif action == "json_patch":
            row["effect"] = "sets %s in the JSON response (left unchanged if the response is not JSON)" % ", ".join(sorted(rule["set"]))
        elif action == "delay":
            row["effect"] = "held %g ms before it is sent" % rule["ms"]
        elif action == "set_header":
            side = rule.get("side", "request")
            row["effect"] = ("removes %s header %s" % (side, rule["header"]) if rule.get("value") is None
                             else "sets %s header %s: %s" % (side, rule["header"], rule["value"]))
        else:
            row["effect"] = _ACTION_LABEL.get(action, action)
    return out
