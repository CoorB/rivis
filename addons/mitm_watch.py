#!/usr/bin/env python3
"""Watch mitmproxy (the engine Rivis pins) for new releases and security advisories. Report only: never installs.

  mitm_watch.py status [--json]          the last check (from the cache; no network)
  mitm_watch.py check PINNED [--json]    ask PyPI now and cache the answer

A newer mitmproxy reaches users only inside an IT-approved Rivis release (the pin and its SHA-256 live in
install/mirror.conf). This tells the user and the maintainers that one exists, and whether the pinned version has
published advisories (PyPI's JSON API lists them per release, from the OSV database).

Source: product.json "mitm_watch_url" (default https://pypi.org), or RIVIS_MITM_WATCH_URL; "off" disables it.
Standard library only; runs under /usr/bin/python3 -I and inside mitmweb (proxy_panel calls check() in the background).
"""
import datetime
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EVERY_HOURS = 24
VERSION_RE = re.compile(r"\d+(\.\d+){1,3}")


def _product():
    try:
        with open(os.path.join(ROOT, "product.json")) as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


PRODUCT = _product()
STATE_ROOT = os.path.expanduser(PRODUCT.get("state_dir") or "~/.rivis")
CACHE = os.path.join(STATE_ROOT, "mitm-watch.json")


def source():
    url = os.environ.get("%s_MITM_WATCH_URL" % (PRODUCT.get("env_prefix") or "RIVIS")) \
        or PRODUCT.get("mitm_watch_url") or "https://pypi.org"
    return None if url.strip().lower() == "off" else url.rstrip("/")


def vkey(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:4])


def _get(url, timeout=15):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "rivis-mitm-watch"})
    with urllib.request.urlopen(req, timeout=timeout) as r:           # nosec - fixed https source from product.json
        return json.loads(r.read(4 * 1024 * 1024))


def check(pinned):
    """Ask the source, cache and return {"checked_at", "pinned", "latest", "newer", "advisories", "error"}."""
    now = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    out = {"checked_at": now, "pinned": pinned, "latest": None, "newer": False, "advisories": [], "error": None}
    base = source()
    if base is None:
        out["error"] = "off"
        return out
    try:
        latest = str((_get(base + "/pypi/mitmproxy/json").get("info") or {}).get("version") or "")
        if not VERSION_RE.fullmatch(latest):
            raise ValueError("no version in the answer")
        out["latest"] = latest
        out["newer"] = bool(pinned) and vkey(latest) > vkey(pinned)
        if pinned:
            for v in _get(base + "/pypi/mitmproxy/%s/json" % pinned).get("vulnerabilities") or []:
                if isinstance(v, dict):
                    out["advisories"].append({"id": str(v.get("id") or "")[:60],
                                              "aliases": [str(a)[:60] for a in (v.get("aliases") or [])][:5],
                                              "summary": str(v.get("summary") or v.get("details") or "")[:300],
                                              "fixed_in": [str(f)[:20] for f in (v.get("fixed_in") or [])][:5]})
    except (OSError, ValueError, urllib.error.URLError) as e:
        out["error"] = "could not check mitmproxy releases: %s" % (getattr(e, "reason", None) or e)
    _save(out)
    return out


def _save(doc):
    try:
        os.makedirs(STATE_ROOT, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=STATE_ROOT, prefix=".mitm-watch-")
        with os.fdopen(fd, "w") as fh:
            json.dump(doc, fh)
        os.chmod(tmp, 0o600)
        os.replace(tmp, CACHE)
    except OSError:
        pass


def status():
    try:
        with open(CACHE) as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError):
        return None


def due(doc=None, now=None):
    """True when the last check is missing or older than EVERY_HOURS."""
    doc = status() if doc is None else doc
    if not doc or not doc.get("checked_at"):
        return True
    try:
        at = datetime.datetime.fromisoformat(doc["checked_at"])
    except ValueError:
        return True
    now = now or datetime.datetime.now().astimezone()
    return now - at >= datetime.timedelta(hours=EVERY_HOURS)


def summary(doc):
    """One line for a person, or None when there is nothing to say."""
    if not doc or doc.get("error") == "off":
        return None
    if doc.get("error"):
        return "mitmproxy watch: %s" % doc["error"]
    parts = []
    if doc.get("newer"):
        parts.append("mitmproxy %s is out (this Rivis uses %s); it reaches you in a Rivis update once IT approves it"
                     % (doc["latest"], doc["pinned"]))
    if doc.get("advisories"):
        ids = ", ".join((a.get("aliases") or [a.get("id")])[0] for a in doc["advisories"][:3])
        parts.append("mitmproxy %s has %d published security advisor%s (%s)"
                     % (doc["pinned"], len(doc["advisories"]), "y" if len(doc["advisories"]) == 1 else "ies", ids))
    return "; ".join(parts) or None


def main(argv):
    cmd = argv[0] if argv else "status"
    as_json = "--json" in argv
    if cmd == "check" and len([a for a in argv[1:] if a != "--json"]) == 1:
        doc = check([a for a in argv[1:] if a != "--json"][0])
    elif cmd == "status":
        doc = status()
    else:
        print("usage: mitm_watch.py status [--json] | check PINNED [--json]", file=sys.stderr)
        return 2
    if as_json:
        print(json.dumps(doc))
    else:
        print(summary(doc) or ("mitmproxy %s is the newest release" % doc["pinned"] if doc and doc.get("latest")
                                else "mitmproxy watch: no check yet"))
    return 0 if not doc or not doc.get("error") or doc.get("error") == "off" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
