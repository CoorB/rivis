#!/usr/bin/env python3
"""Terms of Use gate: Rivis captures, decrypts or changes traffic only for a user who agreed to the CURRENT terms.

  terms.py status [--json]     exit 0 accepted · 3 not accepted, declined or the text changed · 4 no terms text
  terms.py text                print the terms text
  terms.py accept NAME VIA     record that NAME agreed (VIA: cli | window | powershell); prints the record as JSON
  terms.py decline VIA         record that the user did not agree (Rivis stays unusable until they do)

One implementation for every entry point: the bash and PowerShell CLIs call this file, the proxy add-on
(proxy_terms.py) and the panel import it. Standard library only; runs under /usr/bin/python3 -I (3.9).

Trust model
- The text ships with the installed copy (product.json "terms_file", default terms/TERMS.md). A copy with no text
  refuses to run (exit 4): fail closed, never "no terms, so no gate".
- Agreement is to the exact text: its SHA-256 is recorded, so any change to the text asks everyone again.
- The record (~/.rivis-terms-acceptance.json, 0600) keeps who agreed, when, on which Mac and Rivis version, plus
  every earlier answer. It is a compliance record, not a lock against a determined user editing local files.
"""
import datetime
import getpass
import hashlib
import json
import os
import socket
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MAX_HISTORY = 50

ACCEPTED, REQUIRED, CHANGED, DECLINED, MISSING = "accepted", "required", "changed", "declined", "missing"
EXIT = {ACCEPTED: 0, REQUIRED: 3, CHANGED: 3, DECLINED: 3, MISSING: 4}


def _product():
    try:
        with open(os.path.join(ROOT, "product.json")) as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


PRODUCT = _product()
STATE_ROOT = os.path.expanduser(PRODUCT.get("state_dir") or "~/.rivis")


def terms_path():
    rel = PRODUCT.get("terms_file") or os.path.join("terms", "TERMS.md")
    return rel if os.path.isabs(rel) else os.path.join(ROOT, rel)


def record_path():
    """~/.<cli>-terms-acceptance.json: next to the state dir, not in it, so a reset of Rivis's state never erases the
    record of who agreed (and a fresh state dir is still a known user)."""
    return os.path.expanduser("~/.%s-terms-acceptance.json" % (PRODUCT.get("cli") or "rivis"))


def current():
    """{"text", "sha256", "title", "path"} of the shipped terms, or None when this copy has none (fail closed)."""
    path = terms_path()
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    text = raw.decode("utf-8", "replace")
    if not text.strip():
        return None
    title = next((line.lstrip("#").strip() for line in text.splitlines() if line.strip()), "Terms of Use")
    return {"text": text, "sha256": hashlib.sha256(raw).hexdigest(), "title": title[:200], "path": path}


def _load_record():
    try:
        with open(record_path()) as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def status():
    """{"state", "title", "sha256", "accepted" (the last answer for THIS text or None), "path"}."""
    terms = current()
    if terms is None:
        return {"state": MISSING, "title": None, "sha256": None, "accepted": None, "path": terms_path()}
    last = _load_record().get("current")
    state = REQUIRED
    if isinstance(last, dict) and last.get("terms_sha256") == terms["sha256"]:
        state = ACCEPTED if last.get("answer") == "accepted" else DECLINED
    elif isinstance(last, dict) and last.get("answer") == "accepted":
        state = CHANGED                      # agreed to an earlier text: ask again
    return {"state": state, "title": terms["title"], "sha256": terms["sha256"],
            "accepted": last if state == ACCEPTED else None, "path": terms["path"]}


def accepted():
    return status()["state"] == ACCEPTED


def _account_name():
    try:
        import pwd                  # not on Windows (PowerShell edition): no account full name there
        return (pwd.getpwuid(os.getuid()).pw_gecos or "").split(",")[0].strip()
    except (ImportError, KeyError, OSError):
        return ""


def _version():
    for candidate in (os.path.join(ROOT, "VERSION"), os.path.join(ROOT, "install", "VERSION")):
        try:
            with open(candidate) as fh:
                return fh.read().strip() or "dev"
        except OSError:
            continue
    return "dev"


def valid_name(name):
    """Why a typed name is not a usable signature, or None."""
    if not isinstance(name, str):
        return "type your full name"
    name = name.strip()
    if len(name) < 3 or len(name) > 100:
        return "type your full name (3 to 100 characters)"
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        return "the name must be one line of plain text"
    if sum(c.isalpha() for c in name) < 2:
        return "type your full name"
    return None


def _write(doc):
    home = os.path.dirname(record_path())
    fd, tmp = tempfile.mkstemp(dir=home, prefix=".rivis-terms-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, record_path())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _answer(answer, via, name=None):
    terms = current()
    if terms is None:
        raise ValueError("this copy has no Terms of Use text (%s); reinstall it from the official release" % terms_path())
    if via not in ("cli", "window", "powershell"):
        raise ValueError("via must be cli, window or powershell")
    entry = {"answer": answer, "terms_sha256": terms["sha256"], "terms_title": terms["title"],
             "at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
             "mac_user": getpass.getuser(), "account_name": _account_name(), "host": socket.gethostname(),
             "version": _version(), "via": via}
    if name is not None:
        entry["name"] = name.strip()
    doc = _load_record()
    history = doc.get("history") if isinstance(doc.get("history"), list) else []
    if isinstance(doc.get("current"), dict):
        history.append(doc["current"])
    _write({"current": entry, "history": history[-MAX_HISTORY:]})
    return entry


def accept(name, via):
    problem = valid_name(name)
    if problem:
        raise ValueError(problem)
    return _answer("accepted", via, name)


def decline(via):
    return _answer("declined", via)


def main(argv):
    cmd = argv[0] if argv else "status"
    try:
        if cmd == "status":
            st = status()
            if "--json" in argv[1:]:
                print(json.dumps(st))
            else:
                print(st["state"])
            return EXIT[st["state"]]
        if cmd == "text":
            terms = current()
            if terms is None:
                print("no Terms of Use text in this copy (%s)" % terms_path(), file=sys.stderr)
                return 4
            sys.stdout.write(terms["text"])
            return 0
        if cmd == "accept" and len(argv) == 3:
            print(json.dumps(accept(argv[1], argv[2])))
            return 0
        if cmd == "decline" and len(argv) == 2:
            print(json.dumps(decline(argv[1])))
            return 0
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(__doc__.split("\n\n")[1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
