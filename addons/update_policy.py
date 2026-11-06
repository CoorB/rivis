#!/usr/bin/env python3
"""Force update: a signed release can require a minimum version, from a date on.

  update_policy.py status [--json]   exit 0 fine · 12 an update is due (deadline ahead) · 11 an update is required now

The newest signed release manifest (rivis-update.json + .sig, signed with the release key in addons/release-signers)
may carry "min_version": "X.Y.Z" and "required_after": "YYYY-MM-DD" (or a full ISO time). updater.check() keeps that
signed manifest here (<state dir>/update-policy/). It is verified again on every read, so a lower minimum cannot be
written by hand; deleting it only lasts until the next update check. While the running version is below the minimum:
before the date Rivis warns; from the date on it refuses everything except stop / status / off / update / terms, and
the proxy passes no traffic, until `rivis update` (or a new installer) brings a version at or above the minimum.

product.json "update_offline_days" (default 0 = off): when set, an installed copy that has not completed an update
check for that many days counts as "required" too (it cannot know whether it is still allowed).
"""
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

OK, DUE, REQUIRED = "ok", "due", "required"
EXIT = {OK: 0, DUE: 12, REQUIRED: 11}


def _product():
    try:
        with open(os.path.join(ROOT, "product.json")) as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


PRODUCT = _product()
CLI = PRODUCT.get("cli") or "rivis"
STATE_ROOT = os.path.expanduser(PRODUCT.get("state_dir") or "~/.rivis")
POLICY_DIR = os.path.join(STATE_ROOT, "update-policy")
MANIFEST = os.path.join(POLICY_DIR, "manifest.json")
SIGNATURE = MANIFEST + ".sig"
LAST_CHECK = os.path.join(POLICY_DIR, "last-check")
SIGNERS = os.path.join(HERE, "release-signers")
NAMESPACE = CLI + "-release"
VERSION_RE = re.compile(r"\d+\.\d+\.\d+")


def vkey(v):
    return tuple(int(x) for x in str(v).split("."))


def current_version():
    for candidate in (os.path.join(ROOT, "VERSION"), os.path.join(ROOT, "install", "VERSION")):
        try:
            with open(candidate) as fh:
                v = fh.read().strip()
            if VERSION_RE.fullmatch(v):
                return v
        except OSError:
            continue
    return None


def installed():
    return os.path.isfile(os.path.join(ROOT, "VERSION"))      # a release copy; a source checkout keeps it in install/


def verify(manifest_bytes, sig_bytes):
    """True when the release key signed exactly these bytes (ssh-keygen -Y verify, as updater.py does)."""
    if not os.path.isfile(SIGNERS):
        return False
    with tempfile.TemporaryDirectory() as d:
        sig = os.path.join(d, "m.sig")
        with open(sig, "wb") as fh:
            fh.write(sig_bytes)
        try:
            r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", SIGNERS, "-I", NAMESPACE, "-n", NAMESPACE, "-s", sig],
                               input=manifest_bytes, capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return False
    return r.returncode == 0


def parse_deadline(text):
    """A required_after value as an aware datetime (a bare date means that day's start, local time), or None."""
    if not text:
        return None
    text = str(text).strip()
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            return datetime.datetime.strptime(text, "%Y-%m-%d").astimezone()
        if text[-1:] in "Zz":                 # "…Z" is the usual UTC form of release tooling; Python 3.9 rejects it
            text = text[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.astimezone()
    except ValueError:
        return None


def check_manifest(doc):
    """Why a manifest's policy fields are unusable, or None (used when building one and when reading it)."""
    mv = doc.get("min_version")
    if mv is not None and not VERSION_RE.fullmatch(str(mv)):
        return "min_version must look like 1.2.3"
    if doc.get("required_after") is not None:
        if mv is None:
            return "required_after needs min_version"
        if parse_deadline(doc["required_after"]) is None:
            return "required_after must be a date (YYYY-MM-DD) or an ISO time"
    return None


def _atomic(path, data):
    os.makedirs(POLICY_DIR, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=POLICY_DIR, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def store(manifest_bytes, sig_bytes):
    """Keep the newest VERIFIED signed manifest (called by updater.check after it verified the signature)."""
    _atomic(MANIFEST, manifest_bytes)
    _atomic(SIGNATURE, sig_bytes)


def record_check():
    _atomic(LAST_CHECK, datetime.datetime.now().astimezone().isoformat(timespec="seconds").encode())


def _offline_problem(now):
    days = PRODUCT.get("update_offline_days") or 0
    if not isinstance(days, int) or days <= 0 or not installed():
        return None
    try:
        with open(LAST_CHECK) as fh:
            last = datetime.datetime.fromisoformat(fh.read().strip())
    except (OSError, ValueError):
        return None          # never checked yet: the first check decides (a fresh install is not "offline")
    if now - last > datetime.timedelta(days=days):
        return ("no update check has succeeded for %d days (the limit is %d): connect and run '%s update'"
                % ((now - last).days, days, CLI))
    return None


def status(now=None):
    """{"state": ok|due|required, "current", "min_version", "required_after", "reason"}."""
    now = now or datetime.datetime.now().astimezone()
    cur = current_version()
    out = {"state": OK, "current": cur, "min_version": None, "required_after": None, "reason": None}
    offline = _offline_problem(now)
    if offline:
        out.update(state=REQUIRED, reason=offline)
        return out
    try:
        with open(MANIFEST, "rb") as fh:
            manifest_bytes = fh.read()
        with open(SIGNATURE, "rb") as fh:
            sig_bytes = fh.read()
    except OSError:
        return out
    if not verify(manifest_bytes, sig_bytes):
        return out           # not ours (or edited): ignored, never trusted; the next update check replaces it
    try:
        doc = json.loads(manifest_bytes)
    except ValueError:
        return out
    if not isinstance(doc, dict) or doc.get("product") != CLI or check_manifest(doc):
        return out
    mv = doc.get("min_version")
    if not mv or cur is None or vkey(cur) >= vkey(mv):
        return out
    deadline = parse_deadline(doc.get("required_after"))
    out.update(min_version=mv, required_after=deadline.isoformat(timespec="minutes") if deadline else None)
    if deadline and now < deadline:
        out.update(state=DUE, reason="%s %s or newer is required from %s; this is %s — run '%s update'"
                   % (PRODUCT.get("name", "Rivis"), mv, deadline.strftime("%Y-%m-%d %H:%M"), cur, CLI))
    else:
        out.update(state=REQUIRED, reason="%s %s or newer is required; this is %s — run '%s update'"
                   % (PRODUCT.get("name", "Rivis"), mv, cur, CLI))
    return out


def main(argv):
    cmd = argv[0] if argv else "status"
    if cmd != "status":
        print("usage: update_policy.py status [--json]", file=sys.stderr)
        return 2
    st = status()
    print(json.dumps(st) if "--json" in argv[1:] else (st["reason"] or st["state"]))
    return EXIT[st["state"]]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
