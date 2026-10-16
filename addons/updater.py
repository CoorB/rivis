#!/usr/bin/env python3
"""In-app updates from the product's private GitHub releases (standard library only).

  updater.py status                 JSON: current version, configured?, signed in?
  updater.py login                  sign in once with GitHub's device flow (terminal)
  updater.py login-start / login-poll    the same, one step at a time (the browser panel)
  updater.py logout                 forget the GitHub sign-in
  updater.py check                  JSON: is a newer, SIGNED release available?
  updater.py download               download + verify the newer installer zip; prints its path

Trust model
- Sign-in: a GitHub App owned by the org (product.json "github_app_client_id"), device flow, client id only — no secret
  is shipped. The token can do no more than BOTH the app (Contents: read on one repo) and the person allow. It is kept
  in the macOS Keychain (never a file, never a command line) and refreshed without a secret (device-flow tokens).
- Updates: a release must carry rivis-update.json + rivis-update.json.sig, signed with the release key whose public
  half ships in addons/release-signers (ssh-keygen -Y). The installer zip must match the manifest's SHA-256. Nothing
  unsigned, older or tampered is ever installed. The token is never sent to a redirect host (release downloads
  redirect to a storage host).
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PRODUCT = json.load(open(os.path.join(ROOT, "product.json")))
CLI = PRODUCT.get("cli", "rivis")
REPO = PRODUCT.get("update_repo", "")
CLIENT_ID = PRODUCT.get("github_app_client_id", "")
API = PRODUCT.get("update_api", "https://api.github.com").rstrip("/")
LOGIN = PRODUCT.get("update_login", "https://github.com").rstrip("/")
SIGNERS = os.path.join(HERE, "release-signers")
NAMESPACE = CLI + "-release"
MANIFEST, SIGNATURE = CLI + "-update.json", CLI + "-update.json.sig"
STATE = os.path.expanduser(os.environ.get(PRODUCT.get("env_prefix", "RIVIS") + "_STATE_ROOT")
                           or PRODUCT.get("state_dir", "~/.rivis"))
KEYCHAIN_SERVICE = "%s-github-updates" % CLI
UA = "%s-updater" % CLI


class UpdateError(Exception):
    pass


# ── version ───────────────────────────────────────────────────────────────────────────────────────────────────────
def current_version():
    for p in (os.path.join(ROOT, "VERSION"), os.path.join(ROOT, "install", "VERSION")):
        if os.path.isfile(p):
            return open(p).read().strip()
    return "0"


def vkey(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:3]) or (0,)


def installed_copy():
    """Updates replace an INSTALLED copy (~/.local/<cli>/current); a source checkout is updated with git."""
    receipt = os.path.join(os.path.expanduser("~/.local"), CLI, "install-receipt")
    current = os.path.realpath(os.path.join(os.path.expanduser("~/.local"), CLI, "current"))
    return os.path.isfile(receipt) and os.path.realpath(ROOT) == current


def configured():
    return bool(REPO and CLIENT_ID and has_release_key())


def has_release_key():
    return os.path.isfile(SIGNERS) and any(l.strip() and not l.startswith("#") for l in open(SIGNERS))


# ── token store: the macOS Keychain (a file only when a test points RIVIS_TOKEN_FILE at one) ──────────────────────
def _account():
    return "%s:%s" % (REPO, os.environ.get("USER", "user"))


def _keychain_args():
    kc = os.environ.get("RIVIS_KEYCHAIN")
    return [kc] if kc else []


def token_load():
    f = os.environ.get("RIVIS_TOKEN_FILE")
    try:
        if f:
            raw = open(f).read()
        else:
            raw = subprocess.run(["security", "find-generic-password", "-a", _account(), "-s", KEYCHAIN_SERVICE, "-w"]
                                 + _keychain_args(), capture_output=True, text=True, timeout=15).stdout.strip()
        return json.loads(base64.b64decode(raw).decode()) if raw else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def token_save(tok):
    blob = base64.b64encode(json.dumps(tok).encode()).decode()       # base64: no quoting problems, no spaces
    f = os.environ.get("RIVIS_TOKEN_FILE")
    if f:
        fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(blob)
        return
    # through `security -i` on stdin, so the token never appears in a process list
    cmd = "add-generic-password -U -a %s -s %s -l %s -w %s %s\n" % (
        _account(), KEYCHAIN_SERVICE, KEYCHAIN_SERVICE, blob, " ".join(_keychain_args()))
    r = subprocess.run(["security", "-i"], input=cmd, capture_output=True, text=True, timeout=15)
    if r.returncode != 0 or "error" in (r.stdout + r.stderr).lower():
        raise UpdateError("could not save the GitHub sign-in in the Keychain: %s" % (r.stderr or r.stdout).strip()[:200])


def token_delete():
    f = os.environ.get("RIVIS_TOKEN_FILE")
    if f:
        if os.path.exists(f):
            os.remove(f)
        return
    subprocess.run(["security", "delete-generic-password", "-a", _account(), "-s", KEYCHAIN_SERVICE] + _keychain_args(),
                   capture_output=True, timeout=15)


# ── HTTP ──────────────────────────────────────────────────────────────────────────────────────────────────────────
class _NoAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """Release downloads redirect to a storage host: never carry the GitHub token there."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(newurl).netloc != urllib.parse.urlsplit(req.full_url).netloc:
            for h in list(new.headers):
                if h.lower() == "authorization":
                    del new.headers[h]
            new.unredirected_hdrs.pop("Authorization", None)
        return new


_OPENER = urllib.request.build_opener(_NoAuthOnRedirect)


def _http(url, data=None, headers=None, timeout=30):
    h = {"User-Agent": UA}
    h.update(headers or {})
    body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
    req = urllib.request.Request(url, data=body, headers=h, method="POST" if body is not None else "GET")
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _json_post(url, data):
    code, raw = _http(url, data, {"Accept": "application/json"})
    try:
        return code, json.loads(raw.decode() or "{}")
    except ValueError:
        return code, {"error": "bad_response", "error_description": raw[:200].decode("utf-8", "replace")}


# ── device-flow sign-in ───────────────────────────────────────────────────────────────────────────────────────────
def login_start():
    if not CLIENT_ID:
        raise UpdateError("updates are not set up in this build (no GitHub App client id)")
    code, doc = _json_post(LOGIN + "/login/device/code", {"client_id": CLIENT_ID})
    if code != 200 or "device_code" not in doc:
        raise UpdateError("GitHub refused the sign-in request: %s" % (doc.get("error_description") or doc.get("error") or code))
    return {"user_code": doc["user_code"], "verification_uri": doc["verification_uri"],
            "device_code": doc["device_code"], "interval": int(doc.get("interval", 5)),
            "expires_at": time.time() + int(doc.get("expires_in", 900))}


def _store_token(doc):
    now = time.time()
    token_save({"access_token": doc["access_token"], "refresh_token": doc.get("refresh_token"),
                "expires_at": now + int(doc.get("expires_in", 28800)) - 120 if doc.get("expires_in") else None,
                "refresh_expires_at": now + int(doc.get("refresh_token_expires_in", 0)) if doc.get("refresh_token_expires_in") else None})


def login_poll(device_code):
    """One poll. -> 'ok' | 'pending' | 'slow_down' | raises UpdateError (denied/expired/…)."""
    code, doc = _json_post(LOGIN + "/login/oauth/access_token",
                           {"client_id": CLIENT_ID, "device_code": device_code,
                            "grant_type": "urn:ietf:params:oauth:grant-type:device_code"})
    if doc.get("access_token"):
        _store_token(doc)
        return "ok"
    err = doc.get("error", "")
    if err in ("authorization_pending", "slow_down"):
        return "pending" if err == "authorization_pending" else "slow_down"
    raise UpdateError({"expired_token": "the code expired — start the sign-in again",
                       "access_denied": "the sign-in was cancelled on GitHub",
                       "device_flow_disabled": "Device Flow is not enabled for the GitHub App"}.get(err)
                      or "sign-in failed: %s" % (doc.get("error_description") or err or code))


def access_token():
    tok = token_load()
    if not tok:
        return None
    if tok.get("expires_at") and time.time() >= tok["expires_at"]:
        if not tok.get("refresh_token") or (tok.get("refresh_expires_at") and time.time() >= tok["refresh_expires_at"]):
            token_delete()
            return None
        code, doc = _json_post(LOGIN + "/login/oauth/access_token",     # device-flow tokens refresh without a secret
                               {"client_id": CLIENT_ID, "grant_type": "refresh_token", "refresh_token": tok["refresh_token"]})
        if not doc.get("access_token"):
            token_delete()
            return None
        _store_token(doc)
        tok = token_load()
    return tok and tok.get("access_token")


# ── releases ──────────────────────────────────────────────────────────────────────────────────────────────────────
def _api(path, token, accept="application/vnd.github+json"):
    code, raw = _http(API + path, headers={"Authorization": "Bearer " + token, "Accept": accept,
                                          "X-GitHub-Api-Version": "2022-11-28"}, timeout=120)
    if code == 401:
        token_delete()
        raise UpdateError("the GitHub sign-in is no longer valid — sign in again")
    if code in (403, 404):
        raise UpdateError("GitHub refused access to %s (%s): is the app installed on it and do you have access?" % (REPO, code))
    if code != 200:
        raise UpdateError("GitHub answered %s for %s" % (code, path))
    return raw


def verify_signature(manifest_bytes, sig_bytes):
    if not has_release_key():
        raise UpdateError("no release key in this build — updates cannot be verified")
    with tempfile.TemporaryDirectory() as d:
        m, s = os.path.join(d, "m"), os.path.join(d, "m.sig")
        open(m, "wb").write(manifest_bytes)
        open(s, "wb").write(sig_bytes)
        with open(m, "rb") as fh:
            r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", SIGNERS, "-I", NAMESPACE, "-n", NAMESPACE, "-s", s],
                               stdin=fh, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise UpdateError("the update's signature does not verify — refusing it")


def check():
    """-> {"current", "available": None | {"version", "notes", "zip", "sha256", "asset_id", "url"}}"""
    if not configured():
        raise UpdateError("updates are not set up in this build")
    token = access_token()
    if not token:
        raise UpdateError("not signed in to GitHub")
    releases = json.loads(_api("/repos/%s/releases?per_page=20" % REPO, token))
    cur = current_version()
    for rel in releases:
        if rel.get("draft"):
            continue
        assets = {a["name"]: a for a in rel.get("assets", [])}
        if MANIFEST not in assets or SIGNATURE not in assets:
            continue                                                  # releases from before signed updates
        man = _api("/repos/%s/releases/assets/%d" % (REPO, assets[MANIFEST]["id"]), token, "application/octet-stream")
        sig = _api("/repos/%s/releases/assets/%d" % (REPO, assets[SIGNATURE]["id"]), token, "application/octet-stream")
        verify_signature(man, sig)
        m = json.loads(man)
        if m.get("product") != CLI or not re.fullmatch(r"\d+\.\d+\.\d+", str(m.get("version", ""))) \
                or not re.fullmatch(r"[0-9a-f]{64}", str(m.get("sha256", ""))) or m.get("zip") not in assets:
            raise UpdateError("the update manifest is incomplete — refusing it")
        if vkey(m["version"]) <= vkey(cur):
            return {"current": cur, "available": None}
        return {"current": cur, "available": {"version": m["version"], "notes": str(m.get("notes", ""))[:4000],
                                              "zip": m["zip"], "sha256": m["sha256"],
                                              "asset_id": assets[m["zip"]]["id"], "url": rel.get("html_url", "")}}
    return {"current": cur, "available": None}


def download():
    """Download + verify the newer installer; -> path of the verified zip under the state dir."""
    info = check()["available"]
    if not info:
        raise UpdateError("already up to date")
    token = access_token()
    d = os.path.join(STATE, "updates", info["version"])
    os.makedirs(d, mode=0o700, exist_ok=True)
    data = _api("/repos/%s/releases/assets/%d" % (REPO, info["asset_id"]), token, "application/octet-stream")
    if hashlib.sha256(data).hexdigest() != info["sha256"]:
        raise UpdateError("the downloaded installer does not match the signed SHA-256 — refusing it")
    path = os.path.join(d, os.path.basename(info["zip"]))
    fd, tmp = tempfile.mkstemp(dir=d)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return path, info


# ── CLI ───────────────────────────────────────────────────────────────────────────────────────────────────────────
def status():
    return {"current": current_version(), "configured": configured(), "signed_in": bool(token_load()),
            "installed": installed_copy(), "repo": REPO}


def main(argv):
    cmd = argv[0] if argv else "status"
    try:
        if cmd == "status":
            print(json.dumps(status()))
        elif cmd == "check":
            print(json.dumps(check()))
        elif cmd == "download":
            path, info = download()
            print(json.dumps({"path": path, "version": info["version"]}))
        elif cmd == "login-start":
            print(json.dumps(login_start()))
        elif cmd == "login-poll":
            print(json.dumps({"result": login_poll(argv[1])}))
        elif cmd == "logout":
            token_delete()
            print(json.dumps({"signed_in": False}))
        elif cmd == "login":
            s = login_start()
            print("Open %s and enter the code:  %s" % (s["verification_uri"], s["user_code"]), flush=True)
            subprocess.run(["open", s["verification_uri"]], capture_output=True)
            interval = s["interval"]
            while time.time() < s["expires_at"]:
                time.sleep(interval)
                r = login_poll(s["device_code"])
                if r == "ok":
                    print("Signed in. %s will check %s for updates." % (PRODUCT.get("name", CLI), REPO))
                    return 0
                if r == "slow_down":
                    interval += 5
            raise UpdateError("the code expired — run the sign-in again")
        else:
            print("usage: updater.py status|login|logout|check|download", file=sys.stderr)
            return 2
    except UpdateError as e:
        print(json.dumps({"error": str(e)}) if cmd not in ("login",) else "update: %s" % e,
              file=sys.stdout if cmd not in ("login",) else sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
