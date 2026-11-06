#!/usr/bin/env python3
"""In-app updates from the organisation's Azure DevOps feed, or from GitHub releases (standard library only).

  updater.py status                 JSON: current version, configured?, signed in?
  updater.py login                  sign in once with a device code (terminal)
  updater.py login-start / login-poll    the same, one step at a time (the browser panel)
  updater.py logout                 forget the sign-in
  updater.py check                  JSON: is a newer, SIGNED release available?
  updater.py download               download + verify the newer installer zip; prints its path

Sources (product.json "update_source")
- "azure": the Azure Artifacts feed named in "azure_updates" ({org, project, feed, view, package, tenant, client_id}).
  Releases are npm-type packages (a plain authenticated download; Universal Packages need Microsoft's CLI) holding
  rivis-update.json, its .sig and the installer zip. Only the feed VIEW is read (default "Release"): a version
  reaches users once IT promotes it there. Sign-in is the organisation's Entra ID device-code flow with IT's public
  client app registration (no secret); the account must be allowed to read the feed. package.json may also carry
  the manifest and signature ("<cli>Update": {"manifest", "signature"}, base64) so a check needs no package download.
- "github" (default): the product's GitHub releases, below.

Trust model
- Public releases are fetched without a token. Private repositories fall back to a GitHub App owned by the org
  (product.json "github_app_client_id"), device flow, client id only — no secret
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
sys.path.insert(0, HERE)           # run with python3 -I, which leaves the script's own directory off sys.path
import update_policy  # noqa: E402  (force update: keeps the newest signed manifest)
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
SOURCE = PRODUCT.get("update_source") or "github"
AZ = PRODUCT.get("azure_updates") if isinstance(PRODUCT.get("azure_updates"), dict) else {}
AZ_KEYS = ("org", "project", "feed", "package", "tenant", "client_id")
AZ_PKGS = (PRODUCT.get("azure_pkgs_url") or "https://pkgs.dev.azure.com").rstrip("/")
AZ_LOGIN = (PRODUCT.get("azure_login_url") or "https://login.microsoftonline.com").rstrip("/")
AZ_SCOPE = "499b84ac-1321-427f-aa17-267ca6975798/.default offline_access"    # Azure DevOps, delegated
MAX_PACKAGE = 1 << 30
KEYCHAIN_SERVICE = "%s-%s-updates" % (CLI, "azure" if SOURCE == "azure" else "github")
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


def azure():
    return SOURCE == "azure"


def source_label():
    if azure():
        return "the %s feed (%s/%s, view %s)" % (AZ.get("feed", "?"), AZ.get("org", "?"), AZ.get("project", "?"),
                                                 AZ.get("view") or "Release")
    return REPO


def configured():
    if azure():
        return all(isinstance(AZ.get(k), str) and AZ[k].strip() for k in AZ_KEYS) and has_release_key()
    return bool(REPO and has_release_key())


def has_release_key():
    return os.path.isfile(SIGNERS) and any(l.strip() and not l.startswith("#") for l in open(SIGNERS))


# ── token store: the macOS Keychain (a file only when a test points RIVIS_TOKEN_FILE at one) ──────────────────────
def _account():
    where = "azure:%s/%s/%s" % (AZ.get("org"), AZ.get("project"), AZ.get("feed")) if azure() else REPO
    return "%s:%s" % (where, os.environ.get("USER", "user"))


def _keychain_args():
    kc = os.environ.get("RIVIS_KEYCHAIN")
    return [kc] if kc else []


CHUNK = 3000     # `security -i` reads one command per line and truncates a line at about 4 KB: a real Entra access + refresh
#                  token pair is larger than that, so the sign-in is kept in chunks ("i/n:data" in service, service.1, ...)


def _kc_service(i):
    return KEYCHAIN_SERVICE if i == 0 else "%s.%d" % (KEYCHAIN_SERVICE, i)


def _kc_read(i):
    return subprocess.run(["security", "find-generic-password", "-a", _account(), "-s", _kc_service(i), "-w"]
                          + _keychain_args(), capture_output=True, text=True, timeout=15).stdout.strip()


def _kc_raw():
    first = _kc_read(0)
    m = re.match(r"^(\d+)/(\d+):(.*)$", first)
    if not m:
        return first                                   # a sign-in saved whole by an earlier version
    n = int(m.group(2))
    if int(m.group(1)) != 0 or not 0 < n <= 16:
        return ""
    parts = [m.group(3)]
    for i in range(1, n):
        part = _kc_read(i)
        mm = re.match(r"^(\d+)/(\d+):(.*)$", part)
        if not mm or int(mm.group(1)) != i or int(mm.group(2)) != n:
            return ""                                  # a chunk is missing or stale: not signed in, never half a token
        parts.append(mm.group(3))
    return "".join(parts)


def token_load():
    f = os.environ.get("RIVIS_TOKEN_FILE")
    try:
        raw = open(f).read() if f else _kc_raw()
        return json.loads(base64.b64decode(raw).decode()) if raw else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def token_save(tok):
    blob = base64.b64encode(json.dumps(tok).encode()).decode()       # base64: no quoting problems, no spaces
    f = os.environ.get("RIVIS_TOKEN_FILE")
    if f:
        # Temp + replace: a concurrent status/check must never read a truncated token file (O_TRUNC then write
        # emptied it first, so the reader saw "not signed in" and the next private-repo check failed).
        d = os.path.dirname(os.path.abspath(f)) or "."
        os.makedirs(d, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".token-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(blob)
            os.chmod(tmp, 0o600)
            os.replace(tmp, f)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        return
    # through `security -i` on stdin, so the token never appears in a process list
    chunks = [blob[i:i + CHUNK] for i in range(0, len(blob), CHUNK)] or [""]
    token_delete()                                     # no stale chunk from a longer earlier token survives
    for i, part in enumerate(chunks):
        svc = _kc_service(i)
        cmd = "add-generic-password -U -a %s -s %s -l %s -w %s %s\n" % (
            _account(), svc, svc, "%d/%d:%s" % (i, len(chunks), part), " ".join(_keychain_args()))
        r = subprocess.run(["security", "-i"], input=cmd, capture_output=True, text=True, timeout=15)
        if r.returncode != 0 or "error" in (r.stdout + r.stderr).lower():
            token_delete()
            raise UpdateError("could not save the sign-in in the Keychain: %s" % (r.stderr or r.stdout).strip()[:200])
    if token_load() != tok:                            # never claim a sign-in that cannot be read back
        token_delete()
        raise UpdateError("the sign-in was saved but could not be read back from the Keychain — try '%s update login' "
                          "again, and tell the maintainer if it keeps happening" % CLI)


def token_delete():
    f = os.environ.get("RIVIS_TOKEN_FILE")
    if f:
        try:
            os.remove(f)
        except FileNotFoundError:
            pass
        return
    for i in range(0, 17):                              # the sign-in and every chunk of it (a missing item is fine)
        r = subprocess.run(["security", "delete-generic-password", "-a", _account(), "-s", _kc_service(i)]
                           + _keychain_args(), capture_output=True, timeout=15)
        if r.returncode != 0 and i > 0:
            break


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
def _az_login(path):
    return "%s/%s/oauth2/v2.0/%s" % (AZ_LOGIN, urllib.parse.quote(AZ.get("tenant", ""), safe=""), path)


def login_start():
    if azure():
        if not configured():
            raise UpdateError("updates are not set up in this build (no Azure DevOps sign-in details)")
        code, doc = _json_post(_az_login("devicecode"), {"client_id": AZ["client_id"], "scope": AZ_SCOPE})
        if code != 200 or "device_code" not in doc:
            raise UpdateError("the organisation's sign-in refused the request: %s"
                              % (doc.get("error_description") or doc.get("error") or code))
        interval, expires_in = doc.get("interval"), doc.get("expires_in")
        return {"user_code": doc["user_code"], "verification_uri": doc.get("verification_uri") or doc.get("verification_url"),
                "device_code": doc["device_code"], "interval": int(interval if interval is not None else 5),
                "expires_at": time.time() + int(expires_in if expires_in is not None else 900)}
    if not CLIENT_ID:
        raise UpdateError("updates are not set up in this build (no GitHub App client id)")
    code, doc = _json_post(LOGIN + "/login/device/code", {"client_id": CLIENT_ID})
    if code != 200 or "device_code" not in doc:
        raise UpdateError("GitHub refused the sign-in request: %s" % (doc.get("error_description") or doc.get("error") or code))
    # interval / expires_in may be JSON null (key present, value None): .get(key, default) then returns None, and
    # int(None) crashed the sign-in. Treat null like missing.
    interval, expires_in = doc.get("interval"), doc.get("expires_in")
    return {"user_code": doc["user_code"], "verification_uri": doc["verification_uri"],
            "device_code": doc["device_code"], "interval": int(interval if interval is not None else 5),
            "expires_at": time.time() + int(expires_in if expires_in is not None else 900)}


def _store_token(doc):
    now = time.time()
    token_save({"access_token": doc["access_token"], "refresh_token": doc.get("refresh_token"),
                "expires_at": now + int(doc.get("expires_in", 28800)) - 120 if doc.get("expires_in") else None,
                "refresh_expires_at": now + int(doc.get("refresh_token_expires_in", 0)) if doc.get("refresh_token_expires_in") else None})


def login_poll(device_code):
    """One poll. -> 'ok' | 'pending' | 'slow_down' | raises UpdateError (denied/expired/…)."""
    grant = {"device_code": device_code, "grant_type": "urn:ietf:params:oauth:grant-type:device_code"}
    if azure():
        code, doc = _json_post(_az_login("token"), dict(grant, client_id=AZ["client_id"]))
    else:
        code, doc = _json_post(LOGIN + "/login/oauth/access_token", dict(grant, client_id=CLIENT_ID))
    if doc.get("access_token"):
        _store_token(doc)
        return "ok"
    err = doc.get("error", "")
    if err in ("authorization_pending", "slow_down"):
        return "pending" if err == "authorization_pending" else "slow_down"
    raise UpdateError({"expired_token": "the code expired — start the sign-in again",
                       "access_denied": "the sign-in was cancelled",
                       "authorization_declined": "the sign-in was cancelled",
                       "bad_verification_code": "the code was not recognised — start the sign-in again",
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
        form = {"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]}    # no secret needed
        if azure():
            code, doc = _json_post(_az_login("token"), dict(form, client_id=AZ["client_id"], scope=AZ_SCOPE))
        else:
            code, doc = _json_post(LOGIN + "/login/oauth/access_token", dict(form, client_id=CLIENT_ID))
        if not doc.get("access_token"):
            token_delete()
            return None
        _store_token(doc)
        tok = token_load()
    return tok and tok.get("access_token")


# ── releases ──────────────────────────────────────────────────────────────────────────────────────────────────────
def _api(path, token, accept="application/vnd.github+json"):
    headers = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = "Bearer " + token
    code, raw = _http(API + path, headers=headers, timeout=120)
    if code == 401 and token:
        token_delete()
        raise UpdateError("the GitHub sign-in is no longer valid — sign in again")
    if code in (403, 429) and b"rate limit" in raw[:2000].lower():
        raise UpdateError("GitHub's rate limit for update checks is reached — try again in an hour"
                          + ("" if token else ", or sign in with GitHub for a higher limit" if CLIENT_ID else ""))
    if code in (403, 404):
        if not token and CLIENT_ID:
            raise UpdateError("this release repository is private — sign in with GitHub to check updates")
        raise UpdateError("GitHub refused access to %s (%s)" % (REPO, code))
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


# ── Azure DevOps feed (npm-type package in a feed view) ───────────────────────────────────────────────────────────
def _az_registry():
    q = lambda v: urllib.parse.quote(str(v), safe="")
    return "%s/%s/%s/_packaging/%s@%s/npm/registry" % (AZ_PKGS, q(AZ["org"]), q(AZ["project"]), q(AZ["feed"]),
                                                       q(AZ.get("view") or "Release"))


def _az_get(url, token, accept="application/json"):
    code, raw = _http(url, headers={"Accept": accept, "Authorization": "Bearer " + token}, timeout=300)
    # Azure DevOps answers a rejected token with 401, or with 203 and a sign-in page
    if code == 401 or (code == 203 and accept == "application/json"):
        token_delete()
        raise UpdateError("the sign-in is no longer valid — run '%s update login' again" % CLI)
    if code == 403:
        raise UpdateError("this account may not read %s — ask IT to add you to the %s readers group"
                          % (source_label(), PRODUCT.get("name", CLI)))
    if code == 404:
        return None
    if code != 200:
        raise UpdateError("Azure DevOps answered %s" % code)
    if len(raw) > MAX_PACKAGE:
        raise UpdateError("the release package is too large")
    return raw


def _az_tarball(version, token):
    """The release package of VERSION (cached under the state dir until the update is installed)."""
    d = os.path.join(STATE, "updates", version)
    cached = os.path.join(d, "package.tgz")
    if os.path.isfile(cached):
        return open(cached, "rb").read()
    name = AZ["package"]
    url = "%s/%s/-/%s-%s.tgz" % (_az_registry(), name, name.rsplit("/", 1)[-1], version)
    data = _az_get(url, token, "application/octet-stream")
    if data is None:
        raise UpdateError("the feed lists %s but has no package file for it" % version)
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(tmp, 0o600)
    os.replace(tmp, cached)
    return data


def _tar_member(data, name):
    import io
    import tarfile
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            try:
                m = tf.getmember("package/" + name)
            except KeyError:
                raise UpdateError("the release package has no %s" % name)
            if not m.isfile() or m.size > MAX_PACKAGE:
                raise UpdateError("the release package's %s is not a plain file" % name)
            return tf.extractfile(m).read()          # read in memory, never extracted to disk by path
    except (tarfile.TarError, OSError, EOFError) as e:
        raise UpdateError("the release package is damaged: %s" % e)


def _az_manifest(meta, version, token):
    extra = meta.get(CLI + "Update") if isinstance(meta, dict) else None
    if isinstance(extra, dict) and extra.get("manifest") and extra.get("signature"):
        try:
            return base64.b64decode(extra["manifest"]), base64.b64decode(extra["signature"])
        except ValueError:
            pass
    data = _az_tarball(version, token)
    return _tar_member(data, MANIFEST), _tar_member(data, SIGNATURE)


def _az_check():
    cur = current_version()
    token = access_token()
    if not token:
        raise UpdateError("sign in with your organisation account first: %s update login" % CLI)
    name = AZ["package"]
    raw = _az_get("%s/%s" % (_az_registry(), name.replace("/", "%2f")), token)
    update_policy.record_check()
    if raw is None:                                    # nothing promoted to the view yet
        return {"current": cur, "available": None}
    try:
        doc = json.loads(raw)
    except ValueError:
        raise UpdateError("the feed's answer is not JSON")
    versions = {v: m for v, m in (doc.get("versions") or {}).items() if re.fullmatch(r"\d+\.\d+\.\d+", v)}
    if not versions:
        return {"current": cur, "available": None}
    v = max(versions, key=vkey)
    man, sig = _az_manifest(versions[v], v, token)
    verify_signature(man, sig)
    update_policy.store(man, sig)                      # the newest approved release says what is required
    try:
        m = json.loads(man)
    except ValueError:
        raise UpdateError("the update manifest is not JSON — refusing it")
    z = str(m.get("zip", ""))
    if m.get("product") != CLI or m.get("version") != v or not re.fullmatch(r"[0-9a-f]{64}", str(m.get("sha256", ""))) \
            or not re.fullmatch(r"[A-Za-z0-9._-]+\.zip", z):
        raise UpdateError("the update manifest is incomplete — refusing it")
    if vkey(v) <= vkey(cur):
        return {"current": cur, "available": None}
    return {"current": cur, "available": {"version": v, "notes": str(m.get("notes", ""))[:4000], "zip": z,
                                          "sha256": m["sha256"], "url": "", "private": True}}


def _az_download(info):
    token = access_token()
    if not token:
        raise UpdateError("sign in with your organisation account first: %s update login" % CLI)
    data = _tar_member(_az_tarball(info["version"], token), info["zip"])
    d = os.path.join(STATE, "updates", info["version"])
    if hashlib.sha256(data).hexdigest() != info["sha256"]:
        try:
            os.remove(os.path.join(d, "package.tgz"))
        except OSError:
            pass
        raise UpdateError("the downloaded installer does not match the signed SHA-256 — refusing it")
    path = os.path.join(d, info["zip"])
    fd, tmp = tempfile.mkstemp(dir=d)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    try:
        os.remove(os.path.join(d, "package.tgz"))
    except OSError:
        pass
    return path, info


def check():
    """-> {"current", "available": None | {"version", "notes", "zip", "sha256", "asset_id", "url"}}"""
    if not configured():
        raise UpdateError("updates are not set up in this build")
    if azure():
        return _az_check()
    token = None
    try:
        releases = json.loads(_api("/repos/%s/releases?per_page=20" % REPO, None))
    except UpdateError as e:
        if "repository is private" not in str(e):
            raise
        token = access_token()
        if not token:
            raise
        releases = json.loads(_api("/repos/%s/releases?per_page=20" % REPO, token))
    cur = current_version()
    newest = True
    for rel in releases:
        if rel.get("draft"):
            continue
        assets = {a["name"]: a for a in rel.get("assets", [])}
        if MANIFEST not in assets or SIGNATURE not in assets:
            continue                                                  # releases from before signed updates
        man = _api("/repos/%s/releases/assets/%d" % (REPO, assets[MANIFEST]["id"]), token, "application/octet-stream")
        sig = _api("/repos/%s/releases/assets/%d" % (REPO, assets[SIGNATURE]["id"]), token, "application/octet-stream")
        verify_signature(man, sig)
        if newest:                 # the newest signed release says what is required (min_version / required_after)
            update_policy.store(man, sig)
            newest = False
        m = json.loads(man)
        if m.get("product") != CLI or not re.fullmatch(r"\d+\.\d+\.\d+", str(m.get("version", ""))) \
                or not re.fullmatch(r"[0-9a-f]{64}", str(m.get("sha256", ""))) or m.get("zip") not in assets:
            raise UpdateError("the update manifest is incomplete — refusing it")
        update_policy.record_check()
        if vkey(m["version"]) <= vkey(cur):
            return {"current": cur, "available": None}
        return {"current": cur, "available": {"version": m["version"], "notes": str(m.get("notes", ""))[:4000],
                                              "zip": m["zip"], "sha256": m["sha256"],
                                              "asset_id": assets[m["zip"]]["id"], "url": rel.get("html_url", ""),
                                              "private": bool(token)}}
    update_policy.record_check()
    return {"current": cur, "available": None}


def download():
    """Download + verify the newer installer; -> path of the verified zip under the state dir."""
    info = check()["available"]
    if not info:
        raise UpdateError("already up to date")
    if azure():
        return _az_download(info)
    token = access_token() if info["private"] else None
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
            "installed": installed_copy(), "repo": REPO if not azure() else "",
            "source": SOURCE, "where": source_label()}


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
                    print("Signed in. %s will check %s for updates." % (PRODUCT.get("name", CLI), source_label()))
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
