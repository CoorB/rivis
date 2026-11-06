#!/usr/bin/env python3
"""IT approval: only a person IT approved may use Rivis (product.json "access_required").

  access.py status [--json]        exit 0 approved (or the check is off) · 13 not approved, not signed in or expired
  access.py check [--json] [--force]   ask the organisation now (only when due, unless --force); same exit codes
  access.py login                  sign in with the organisation account in this terminal, then check
  access.py gate                   for the CLIs: check when due, print "STATE<TAB>reason"; same exit codes

How approval works
- The organisation's policy allows the tool only to people IT approved in writing. A person reads the policy and fills
  in IT's form; IT then adds them to the Rivis readers group in Azure DevOps. Membership of that group IS the approval:
  it is what lets them download Rivis and its updates from the "rivis" feed.
- Rivis asks the person to sign in once with their organisation account (the same device-code sign-in and Keychain
  token as in-app updates, addons/updater.py) and then asks Azure DevOps for the feed. An answer with the feed means
  approved; "not authorised" means not approved (yet), and Rivis says to fill in the form. Removing someone from the
  group locks their copy at its next check.
- The answer is kept in ~/.rivis-access.json (0600, next to the state dir like the Terms of Use record): who signed in,
  when it was last confirmed, earlier answers. The check repeats every "access_recheck_hours" (default 24) while Rivis
  runs; a copy that cannot reach Azure DevOps keeps working for "access_offline_days" (default 7) after the last
  confirmation, then locks until it can confirm again. A copy that was never confirmed is locked.
- A build with "access_required" but without the sign-in ids is locked (fail closed): the release build writes both.
- Like the Terms of Use record this is a compliance control, not a lock against someone editing local files.

Standard library only; runs under /usr/bin/python3 -I (3.9) and inside mitmweb (status only: no network there).
"""
import base64
import datetime
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

OK, OFF, SIGN_IN, REFUSED, EXPIRED, UNCONFIGURED = "ok", "off", "sign_in", "refused", "expired", "unconfigured"
ALLOWED = (OK, OFF)
EXIT_LOCKED = 13
MAX_HISTORY = 50


def _product():
    try:
        with open(os.path.join(ROOT, "product.json")) as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


PRODUCT = _product()
CLI = PRODUCT.get("cli") or "rivis"
NAME = PRODUCT.get("name") or "Rivis"
ENV = PRODUCT.get("env_prefix") or "RIVIS"
AZ = PRODUCT.get("azure_updates") if isinstance(PRODUCT.get("azure_updates"), dict) else {}
AZ_FEEDS = (PRODUCT.get("azure_feeds_url") or "https://feeds.dev.azure.com").rstrip("/")
FORM_HINT = PRODUCT.get("access_form_hint") or "read the policy, fill in IT's confirmation form and ask IT for access"

if os.name == "nt" and not os.environ.get(ENV + "_TOKEN_FILE"):
    # no Keychain on Windows: the sign-in lives in a file in the user's own profile (updater.py writes it 0600)
    os.environ[ENV + "_TOKEN_FILE"] = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
                                                   NAME, "signin-token")


def _int(key, default):
    v = PRODUCT.get(key)
    return v if isinstance(v, int) and not isinstance(v, bool) and v > 0 else default


OFFLINE_DAYS = _int("access_offline_days", 7)
RECHECK_HOURS = _int("access_recheck_hours", 24)
RETRY_MINUTES = 60          # after a check that could not reach Azure DevOps, wait this long before trying again


def required():
    return PRODUCT.get("access_required") is True


def configured():
    return all(isinstance(AZ.get(k), str) and AZ[k].strip() for k in ("org", "project", "feed", "tenant", "client_id"))


def check_url():
    """The feed itself: an approved reader may read it, anybody else may not."""
    if PRODUCT.get("access_check_url"):
        return PRODUCT["access_check_url"]
    q = lambda v: urllib.parse.quote(str(v), safe="")
    return "%s/%s/%s/_apis/packaging/feeds/%s?api-version=7.1" % (AZ_FEEDS, q(AZ["org"]), q(AZ["project"]), q(AZ["feed"]))


def record_path():
    return os.path.expanduser("~/.%s-access.json" % CLI)


def _now():
    return datetime.datetime.now().astimezone()


def _iso(dt):
    return dt.isoformat(timespec="seconds")


def _parse(text):
    try:
        dt = datetime.datetime.fromisoformat(str(text))
        return dt if dt.tzinfo else dt.astimezone()
    except (TypeError, ValueError):
        return None


def load():
    try:
        with open(record_path()) as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(doc):
    path = record_path()
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".%s-access-" % CLI, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def status(now=None):
    """{"state", "allowed", "account", "name", "approved_at", "checked_at", "due", "reason"} from the local record."""
    now = now or _now()
    rec = load()
    out = {"state": OK, "allowed": True, "account": rec.get("account"), "name": rec.get("name"),
           "approved_at": rec.get("approved_at"), "checked_at": rec.get("checked_at"), "due": False, "reason": None}
    if not required():
        out.update(state=OFF)
        return out
    if not configured():
        out.update(state=UNCONFIGURED, reason="this copy of %s has no organisation sign-in details, so it cannot "
                                              "confirm that IT approved you; reinstall it from the official release" % NAME)
    elif rec.get("result") == "refused":
        out.update(state=REFUSED, reason="%s is not approved to use %s: %s. Once IT has added you, run '%s access'"
                                         % (rec.get("account") or "this account", NAME, FORM_HINT, CLI))
    else:
        approved = _parse(rec.get("approved_at")) if rec.get("result") == "approved" else None
        if approved is None:
            out.update(state=SIGN_IN, reason="%s needs to confirm that IT approved you: sign in with your organisation "
                                             "account ('%s access' in a terminal, or in the %s window)" % (NAME, CLI, NAME))
        elif now - approved > datetime.timedelta(days=OFFLINE_DAYS):
            out.update(state=EXPIRED, reason="%s could not confirm your approval for %d days (the limit is %d): connect "
                                             "to the network and sign in again ('%s access')"
                                             % (NAME, (now - approved).days, OFFLINE_DAYS, CLI))
    checked, tried = _parse(rec.get("checked_at")), _parse(rec.get("tried_at"))
    out["due"] = out["state"] != OFF and (checked is None or now - checked >= datetime.timedelta(hours=RECHECK_HOURS)) \
        and (tried is None or now - tried >= datetime.timedelta(minutes=RETRY_MINUTES))
    out["allowed"] = out["state"] in ALLOWED
    return out


def allowed():
    return status()["allowed"]


# ── the check ─────────────────────────────────────────────────────────────────────────────────────────────────────
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None          # a redirect is Azure DevOps sending a stale sign-in to its login page: never follow it


_OPENER = urllib.request.build_opener(_NoRedirect)


def _get(url, token):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "Authorization": "Bearer " + token,
                                               "User-Agent": "%s-access" % CLI})
    try:
        with _OPENER.open(req, timeout=20) as r:
            return r.status, r.headers.get("Content-Type") or "", r.read(1 << 20)
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type") or "", e.read(1 << 16)


def classify(code, ctype, body):
    """-> "approved" | "refused" | "signin" (the token is not accepted) | "unknown"."""
    text = body[:4000].decode("utf-8", "replace")
    if code == 200 and "json" in ctype.lower():
        try:
            doc = json.loads(body)
        except ValueError:
            return "unknown"
        if isinstance(doc, dict) and doc.get("id") and str(doc.get("name", "")).lower() == str(AZ.get("feed", "")).lower():
            return "approved"
        return "unknown"
    if code in (301, 302, 303, 307, 308, 203):
        return "signin"                  # Azure DevOps sends a token it does not accept to its sign-in page
    if code == 401:
        # TF400813: a valid organisation account that is not a member of this Azure DevOps organisation
        return "refused" if "TF400813" in text else "signin"
    if code in (403, 404):
        return "refused"                 # signed in, but not allowed to read the feed (not in the readers group)
    return "unknown"


def _who(token):
    """The signed-in account, from the access token's claims (shown and recorded only: the server's answer decides)."""
    try:
        part = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (IndexError, ValueError):
        return None, None
    account = claims.get("upn") or claims.get("preferred_username") or claims.get("unique_name") or claims.get("email")
    return (str(account)[:200] if account else None), (str(claims["name"])[:200] if claims.get("name") else None)


def _remember(result, account, name):
    now = _iso(_now())
    rec = load()
    history = rec.get("history") if isinstance(rec.get("history"), list) else []
    if rec.get("result") and (rec.get("result"), rec.get("account")) != (result, account):
        history.append({k: rec.get(k) for k in ("result", "account", "checked_at")})
    doc = {"result": result, "account": account or rec.get("account"), "name": name or rec.get("name"),
           "checked_at": now, "approved_at": now if result == "approved" else None, "history": history[-MAX_HISTORY:]}
    _write(doc)


def _tried():
    rec = load()
    if rec:                            # only an existing record: an attempt alone never creates one
        rec["tried_at"] = _iso(_now())
        _write(rec)


def check(force=False):
    """Ask Azure DevOps (when due, or always with force) and return status() plus "check": what happened."""
    st = status()
    if st["state"] in (OFF, UNCONFIGURED) or not (force or st["due"] or not st["allowed"]):
        return dict(st, check="skipped")
    import updater                     # the sign-in (token in the Keychain) is shared with in-app updates
    token = updater.access_token()
    if not token:
        return dict(st, check="signin")
    try:
        code, ctype, body = _get(check_url(), token)
    except (OSError, urllib.error.URLError) as e:
        _tried()
        return dict(st, check="unknown", error="could not reach Azure DevOps: %s" % (getattr(e, "reason", None) or e))
    verdict = classify(code, ctype, body)
    if verdict == "signin":
        updater.token_delete()           # an expired or revoked sign-in: ask for a new one (the record is unchanged)
        return dict(status(), check="signin")
    if verdict == "unknown":
        _tried()
        return dict(st, check="unknown", error="Azure DevOps answered %s" % code)
    account, name = _who(token)
    _remember(verdict, account, name)
    return dict(status(), check=verdict)


def login(out=sys.stdout):
    """Device-code sign-in in this terminal, then a check. -> exit code."""
    import updater
    s = updater.login_start()
    print("Sign in with your organisation account: open %s and enter the code  %s" % (s["verification_uri"], s["user_code"]),
          file=out, flush=True)
    if sys.platform == "darwin":
        import subprocess
        subprocess.run(["open", s["verification_uri"]], capture_output=True)
    interval = s["interval"]
    while time.time() < s["expires_at"]:
        time.sleep(interval)
        r = updater.login_poll(s["device_code"])
        if r == "ok":
            break
        if r == "slow_down":
            interval += 5
    else:
        raise updater.UpdateError("the code expired — run '%s access' again" % CLI)
    return check(force=True)


def describe(st):
    if st["state"] == OFF:
        return "IT approval check: off in this build"
    if st["state"] == OK:
        return "approved by IT: %s (confirmed %s)" % (st.get("account") or "signed in", (st.get("approved_at") or "")[:16])
    return st["reason"]


def main(argv):
    cmd = argv[0] if argv else "status"
    as_json = "--json" in argv[1:]
    if cmd == "status" and set(argv[1:]) <= {"--json"}:
        st = status()
    elif cmd == "check" and set(argv[1:]) <= {"--json", "--force"}:
        st = check(force="--force" in argv[1:])
    elif cmd == "gate" and len(argv) == 1:
        st = check()
        print("%s\t%s" % (st["state"], st.get("reason") or ""))
        return 0 if st["allowed"] else EXIT_LOCKED
    elif cmd == "login" and len(argv) == 1:
        import updater
        try:
            st = login()
        except updater.UpdateError as e:
            print("%s: %s" % (CLI, e), file=sys.stderr)
            return 1
    else:
        print("usage: access.py status [--json] | check [--json] [--force] | login | gate", file=sys.stderr)
        return 2
    if as_json:
        print(json.dumps(st))
    else:
        print(describe(st))
        if st.get("error"):
            print("(%s)" % st["error"], file=sys.stderr)
    return 0 if st["allowed"] else EXIT_LOCKED


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
