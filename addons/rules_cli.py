"""rules_cli — edit a project rules file. Stdlib only (runs on system Python 3.9).

  rules_cli.py FILE rules list
  rules_cli.py FILE rules on|off|show|rm NAME
  rules_cli.py FILE rules test URL [METHOD]     what each rule would do to this call (no traffic is sent)
  rules_cli.py FILE rules add NAME match=REGEX action=ACTION [key=value ...]
  rules_cli.py FILE rules edit
  rules_cli.py FILE throttle off|lte|3g|edge|slow|<ms>ms[/<kbps>kbps] [match=REGEX] [loss=PCT]
  rules_cli.py FILE nocache on|off|status       strip conditional request headers, force fresh responses

Values are parsed as JSON when they can be (status=500 → 500, set={"a":1} → object),
otherwise kept as text. The running proxy picks every change up within a second.
"""
import json
import math
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:       # /usr/bin/python3 -I removes the script directory
    sys.path.insert(0, HERE)
from proxy_common import (ACTION_REQUIREMENTS, PRESETS, PROFILE_VALUES, PRODUCT, SAFE_NAME, atomic_json, breakpoints, confined_path,
                           forbidden_file, migrate_rules, owned_mock_file, project_profile, project_state, remote_url_problem, set_trusted_file,
                           throttle_shorthand, trusted_files, user_regex)
from proxy_rule_validation import compile_rule, explain_rules, map_remote_warning, rule_fingerprint

ACTIONS = ACTION_REQUIREMENTS


def die(msg):
    print(PRODUCT["cli"] + ": " + msg, file=sys.stderr)
    sys.exit(1)


def load(path):
    with open(path) as f:
        try:
            cfg = migrate_rules(json.load(f))
        except ValueError as e:              # a hand edit gone wrong: say where, never a traceback
            die("%s is not valid JSON: %s — fix it (rivis rules edit) or restore it" % (path, e))
    if not isinstance(cfg, dict) or not isinstance(cfg.get("rules", []), list):
        die("%s: rules.json must be an object with a rules list" % path)
    return cfg


def save(path, cfg):
    try:
        atomic_json(path, migrate_rules(cfg))
    except OSError as e:
        die("could not save rules to %s: %s" % (path, e.strerror or e))


def acquire_lock(path):
    try:
        import fcntl
    except ImportError:
        return None                    # Windows has no flock; commands must still work there
    lock = None
    try:
        lock = os.fdopen(os.open(os.path.join(os.path.dirname(os.path.abspath(os.path.expanduser(path))), ".rules.lock"),
                                 os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), "a")
        fcntl.flock(lock, fcntl.LOCK_EX)
        return lock
    except OSError:
        if lock is not None:
            lock.close()
        return None                    # read-only or missing dir: the command reports that itself


def value(v):
    try:
        return json.loads(v)
    except ValueError:
        return v


def throttle_number(text, name):
    try:
        number = float(text)
    except ValueError:
        die("%s must be a number" % name)
    cap = 100 if name in ("loss", "loss_pct") else 120000 if name in (
        "latency_ms", "jitter_ms", "response_delay_ms") else 1000000
    if not math.isfinite(number) or number < 0 or number > cap:
        die("%s must be 0–%s" % (name, cap))
    return number


def find(cfg, name):
    for r in cfg.get("rules", []):
        if isinstance(r, dict) and r.get("name") == name:
            return r
    die("no rule named '%s' (%s rules list)" % (name, PRODUCT["cli"]))


def describe(r, status=None):
    extra = {k: v for k, v in r.items() if k not in ("name", "enabled", "match", "action", "method", "note", "rivis_created_mock")}
    bits = " ".join("%s=%s" % (k, json.dumps(v, ensure_ascii=False)) for k, v in extra.items())
    return "%-3s %-24s %-10s %s%s  %s" % (
        status or ("ON" if r.get("enabled", True) else "off"), r.get("name", "?"), r.get("action", "?"),
        (str(r["method"]) + " ") if r.get("method") else "", r.get("match", "."), bits)


def proxy_rule_error(path, r):
    # R5A-02: use the proxy's own per-rule load check before claiming a rule is ON.
    try:
        compile_rule(r, os.path.dirname(os.path.abspath(path)), confdir=os.environ.get("RIVIS_RULE_CONFDIR") or os.environ.get("RIVIS_CONFDIR"))
    except (KeyError, TypeError, ValueError, re.error) as e:
        return str(e)
    return None


def validate(r):
    a = r.get("action")
    if a not in ACTIONS:
        die("action must be one of: " + ", ".join(ACTIONS))
    missing = [k for k in ACTIONS[a] if k not in r]
    if missing:
        die("action '%s' needs: %s" % (a, ", ".join(missing)))
    if a in ("respond", "status") and "status" in r:
        status = r["status"]
        if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
            die("status must be an integer from 100 to 599")
    for k in ("match", "replace"):
        if k in r:
            try:
                user_regex(r[k])
            except re.error as e:
                die("bad regex in %s: %s" % (k, e))
    if "method" in r and not isinstance(r["method"], str):
        die("method must be text, e.g. method=POST")
    if a == "delay":
        try:
            ms = float(r["ms"])
        except (TypeError, ValueError):
            ms = -1
        if not 0 <= ms <= 600000:                  # inf / nan / 1e12 would hang every matching call
            die("delay ms must be a number from 0 to 600000")
    if a == "map_remote" and isinstance(r.get("with"), str):
        # R2A-11: a rewrite that turns an ordinary URL into something that is not http(s)+host can never work. The
        # replacement alone is not a URL (it may be a path fragment), so probe it on a sample URL the pattern matches
        try:
            probe = "https://example.com/p?q=1"
            out = user_regex(r["replace"]).sub(r["with"], probe)
        except (re.error, IndexError, ValueError):
            out = probe
        if out != probe and remote_url_problem(out):
            die("map_remote with=%r turns a URL into something unusable: %s" % (r["with"], remote_url_problem(out)))
    if a == "map_local" and not os.path.isfile(os.path.expanduser(r["file"])):
        die("file not found: %s" % r["file"])


def trust_local_files(path, r):
    """A rule typed on this machine may read the user's own files outside the project: trust them here.
    (rules.json itself can never do this — the trust list lives in a separate file only this CLI writes.)"""
    state_dir = os.path.dirname(os.path.abspath(path))
    for key in ("file", "body_file"):
        f = r.get(key)
        if not isinstance(f, str) or not f:
            continue
        try:
            confined_path(state_dir, f, key)
            continue
        except ValueError:
            pass
        why = forbidden_file(f)
        if why:
            die("refusing %s=%s: %s" % (key, f, why))
        set_trusted_file(state_dir, f)
        print("note: %s is outside the project; trusted on this machine only (undo: %s rules disallow-file '%s')"
              % (f, PRODUCT["cli"], f))


def trust_cmd(path, cmd, args):
    state_dir = os.path.dirname(os.path.abspath(path))
    if cmd == "trusted-files":
        files = sorted(trusted_files(state_dir))
        print("\n".join(files) if files else "(no files outside the project are trusted)")
        return
    if len(args) != 1:
        die("usage: rules %s PATH" % cmd)
    if cmd == "allow-file":
        if not os.path.isfile(os.path.abspath(os.path.expanduser(args[0]))):
            die("file not found: %s" % args[0])
        try:
            real = set_trusted_file(state_dir, os.path.abspath(os.path.expanduser(args[0])))
        except ValueError as e:
            die(str(e))
        print("trusted on this machine: %s — rules may now read it (restart not needed)" % real)
    else:
        print("no longer trusted: %s" % set_trusted_file(state_dir, args[0], trusted=False))
    if os.path.exists(path):
        os.utime(path)      # the proxy hot-reloads rules when rules.json changes


NEVER_MATCHED_AFTER = 10      # calls seen since a rule was switched on before "never matched" is reported


def read_hits(path):
    """The running proxy's hit counts for this rules file (rule-hits.json next to it), or None."""
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(path)), "rule-hits.json")) as f:
            doc = json.load(f)
        return doc if isinstance(doc, dict) and isinstance(doc.get("rules"), dict) else None
    except (OSError, ValueError):
        return None


def _ago(t):
    import time
    d = max(0, time.time() - float(t))
    return "%ds ago" % d if d < 60 else "%d min ago" % (d // 60) if d < 3600 else "%d h ago" % (d // 3600)


def hit_line(hits, r):
    """One line about how this rule has behaved on real traffic, or None when nothing is known."""
    if not hits or not r.get("enabled", True):
        return None
    h = hits["rules"].get(r.get("name"))
    if not isinstance(h, dict) or (hits.get("fingerprints") or {}).get(r.get("name")) != rule_fingerprint(r):
        return None                      # edited since the proxy last wrote its counts
    count, noop, since = h.get("count", 0), h.get("noop", 0), h.get("calls_since", 0)
    if count:
        return "    matched %d call%s · last %s%s" % (count, "" if count == 1 else "s", _ago(h["last"]),
                                                    " · %d matched without changing anything" % noop if noop else "")
    if noop:
        return "      ! matched %d call%s but changed nothing — %s" % (noop, "" if noop == 1 else "s", h.get("noop_reason") or "")
    if since >= NEVER_MATCHED_AFTER:
        return ("      ! ON, but none of the %d calls since it was switched on matched it — try: rules test URL [METHOD]" % since)
    return "    no matching call yet"


def rules_cmd(path, args):
    cfg = load(path)
    cmd = args[0] if args else "list"
    if cmd == "list":
        rules = cfg.get("rules", [])
        print(throttle_description(cfg))
        print("rules (%s):" % path)
        hits = read_hits(path)
        for i, r in enumerate(rules, 1):
            if not isinstance(r, dict):
                print("  ! rules.json entry %d is not an object (skipped)" % i)  # R3A-07: hand edits can contain junk
                continue
            reason = proxy_rule_error(path, r) if r.get("enabled", True) else None
            print("  " + describe(r, "SKIPPED" if reason else None))
            if reason:
                print("      ! " + reason)
            warning = map_remote_warning(r)
            if warning:
                print("      ! " + warning)
            f = r.get("file") if r.get("action") == "map_local" else r.get("body_file")
            if isinstance(f, str) and f and r.get("enabled", True) and not os.access(os.path.expanduser(f), os.R_OK):
                print("      ! %s is missing or unreadable — this rule answers 502" % f)
            line = None if reason else hit_line(hits, r)
            if line:
                print(line)
        if not rules:
            print("  (none)")
        return
    if cmd == "edit":
        # R5A-02: edit a staging copy so a rule the proxy would skip never replaces the active file.
        fd, staged = tempfile.mkstemp(prefix=".rules-edit-", suffix=".json", dir=os.path.dirname(path))
        staged_ready = saved = False
        try:
            with open(path, "rb") as src, os.fdopen(fd, "wb") as out:
                original = src.read()
                out.write(original)
            staged_ready = True
            if subprocess.call([os.environ.get("EDITOR", "nano"), staged]):
                die("editor exited without saving rules")
            edited = load(staged)
            for r in edited.get("rules", []):
                if isinstance(r, dict) and r.get("enabled", True):
                    reason = proxy_rule_error(path, r)
                    if reason:
                        die("rule '%s' skipped by proxy: %s" % (r.get("name", "?"), reason))
            lock = acquire_lock(path)
            try:
                with open(path, "rb") as current:
                    if current.read() != original:
                        die("rules changed while the editor was open; review the current rules and merge your edit")
                save(path, edited)
                saved = True
            finally:
                if lock is not None:
                    lock.close()
        finally:
            if saved or not staged_ready:
                os.unlink(staged)
            else:
                print("%s: edited rules kept at %s" % (PRODUCT["cli"], staged), file=sys.stderr)
        return
    if cmd == "test":
        if len(args) < 2 or len(args) > 3:
            die("usage: rules test URL [METHOD]   (e.g. rules test https://api.example.com/v1/users POST)")
        url, method = args[1], (args[2] if len(args) == 3 else "GET").upper()
        if not re.match(r"(?i)^https?://[^/\s]+", url):
            die("rules test needs a full URL starting with http:// or https://, got '%s'" % url)
        rows = explain_rules(cfg.get("rules", []), os.path.dirname(os.path.abspath(path)), url, method,
                             os.environ.get("RIVIS_RULE_CONFDIR") or os.environ.get("RIVIS_CONFDIR"))
        print("%s %s" % (method, url))
        for x in rows:
            if x["fires"]:
                print("  FIRES  %-24s %s" % (x["name"], x["effect"]))
            else:
                print("  %-6s %-24s %s" % ("!" if x.get("inert") else "-", x["name"], x["reason"]))
        if not rows:
            print("  (no rules)")
        elif not any(x["fires"] for x in rows):
            print("no rule changes this call")
        return
    if cmd in ("allow-file", "disallow-file", "trusted-files"):
        return trust_cmd(path, cmd, args[1:])
    if len(args) < 2:
        die("usage: rules %s NAME" % cmd)
    name = args[1]
    if cmd in ("on", "off"):
        r = find(cfg, name)
        if cmd == "on":
            reason = proxy_rule_error(path, r)
            if reason:
                die("rule '%s' skipped by proxy: %s" % (name, reason))
        r["enabled"] = cmd == "on"
        if cmd == "on":
            r.pop("draft", None)         # switched on by hand: no longer a discardable draft (the panel toggle does the same)
        save(path, cfg)
        print("%s → %s" % (name, cmd.upper()))
    elif cmd == "show":
        print(json.dumps(find(cfg, name), indent=2, ensure_ascii=False))
    elif cmd == "rm":
        r = find(cfg, name)
        cfg["rules"].remove(r)
        mock = owned_mock_file(r, cfg.get("rules", []), os.path.join(project_state(active_project(path)), "mocks"), path)
        undeleted = None
        if mock:
            try:
                os.remove(mock)          # before the save, as the panel does: no reader sees the rule gone with its mock still there
            except OSError as e:
                undeleted = e
        save(path, cfg)
        if mock:
            if undeleted:
                print("removed %s (its mock file %s could not be deleted: %s)" % (name, mock, undeleted.strerror))
                return
            print("removed %s and its mock file %s" % (name, mock))
            return
        if r.get("action") == "map_local" and isinstance(r.get("file"), str) and os.path.isfile(os.path.expanduser(r["file"])):
            print("removed %s; mock file kept: %s" % (name, r["file"]))
        else:
            print("removed " + name)
    elif cmd in ("add", "mock-set"):
        if not SAFE_NAME.fullmatch(name) or name.startswith("."):      # F-17: same rule as the panel
            die("rule name '%s': letters, digits, . _ - only (max 64, not starting with .)" % name)
        if any(str(r.get("name", "")).lower() == name.lower() and
               (cmd != "mock-set" or r.get("action") != "map_local")
               for r in cfg.get("rules", []) if isinstance(r, dict)):
            die("rule '%s' exists — rm it first or pick another name" % name)
        r = {"name": name, "enabled": True}
        for kv in args[2:]:
            if "=" not in kv:
                die("expected key=value, got '%s'" % kv)
            k, v = kv.split("=", 1)
            if k == "rivis_created_mock":
                die("rivis_created_mock is managed by Rivis")
            r[k] = value(v) if k not in ("match", "replace", "with", "file", "header", "body") else v
        created = r.pop("created_mock", None)
        if created is not None and (cmd != "mock-set" or created not in (0, 1)):
            die("created_mock is only for mock capture")
        if cmd == "add" and r.get("action") == "map_local" and "body" in r and "file" not in r:
            mock_dir = os.path.join(project_state(active_project(path)), "mocks")
            os.makedirs(mock_dir, exist_ok=True)
            mock_path = os.path.join(mock_dir, name + ".txt")
            if os.path.exists(mock_path):
                die("mock file exists: %s" % mock_path)
            from proxy_common import atomic_write_text
            atomic_write_text(mock_path, r.pop("body"))
            r["file"] = mock_path
            created = 1
        r.setdefault("match", ".")
        if r.get("action") == "map_local" and isinstance(r.get("file"), str):
            r["file"] = os.path.abspath(os.path.expanduser(r["file"]))  # R3A-08: proxy cwd differs from CLI cwd
        if created == 1:
            real = os.path.realpath(r.get("file", ""))
            if r.get("action") != "map_local" or os.path.dirname(real) != os.path.realpath(
                    os.path.join(project_state(active_project(path)), "mocks")):
                die("created mock must be inside this project's mocks folder")
            r["rivis_created_mock"] = real
        if "method" in r and not str(r["method"] or "").strip():     # method= (empty) means any method
            del r["method"]
        validate(r)
        trust_local_files(path, r)
        reason = proxy_rule_error(path, r)
        if reason:
            die("rule '%s' skipped by proxy: %s" % (name, reason))
        superseded = []
        if cmd == "mock-set":
            if r.get("action") != "map_local":
                die("mock-set requires action=map_local")
            # A Map Local rule for another method can serve the same URL independently.
            # Replace the same named rule, or a rule with both the same match and method.
            def is_superseded(old):
                return (isinstance(old, dict) and old.get("action") == "map_local" and
                        (str(old.get("name", "")).lower() == name.lower() or
                         (old.get("match") == r["match"] and
                          str(old.get("method") or "").strip().upper() ==
                          str(r.get("method") or "").strip().upper())))

            superseded = [old.get("name", "?") for old in cfg.get("rules", []) if is_superseded(old)]
            cfg["rules"] = [old for old in cfg.get("rules", []) if not is_superseded(old)]
        cfg.setdefault("rules", []).append(r)
        save(path, cfg)
        if superseded:
            print("replaced Map Local rule%s: %s" % ("s" if len(superseded) != 1 else "", ", ".join(superseded)))
        print("added and ON: " + describe(r))
        warning = map_remote_warning(r)
        if warning:
            print("  ! " + warning)
    else:
        die("unknown rules command '%s'" % cmd)


def active_project(path):
    explicit = os.environ.get("RIVIS_ACTIVE_PROJECT")
    if explicit:
        return explicit
    folder = os.path.dirname(os.path.abspath(os.path.expanduser(path)))
    return os.path.basename(folder) if os.path.basename(os.path.dirname(folder)) == "projects" else "default"


def default_throttle_match(path):
    """The active project's own throttle scope, including when rules.json is overridden."""
    try:
        scope = project_profile(active_project(path)).get("throttle_match", "")
        scope = scope.strip() if isinstance(scope, str) else ""
        user_regex(scope)
    except (OSError, ValueError, re.error):
        return ""
    return "" if scope == "." else scope


def throttle_cmd(path, args):
    cfg = load(path)
    if not args:
        print(throttle_description(cfg))
        return
    spec = args[0].lower()
    try:
        shorthand = throttle_shorthand(spec)
    except ValueError as e:
        die("throttle: %s" % e)
    if spec not in PRESETS and shorthand is None:
        die("throttle: " + " | ".join(PRESETS) + " | <ms>ms[/<kbps>kbps]")
    cfg["throttle"] = spec
    cfg["loss"] = 0              # R3A-03: loss= belongs to one command; a later profile uses its own loss
    cfg["throttle_match"] = default_throttle_match(path)  # a later profile goes back to the project's own scope
    for kv in args[1:]:
        k, _, v = kv.partition("=")
        if k == "match":
            v = v.strip()                                 # a pasted " /x " must not silently match nothing
            try:
                user_regex(v)
            except re.error as e:
                die("throttle: bad regex in match: %s" % e)
            cfg["throttle_match"] = v
        elif k == "loss":
            cfg["loss"] = throttle_number(v, k)
        elif k in ("latency_ms", "jitter_ms", "down_kbps", "up_kbps", "loss_pct", "response_delay_ms"):
            cfg.setdefault("manual", {})[k] = throttle_number(v, k)   # used when the profile is "manual"
        else:
            die("throttle options: match=REGEX loss=PCT, and for manual: latency_ms= jitter_ms= down_kbps= up_kbps= loss_pct= response_delay_ms=")
    save(path, cfg)
    print(throttle_description(cfg))


def nocache_description(cfg):
    return "No caching: %s" % ("on" if cfg.get("no_cache") else "off")


def nocache_cmd(path, args):
    cfg = load(path)
    cmd = (args[0].lower() if args else "status")
    if cmd in ("on", "off"):
        if len(args) > 1:
            die("nocache: on | off | status")
        cfg["no_cache"] = cmd == "on"
        save(path, cfg)
    elif cmd != "status" or len(args) > 1:
        die("nocache: on | off | status")
    print(nocache_description(cfg))


def throttle_description(cfg):
    # R5A-04: include the manual fields that actually shape traffic, including profile loss.
    spec = cfg.get("throttle", "off")
    manual = cfg.get("manual", {}) if spec == "manual" else {}
    detail = "  " + "  ".join("%s=%s" % (k, manual.get(k, 0)) for k in (
        "latency_ms", "jitter_ms", "down_kbps", "up_kbps", "loss_pct", "response_delay_ms")) if isinstance(manual, dict) and manual else ""
    preset = PROFILE_VALUES.get(spec) if isinstance(spec, str) else None
    loss = cfg.get("loss", 0) or (manual.get("loss_pct", 0) if isinstance(manual, dict) else 0) or (preset[4] if preset else 0)
    return "throttle: %s  match: %s  loss: %s%%%s" % (spec,
           cfg.get("throttle_match", "") or "(all)", loss, detail)


def breakpoint_cmd(path, args):
    """breakpoint                         list
       breakpoint REGEX [--request|--response] [--method M]   add (both phases by default)
       breakpoint off [NAME]              remove one, or all"""
    cfg = load(path)
    bps = breakpoints(cfg, migrate=bool(args))
    if not args:
        if not bps:
            print("breakpoints: none")
        for b in bps:
            ph = "+".join(x for x in ("request", "response") if b.get(x))
            print("  %-3s %-22s %s%s (%s)" % ("ON" if b.get("enabled", True) else "off", b.get("name"),
                  (b["method"] + " ") if b.get("method") else "", b["match"], ph))
        return
    if args[0] == "off":
        if len(args) > 1:
            if not any(b.get("name") == args[1] for b in bps):
                die("no breakpoint named '%s' (existing: %s)" % (args[1], ", ".join(b.get("name", "?") for b in bps) or "none"))  # R5A-05
            cfg["breakpoints"] = [b for b in bps if b.get("name") != args[1]]
        else:
            cfg["breakpoints"] = []
        save(path, cfg)
        print("breakpoints off" + (" (" + args[1] + ")" if len(args) > 1 else " (all)") +
              " — calls already paused are sent on unchanged within a second (when the proxy is running)")
        return
    rx, req, resp, method, i = args[0], False, False, None, 1
    while i < len(args):
        if args[i] == "--request":        # the flags name the phases to pause on; both (or neither) = both
            req = True
        elif args[i] == "--response":
            resp = True
        elif args[i] == "--method" and i + 1 < len(args):
            method = args[i + 1].upper(); i += 1
        else:
            die("breakpoint options: --request | --response | --method M")
        i += 1
    if not req and not resp:
        req = resp = True
    try:
        user_regex(rx)
    except re.error as e:
        die("bad regex: %s" % e)
    names = {b.get("name") for b in bps}
    base = re.sub(r"[^A-Za-z0-9._-]", "-", rx.strip("^$\\"))[-30:].strip("-") or "bp"
    name, n = base, 2
    while name in names:
        name, n = "%s-%d" % (base, n), n + 1
    bps.append({"name": name, "match": rx, "method": method, "request": req, "response": resp, "enabled": True})
    save(path, cfg)
    print("breakpoint '%s' ON: %s (%s) — matching calls pause; edit in the project panel, then Continue" %
          (name, rx, "+".join(x for x, on in (("request", req), ("response", resp)) if on)))


def mock_cmd(path, args, flows_json, body_file):
    """mock NAME REGEX: save the newest matching call's real response to a file + map_local rule on it."""
    cfg = load(path)
    try:
        rx = user_regex(args[1])
    except re.error as e:
        die("bad regex: %s" % e)  # R5A-01: bad input must produce one CLI error, not a traceback
    flows = [f for f in json.load(open(flows_json)) if f.get("type") == "http" and f.get("response")
             and rx.search(f["request"]["scheme"] + "://" + f["request"]["pretty_host"] + f["request"]["path"])]
    if not flows:
        die("no captured call with a response matches '%s' — run the journey once with %s, then retry" % (args[1], PRODUCT["cli"]))
    f = flows[-1]
    print(f["id"])
    print(f["response"]["status_code"])
    print(f["request"]["method"])
    headers = f["response"].get("headers") or []
    if isinstance(headers, dict):
        headers = headers.items()
    content_type = next((v for k, v in headers if k.lower() == "content-type"), None)
    print(json.dumps([["Content-Type", content_type]] if content_type else []))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        die(__doc__)
    path, what, rest = sys.argv[1], sys.argv[2], sys.argv[3:]
    # R7B-03: two commands at once each read the file, changed it and wrote it back: both said "added", one was lost.
    # Hold an exclusive sidecar lock for the whole read-change-write where flock is available.
    # An editor may stay open for minutes. It takes this lock only when saving.
    _lock = None if what == "rules" and rest and rest[0] == "edit" else acquire_lock(path)
    if what == "rules":
        rules_cmd(path, rest)
    elif what == "throttle":
        throttle_cmd(path, rest)
    elif what == "nocache":
        nocache_cmd(path, rest)
    elif what == "breakpoint":
        breakpoint_cmd(path, rest)
    elif what == "mock-pick":
        mock_cmd(path, rest[:2], rest[2], None)
    else:
        die(__doc__)
