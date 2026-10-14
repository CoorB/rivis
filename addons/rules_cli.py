"""rules_cli — edit a project rules file. Stdlib only (runs on system Python 3.9).

  rules_cli.py FILE rules list
  rules_cli.py FILE rules on|off|show|rm NAME
  rules_cli.py FILE rules add NAME match=REGEX action=ACTION [key=value ...]
  rules_cli.py FILE rules edit
  rules_cli.py FILE throttle off|lte|3g|edge|slow|<ms>ms[/<kbps>kbps] [match=REGEX] [loss=PCT]

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
from proxy_common import ACTION_REQUIREMENTS, PRESETS, PRODUCT, breakpoints

ACTIONS = ACTION_REQUIREMENTS


def die(msg):
    print(PRODUCT["cli"] + ": " + msg, file=sys.stderr)
    sys.exit(1)


def load(path):
    with open(path) as f:
        return json.load(f)


def save(path, cfg):
    # write-then-rename so the running proxy never reads a half-written file
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".rules-", suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)


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
        if r.get("name") == name:
            return r
    die("no rule named '%s' (%s rules list)" % (name, PRODUCT["cli"]))


def describe(r):
    extra = {k: v for k, v in r.items() if k not in ("name", "enabled", "match", "action", "method", "note")}
    bits = " ".join("%s=%s" % (k, json.dumps(v, ensure_ascii=False)) for k, v in extra.items())
    return "%-3s %-24s %-10s %s%s  %s" % (
        "ON" if r.get("enabled", True) else "off", r.get("name", "?"), r.get("action", "?"),
        (r.get("method", "") + " ") if r.get("method") else "", r.get("match", "."), bits)


def validate(r):
    a = r.get("action")
    if a not in ACTIONS:
        die("action must be one of: " + ", ".join(ACTIONS))
    missing = [k for k in ACTIONS[a] if k not in r]
    if missing:
        die("action '%s' needs: %s" % (a, ", ".join(missing)))
    for k in ("match", "replace"):
        if k in r:
            try:
                re.compile(r[k])
            except re.error as e:
                die("bad regex in %s: %s" % (k, e))
    if a == "map_local" and not os.path.isfile(os.path.expanduser(r["file"])):
        die("file not found: %s (use an absolute path)" % r["file"])


def rules_cmd(path, args):
    cfg = load(path)
    cmd = args[0] if args else "list"
    if cmd == "list":
        rules = cfg.get("rules", [])
        print("throttle: %s%s   loss: %s%%" % (cfg.get("throttle", "off"),
              ("  (match %s)" % cfg["throttle_match"]) if cfg.get("throttle_match") else "", cfg.get("loss", 0)))
        print("rules (%s):" % path)
        for r in rules:
            print("  " + describe(r))
        if not rules:
            print("  (none)")
        return
    if cmd == "edit":
        subprocess.call([os.environ.get("EDITOR", "nano"), path])
        try:
            load(path)
        except ValueError as e:
            die("file is no longer valid JSON: %s — the proxy keeps the previous rules until fixed" % e)
        return
    if len(args) < 2:
        die("usage: rules %s NAME" % cmd)
    name = args[1]
    if cmd in ("on", "off"):
        find(cfg, name)["enabled"] = cmd == "on"
        save(path, cfg)
        print("%s → %s" % (name, cmd.upper()))
    elif cmd == "show":
        print(json.dumps(find(cfg, name), indent=2, ensure_ascii=False))
    elif cmd == "rm":
        r = find(cfg, name)
        cfg["rules"].remove(r)
        save(path, cfg)
        print("removed " + name)
    elif cmd == "add":
        if any(r.get("name") == name for r in cfg.get("rules", [])):
            die("rule '%s' exists — rm it first or pick another name" % name)
        r = {"name": name, "enabled": True}
        for kv in args[2:]:
            if "=" not in kv:
                die("expected key=value, got '%s'" % kv)
            k, v = kv.split("=", 1)
            r[k] = value(v) if k not in ("match", "replace", "with", "file", "header", "body") else v
        r.setdefault("match", ".")
        validate(r)
        cfg.setdefault("rules", []).append(r)
        save(path, cfg)
        print("added and ON: " + describe(r))
    else:
        die("unknown rules command '%s'" % cmd)


def throttle_cmd(path, args):
    cfg = load(path)
    if not args:
        print("throttle: %s  match: %s  loss: %s%%" % (cfg.get("throttle", "off"),
              cfg.get("throttle_match", "") or "(all)", cfg.get("loss", 0)))
        return
    spec = args[0].lower()
    if spec not in PRESETS and not re.fullmatch(r"\d+ms(/\d+kbps)?", spec):
        die("throttle: " + " | ".join(PRESETS) + " | <ms>ms[/<kbps>kbps]")
    cfg["throttle"] = spec
    if spec == "off":
        cfg["loss"] = 0          # "throttle off" = clean network, unless loss= is given below
    for kv in args[1:]:
        k, _, v = kv.partition("=")
        if k == "match":
            re.compile(v)
            cfg["throttle_match"] = v
        elif k == "loss":
            cfg["loss"] = throttle_number(v, k)
        elif k in ("latency_ms", "jitter_ms", "down_kbps", "up_kbps", "loss_pct", "response_delay_ms"):
            cfg.setdefault("manual", {})[k] = throttle_number(v, k)   # used when the profile is "manual"
        else:
            die("throttle options: match=REGEX loss=PCT, and for manual: latency_ms= jitter_ms= down_kbps= up_kbps= loss_pct= response_delay_ms=")
    save(path, cfg)
    print("throttle: %s  match: %s  loss: %s%%" % (spec, cfg.get("throttle_match", "") or "(all)", cfg.get("loss", 0)))


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
            cfg["breakpoints"] = [b for b in bps if b.get("name") != args[1]]
        else:
            cfg["breakpoints"] = []
        save(path, cfg)
        print("breakpoints off" + (" (" + args[1] + ")" if len(args) > 1 else " (all)") +
              " — calls already paused stay paused until you Continue them in the UI")
        return
    rx, req, resp, method, i = args[0], True, True, None, 1
    while i < len(args):
        if args[i] == "--request":
            resp = False
        elif args[i] == "--response":
            req = False
        elif args[i] == "--method" and i + 1 < len(args):
            method = args[i + 1].upper(); i += 1
        else:
            die("breakpoint options: --request | --response | --method M")
        i += 1
    try:
        re.compile(rx)
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
    name, rx = args[0], re.compile(args[1])
    flows = [f for f in json.load(open(flows_json)) if f.get("type") == "http" and f.get("response")
             and rx.search(f["request"]["scheme"] + "://" + f["request"]["pretty_host"] + f["request"]["path"])]
    if not flows:
        die("no captured call with a response matches '%s' — run the journey once with %s, then retry" % (args[1], PRODUCT["cli"]))
    f = flows[-1]
    print(f["id"])
    print(f["response"]["status_code"])
    print(f["request"]["method"])


if __name__ == "__main__":
    if len(sys.argv) < 3:
        die(__doc__)
    path, what, rest = sys.argv[1], sys.argv[2], sys.argv[3:]
    if what == "rules":
        rules_cmd(path, rest)
    elif what == "throttle":
        throttle_cmd(path, rest)
    elif what == "breakpoint":
        breakpoint_cmd(path, rest)
    elif what == "mock-pick":
        mock_cmd(path, rest[:2], rest[2], None)
    else:
        die(__doc__)
