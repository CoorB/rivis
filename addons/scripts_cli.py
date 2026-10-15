#!/usr/bin/env python3
"""CLI parity for per-project scripts. Usage: scripts_cli.py RULES command ..."""
import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from proxy_common import SAFE_NAME, atomic_json, atomic_write_text, migrate_rules, user_regex

TEMPLATES = {
    "py": {
        "header": 'def on_request(context, url, request):\n    request["headers"]["X-QA"] = "enabled"\n    return request\n',
        "json": 'def on_response(context, url, request, response):\n    if isinstance(response["body"], dict):\n        response["body"]["featureEnabled"] = True\n        return response\n',
        "mock": 'def on_request(context, url, request):\n    return mock(200, {"message": "local response"}, {"Content-Type": "application/json"})\n',
        "latency": 'async def on_request(context, url, request):\n    await sleep(500)\n',
        "token": 'def on_response(context, url, request, response):\n    if "token" in url.lower():\n        log("token refresh", response["statusCode"])\n',
    },
    "js": {
        "header": 'async function onRequest(context, url, request) {\n  request.headers["X-QA"] = "enabled";\n  return request;\n}\n',
        "json": 'async function onResponse(context, url, request, response) {\n  if (response.body && typeof response.body === "object") {\n    response.body.featureEnabled = true;\n    return response;\n  }\n}\n',
        "mock": 'async function onRequest(context, url, request) {\n  return mock(200, {message: "local response"}, {"Content-Type": "application/json"});\n}\n',
        "latency": 'async function onRequest(context, url, request) {\n  await sleep(500);\n}\n',
        "token": 'async function onResponse(context, url, request, response) {\n  if (url.toLowerCase().includes("token")) log("token refresh", response.statusCode);\n}\n',
    },
}


def load(path):
    try:
        with open(path, encoding="utf-8") as fh: cfg = json.load(fh)
    except FileNotFoundError: cfg = {}
    cfg = migrate_rules(cfg)
    if not isinstance(cfg.get("rules"), list): cfg["rules"] = []
    if not isinstance(cfg.get("scripts"), list): cfg["scripts"] = []
    return cfg


def save(path, cfg):
    atomic_json(path, migrate_rules(cfg))


def find(cfg, name):
    hits = [x for x in cfg["scripts"] if x.get("name") == name or x.get("file") == name]
    if not hits: raise SystemExit(f"no script named '{name}'")
    return hits[0]


def main(argv):
    if len(argv) < 2: raise SystemExit("usage: scripts list|new NAME --lang py|js [--match REGEX]|on NAME|off NAME|edit NAME|rm NAME")
    rules = os.path.abspath(os.path.expanduser(argv[0]))
    if argv[1] == "--script-dir" and len(argv) < 4:
        raise SystemExit("--script-dir needs a path and command")
    if len(argv) >= 4 and argv[1] == "--script-dir":
        script_dir, command, rest = os.path.abspath(os.path.expanduser(argv[2])), argv[3], argv[4:]
    else:
        command, rest = argv[1], argv[2:]
        script_dir = os.path.join(os.path.dirname(rules), "scripts")
    os.makedirs(script_dir, mode=0o700, exist_ok=True)
    cfg = load(rules)
    if command == "list":
        print(f"scripts ({script_dir}):")
        for item in sorted(cfg["scripts"], key=lambda x: x.get("file", "").lower()):
            state = "ON " if item.get("enabled", True) else "off"
            print(f"  {state} {item.get('name','?'):<24} {item.get('lang','?'):<2} {item.get('method') or 'ANY':<6} {item.get('match') or '.'}  {item.get('file','?')}")
        if not cfg["scripts"]: print("  (none)")
        return
    if not rest: raise SystemExit(f"scripts {command}: NAME required")
    name = rest[0]
    if command == "new":
        p = argparse.ArgumentParser(prog="scripts new")
        p.add_argument("name"); p.add_argument("--lang", choices=("py", "js"), required=True)
        p.add_argument("--match", default="."); p.add_argument("--method", default="")
        p.add_argument("--template", choices=tuple(TEMPLATES["py"]), default="header")
        a = p.parse_args(rest)
        if not SAFE_NAME.fullmatch(a.name): raise SystemExit("bad script name")
        try:
            user_regex(a.match)
        except re.error as e:
            raise SystemExit("bad regex in --match: %s" % e)
        filename = f"{a.name}.{a.lang}"; path = os.path.join(script_dir, filename)
        if any(x.get("name") == a.name or x.get("file") == filename for x in cfg["scripts"]) or os.path.exists(path):
            raise SystemExit("script already exists")
        if os.path.exists(path): raise SystemExit("script already exists")
        atomic_write_text(path, TEMPLATES[a.lang][a.template])
        cfg["scripts"].append({"name": a.name, "file": filename, "lang": a.lang, "enabled": True,
                               "match": a.match, "method": a.method.upper() or None})
        save(rules, cfg); print(f"created {path}")
        return
    item = find(cfg, name); filename = item["file"]
    if os.path.basename(filename) != filename: raise SystemExit("unsafe script filename")
    path = os.path.join(script_dir, filename)
    if command in ("on", "off"):
        item["enabled"] = command == "on"; save(rules, cfg); print(f"{item['name']} -> {command.upper()}")
    elif command == "rm":
        cfg["scripts"].remove(item); save(rules, cfg)
        if os.path.exists(path): os.unlink(path)
        print(f"removed {item['name']}")
    elif command == "edit":
        editor = os.environ.get("EDITOR") or ("notepad.exe" if os.name == "nt" else "vi")
        raise SystemExit(subprocess.call([editor, path]))
    else: raise SystemExit(f"unknown scripts command '{command}'")


if __name__ == "__main__": main(sys.argv[1:])
