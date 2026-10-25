"""Import Proxyman Map Local RuleTree entries into a Rivis project."""
import json
import os
import re
import shutil
from urllib.parse import urlsplit

from proxy_common import SAFE_NAME, atomic_json, migrate_rules, user_regex
from proxy_rule_validation import compile_rule

DEFAULT_TREE = os.path.expanduser(
    "~/Library/Application Support/com.proxyman.NSProxy/user-data/MapLocalFiles-RuleTree")


def _entries(value, groups=()):
    if isinstance(value, list):
        for item in value:
            yield from _entries(item, groups)
    elif isinstance(value, dict):
        if "url" in value and ("localFile" in value or "directoryFile" in value):
            yield value, groups
            return
        group = value.get("name") if isinstance(value.get("name"), str) else None
        if group and any(k in value for k in ("nodeType", "children", "nodes")):
            groups += (group,)
        for key, child in value.items():
            if key == "name":
                continue
            if key not in ("nodes", "nodeType", "node", "group", "children", "_0") and not isinstance(child, (list, dict)):
                continue
            yield from _entries(child, groups)


def _pattern(url, mode, including):
    if mode == "useRegex":
        pattern = url
    elif mode == "useWildcard":
        pattern = "".join(".*" if char == "*" else "." if char == "?" else re.escape(char) for char in url)
    else:
        raise ValueError("unknown matching mode: %s" % mode)
    if pattern.startswith("^"):
        pattern = pattern[1:]
    if pattern.endswith("$") and not pattern.endswith(r"\$"):
        pattern = pattern[:-1]
    if including:
        pattern = "(?:%s)(?:/.*)?" % pattern.rstrip("/")
    if mode == "useWildcard" and "?" not in url:
        pattern += r"(?:\?.*)?"            # a URL without a query also matches the call with one, as in Proxyman
    result = "^(?:%s)$" % pattern
    user_regex(result)
    return result


def _base(url, mode):
    if mode == "useWildcard":
        literal = url.split("*", 1)[0].split("?", 1)[0]
    else:
        literal = re.split(r"(?<!\\)[(*+?[$]", url, 1)[0]
        literal = re.sub(r"\\([/:.])", r"\1", literal)
    literal = literal.removeprefix("^")
    parsed = urlsplit(literal)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("folder URL needs a literal http(s) prefix")
    if not literal.endswith("/"):
        literal = literal.rsplit("/", 1)[0] + "/" if parsed.path else literal + "/"
    return literal


def _method(value):
    if not isinstance(value, dict):
        return None
    exact = value.get("exact")
    if isinstance(exact, list) and len(exact) == 1:
        item = exact[0]
        return (item.get("name") if isinstance(item, dict) else item).upper()
    return None


def _source(entry, directory, config_dir):
    data = entry.get("directoryFile") if directory else entry.get("localFile")
    path = data.get("path") if isinstance(data, dict) else data
    if not isinstance(path, str) or not path:
        raise ValueError("no local path")
    return os.path.abspath(os.path.join(config_dir, os.path.expanduser(path)))


def import_proxyman(rules_path, source=None, dry_run=False):
    config = os.path.expanduser(source) if source else DEFAULT_TREE
    if os.path.isdir(config):
        config = os.path.join(config, "MapLocalFiles-RuleTree")
    with open(config, encoding="utf-8") as fh:
        tree = json.load(fh)
    if not isinstance(tree, dict) or not isinstance(tree.get("nodes"), list):
        raise ValueError("expected Proxyman MapLocalFiles-RuleTree with nodes")
    with open(rules_path, encoding="utf-8") as fh:
        cfg = migrate_rules(json.load(fh))
    state_dir = os.path.dirname(os.path.abspath(rules_path))
    mocks = os.path.join(state_dir, "mocks")
    names = {r.get("name") for r in cfg.get("rules", []) if isinstance(r, dict)}
    lines, imported, skipped = [], 0, 0
    for entry, groups in _entries(tree["nodes"]):
        label = str(entry.get("name") or "proxyman-" + str(entry.get("id") or "rule"))
        try:
            directory = bool(entry.get("isDirectoryFileEnable"))
            source_path = _source(entry, directory, os.path.dirname(config))
            if not (os.path.isdir(source_path) if directory else os.path.isfile(source_path)):
                raise ValueError("file missing: %s" % source_path)
            if os.path.islink(source_path) or (directory and any(os.path.islink(os.path.join(root, f))
                    for root, dirs, files in os.walk(source_path) for f in dirs + files)):
                raise ValueError("source contains a symlink")
            base_name = re.sub(r"[^A-Za-z0-9._-]", "-", label).strip("-.")[:60] or "proxyman-rule"
            if not SAFE_NAME.fullmatch(base_name):
                raise ValueError("invalid rule name")
            name, number = base_name, 2
            while name in names or os.path.exists(os.path.join(mocks, name)) or os.path.exists(os.path.join(mocks, name + os.path.splitext(source_path)[1])):
                name, number = "%s-%d" % (base_name, number), number + 1
            names.add(name)
            target = os.path.join(mocks, name if directory else name + (os.path.splitext(source_path)[1] or ".mock"))
            rule = {"name": name, "enabled": bool(entry.get("isEnabled", True)), "action": "map_local",
                    "match": _pattern(str(entry["url"]), entry.get("regex", "useWildcard"), bool(entry.get("isIncludingPaths"))),
                    "file": target, "note": "imported from Proxyman" + ("; group: " + " / ".join(groups) if groups else "")}
            method = _method(entry.get("method"))
            if method:
                rule["method"] = method
            if directory:
                rule["base"] = _base(str(entry["url"]), entry.get("regex", "useWildcard"))
            if not dry_run:
                os.makedirs(mocks, exist_ok=True)
                if directory:
                    shutil.copytree(source_path, target)
                else:
                    shutil.copy2(source_path, target)
                try:
                    compile_rule(rule, state_dir)
                except Exception:
                    if directory:
                        shutil.rmtree(target)
                    else:
                        os.remove(target)
                    raise
                cfg.setdefault("rules", []).append(rule)
            imported += 1
            lines.append(("would import " if dry_run else "imported ") + name)
        except (KeyError, TypeError, ValueError, OSError) as exc:
            skipped += 1
            lines.append("skipped %s: %s" % (label, exc))
    if not dry_run and imported:
        atomic_json(rules_path, cfg)
    lines.append(("dry-run: " if dry_run else "") + "imported %d, skipped %d" % (imported, skipped))
    return "\n".join(lines)
