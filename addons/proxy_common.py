"""Shared, stdlib-only constants and product/profile helpers."""
import ipaddress
import json
import os
import re
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "product.json")) as _fh:
    PRODUCT = json.load(_fh)
STATE_ROOT = os.path.expanduser(PRODUCT["state_dir"])
# A file-name-safe identifier on every OS (F-18): no path characters, no leading/trailing dot (".", "..", hidden
# files, Windows strips trailing dots) and none of Windows' reserved device names (CON.json opens the console).
SAFE_NAME = re.compile(r"^(?!(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$))(?!\.)[A-Za-z0-9._-]{1,64}(?<!\.)$", re.I)
PROJECT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
TLS_MODES = ("all", "allow", "ignore")
NEVER_MATCH = "(?!)"
RULES_SCHEMA_VERSION = 1
COLLECTION_SCHEMA_VERSION = 1


def hosts_file_path():
    """The hosts file the OS resolver reads. RIVIS_HOSTS_FILE replaces it (tests; never set it in normal use)."""
    path = os.environ.get("RIVIS_HOSTS_FILE")
    if path:
        return path
    if os.name == "nt":
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
    return "/etc/hosts"


def _same_ip(a, b):
    try:
        return ipaddress.ip_address(str(a).split("%")[0]) == ipaddress.ip_address(str(b).split("%")[0])
    except ValueError:
        return str(a) == str(b)


def hosts_entry(host, ip=None):
    """The hosts-file line that gives `host` an address, as {path, line, ip, text}; None if there is none. When several
    lines name the host, the one with `ip` (the address actually connected to) wins, else the first."""
    path = hosts_file_path()
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read(1 << 20).splitlines()
    except OSError:
        return None
    want, first = str(host).lower().rstrip("."), None
    for number, line in enumerate(lines, 1):
        parts = line.split("#", 1)[0].split()
        if len(parts) < 2 or want not in (p.lower().rstrip(".") for p in parts[1:]):
            continue
        found = {"path": path, "line": number, "ip": parts[0], "text": " ".join(parts)}
        if ip is None or _same_ip(parts[0], ip):
            return found
        first = first or found
    return first


def describe_connection(host, ip):
    """One or two sentences for a certificate error: the address actually connected to and, if the hosts file has a line
    for the host, whether that line is where the address came from. "" when no connection was made."""
    if not ip:
        return ""
    text = "Connected to %s." % ip
    entry = hosts_entry(host, ip)
    if entry and _same_ip(entry["ip"], ip):
        text += (" That address comes from your hosts file, %s line %d: \"%s\". It is used instead of DNS: if it is an "
                 "old or wrong server, fix or remove that line." % (entry["path"], entry["line"], entry["text"]))
    elif entry:
        text += (" Your hosts file (%s line %d) lists %s for this host, but that is not the address that answered."
                 % (entry["path"], entry["line"], entry["ip"]))
    return text


def _fsync_directory(path):
    """Persist a rename on platforms that permit fsync on directories."""
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def atomic_write_bytes(path, data, mode=0o600, durable=True):
    """Crash-safe private write: temp file, flush+fsync, replace, then directory fsync.

    durable=False keeps the atomic replace (a reader never sees a half-written file) but skips both fsyncs:
    for diagnostic files rewritten on the proxy's hot path, where losing the last write in a power cut is harmless."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".%s-" % os.path.basename(path), suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            if durable:
                os.fsync(fh.fileno())
        commit_temp_file(tmp, path, mode, durable)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def atomic_write_text(path, text, mode=0o600, durable=True):
    atomic_write_bytes(path, str(text).encode("utf-8"), mode, durable)


def atomic_json(path, value, mode=0o600, durable=True):
    atomic_write_text(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n", mode, durable)


def commit_temp_file(tmp, path, mode=0o600, durable=True):
    """Commit an already flushed temporary file and persist its directory entry."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    os.chmod(path, mode)
    if durable:
        _fsync_directory(directory)


def _migrate(doc, current, kind):
    if not isinstance(doc, dict):
        raise ValueError("%s top level must be an object" % kind)
    version = doc.get("schema_version", 0)
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise ValueError("%s schema_version must be a non-negative integer" % kind)
    if version > current:
        raise ValueError("%s schema version %d is newer than this Rivis supports (%d); upgrade Rivis" %
                         (kind, version, current))
    migrated = dict(doc)
    while version < current:
        # v0 -> v1 is intentionally shape-preserving: it establishes the migration hook without breaking legacy data.
        if version == 0:
            version = 1
        else:  # every future schema bump must add an explicit step here
            raise ValueError("no %s migration from schema version %d" % (kind, version))
        migrated["schema_version"] = version
    return migrated


def migrate_rules(doc):
    return _migrate(doc, RULES_SCHEMA_VERSION, "rules.json")


def migrate_collection(doc):
    return _migrate(doc, COLLECTION_SCHEMA_VERSION, "collection")


_JWT = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])")
_SECRET = re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer\s+)?|(?:access_|refresh_)?token|password|secret|api[_-]?key)(\s*[=:]\s*|\s+)([^\s,;&]+)")


_SECRET_NAMES = (r"(?:proxy-)?authorization|cookie|set-cookie|x-api-key|x-auth-token|api[_-]?key|client[_-]?secret"
                 r"|(?:access_|refresh_|id_)?token|password|passwd|secret")
# a header line: everything after the colon is the secret ("Bearer abc", "sid=1; theme=x"), not only the first word
_HEADER_LINE = re.compile(r"(?im)\b((?:proxy-)?authorization|cookie|set-cookie|x-api-key|x-auth-token)(\s*:\s*)(?![\"'\[])([^\r\n]+)")
# quoted key and value: JSON {"Cookie": "…"}, a Python dict {'cookie': '…'} or header tuples ('Cookie', '…')
_QUOTED = re.compile(r"(?i)([\"'](?:%s)[\"']\s*[:,]\s*[\"'])(.*?)([\"'])" % _SECRET_NAMES)
_SCHEME = re.compile(r"(?i)\b(bearer|basic|digest)\s+(?!\[REDACTED)([A-Za-z0-9._~+/=-]{6,})")


def redact_diagnostic(value):
    """Conservative text redaction for product logs and support bundles."""
    text = str(value)
    text = _HEADER_LINE.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]", text)
    text = _QUOTED.sub(lambda m: m.group(1) + "[REDACTED]" + m.group(3), text)
    text = _SCHEME.sub(lambda m: m.group(1) + " [REDACTED]", text)
    text = _JWT.sub("[REDACTED-JWT]", text)
    return _SECRET.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]", text)


def rotate_file(path, max_bytes=2 * 1024 * 1024, backups=3, copytruncate=False, incoming=0):
    """Rotate a file when its size (+ incoming) exceeds max_bytes, keeping `backups` old files.
    If copytruncate=True, copy to .1 and truncate the original file so open file descriptors
    continue appending to it.
    """
    path = os.path.abspath(os.path.expanduser(path))
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    if size + incoming <= max_bytes:
        return False
    if backups < 1:
        try:
            if copytruncate:
                with open(path, "r+", encoding="utf-8", errors="replace") as f:
                    f.truncate(0)
            else:
                os.unlink(path)
        except OSError:
            pass
        return True
    oldest = "%s.%d" % (path, backups)
    try:
        os.unlink(oldest)
    except OSError:
        pass
    for index in range(backups - 1, 0, -1):
        source = "%s.%d" % (path, index)
        if os.path.exists(source):
            try:
                os.replace(source, "%s.%d" % (path, index + 1))
            except OSError:
                pass
    if os.path.exists(path):
        if copytruncate:
            import shutil
            try:
                shutil.copyfile(path, path + ".1")
                with open(path, "r+", encoding="utf-8", errors="replace") as f:
                    f.truncate(0)
            except OSError:
                pass
        else:
            try:
                os.replace(path, path + ".1")
            except OSError:
                pass
    return True


class RotatingTextLog:
    """Small dependency-free rotating log, suitable inside mitmproxy's packaged runtime."""
    def __init__(self, path, max_bytes=2 * 1024 * 1024, backups=3):
        self.path = os.path.abspath(os.path.expanduser(path))
        self.max_bytes = int(max_bytes)
        self.backups = int(backups)
        self._lock = threading.Lock()

    def _rotate(self, incoming):
        rotate_file(self.path, max_bytes=self.max_bytes, backups=self.backups, incoming=incoming)

    def append(self, level, message):
        directory = os.path.dirname(self.path)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        data = (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " " +
                str(level).upper() + " " + redact_diagnostic(message).replace("\n", "\\n")[:16384] + "\n").encode("utf-8")
        with self._lock:
            self._rotate(len(data))
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
            os.chmod(self.path, 0o600)


def project_profile(project_id):
    """Load a profile; a user profile with the same ID overrides the shipped one."""
    if not PROJECT_ID.fullmatch(project_id or ""):
        raise ValueError("bad project ID")
    for base in (os.path.join(STATE_ROOT, "profiles"), os.path.join(ROOT, "projects")):
        path = os.path.join(base, project_id, "project.json")
        if os.path.isfile(path):
            with open(path) as fh:
                doc = json.load(fh)
            # R5A-06: these regexes run on the event loop for every call (project filter, private-host allow-list,
            # recording, throttle scope): one that can backtrack forever is dropped, never matched
            for key in ("hosts", "record_match", "throttle_match"):
                if isinstance(doc, dict) and isinstance(doc.get(key), str) and doc[key]:
                    try:
                        user_regex(doc[key])
                    except re.error as e:
                        doc.setdefault("regex_errors", {})[key] = str(e)
                        doc[key] = "" if key == "hosts" else "."
            return doc
    raise ValueError("unknown project '%s'" % project_id)


def project_profiles():
    items = {}
    for base in (os.path.join(ROOT, "projects"), os.path.join(STATE_ROOT, "profiles")):
        if not os.path.isdir(base):
            continue
        for project_id in os.listdir(base):
            if project_id.startswith("_"):
                continue
            try:
                profile = project_profile(project_id)
                profile["id"] = project_id
                items[project_id] = profile
            except (OSError, ValueError):
                pass
    return [items[key] for key in sorted(items)]


def state_subdir(rules_path, name):
    return os.path.join(os.path.dirname(os.path.abspath(os.path.expanduser(rules_path))), name)


def project_state(project_id):
    if not PROJECT_ID.fullmatch(project_id or ""):
        raise ValueError("bad project ID")
    return os.path.join(STATE_ROOT, "projects", project_id)


HOP_HEADERS = frozenset(("connection", "keep-alive", "proxy-connection", "te", "trailer", "upgrade"))


def without_hop_headers(pairs):
    """[name, value] pairs without the headers that belong to one connection: those in HOP_HEADERS and any that a
    Connection header names. A mock answers the app itself, so a server's `Connection: close` copied into it made
    every mocked answer end the app's connection."""
    pairs = list(pairs)
    named = {t.strip().lower() for k, v in pairs if str(k).lower() == "connection" for t in str(v).split(",")}
    return [p for p in pairs if str(p[0]).lower() not in HOP_HEADERS and str(p[0]).lower() not in named]


def owned_mock_file(removed, remaining_rules, mocks_dir, current_rules_file=None):
    """Return a Rivis-created mock only when no project still reads it. Fail closed.

    `current_rules_file` is the rules.json of the project the rule is being removed from: `remaining_rules` already
    says what it will still read, so its on-disk copy (which may not be saved yet) is not consulted. That lets a caller
    delete the mock BEFORE saving, so nobody sees the rule gone while its mock file is still there."""
    if not isinstance(removed, dict) or removed.get("action") != "map_local" or not isinstance(removed.get("file"), str):
        return None
    value = removed["file"]
    if not value:
        return None
    real = os.path.realpath(os.path.expanduser(value))
    if removed.get("rivis_created_mock") != real:
        return None
    if os.path.dirname(real) != os.path.realpath(mocks_dir) or not os.path.isfile(real):
        return None
    def references(rules):
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            for key in ("file", "body_file"):
                ref = rule.get(key)
                if isinstance(ref, str) and ref and os.path.realpath(os.path.expanduser(ref)) == real:
                    return True
        return False
    if references(remaining_rules):
        return None
    projects = os.path.join(STATE_ROOT, "projects")
    try:
        for project in os.scandir(projects):
            if not project.is_dir():
                continue
            path = os.path.join(project.path, "rules.json")
            if not os.path.exists(path):
                continue
            if current_rules_file and os.path.realpath(path) == os.path.realpath(current_rules_file):
                continue
            with open(path) as fh:
                rules = json.load(fh).get("rules")
            if not isinstance(rules, list) or references(rules):
                return None
    except (OSError, ValueError, AttributeError):
        return None
    return real


def confined_path(base, path, what="path"):
    """Real path of `path`, refused unless it stays inside the `base` directory.

    One containment rule for every file the product reads or writes (STANDARDS §2):
    realpath resolves symlinks on BOTH sides, so a link planted inside the project
    cannot point out of it, and a base under /tmp (macOS: /private/tmp) still
    contains its own files. Paths that do not exist yet are checked the same way,
    so new files are confined before they are created.
    """
    base = os.path.realpath(os.path.expanduser(str(base)))
    resolved = os.path.realpath(os.path.expanduser(str(path)))
    if resolved != base and not resolved.startswith(base + os.sep):
        raise ValueError("%s '%s' is outside the project state directory '%s'" % (what, path, base))
    return resolved


TRUSTED_FILES = "trusted-files.json"
# never served, even from a file the user trusted: CA keys, Rivis's own login secrets, the usual credential stores
_FORBIDDEN_DIRS = ("~/.mitmproxy", "~/.ssh", "~/.aws", "~/.gnupg", "~/.kube", "~/.docker", "~/Library/Keychains")
_FORBIDDEN_NAMES = ("web-token", "web-bootstrap", TRUSTED_FILES)
_FORBIDDEN_SUFFIXES = (".pem", ".p12", ".pfx", ".key")


def forbidden_file(path, extra_dirs=()):
    """Why a real path must never be served by a rule, or None. `extra_dirs`: e.g. the running proxy's confdir."""
    real = os.path.realpath(os.path.expanduser(str(path)))
    if isinstance(extra_dirs, str):
        extra_dirs = (extra_dirs,)
    for d in _FORBIDDEN_DIRS + tuple(x for x in extra_dirs if x and os.path.isabs(os.path.expanduser(x))):
        d = os.path.realpath(os.path.expanduser(d))
        if real == d or real.startswith(d + os.sep):
            return "it is inside %s (keys and credentials)" % d
    name = os.path.basename(real)
    if name in _FORBIDDEN_NAMES or re.fullmatch(r"web-(?:token|bootstrap)-[0-9]+", name) or name.lower().endswith(_FORBIDDEN_SUFFIXES):  # R4A-05
        return "it looks like a key or a %s secret (%s)" % (PRODUCT["name"], name)
    return None


def trusted_files(state_dir):
    """Real paths outside the project that the user trusted on this machine (rivis rules allow-file / rules add).

    Kept apart from rules.json on purpose: a shared or imported rules file can name any path, but it cannot add
    itself to this list, so it can never read outside the project (F-09)."""
    try:
        with open(os.path.join(state_dir, TRUSTED_FILES)) as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return set()
    return {p for p in (doc.get("files") if isinstance(doc, dict) else None) or [] if isinstance(p, str)}


def set_trusted_file(state_dir, path, trusted=True):
    """Add or remove a real path in the project's trust list (0600, atomic). Returns the real path."""
    real = os.path.realpath(os.path.expanduser(str(path)))
    why = forbidden_file(real)
    if trusted and why:
        raise ValueError("refusing to trust %s: %s" % (path, why))
    files = trusted_files(state_dir)
    files = (files | {real}) if trusted else (files - {real})
    atomic_json(os.path.join(state_dir, TRUSTED_FILES), {"files": sorted(files)})
    return real


def rule_file_path(state_dir, path, what, extra_forbidden=()):
    """Real path a rule may read: inside the project, or a file the user trusted here (never a forbidden one)."""
    try:
        return confined_path(state_dir, path, what)
    except ValueError:
        real = os.path.realpath(os.path.expanduser(str(path)))
        if real in trusted_files(state_dir) and not forbidden_file(real, extra_forbidden):
            return real
        raise ValueError("%s '%s' is outside the project — if it is your own file, trust it on this machine: "
                         "%s rules allow-file '%s'" % (what, path, PRODUCT["cli"], path)) from None


try:                                    # stdlib parser: sre_parse on 3.9, re._parser on 3.11+ (mitmproxy's bundle)
    from re import _parser as _sre
except ImportError:                     # pragma: no cover - Python < 3.11
    import sre_parse as _sre

MAX_PATTERN = 1000
_REPEATS = {_sre.MAX_REPEAT, _sre.MIN_REPEAT}
_POSSESSIVE = getattr(_sre, "POSSESSIVE_REPEAT", None)


def _unbounded_inside(items):
    """True when a parsed sub-pattern contains a repeat with no upper bound (or a large one)."""
    for op, av in items:
        if op in _REPEATS:
            lo, hi, sub = av
            if hi == _sre.MAXREPEAT or hi > 100 or _unbounded_inside(sub):
                return True
        elif op == _sre.SUBPATTERN:
            if _unbounded_inside(av[-1]):
                return True
        elif op == _sre.BRANCH:
            if any(_unbounded_inside(b) for b in av[1]):
                return True
        elif op in (_sre.ASSERT, _sre.ASSERT_NOT):
            if _unbounded_inside(av[1]):
                return True
    return False


def _nested_repeat(items):
    for op, av in items:
        if op in _REPEATS:
            lo, hi, sub = av
            if (hi == _sre.MAXREPEAT or hi > 100) and _unbounded_inside(sub):
                return True
            if _nested_repeat(sub):
                return True
        elif op == _sre.SUBPATTERN:
            if _nested_repeat(av[-1]):
                return True
        elif op == _sre.BRANCH:
            if any(_nested_repeat(b) for b in av[1]):
                return True
        elif op in (_sre.ASSERT, _sre.ASSERT_NOT):
            if _nested_repeat(av[1]):
                return True
    return False


def _unbounded(av):
    return av[1] == _sre.MAXREPEAT or av[1] > 100


def _ambiguous_repeat(items):
    """An unbounded repeat whose body can split the same text in several ways (review R2), which backtracks
    exponentially: alternatives that can start with the same character, as in (a|aa)+ or (ab|ab)+, or an optional
    character that the next one can also take, as in (a?a)+. (foo|bar)+ and (ab?)+ are unambiguous and allowed."""
    for op, av in items:
        if op in _REPEATS:
            sub = av[2]
            if _unbounded(av) and (_overlapping_branch(sub) or _optional_overlap(sub)):
                return True
            if _ambiguous_repeat(sub):
                return True
        elif op == _sre.SUBPATTERN:
            if _ambiguous_repeat(av[-1]):
                return True
        elif op == _sre.BRANCH:
            if any(_ambiguous_repeat(b) for b in av[1]):
                return True
        elif op in (_sre.ASSERT, _sre.ASSERT_NOT):
            if _ambiguous_repeat(av[1]):
                return True
    return False


def _first_chars(items):
    """Probe characters a sequence can start with; everything when it can match empty or is not simple."""
    acc = set()
    for op, av in _flatten(items):
        if op in (_sre.AT,):
            continue
        if op in _REPEATS:
            acc |= _first_chars(av[2])
            if av[0] > 0:
                return acc
            continue
        if op == _sre.BRANCH:
            for b in av[1]:
                acc |= _first_chars(b)
            return acc
        chars = _char_set(op, av)
        return acc | (set(_PROBE) if chars is None else chars)
    return set(_PROBE)


def _overlapping_branch(sub):
    for op, av in _flatten(sub):
        if op == _sre.BRANCH:
            seen = set()
            for b in av[1]:
                first = _first_chars(b)
                if seen & first:
                    return True
                seen |= first
        elif op in _REPEATS and _overlapping_branch(av[2]):
            return True
    return False


def _optional_overlap(sub):
    """In a repeated body: an optional one-character item followed by an item (or, at the end, the body's start
    on the next round) that can take the same character."""
    flat = _flatten(sub)
    for i, (op, av) in enumerate(flat):
        if op in _REPEATS and av[0] == 0 and len(av[2]) == 1:
            chars = _char_set(*list(av[2])[0])
            if chars is None:
                continue
            nxt = _first_chars(flat[i + 1:]) if i + 1 < len(flat) else _first_chars(flat)
            if chars & nxt:
                return True
    return False


def _flatten(items):
    """The items of a sequence with plain groups opened up: (a*)(a*) is a*a*."""
    out = []
    for op, av in items:
        if op == _sre.SUBPATTERN:
            out.extend(_flatten(av[-1]))
        else:
            out.append((op, av))
    return out


_PROBE = [chr(c) for c in range(32, 127)] + ["\t", "\n", "\u00e9"]


def _char_set(op, av):
    """The probe characters a one-character item matches (None: not a one-character item)."""
    if op == _sre.SUBPATTERN and len(av[-1]) == 1:
        return _char_set(*list(av[-1])[0])
    if op not in (_sre.LITERAL, _sre.NOT_LITERAL, _sre.ANY, _sre.IN, _sre.CATEGORY):
        return None
    sub = _sre.SubPattern(_sre.State(), [(op, av)])
    try:
        rx = re.compile(_sre_compile_items(sub))
    except Exception:  # noqa: BLE001 - when in doubt, treat it as matching everything
        return set(_PROBE)
    return {c for c in _PROBE if rx.fullmatch(c)}


def _sre_compile_items(sub):
    try:
        from re import _compiler as _sc
    except ImportError:                 # pragma: no cover - Python < 3.11
        import sre_compile as _sc
    return _sc.compile(sub)


def _adjacent_overlap(items):
    """Unbounded repeats next to each other that can take the same characters (a*a*, .*.*, \\d+\\d*): each extra one
    multiplies the work by the URL length. Optional items between them do not separate them (a*b?a*)."""
    prev = None                         # the character set of the last unbounded repeat still "open"
    for op, av in _flatten(items):
        if op in _REPEATS:
            body = list(av[2])
            if _ambiguous_nested(body):
                return True
            chars = _char_set(*body[0]) if len(body) == 1 else None
            if _unbounded(av) and chars is not None:
                if prev is not None and prev & chars:
                    return True
                prev = chars if prev is None or av[0] > 0 else (prev | chars)
                continue
            if av[0] > 0:
                prev = None
        elif op == _sre.BRANCH:
            if any(_adjacent_overlap(b) for b in av[1]):
                return True
            prev = None
        elif op in (_sre.AT, _sre.ASSERT, _sre.ASSERT_NOT):
            continue                     # zero width: does not separate
        else:
            prev = None
    return False


def _ambiguous_nested(body):
    return any(op in _REPEATS and _adjacent_overlap(av[2]) for op, av in body)


def remote_url_problem(url):
    """R2A-11: why a map_remote result cannot be connected to (None when usable): it must be http(s) with a host."""
    from urllib.parse import urlsplit
    try:
        u = urlsplit(url)
        u.port
    except ValueError as e:
        return str(e)
    if u.scheme not in ("http", "https") or not u.hostname:
        return "'%s' is not an http(s) URL with a host" % url[:80]
    return None


def user_regex(pattern, flags=0):
    """Compile a user-, rule- or profile-supplied regex, refusing the shapes that hang the proxy (F-05).

    Python's re has no timeout and every match runs on mitmproxy's single event loop, so a pattern like
    (a+)+ or (.*)*x against a crafted URL would stall all traffic. Nested unbounded repeats are refused and the
    pattern length is capped; the error is a re.error, so callers' existing handling applies."""
    if not isinstance(pattern, str):
        raise re.error("pattern must be text")
    if len(pattern) > MAX_PATTERN:
        raise re.error("pattern is longer than %d characters" % MAX_PATTERN)
    compiled = re.compile(pattern, flags)
    parsed = _sre.parse(pattern, flags)
    if _nested_repeat(parsed):
        raise re.error("nested repetition such as (a+)+ or (.*)* can freeze the proxy; "
                       "simplify it (e.g. a+ instead of (a+)+)")
    if _ambiguous_repeat(parsed):
        raise re.error("a repeated group with alternatives or optional parts, such as (a|aa)+ or (a?a)+, can freeze "
                       "the proxy; repeat one thing, or use a character class such as [ab]+")
    if _adjacent_overlap(parsed):
        raise re.error("two repeats in a row that can match the same characters, such as .*.* or \\d+\\d*, can freeze "
                       "the proxy on a long URL; keep one of them")
    return compiled


def tls_host_regex(pattern):
    """Convert a Proxyman-style host wildcard to mitmproxy's host:port regex."""
    pattern = str(pattern or "").strip().lower().rstrip(".")
    if not pattern or "/" in pattern or "://" in pattern or any(c.isspace() for c in pattern):
        raise ValueError("TLS host pattern must be a hostname such as *.example.test")
    port = ""
    if pattern.count(":") == 1:
        host, possible_port = pattern.rsplit(":", 1)
        if possible_port.isdigit():
            if not (1 <= int(possible_port) <= 65535):
                raise ValueError("TLS host pattern port must be 1..65535")
            pattern, port = host, ":" + possible_port
    if not pattern or pattern.startswith(".") or pattern.endswith("."):
        raise ValueError("TLS host pattern is not a valid hostname")
    expression = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c)
                         for c in pattern)
    suffix = re.escape(port) if port else r"(?::\d+)?"
    return "^" + expression + suffix + "$"


def tls_config(cfg):
    """Validate a rules document's TLS block and return normalized values."""
    source = cfg.get("tls")
    if source is None:
        source = {}
    if not isinstance(source, dict):
        raise ValueError("tls must be an object")
    mode = str(source.get("mode") or "all").lower()
    if mode not in TLS_MODES:
        raise ValueError("tls mode must be all, allow or ignore")
    out = {"mode": mode, "allow": [], "ignore": []}
    for key in ("allow", "ignore"):
        values = source.get(key) or []
        if not isinstance(values, list) or not all(isinstance(x, str) for x in values):
            raise ValueError("tls.%s must be a list of host patterns" % key)
        for value in values:
            value = value.strip().lower()
            tls_host_regex(value)
            if value and value not in out[key]:
                out[key].append(value)
    return out


def tls_options(cfg):
    """Return (allow_hosts, ignore_hosts) for mitmproxy from a rules document."""
    tls = tls_config(cfg)
    if tls["mode"] == "allow":
        # mitmproxy ignores nothing when both lists are empty, so an empty allow list needs a
        # pattern that matches no host: "decrypt only the listed hosts" with none listed = decrypt nothing.
        return [tls_host_regex(x) for x in tls["allow"]] or [NEVER_MATCH], []
    if tls["mode"] == "ignore":
        return [], [tls_host_regex(x) for x in tls["ignore"]]
    return [], []

def tls_covering(tls, host, which):
    """Patterns in tls[which] that match this host (used for 'Decrypt this host')."""
    host = str(host or "").strip().lower()
    return [p for p in tls.get(which, []) if re.search(tls_host_regex(p), host)]


def tls_update(cfg, mode=None, add=(), remove=()):
    """Edit cfg['tls'] in place. add/remove are (list_name, pattern) pairs. Returns the new block."""
    tls = tls_config(cfg)
    if mode is not None:
        if str(mode).lower() not in TLS_MODES:
            raise ValueError("tls mode must be all, allow or ignore")
        tls["mode"] = str(mode).lower()
    for which, pattern in remove:
        if which not in ("allow", "ignore"):
            raise ValueError("tls list must be allow or ignore")
        tls[which] = [x for x in tls[which] if x != str(pattern).strip().lower()]
    for which, pattern in add:
        if which not in ("allow", "ignore"):
            raise ValueError("tls list must be allow or ignore")
        pattern = str(pattern).strip().lower()
        tls_host_regex(pattern)
        if pattern not in tls[which]:
            tls[which].append(pattern)
    cfg["tls"] = tls
    return tls


ACTION_REQUIREMENTS = {
    "respond": (),
    "map_local": ("file",),
    "status": ("status",),
    "json_patch": ("set",),
    "delay": ("ms",),
    "set_header": ("header",),
    "map_remote": ("replace", "with"),
    "block": (),
}
ACTIONS = frozenset(ACTION_REQUIREMENTS)

# latency ms, jitter ms, down kbps, up kbps, loss %, response delay ms
PROFILE_VALUES = {
    "3g-urban":         (320, 60, 750, 330, 2, 0),
    "lte-congested":    (160, 40, 3000, 1200, 3, 0),
    "high-latency-vpn": (650, 120, 5000, 2000, 1, 0),
    "packet-loss-8":    (120, 30, 8000, 4000, 8, 0),
    # Legacy presets remain valid for existing files and scripts.
    "lte":  (70, 0, 12000, 0, 0, 0),
    "3g":   (300, 0, 750, 0, 0, 0),
    "edge": (850, 0, 240, 0, 0, 0),
    "slow": (2000, 0, 50, 0, 0, 0),
}
PRESETS = ("off", *PROFILE_VALUES, "manual")


def throttle_shorthand(spec):
    """Parse <ms>ms[/<kbps>kbps], or None when the shape is not shorthand."""
    m = re.fullmatch(r"(\d+)ms(?:/(\d+)kbps)?", spec)
    if not m:
        return None
    # R1A-01: use the manual latency/bandwidth caps before a typo can hang every matching call.
    for raw, key, cap in ((m.group(1), "latency_ms", 120000), (m.group(2), "down_kbps", 1000000)):
        if raw is not None and (len(raw.lstrip("0")) > len(str(cap)) or int(raw.lstrip("0") or "0") > cap):
            raise ValueError("%s must be 0..%s" % (key, cap))
    return int(m.group(1).lstrip("0") or "0"), int((m.group(2) or "").lstrip("0") or "0")
PANEL_PROFILES = [{"id": "off", "name": "No profile", "desc": "No throttling applied"}]
for _profile_id, _profile_name in (
        ("3g-urban", "3G Urban"), ("lte-congested", "LTE (congested)"),
        ("high-latency-vpn", "High Latency VPN"), ("packet-loss-8", "Packet loss 8%")):
    _latency, _jitter, _down, _up, _loss, _delay = PROFILE_VALUES[_profile_id]
    PANEL_PROFILES.append({"id": _profile_id, "name": _profile_name, "latency_ms": _latency,
                           "jitter_ms": _jitter, "down_kbps": _down, "up_kbps": _up,
                           "loss_pct": _loss})
PANEL_PROFILES.append({"id": "manual", "name": "Advanced (manual)",
                       "desc": "Your own latency, jitter, bandwidth and loss"})


def breakpoints(cfg, migrate=False):
    """Return breakpoints, optionally moving the legacy singleton into the list."""
    bps = list(cfg.get("breakpoints") or [])
    old = cfg.get("breakpoint") or {}
    if old.get("match"):
        phase = old.get("phase", "both")
        bps.append({"name": "legacy", "match": old["match"], "enabled": True,
                    "request": phase in ("request", "both"),
                    "response": phase in ("response", "both")})
    if migrate:
        cfg["breakpoints"] = bps
        cfg.pop("breakpoint", None)
    return bps
