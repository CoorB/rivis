"""Shared, stdlib-only constants and product/profile helpers."""
import json
import os
import re
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "product.json")) as _fh:
    PRODUCT = json.load(_fh)
STATE_ROOT = os.path.expanduser(PRODUCT["state_dir"])
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
PROJECT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
TLS_MODES = ("all", "allow", "ignore")
NEVER_MATCH = "(?!)"


def project_profile(project_id):
    """Load a profile; a user profile with the same ID overrides the shipped one."""
    if not PROJECT_ID.fullmatch(project_id or ""):
        raise ValueError("bad project ID")
    for base in (os.path.join(STATE_ROOT, "profiles"), os.path.join(ROOT, "projects")):
        path = os.path.join(base, project_id, "project.json")
        if os.path.isfile(path):
            with open(path) as fh:
                return json.load(fh)
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
    if name in _FORBIDDEN_NAMES or name.lower().endswith(_FORBIDDEN_SUFFIXES):
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
    fd, tmp = tempfile.mkstemp(dir=state_dir, prefix=".trusted-", suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump({"files": sorted(files)}, fh, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, os.path.join(state_dir, TRUSTED_FILES))
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
