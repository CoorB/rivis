"""Compact command/state contract across bash, PowerShell and the running proxy.

Before this file grew an inventory check it only exercised runtime state parity
(breakpoint phases, throttle profiles, rules rm ownership) across the two CLIs.
Command/flag drift was invisible until a Windows user hit it — the CliSurface
class below now enforces the surface inventory with an explicit exception list.
"""
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from harness import Background, LiveCase, PWSH, REPO, Suite, wait_for


PHASES = [
    ((), True, True),
    (("--request",), True, False),
    (("--response",), False, True),
    (("--request", "--response"), True, True),
    (("--response", "--request"), True, True),
    (("--method", "post"), True, True),
]
PROFILES = ("3g-urban", "lte-congested", "high-latency-vpn", "packet-loss-8",
            "lte", "3g", "edge", "slow", "manual", "400ms", "250ms/512kbps")
MANUAL = ("latency_ms=120", "jitter_ms=4", "down_kbps=500", "up_kbps=250",
          "loss_pct=3", "response_delay_ms=20")

# ── surface inventory (commands + flags) ──────────────────────────────────────
# Flag names are normalised: leading dashes stripped, lowercased, non-alnum gone
# so --verify-upstream and -VerifyUpstream both become "verifyupstream".

# Top-level commands present on bash only, with why Windows does not get them.
BASH_ONLY_COMMANDS = {
    # (command, reason)
    "ios": "no iOS Simulator on Windows",
    "update": "signed in-app updater is macOS-only",
    "rollback": "rolls back an installed macOS tool tree; Windows installs differ",
    "restart": "replays start args after a macOS in-app update",
    "health": "checks the installed macOS tool tree is answering",
    "uninstall": "points at install.sh; Windows uses install.ps1 --uninstall",
}

# Internal / non-user arms excluded from the inventory entirely.
BASH_INTERNAL_COMMANDS = frozenset({"__android_settings"})

# (command, normalised_flag) present on bash only.
BASH_ONLY_FLAGS = {
    ("start", "background"): "keeps mitmweb alive after the Terminal closes; Windows start already owns the process",
    ("start", "noios"): "iOS Simulator local-capture; no Simulator on Windows",
    ("start", "iosfilter"): "iOS local-capture process filter; no Simulator on Windows",
    ("app", "build"): "builds the native macOS window; app is a stub on Windows",
    ("browser", "chrome"): "bash shorthand for --browser chrome; PowerShell uses -Browser chrome",
    ("browser", "edge"): "bash shorthand for --browser edge; PowerShell uses -Browser chrome|edge|…",
    ("browser", "chromium"): "bash shorthand for --browser chromium; PowerShell uses -Browser …",
    ("browser", "brave"): "bash shorthand for --browser brave; PowerShell uses -Browser …",
    ("android", "manual"): "prints Settings steps for Play-image UI automation; Windows pushes the CA and instructs by hand",
    ("android", "yes"): "consents to one-time Play-image setup; Windows has no Play Settings driver",
    ("android", "strict"): "Play Magisk boot cleanup; Windows system-CA path is Google APIs + adb root only",
    ("android", "autoui"): "legacy no-op still accepted on bash; Windows never had the flag",
    ("ios", "udid"): "iOS Simulator only",
    ("ios", "all"): "iOS Simulator only",
    ("net-reset", "auto"): "macOS start clears proven-dead loopback leftovers; Windows net-reset only reports",
}

# (command, normalised_flag) present on PowerShell only — deliberate conveniences.
PS_ONLY_FLAGS = {
    ("rules", "match"): "PowerShell also accepts -Match; bash uses match= key=value only",
    ("rules", "method"): "PowerShell also accepts -Method on rules add/test; bash uses a positional / method=",
    ("rules", "operation"): "PowerShell also accepts -Operation on rules add; bash uses operation= key=value only",
    ("throttle", "match"): "PowerShell also accepts -Match; bash uses match= only",
    ("throttle", "loss"): "PowerShell also accepts -Loss; bash uses loss= only",
}

# Alias pairs so -s and -Serial, --dev and -Dev, compare equal.
FLAG_ALIASES = {
    "s": "serial",
    "dev": "insecure",
    "neoonly": "projectonly",
    "printuiurl": "url",
}


def _norm_flag(token):
    token = token.strip().lstrip("-")
    return re.sub(r"[^a-z0-9]", "", token.lower())


def _canon_flag(name):
    name = _norm_flag(name)
    return FLAG_ALIASES.get(name, name)


def _read_clis():
    with open(os.path.join(REPO, "rivis")) as fh:
        bash = fh.read()
    with open(os.path.join(REPO, "rivis.ps1")) as fh:
        ps = fh.read()
    return bash, ps


def _bash_implemented_commands(bash):
    idx = bash.rfind('case "${1:-}" in')
    assert idx >= 0, "bash CLI dispatch case missing"
    block = bash[idx:]
    end = block.find("\nesac")
    block = block if end < 0 else block[:end]
    out = set()
    for m in re.finditer(r"^\s+([^)\n]+)\)", block, re.M):
        for part in m.group(1).split("|"):
            part = part.strip().strip('"').strip("'")
            if not part or part == "*" or part.startswith("-"):
                continue
            if part in BASH_INTERNAL_COMMANDS:
                continue
            if part in ("help", "version"):
                continue  # meta: both CLIs handle version/--version outside the command switch
            # skip fragments that are clearly not command names
            if not re.match(r"^[a-z][a-z0-9-]*$", part):
                continue
            out.add(part)
    return out


def _ps_implemented_commands(ps):
    return set(re.findall(r'^\s+"([a-z][a-z0-9-]*)" \{', ps, re.M))


def _bash_usage_commands(bash):
    """Commands named on a `<cli> …` usage line (header comment)."""
    header = []
    for line in bash.splitlines()[1:]:
        if line.startswith("#"):
            header.append(line[1:].lstrip())
        elif not line.strip():
            continue
        else:
            break
    text = "\n".join(header)
    found = set()
    for m in re.finditer(r"<cli>(?:\s+\[[^\]]+\])*\s+([a-z][a-z0-9-]*)", text):
        found.add(m.group(1))
    # ui line also lists stop | restart | status | cert inline
    for m in re.finditer(r"<cli>\s+ui[^\n]*\|\s*(stop)\s*\|\s*(restart)\s*\|\s*(status)\s*\|\s*(cert)", text):
        found.update(g for g in m.groups() if g)
    # bare words after the first command on multi-command lines: stop | restart already handled;
    # also "health" / "rollback" / "update" have their own lines.
    return found


def _ps_usage_commands(ps):
    m = re.search(r"<#(.*?)#>", ps, re.S)
    assert m, "PowerShell usage header missing"
    text = m.group(1)
    found = set()
    for cm in re.finditer(r"\\?<cli>\.ps1\s+([a-z][a-z0-9-]*)", text):
        found.add(cm.group(1))
    # stop | ui | status | cert packed on one line
    for cm in re.finditer(r"\\?<cli>\.ps1\s+(stop)\s*\|\s*ui[^\n]*\|\s*(status)\s*\|\s*(cert)", text):
        found.update(g for g in cm.groups() if g)
    return found


def _bash_fn_body(bash, fn_name):
    m = re.search(r"^cmd_%s\(\)\s*\{" % re.escape(fn_name), bash, re.M)
    if not m:
        return ""
    start = m.end()
    nxt = re.search(r"\n(?:cmd_[a-z_]+\(\)|# ─|case \"\$\{1:-\}\" in)", bash[start:])
    return bash[start:start + nxt.start()] if nxt else bash[start:]


def _flags_in_bash_cases(body):
    """Flags from `case … in --foo|--bar)` arms and from `[ "$1" = --foo ]` tests."""
    found = set()
    for m in re.finditer(r"(--[a-z0-9-]+|-s)(?=\)|\|)", body):
        found.add(_canon_flag(m.group(1)))
    for m in re.finditer(r'=\s*"(--[a-z0-9-]+)"', body):
        found.add(_canon_flag(m.group(1)))
    for m in re.finditer(r"\[ \"\$\{1:-\}\" = \"(--[a-z0-9-]+)\" \]", body):
        found.add(_canon_flag(m.group(1)))
    return found


def _bash_flags_by_command(bash):
    """Implemented user-facing flags per command (plus the global --project)."""
    mapping = {
        "start": "start", "android": "android", "ios": "ios", "ui": "ui", "app": "app",
        "browser": "browser", "net-reset": "net_reset", "bug-report": "bug_report",
        "projects": "projects", "compose": "compose", "scripts": "scripts",
        "update": "update", "rollback": "rollback",
    }
    out = {"*global*": {_canon_flag("project")}}
    for cmd, fn in mapping.items():
        out[cmd] = _flags_in_bash_cases(_bash_fn_body(bash, fn))
    # Delegated commands: flags live in the usage header / shared Python CLI.
    out["doctor"] = {_canon_flag(x) for x in (
        "--json", "--no-net", "--fix-safe", "--yes", "--allow-profile-network")}
    out["breakpoint"] = {_canon_flag(x) for x in ("--request", "--response", "--method", "--operation")}
    out["mocks"] = {_canon_flag("--dry-run")}
    out["tls"] = {_canon_flag(x) for x in ("--key", "--password-stdin")}
    out["compose"] = {_canon_flag(x) for x in ("--var", "--no-wait")}
    out["scripts"] = {_canon_flag(x) for x in ("--lang", "--match")}
    # browser: only the user options, not Chromium argv (--no-first-run etc.)
    out["browser"] = {_canon_flag(x) for x in (
        "--browser", "--chrome", "--edge", "--chromium", "--brave",
        "--fresh", "--list", "--current")}
    out["app"] = {_canon_flag("build")} if re.search(r"--build", _bash_fn_body(bash, "app")) else set()
    return out


def _ps_block(ps, cmd):
    m = re.search(r'^\s+"%s" \{' % re.escape(cmd), ps, re.M)
    if not m:
        return ""
    start = m.end()
    nxt = re.search(r'\n  "(?:[a-z][a-z0-9-]*)" \{|\n  default \{', ps[start:])
    return ps[start:start + nxt.start()] if nxt else ps[start:]


# Positionals and catch-alls — not per-command flags.
_PS_NON_FLAG_PARAMS = frozenset({
    "Command", "Action", "Name", "Rest", "FromCurl", "Help",
})


def _ps_flag_param_names(ps):
    """Names of switch/string params from the rivis.ps1 param() block (excludes positionals)."""
    start = ps.index("param(")
    end = ps.index(")\n$ErrorActionPreference")
    block = ps[start:end]
    names = set()
    # Only declarations (`[switch]$Lan` / `[string]$Serial = ""`), not attribute values like $true.
    for m in re.finditer(r"\]\$(\w+)", block):
        name = m.group(1)
        if name in _PS_NON_FLAG_PARAMS:
            continue
        names.add(name)
    return names


def _ps_flags_by_command(ps):
    params = _ps_flag_param_names(ps)
    out = {"*global*": {_canon_flag("project")}}
    for cmd in _ps_implemented_commands(ps):
        body = _ps_block(ps, cmd)
        found = set()
        for pname in params:
            if re.search(r"\$" + re.escape(pname) + r"\b", body):
                found.add(_canon_flag(pname))
        out[cmd] = found
    return out


def _surface_diff(bash_cmds, ps_cmds, bash_flags, ps_flags):
    """Return (missing_on_ps_cmds, missing_on_bash_cmds, missing_on_ps_flags, missing_on_bash_flags)."""
    known_bash_cmds = set(BASH_ONLY_COMMANDS)
    miss_ps_cmds = sorted((bash_cmds - ps_cmds) - known_bash_cmds)
    miss_bash_cmds = sorted(ps_cmds - bash_cmds)  # every PS command should exist on bash

    miss_ps_flags = []
    miss_bash_flags = []
    shared = (bash_cmds & ps_cmds) | {"*global*"}
    for cmd in sorted(shared):
        b = set(bash_flags.get(cmd, ()))
        p = set(ps_flags.get(cmd, ()))
        # global project is compared under *global* only
        if cmd != "*global*":
            b.discard("project")
            p.discard("project")
        for flag in sorted(b - p):
            key = (cmd, flag)
            if key in BASH_ONLY_FLAGS:
                continue
            if cmd in BASH_ONLY_COMMANDS:
                continue
            miss_ps_flags.append(key)
        for flag in sorted(p - b):
            key = (cmd, flag)
            if key in PS_ONLY_FLAGS:
                continue
            miss_bash_flags.append(key)
    return miss_ps_cmds, miss_bash_cmds, miss_ps_flags, miss_bash_flags


def _fmt_flag_gap(side_missing, command, flag):
    return "%s is missing flag '%s' on command '%s'" % (side_missing, flag, command)


class Matrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()
        cls.ps = os.path.isfile(PWSH) and os.access(PWSH, os.X_OK)
        if not cls.ps:
            raise AssertionError("pwsh 7 is required for CLI state parity: " + PWSH)
        version = cls.suite.run([PWSH, "-NoProfile", "-NonInteractive", "-Command",
                                 "$PSVersionTable.PSVersion.Major"], timeout=30)
        if version.returncode or version.stdout.strip() != "7":
            raise AssertionError("pwsh 7 is required: " + version.stdout + version.stderr)

    def setUp(self):
        self.home = self.suite.new_home("matrix")
        self.env = self.suite.cli_env(self.home)

    def run_cli(self, surface, project, *args):
        if surface == "bash":
            argv = ["/bin/bash", os.path.join(REPO, "rivis")]
            if project == "neo":
                argv += ["--project", "neo"]
        else:
            argv = [PWSH, "-NoProfile", "-NonInteractive", "-File", os.path.join(REPO, "rivis.ps1")]
        argv += list(args)
        if surface == "ps" and project == "neo":
            argv += ["-Project", "neo"]
        cp = self.suite.run(argv, home=self.home, env=self.env, timeout=120)
        self.assertEqual(cp.returncode, 0, "%s -> %s\n%s\n%s" % (argv, cp.returncode, cp.stdout, cp.stderr))
        return cp.stdout

    def cfg(self, project):
        with open(os.path.join(self.home, ".rivis", "projects", project, "rules.json")) as fh:
            return json.load(fh)

    def surfaces(self):
        return ("bash", "ps") if self.ps else ("bash",)

    def test_breakpoint_phase_matrix(self):
        for project in ("default", "neo"):
            for flags, request, response in PHASES:
                for surface in self.surfaces():
                    with self.subTest(project=project, flags=flags, surface=surface):
                        self.run_cli(surface, project, "breakpoint", "off")
                        args = ["breakpoint", "/matrix", *flags]
                        if surface == "ps":
                            args = ["breakpoint", "/matrix"] + [x.replace("--", "-") for x in flags]
                        out = self.run_cli(surface, project, *args)
                        self.assertIn("ON", out)
                        bp = self.cfg(project)["breakpoints"]
                        self.assertEqual(len(bp), 1)
                        self.assertEqual((bp[0]["request"], bp[0]["response"]), (request, response))
                        self.assertEqual(bp[0].get("method"), "POST" if "post" in flags else None)

    def test_throttle_scope_profiles_and_options(self):
        for project in ("default", "neo"):
            scope = r"neo\.sa" if project == "neo" else ""
            for surface in self.surfaces():
                for profile in PROFILES:
                    with self.subTest(project=project, surface=surface, profile=profile):
                        self.run_cli(surface, project, "throttle", profile)
                        cfg = self.cfg(project)
                        self.assertEqual((cfg["throttle"], cfg["throttle_match"], cfg["loss"]), (profile, scope, 0))
                self.run_cli(surface, project, "throttle", "lte", "match=/only", "loss=7")
                self.assertEqual((self.cfg(project)["throttle_match"], self.cfg(project)["loss"]), ("/only", 7))
                self.run_cli(surface, project, "throttle", "off")
                self.assertEqual((self.cfg(project)["throttle"], self.cfg(project)["throttle_match"], self.cfg(project)["loss"]),
                                 ("off", scope, 0))
                self.run_cli(surface, project, "throttle", "3g-urban")
                self.assertEqual(self.cfg(project)["throttle_match"], scope)
                self.run_cli(surface, project, "throttle", "manual", *MANUAL)
                self.assertEqual(self.cfg(project)["manual"], dict(latency_ms=120, jitter_ms=4, down_kbps=500,
                    up_kbps=250, loss_pct=3, response_delay_ms=20))

    def test_rules_rm_file_ownership(self):
        for project in ("default", "neo"):
            for surface in self.surfaces():
                with self.subTest(project=project, surface=surface):
                    self.run_cli("bash", project, "rules", "list")
                    root = os.path.join(self.home, ".rivis", "projects", project, "mocks")
                    user = os.path.join(self.home, "outside.json")
                    paths = {key: os.path.join(root, key + ".json") for key in ("owned", "file", "body")}
                    paths["user"] = user
                    for key, path in paths.items():
                        if key == "owned": continue
                        with open(path, "w") as fh: fh.write("{}")
                    for name, key in (("owned", "owned"), ("file-owner", "file"),
                                      ("file-reader", "file"), ("body-owner", "body"), ("user", "user")):
                        self.run_cli("bash", project, "rules", "add", name, "match=/" + name,
                                     "action=map_local", "body={}" if key == "owned" else "file=" + paths[key])
                    paths["owned"] = next(r["file"] for r in self.cfg(project)["rules"] if r["name"] == "owned")
                    cfg = self.cfg(project)
                    cfg["rules"].append({"name": "body-reader", "action": "respond", "match": "/reader",
                                         "body_file": paths["body"]})
                    rules = os.path.join(self.home, ".rivis", "projects", project, "rules.json")
                    with open(rules, "w") as fh: json.dump(cfg, fh)
                    for name, remains in (("owned", False), ("file-owner", True), ("body-owner", True),
                                          ("user", True), ("file-reader", True)):
                        self.run_cli(surface, project, "rules", "rm", name)
                        self.assertNotIn(name, [r["name"] for r in self.cfg(project)["rules"]])
                        key = {"file-owner": "file", "file-reader": "file", "body-owner": "body"}.get(name, name)
                        self.assertEqual(os.path.isfile(paths[key]), remains, name)


class LiveBreakpointMatrix(LiveCase):
    def tearDown(self):
        for paused in self.panel.state()["paused"]:
            self.panel.post("paused_abort", {"id": paused["id"]})

    def test_each_phase_combination_arms_before_return(self):
        for flags, request, response in PHASES:
            with self.subTest(flags=flags):
                self.reset_state()
                self.fetch("/json/small")
                project_args = ("--project", self.PROJECT) if self.PROJECT else ()
                cp = self.suite.rivis(*project_args, "breakpoint", "/echo", *flags,
                                      home=self.inst.home, env=self.inst.env)
                self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
                call = Background(self.fetch, "/echo?matrix=" + str(PHASES.index((flags, request, response))),
                                  method="POST" if "post" in flags else "GET",
                                  data="x" if "post" in flags else None)
                expected = [p for p, on in (("request", request), ("response", response)) if on]
                seen = []
                for phase in expected:
                    paused = wait_for(lambda: next((p for p in self.panel.state()["paused"] if p["phase"] == phase), None),
                                      10, 0.1, phase + " pause")
                    seen.append(paused["phase"])
                    self.panel.ok("paused_continue" if phase == "request" and response else "paused_skip", {"id": paused["id"]})
                self.assertEqual(seen, expected)
                self.assertEqual(call.result().status, 200)
                self.assertEqual(self.panel.state()["paused"], [])


class LiveBreakpointNeo(LiveBreakpointMatrix):
    PROJECT = "neo"


class CliSurface(unittest.TestCase):
    """Enforce bash ↔ PowerShell command/flag inventory. Failures name the gap."""

    @classmethod
    def setUpClass(cls):
        cls.bash, cls.ps = _read_clis()
        cls.bash_cmds = _bash_implemented_commands(cls.bash)
        cls.ps_cmds = _ps_implemented_commands(cls.ps)
        cls.bash_flags = _bash_flags_by_command(cls.bash)
        cls.ps_flags = _ps_flags_by_command(cls.ps)

    def test_every_bash_only_exception_still_exists_on_bash(self):
        for cmd, reason in BASH_ONLY_COMMANDS.items():
            self.assertIn(cmd, self.bash_cmds, "exception for '%s' (%s) but bash no longer has it" % (cmd, reason))
            self.assertNotIn(cmd, self.ps_cmds, "exception says '%s' is bash-only (%s) but PowerShell now has it — remove the exception" % (cmd, reason))

    def test_every_bash_only_flag_exception_still_exists_on_bash(self):
        for (cmd, flag), reason in BASH_ONLY_FLAGS.items():
            if cmd in BASH_ONLY_COMMANDS:
                continue
            self.assertIn(flag, self.bash_flags.get(cmd, ()),
                          "exception for %s --%s (%s) but bash no longer has that flag" % (cmd, flag, reason))
            self.assertNotIn(flag, self.ps_flags.get(cmd, ()),
                             "exception says %s flag '%s' is bash-only (%s) but PowerShell now has it — remove the exception" % (cmd, flag, reason))

    def test_top_level_commands_match_except_known(self):
        miss_ps, miss_bash, _, _ = _surface_diff(self.bash_cmds, self.ps_cmds, self.bash_flags, self.ps_flags)
        for cmd in miss_ps:
            self.fail("PowerShell is missing command '%s' (present in bash). "
                      "Port it to rivis.ps1, or add it to BASH_ONLY_COMMANDS with a reason." % cmd)
        for cmd in miss_bash:
            self.fail("bash is missing command '%s' (present in PowerShell). "
                      "Port it to rivis, or explain the gap (this lane cannot edit bash)." % cmd)

    def test_flags_match_except_known(self):
        _, _, miss_ps, miss_bash = _surface_diff(self.bash_cmds, self.ps_cmds, self.bash_flags, self.ps_flags)
        for cmd, flag in miss_ps:
            self.fail(_fmt_flag_gap("PowerShell", cmd, flag) +
                      ". Add -%s to rivis.ps1 for that command, or add (%r, %r) to BASH_ONLY_FLAGS with a reason."
                      % (flag, cmd, flag))
        for cmd, flag in miss_bash:
            self.fail(_fmt_flag_gap("bash", cmd, flag) +
                      ". Add --%s to rivis for that command, or add (%r, %r) to PS_ONLY_FLAGS with a reason."
                      % (flag, cmd, flag))

    def test_usage_header_lists_every_implemented_user_command(self):
        bash_doc = _bash_usage_commands(self.bash)
        ps_doc = _ps_usage_commands(self.ps)
        # help/version are meta; uninstall is implemented as a refusal message
        skip = {"uninstall"}
        for cmd in sorted(self.bash_cmds - skip):
            if cmd in BASH_INTERNAL_COMMANDS:
                continue
            self.assertIn(cmd, bash_doc,
                          "bash implements '%s' but the usage header at the top of rivis does not mention it" % cmd)
        for cmd in sorted(self.ps_cmds):
            self.assertIn(cmd, ps_doc,
                          "PowerShell implements '%s' but the usage header at the top of rivis.ps1 does not mention it" % cmd)

    def test_inventory_fails_when_a_flag_is_added_to_one_cli_only(self):
        """Scratch mutation of the PowerShell source: a lone flag must trip the inventory."""
        mutated = self.ps.replace(
            "[switch]$Lan,",
            "[switch]$Lan,\n  [switch]$ScratchOnlyFlag,",
            1,
        )
        self.assertNotEqual(mutated, self.ps, "scratch flag insert failed — param block moved?")
        # reference the new switch inside the start block so the per-command extractor sees it
        start = '  "start" {'
        self.assertIn(start, mutated)
        mutated = mutated.replace(start, start + "\n    $null = $ScratchOnlyFlag", 1)
        ps_flags = _ps_flags_by_command(mutated)
        _, _, miss_ps, miss_bash = _surface_diff(
            self.bash_cmds, _ps_implemented_commands(mutated), self.bash_flags, ps_flags)
        self.assertIn(("start", "scratchonlyflag"), miss_bash,
                      "expected the inventory to report bash missing start flag 'scratchonlyflag'; got miss_bash=%r miss_ps=%r"
                      % (miss_bash, miss_ps))

    def test_inventory_fails_when_a_command_is_added_to_one_cli_only(self):
        mutated = self.ps.replace(
            '  "cert" {',
            '  "scratchcmd" { Die "scratch" }\n  "cert" {',
            1,
        )
        self.assertNotEqual(mutated, self.ps)
        miss_ps, miss_bash, _, _ = _surface_diff(
            self.bash_cmds, _ps_implemented_commands(mutated), self.bash_flags, self.ps_flags)
        self.assertIn("scratchcmd", miss_bash,
                      "expected bash missing command 'scratchcmd'; got miss_bash=%r miss_ps=%r" % (miss_bash, miss_ps))


class TlsNoopParity(unittest.TestCase):
    """tls allow|ignore add|rm must refuse no-ops on both CLIs (same exit, same message class)."""

    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()
        if not (os.path.isfile(PWSH) and os.access(PWSH, os.X_OK)):
            raise AssertionError("pwsh 7 is required for CLI state parity: " + PWSH)
        cls.bash, cls.ps = _read_clis()

    def test_ps_tls_source_keeps_noop_and_ascii_guards(self):
        """Source-level net: the -match Unicode range bug and silent add/rm must not return."""
        tls_block = _ps_block(self.ps, "tls")
        self.assertIn("already on the list", tls_block)
        self.assertIn("no $sub pattern", tls_block)
        self.assertIn("-cmatch", self.ps)
        self.assertNotRegex(self.ps, r"\$p -match '\[\\s<>\\x80-\\uffff\]'")

    def test_duplicate_add_and_missing_rm_match_across_clis(self):
        for surface in ("bash", "ps"):
            with self.subTest(surface=surface):
                home = self.suite.new_home("tls-noop-" + surface)
                env = self.suite.cli_env(home)
                def run(*args):
                    if surface == "bash":
                        argv = ["/bin/bash", os.path.join(REPO, "rivis")]
                    else:
                        argv = [PWSH, "-NoProfile", "-NonInteractive", "-File", os.path.join(REPO, "rivis.ps1")]
                    return self.suite.run(argv + list(args), home=home, env=env, timeout=120)

                # Hosts without i/k: under PowerShell's default -match, [\x80-\uffff]
                # wrongly hits ASCII i/k and would fail this test for the wrong reason.
                first = run("tls", "allow", "add", "noop.host")
                self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
                with open(os.path.join(home, ".rivis", "projects", "default", "rules.json")) as fh:
                    before = json.load(fh)["tls"]

                dup = run("tls", "allow", "add", "NOOP.host")
                self.assertNotEqual(dup.returncode, 0, "%s claimed a duplicate add succeeded" % surface)
                self.assertIn("already on the list", dup.stdout + dup.stderr)
                self.assertNotIn("added", dup.stdout)

                missing = run("tls", "ignore", "rm", "absent.host")
                self.assertNotEqual(missing.returncode, 0, "%s claimed a missing rm succeeded" % surface)
                self.assertIn("no ignore pattern", missing.stdout + missing.stderr)
                self.assertNotIn("removed", missing.stdout)

                trailing = run("tls", "list", "EXTRA")
                self.assertNotEqual(trailing.returncode, 0, "%s swallowed tls list EXTRA" % surface)

                with open(os.path.join(home, ".rivis", "projects", "default", "rules.json")) as fh:
                    after = json.load(fh)["tls"]
                self.assertEqual(after, before)
