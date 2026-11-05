"""Shipped scripts must stay on Apple's /bin/bash 3.2 and system /usr/bin/python3 (3.9).

A construct that only works on bash 4+, Python 3.10+, or GNU userland will pass every other test on a
developer machine (Homebrew bash, mitmproxy's bundled Python) and fail on a QA Mac. This module is the
table that stops the next one: every banned form is one row. Deliberate exceptions live in ALLOW.

Interpreter map (see also the comments on each SYSTEM_PYTHON file):
  * Bash host scripts — Apple /bin/bash 3.2 (rivis, install.sh, host helpers).
  * Android on-device scripts — /system/bin/sh (POSIX); separate bashism check.
  * SYSTEM_PYTHON — invoked by the CLI as /usr/bin/python3 (or imported by those modules).
  * MITM_PYTHON — loaded into mitmweb via -s (bundled 3.14); still parsed here on 3.9 so a slip that
    also imports them from a CLI helper stays visible. python_host.py is launched from the mitm
    add-on but often falls back to /usr/bin/python3, so it is treated as SYSTEM_PYTHON.
"""
import ast
import os
import re
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness

REPO = harness.REPO
BASH = "/bin/bash"
PY39 = "/usr/bin/python3"

# Host bash scripts a QA engineer actually runs (not tests/, not release-tools/).
HOST_BASH = (
    "rivis",
    "neo-mitm",
    "install/install.sh",
    "install/mirror/make-bundle.sh",
    "install/mirror/make-release.sh",
    "addons/android_magisk.sh",
    "addons/update_install.sh",
    "addons/macapp/build.sh",
)

# Runs on the emulator as /system/bin/sh — no bashisms.
ANDROID_SH = (
    "addons/android/rivis_ca.sh",
    "addons/android/rivis_inject.sh",
    "addons/android/rivis_system_ca.sh",
)

# CLI helpers: /usr/bin/python3 -I … or imported by those helpers.
SYSTEM_PYTHON = (
    "addons/android_picker.py",
    "addons/android_settings_timeout.py",
    "addons/android_setup_log.py",
    "addons/bug_report.py",
    "addons/client_certs.py",
    "addons/compose_cli.py",
    "addons/curl_import.py",
    "addons/devices.py",
    "addons/doctor.py",
    "addons/proxy_common.py",
    "addons/proxy_lan.py",
    "addons/proxy_rule_validation.py",
    "addons/proxy_scripts.py",  # runpy.find_node from rivis status
    "addons/proxyman_import.py",
    "addons/python_host.py",    # often /usr/bin/python3 when mitmweb's argv0 is not "python*"
    "addons/qr.py",
    "addons/rules_cli.py",
    "addons/scripts_cli.py",
    "addons/system_trust.py",
    "addons/terms.py",          # the Terms of Use gate: both CLIs run it with /usr/bin/python3 -I (and mitmweb imports it)
    "addons/tls_cli.py",
    "addons/updater.py",
)

# Loaded only via mitmweb -s (bundled Python). Listed so the tree stays classified.
MITM_PYTHON = (
    "addons/panel_har.py",
    "addons/panel_mitmweb.py",
    "addons/panel_view.py",
    "addons/proxy_auth.py",
    "addons/proxy_codegen.py",
    "addons/proxy_collections.py",
    "addons/proxy_compose.py",
    "addons/proxy_operability.py",
    "addons/proxy_panel.py",
    "addons/proxy_redact.py",
    "addons/proxy_retention.py",
    "addons/proxy_rules.py",
    "addons/proxy_quic.py",
    "addons/proxy_source.py",
    "addons/proxy_terms.py",
)

# (relpath, rule_id) pairs that are deliberate and must not fail the suite.
# Add a one-line reason in the nearby comment when extending this.
ALLOW = frozenset({
    # install.sh resolves paths with Python on purpose; the `realpath` *command* in rivis/neo-mitm is
    # macOS /bin/realpath (not GNU readlink -f). No exception needed for a hit that is not a hit.
})

# bash 4+ / bash 4.2+ / bash 4.3+ tokens that must not appear as code in host scripts.
# Patterns are applied line-wise after stripping a trailing comment; strings can still false-hit, so
# ALLOW exists and each hit is reported with file:line for a human to confirm.
BASH4_RULES = (
    ("declare_A", re.compile(r"(^|[^[:alnum:]_])declare\s+-A\b")),
    ("declare_g", re.compile(r"(^|[^[:alnum:]_])declare\s+-g\b")),
    ("mapfile", re.compile(r"(^|[^[:alnum:]_])mapfile\b")),
    ("readarray", re.compile(r"(^|[^[:alnum:]_])readarray\b")),
    ("local_n", re.compile(r"(^|[^[:alnum:]_])local\s+-n\b")),
    ("coproc", re.compile(r"(^|[^[:alnum:]_])coproc\b")),
    ("wait_n", re.compile(r"(^|[^[:alnum:]_])wait\s+-n\b")),
    ("pipe_amp", re.compile(r"\|\&")),
    ("amp_append", re.compile(r"\&\>\>")),
    ("test_v", re.compile(r"\[\[\s+-v\s")),
    ("at_Q", re.compile(r"\$\{[^}]+@Q\}")),
    ("case_fold_lower", re.compile(r"\$\{[^}]+,,\}")),
    ("case_fold_upper", re.compile(r"\$\{[^}]+\^\^\}")),
    ("printf_T", re.compile(r"printf\s+['\"]?%\([^)]*\)T")),
    ("neg_substr_len", re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:[0-9]+:-[0-9]+\}")),
)

# GNU userland flags that fail or mean something else on macOS's BSD tools.
GNU_RULES = (
    ("sed_i_gnu", re.compile(r"(^|[^[:alnum:]_])sed\s+-i[^\s'\"-]")),  # sed -iSUFFIX or sed -i -e without ''
    ("date_d", re.compile(r"(^|[^[:alnum:]_])date\s+-d\b")),
    ("readlink_f", re.compile(r"(^|[^[:alnum:]_])readlink\s+-f\b")),
    ("stat_c", re.compile(r"(^|[^[:alnum:]_])stat\s+-c\b")),
    ("grep_P", re.compile(r"(^|[^[:alnum:]_])grep\s+(-[A-Za-z0-9]*P|-P)\b")),
    ("xargs_r", re.compile(r"(^|[^[:alnum:]_])xargs\s+(-[A-Za-z0-9]*r|-r)\b")),
    ("find_printf", re.compile(r"(^|[^[:alnum:]_])find\b[^\n]*\s-printf\b")),
    ("sort_V", re.compile(r"(^|[^[:alnum:]_])sort\s+(-[A-Za-z0-9]*V|-V)\b")),
)

# Bashisms that /system/bin/sh on the emulator will not run.
ANDROID_BASHISM_RULES = (
    ("double_bracket", re.compile(r"\[\[")),
    ("declare", re.compile(r"(^|[^[:alnum:]_])declare\b")),
    ("local", re.compile(r"(^|[^[:alnum:]_])local\b")),
    ("process_sub", re.compile(r"<\(|\>\(")),
    ("pipe_amp", re.compile(r"\|\&")),
)


def _strip_bash_comment(line):
    """Drop a trailing # comment that is not inside a single- or double-quoted span (good enough for guards)."""
    in_s = in_d = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line) and (in_s or in_d):
            i += 2
            continue
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d:
            return line[:i]
        i += 1
    return line


def _read(rel):
    return open(os.path.join(REPO, rel), encoding="utf-8").read()


def scan_lines(rel, rules):
    hits = []
    for lineno, raw in enumerate(_read(rel).splitlines(), 1):
        line = _strip_bash_comment(raw)
        for rule_id, rx in rules:
            if (rel, rule_id) in ALLOW:
                continue
            if rx.search(line):
                hits.append("%s:%d:%s:%s" % (rel, lineno, rule_id, raw.strip()[:120]))
    return hits


def scan_host_bash(rel):
    return scan_lines(rel, BASH4_RULES) + scan_lines(rel, GNU_RULES)


def scan_android_sh(rel):
    return scan_lines(rel, ANDROID_BASHISM_RULES)


def _annotation_has_bitor(node):
    return any(isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.BitOr) for sub in ast.walk(node))


def scan_python39(rel):
    """Return hits for syntax / forms that parse on 3.10+ but not on system 3.9, or fail at runtime on 3.9."""
    hits = []
    src = _read(rel)
    try:
        tree = ast.parse(src, filename=rel)
    except SyntaxError as exc:
        return ["%s:%s:syntax:%s" % (rel, exc.lineno or "?", exc.msg)]

    # ast.Match exists only on 3.10+; on 3.9 a match statement is already a SyntaxError above.
    match_type = getattr(ast, "Match", ())
    for node in ast.walk(tree):
        if match_type and isinstance(node, match_type):
            hits.append("%s:%d:match_stmt" % (rel, node.lineno))
        # PEP 604 X | Y in annotations evaluated at definition time (no from __future__ import annotations)
        if isinstance(node, ast.FunctionDef):
            for arg in node.args.args + node.args.kwonlyargs:
                if arg.annotation is not None and _annotation_has_bitor(arg.annotation):
                    hits.append("%s:%d:pep604_ann" % (rel, node.lineno))
            if node.returns is not None and _annotation_has_bitor(node.returns):
                hits.append("%s:%d:pep604_ann" % (rel, node.lineno))
        if isinstance(node, ast.AnnAssign) and node.annotation is not None and _annotation_has_bitor(node.annotation):
            hits.append("%s:%d:pep604_ann" % (rel, node.lineno))
        # zip(..., strict=True) — 3.10
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name == "zip" and any(k.arg == "strict" for k in node.keywords):
                hits.append("%s:%d:zip_strict" % (rel, node.lineno))
        # dict | dict merge is 3.9+ — allowed. ExceptionGroup / except* are SyntaxError on 3.9 (caught above).
    for rule_id, rx in (
        ("tomllib", re.compile(r"(^|[^[:alnum:]_])(import\s+tomllib|from\s+tomllib\b)")),
        ("datetime_UTC", re.compile(r"datetime\.UTC\b")),
        ("ExceptionGroup", re.compile(r"(^|[^[:alnum:]_])ExceptionGroup\b")),
        ("typing_Self", re.compile(r"typing\.Self\b|from typing import Self\b")),
    ):
        if (rel, rule_id) in ALLOW:
            continue
        for lineno, raw in enumerate(src.splitlines(), 1):
            if rx.search(raw):
                hits.append("%s:%d:%s" % (rel, lineno, rule_id))
    return hits


class HostBashCompat(unittest.TestCase):
    def test_shipped_host_scripts_have_no_bash4_or_gnu_constructs(self):
        hits = []
        for rel in HOST_BASH:
            hits.extend(scan_host_bash(rel))
        self.assertEqual(hits, [], "banned bash 4+ / GNU userland in shipped host scripts")

    def test_shipped_host_scripts_parse_under_apple_bash_3_2(self):
        self.assertTrue(os.path.isfile(BASH), "Apple /bin/bash missing")
        ver = subprocess.run([BASH, "--version"], capture_output=True, text=True, check=True).stdout
        self.assertIn("version 3.2", ver)
        for rel in HOST_BASH:
            path = os.path.join(REPO, rel)
            cp = subprocess.run([BASH, "-n", path], capture_output=True, text=True)
            self.assertEqual(cp.returncode, 0, "%s: %s" % (rel, cp.stderr))

    def test_scanner_flags_an_injected_declare_A(self):
        # Fails if the declare -A rule is deleted or loosened.
        hits = []
        for rule_id, rx in BASH4_RULES:
            if rx.search("declare -A map=()"):
                hits.append(rule_id)
        self.assertIn("declare_A", hits)
    def test_scanner_flags_an_injected_grep_P(self):
        hits = []
        for rule_id, rx in GNU_RULES:
            if rx.search("grep -P 'foo' file"):
                hits.append(rule_id)
        self.assertIn("grep_P", hits)

    def test_empty_array_expansion_is_unbound_under_bash_3_2_set_u(self):
        # The pilot crash: set -u + "${a[@]}" on an empty array. Guards use ${a[@]+"${a[@]}"}.
        cp = subprocess.run([BASH, "-c", 'set -u; a=(); echo "${a[@]}"'], capture_output=True, text=True)
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("unbound variable", cp.stderr)
        cp = subprocess.run([BASH, "-c", 'set -u; a=(); echo ${a[@]+"${a[@]}"}; echo ok'],
                            capture_output=True, text=True)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("ok", cp.stdout)


class AndroidShCompat(unittest.TestCase):
    def test_on_device_scripts_have_no_bashisms(self):
        hits = []
        for rel in ANDROID_SH:
            hits.extend(scan_android_sh(rel))
        self.assertEqual(hits, [], "bashism in an on-device /system/bin/sh script")

    def test_on_device_scripts_parse_under_bin_sh(self):
        for rel in ANDROID_SH:
            cp = subprocess.run(["/bin/sh", "-n", os.path.join(REPO, rel)], capture_output=True, text=True)
            self.assertEqual(cp.returncode, 0, "%s: %s" % (rel, cp.stderr))

    def test_scanner_flags_an_injected_double_bracket(self):
        hits = []
        for rule_id, rx in ANDROID_BASHISM_RULES:
            if rx.search('[[ "$x" = y ]]'):
                hits.append(rule_id)
        self.assertIn("double_bracket", hits)


class SystemPythonCompat(unittest.TestCase):
    def test_system_python_is_3_9(self):
        ver = subprocess.run([PY39, "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
                             capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(ver, "3.9")

    def test_system_python_modules_have_no_3_10_plus_forms(self):
        hits = []
        for rel in SYSTEM_PYTHON:
            hits.extend(scan_python39(rel))
        self.assertEqual(hits, [], "Python 3.10+ form in a /usr/bin/python3 module")

    def test_system_python_modules_compile_under_3_9(self):
        for rel in SYSTEM_PYTHON:
            path = os.path.join(REPO, rel)
            cp = subprocess.run([PY39, "-m", "py_compile", path], capture_output=True, text=True)
            self.assertEqual(cp.returncode, 0, "%s: %s" % (rel, cp.stderr))

    def test_mitm_python_modules_still_parse_on_3_9(self):
        # mitmweb bundles a newer Python; keeping these 3.9-parseable avoids a surprise when a CLI
        # helper imports one. If a mitm-only file deliberately needs 3.10+, move it to ALLOW.
        hits = []
        for rel in MITM_PYTHON:
            hits.extend(scan_python39(rel))
        self.assertEqual(hits, [], "Python 3.10+ form in a mitm -s module (add ALLOW if deliberate)")

    def test_scanner_flags_an_injected_match_statement(self):
        src = "def f(x):\n    match x:\n        case 1:\n            return 1\n"
        try:
            ast.parse(src)
            parsed_on_this_interpreter = True
        except SyntaxError as exc:
            parsed_on_this_interpreter = False
            syntax_lineno = exc.lineno
        # Suite runs on 3.9: match must be a SyntaxError here — that is what scan_python39 reports for a file.
        self.assertFalse(parsed_on_this_interpreter)
        self.assertIsNotNone(syntax_lineno)
        # And when the same source is a real module path, the scanner surfaces it as a syntax hit.
        with tempfile.TemporaryDirectory(prefix="rivis-compat-") as tmp:
            path = os.path.join(tmp, "injected.py")
            open(path, "w").write(src)
            cp = subprocess.run([PY39, "-c",
                                 "import ast,sys; ast.parse(open(sys.argv[1]).read())", path],
                                capture_output=True, text=True)
            self.assertNotEqual(cp.returncode, 0)
            self.assertTrue("match" in cp.stderr or "invalid syntax" in cp.stderr or "Error" in cp.stderr, cp.stderr)
    def test_scanner_flags_an_injected_pep604_annotation(self):
        src = "def f(x: int | None) -> str | None:\n    return None\n"
        tree = ast.parse(src)
        hits = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for arg in node.args.args:
                    if arg.annotation is not None and _annotation_has_bitor(arg.annotation):
                        hits.append("pep604")
                if node.returns is not None and _annotation_has_bitor(node.returns):
                    hits.append("pep604")
        self.assertEqual(hits, ["pep604", "pep604"])


class InventoryComplete(unittest.TestCase):
    def test_every_addon_py_is_classified(self):
        classified = set(SYSTEM_PYTHON) | set(MITM_PYTHON)
        found = []
        for name in sorted(os.listdir(os.path.join(REPO, "addons"))):
            if name.endswith(".py"):
                found.append("addons/" + name)
        missing = [p for p in found if p not in classified]
        self.assertEqual(missing, [], "classify new addon modules as SYSTEM_PYTHON or MITM_PYTHON")

    def test_every_host_shell_script_is_listed(self):
        # Walk install/ and addons/ for *.sh plus the two CLI entrypoints; ignore android on-device (listed apart).
        expected = set(HOST_BASH) | set(ANDROID_SH)
        found = {"rivis", "neo-mitm"}
        for root, dirs, files in os.walk(REPO):
            dirs[:] = [d for d in dirs if d not in (".git", "tests", "release-tools", "node_modules", "__pycache__")]
            for name in files:
                if name.endswith(".sh"):
                    rel = os.path.relpath(os.path.join(root, name), REPO)
                    if rel.startswith("addons/android/"):
                        found.add(rel.replace("\\", "/"))
                    elif "/android/" not in rel.replace("\\", "/"):
                        found.add(rel.replace("\\", "/"))
        self.assertEqual(sorted(found), sorted(expected), "new shipped shell script is not in the compat inventory")
