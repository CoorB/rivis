"""PowerShell edition (rivis.ps1, neo-mitm.ps1, install.ps1) under the portable pwsh on macOS: parse checks, and the commands
that do not need Windows (projects, rules, throttle, scripts, tls, compose, cert, help) against a fake HOME.
Registry / netstat / Android parts are skipped with a reason."""
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import Suite

PWSH = harness.PWSH
HAVE_PWSH = os.path.isfile(PWSH) and os.access(PWSH, os.X_OK)
NO_PWSH = "portable pwsh not found at %s" % PWSH
WINDOWS_ONLY = "needs the Windows registry (HKCU:) / netstat, which do not exist in pwsh on macOS"
IS_WIN = harness.IS_WIN
NO_BASH_CLI = "the bash CLI needs /usr/bin/python3 under Git bash (the Windows workflow provides it)"


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class PowerShellSource(unittest.TestCase):
    """Parity checks that still run on development Macs where pwsh is intentionally absent."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(harness.REPO, "rivis.ps1")) as fh:
            cls.src = fh.read()

    def test_windows_has_the_cross_platform_command_cases(self):
        for command in ("stop", "breakpoint", "mock", "setup"):
            self.assertRegex(self.src, r'(?m)^  "' + command + r'" \{', command)

    def test_start_keeps_its_token_until_the_first_process_exits(self):
        self.assertIn('RivisStart-', self.src)
        self.assertIn('start already in progress', self.src)

    def test_unproven_windows_proxy_is_left_unchanged(self):
        block = self.src[self.src.index('  "net-reset" {'):self.src.index('  "doctor" {')]
        self.assertNotIn('ProxyEnable -Value 0', block)
        self.assertNotIn('netsh winhttp reset proxy', block)

    def test_fresh_browser_profile_is_private_and_swept_like_bash(self):
        """Review m11 parity: -Fresh keeps its profile under the state root and deletes leftovers, sparing one still in use."""
        block = self.src[self.src.index("if ($Fresh) {"):self.src.index("Web apps on localhost go through Rivis")]
        self.assertIn('Join-Path $StateRoot "browser"', block)
        self.assertIn('"tmp-"', block)
        self.assertNotRegex(block, r'GetTempPath\(\)\)\s*\("\$Cli-browser')
        self.assertIn('--user-data-dir=$($old.FullName)', block)
        self.assertRegex(block, r'Remove-Item -LiteralPath \$old\.FullName -Recurse')

    def test_help_guard_precedes_dispatch_and_recognises_all_spellings(self):
        guard = self.src.index("$helpRequested =")
        dispatch = self.src.index("switch ($Command)")
        self.assertLess(guard, dispatch)
        self.assertIn('@("-h","--help","-Help")', self.src)
        self.assertRegex(self.src[guard:dispatch], r'if \(\$helpRequested.*Write-Usage.*exit 0')

    def test_new_commands_keep_the_bash_safety_and_delegation_contracts(self):
        self.assertIn('$process.ProcessName -eq "mitmweb"', self.src)
        self.assertIn('Stop-Process -Id $ownerPid', self.src)
        self.assertRegex(self.src, r'rules_cli\.py"\) \$RulesPath breakpoint @arguments')
        self.assertRegex(self.src, r'rules_cli\.py"\) \$RulesPath mock-pick')
        self.assertIn('& $PSCommandPath android on -All', self.src)
        self.assertIn('iOS: unavailable on Windows', self.src)

    def test_rules_cli_runs_when_fcntl_is_unavailable(self):
        script = """import builtins, runpy, sys
original_import = builtins.__import__
def without_fcntl(name, *args, **kwargs):
    if name == 'fcntl':
        raise ModuleNotFoundError("No module named 'fcntl'")
    return original_import(name, *args, **kwargs)
builtins.__import__ = without_fcntl
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name='__main__')
"""
        with tempfile.TemporaryDirectory() as directory:
            rules_path = os.path.join(directory, "rules.json")
            with open(rules_path, "w") as fh:
                json.dump({"rules": []}, fh)
            cli = os.path.join(harness.REPO, "addons", "rules_cli.py")
            for args in (("rules", "list"), ("rules", "test", "https://example.test/x"),
                         ("breakpoint", "off")):
                cp = subprocess.run([sys.executable, "-I", "-c", script, cli, rules_path, *args],
                                    capture_output=True, text=True, timeout=15)
                self.assertEqual(cp.returncode, 0, (args, cp.stdout, cp.stderr))

    def test_mock_keeps_captured_headers_and_replaces_prior_mock(self):
        mock = self.src[self.src.index('  "mock" {'):self.src.index('  "android" {')]
        self.assertIn('$pick.Count -ne 4', mock)
        self.assertIn('$id,$status,$method,$headers = $pick', mock)
        self.assertIn('rules mock-set $Action', mock)
        self.assertIn('"headers=$headers"', mock)
        self.assertIn('"created_mock=$createdMock"', mock)

    def test_state_root_acl_is_not_applied_recursively(self):
        """icacls /T put the owner entry on existing files as inherit-only, so with inheritance removed they became
        unreadable on Windows ("Access denied" on a profile's rules.example.json after `projects new`)."""
        guard = self.src[self.src.index('function Protect-StateRoot'):self.src.index('function New-UiBootstrap')]
        acl = [l for l in guard.splitlines() if "icacls.exe $StateRoot" in l]
        self.assertEqual(len(acl), 1, guard)
        self.assertNotIn("/T", acl[0])

    def test_stop_waits_for_both_ports_and_has_a_forced_bounded_fallback(self):
        stop = self.src[self.src.index('  "stop" {'):self.src.index('  "ui" {')]
        self.assertIn('Wait-Process', stop)
        self.assertIn('-Timeout 10', stop)
        self.assertIn('-Force', stop)
        self.assertIn('Ports-Free', stop)

    def test_stop_only_targets_mitmweb_owned_by_this_state_root(self):
        ownership = self.src[self.src.index('function Test-OurMitmweb'):self.src.index('function Ensure-Rules')]
        stop = self.src[self.src.index('  "stop" {'):self.src.index('  "ui" {')]
        self.assertIn('$process.ProcessName -eq "mitmweb"', ownership)
        self.assertIn('"proxy_auth_token_file=" + [regex]::Escape($TokenPath)', ownership)   # R4A-05: whole value, not a prefix
        self.assertIn('web_port=$WebPort', ownership)
        self.assertGreaterEqual(stop.count('Our-Listening-Pids'), 2)
        self.assertNotIn('Listening-Pids @', stop.replace('Our-Listening-Pids @', ''))


@unittest.skipUnless(HAVE_PWSH, NO_PWSH)
class Parse(unittest.TestCase):
    def errors(self, path):
        script = ("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('%s',[ref]$t,[ref]$e);"
                  "$e | ForEach-Object { '{0}:{1} {2}' -f $_.Extent.StartLineNumber,$_.Extent.StartColumnNumber,$_.Message }" % path)
        cp = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=60)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        return cp.stdout.strip()

    def test_every_powershell_file_parses(self):
        for rel in ("rivis.ps1", "neo-mitm.ps1", os.path.join("install", "install.ps1")):
            self.assertEqual(self.errors(os.path.join(harness.REPO, rel)), "", rel)

    def test_no_obviously_unsafe_constructs(self):
        for rel in ("rivis.ps1", "install/install.ps1", "neo-mitm.ps1"):
            src = open(os.path.join(harness.REPO, rel)).read()
            self.assertNotIn("Invoke-Expression", src, rel)
            self.assertNotRegex(src, r"(?i)\biex\s", rel)
            self.assertNotRegex(src, r"Set-ItemProperty[^\n]*Internet Settings", rel + ": system proxy registry write")
            self.assertNotRegex(src, r"(?i)netsh\s+winhttp\s+set", rel)


@unittest.skipUnless(HAVE_PWSH, NO_PWSH)
class Commands(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()

    def setUp(self):
        self.home = self.suite.new_home("ps")
        self.env = self.suite.cli_env(self.home)
        self.state = os.path.join(self.home, ".rivis")

    def ps(self, *args, bin="rivis.ps1"):
        return self.suite.run([PWSH, "-NoProfile", "-NonInteractive", "-File", os.path.join(harness.REPO, bin)] + list(args),
                              home=self.home, env=self.env, timeout=120)

    def ok(self, *args, **kw):
        cp = self.ps(*args, **kw)
        self.assertEqual(cp.returncode, 0, "rivis.ps1 %s -> %s\n%s\n%s" % (" ".join(args), cp.returncode, cp.stdout, cp.stderr))
        return cp.stdout

    def bad(self, *args, msg=None):
        cp = self.ps(*args)
        self.assertNotEqual(cp.returncode, 0, "rivis.ps1 %s unexpectedly succeeded: %s" % (" ".join(args), cp.stdout))
        if msg:
            self.assertIn(msg, cp.stdout + cp.stderr)
        return cp

    def test_trusted_files_parity_with_the_bash_cli(self):
        mine = os.path.join(self.home, "Desktop", "mock.json")
        os.makedirs(os.path.dirname(mine), exist_ok=True)
        with open(mine, "w") as fh:
            fh.write("{}")
        self.assertIn("trusted on this machine", self.ok("rules", "allow-file", mine))
        listed = self.bash("rules", "trusted-files")                                 # same file both CLIs read
        self.assertIn(os.path.normcase(os.path.realpath(mine)).replace("\\", "/"), os.path.normcase(listed).replace("\\", "/"))
        key = os.path.join(self.home, ".ssh", "id_rsa")
        os.makedirs(os.path.dirname(key), exist_ok=True)
        with open(key, "w") as fh:
            fh.write("k")
        self.bad("rules", "allow-file", key, msg="refusing")
        self.ok("rules", "disallow-file", mine)
        self.assertIn("no files outside", self.ok("rules", "trusted-files"))

    def test_start_keeps_the_ui_password_off_argv_and_out_of_the_output(self):
        """F-03 parity: the password is in a private file read by proxy_auth.py; the browser gets a one-time link."""
        log = os.path.join(self.suite.shimlog, "mitm-argv.log")
        open(log, "w").close()
        env = dict(self.env, SHIM_DRYRUN="1", RIVIS_WEB_PASSWORD="ps-secret-0123456789abcdef")
        cp = self.suite.run([PWSH, "-NoProfile", "-NonInteractive", "-File", os.path.join(harness.REPO, "rivis.ps1"),
                             "start", "-NoOpen"], home=self.home, env=env, timeout=120)
        lines = [l for l in self.suite.shim_log("mitm-argv.log").splitlines() if l.startswith("mitmweb ")]
        self.assertEqual(len(lines), 1, cp.stdout + cp.stderr)
        line = lines[0]
        self.assertNotIn("ps-secret", line)
        self.assertNotIn("web_password", line)
        self.assertNotIn("ps-secret", cp.stdout + cp.stderr)
        self.assertIn("proxy_auth.py", line)
        sfx = "" if env.get("RIVIS_WEB_PORT", "8083") == "8083" else "-" + env["RIVIS_WEB_PORT"]   # R4A-05: per UI port
        token, boot = os.path.join(self.state, "web-token" + sfx), os.path.join(self.state, "web-bootstrap" + sfx)
        self.assertIn("proxy_auth_token_file=%s " % token, line + " ")
        self.assertIn("proxy_bootstrap_file=%s " % boot, line + " ")
        self.assertIn("http2=false", line)
        for path in (token, boot):
            self.assertTrue(os.path.isfile(path), path)
            if not IS_WIN:      # on Windows the private file is an NTFS ACL (icacls), not a mode
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600, path)
        with open(token) as fh:
            self.assertEqual(fh.read().strip(), "ps-secret-0123456789abcdef")

    def test_upstream_setting_matches_bash_start_and_status(self):
        log = os.path.join(self.suite.shimlog, "mitm-argv.log")
        open(log, "w").close()
        env = dict(self.env, SHIM_DRYRUN="1")
        cmd = [PWSH, "-NoProfile", "-NonInteractive", "-File", os.path.join(harness.REPO, "rivis.ps1")]
        url = "http://127.0.0.1:3128"
        first = self.suite.run(cmd + ["start", "-NoOpen", "-Upstream", url], home=self.home, env=env, timeout=120)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertIn("upstream:" + url + "@" + env["RIVIS_PORT"], self.suite.shim_log("mitm-argv.log"))
        status = self.suite.run(cmd + ["status"], home=self.home, env=env, timeout=120)
        self.assertIn("upstream proxy: " + url, status.stdout)
        doctor = self.suite.run(cmd + ["doctor", "-NoNet"], home=self.home, env=env, timeout=120)
        self.assertIn("upstream proxy: " + url, doctor.stdout)
        direct = self.suite.run(cmd + ["start", "-NoOpen", "-Upstream", "direct"], home=self.home, env=env, timeout=120)
        self.assertEqual(direct.returncode, 0, direct.stdout + direct.stderr)
        self.assertIn("regular@" + env["RIVIS_PORT"], self.suite.shim_log("mitm-argv.log"))

    def bash(self, *args):
        if not harness.BASH_CLI_READY:
            self.skipTest(NO_BASH_CLI)
        if IS_WIN and not os.path.exists(self.rules_file()):
            self.ok("rules", "list")        # let PowerShell create the state: Git bash's POSIX-emulation ACL on a file it creates can be unreadable to PowerShell
        cp = self.suite.rivis(*args, home=self.home, env=self.env)
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        return cp.stdout

    def rules_file(self, project="default"):
        return os.path.join(self.state, "projects", project, "rules.json")

    def cfg(self, project="default"):
        with open(self.rules_file(project)) as fh:
            return json.load(fh)

    def test_version_prints_the_release(self):
        want = open(os.path.join(harness.REPO, "install", "VERSION")).read().strip()
        for flag in ("--version", "version"):
            self.assertEqual(self.ok(flag).strip(), "rivis " + want, flag)

    def test_help_lists_commands(self):
        out = self.ok("help")
        for word in ("start", "projects", "rules", "scripts", "throttle", "tls", "compose", "android", "net-reset"):
            self.assertIn(word, out)

    def test_unexpected_remaining_arguments_are_rejected(self):
        for args in (("status", "extra"), ("cert", "extra"), ("doctor", "extra"),
                     ("rules", "list", "extra", "more"), ("compose", "list", "extra", "more")):
            self.bad(*args, msg="unexpected argument")

    def test_ca_generation_and_profile_network_are_explicitly_scoped(self):
        src = open(os.path.join(harness.REPO, "rivis.ps1")).read()
        self.assertRegex(src, r'Start-Process mitmdump[^\n]+"--listen-host","127\.0\.0\.1"')
        self.assertIn('$argv += "--allow-profile-network"', src)

    def test_doctor_runs_with_single_element_python_command(self):
        """C1 review #1: a one-element python3 command must not expand PowerShell's descending 1..0 range."""
        cp = self.ps("doctor", "-NoNet", "-Json")
        self.assertNotIn("can't open file ''", cp.stdout + cp.stderr)
        self.assertNotIn("doctor.py: error", cp.stdout + cp.stderr)
        self.assertTrue((cp.stdout.strip().startswith("[") or cp.stdout.strip().startswith("{")), cp.stdout + cp.stderr)

    def test_native_doctor_uses_the_configured_pin_and_propagates_warn_error_exit_codes(self):
        with open(os.path.join(harness.REPO, "rivis.ps1")) as fh:
            src = fh.read()
        self.assertIn('$PinnedMitmproxy', src)
        self.assertIn('$doctorExit = 2', src)
        self.assertIn('exit $doctorExit', src)

    def test_projects_list_new_use_show_and_validation(self):
        out = self.ok("projects", "list")
        self.assertIn("* default", out)
        self.assertIn("neo", out)
        self.ok("projects", "new", "qa", "-Hosts", r"example\.test", "-Label", "QA")
        self.assertTrue(os.path.isfile(os.path.join(self.state, "profiles", "qa", "project.json")))
        self.assertIn("current project: qa", self.ok("projects", "use", "qa"))
        shown = json.loads(self.ok("projects", "show"))
        self.assertEqual((shown["id"], shown["hosts"]), ("qa", r"example\.test"))
        self.assertEqual(open(os.path.join(self.state, "current-project")).read().strip(), "qa")
        for bad in ("Bad Name", "../x", "UPPER", "-x", "a" * 70):
            self.bad("projects", "use", bad)
            self.bad("projects", "new", bad)
        self.bad("projects", "use", "nosuchproject")
        self.assertIn("qa", self.bash("projects", "list"))                  # the bash edition sees the same state

    def test_project_resolution_flag_env_current(self):
        self.ok("projects", "new", "qa", "-Label", "QA", "-Hosts", r"example\.test")
        self.ok("projects", "use", "qa")
        self.assertEqual(json.loads(self.ok("projects", "show"))["id"], "qa")
        self.assertEqual(json.loads(self.ok("projects", "show", "-Project", "neo"))["id"], "neo")
        self.env["RIVIS_PROJECT"] = "neo"
        self.assertEqual(json.loads(self.ok("projects", "show"))["id"], "neo")
        self.assertEqual(json.loads(self.ok("projects", "show", "-Project", "default"))["id"], "default")

    def test_rules_list_on_off_show_rm_share_the_file_with_bash(self):
        self.bash("rules", "add", "r1", "match=/a", "action=respond", "body=x")
        self.bash("rules", "add", "r2", "match=/b", "action=block")
        out = self.ok("rules", "list")
        self.assertIn("r1", out)
        self.assertIn("r2", out)
        self.ok("rules", "off", "r1")
        self.assertFalse({r["name"]: r for r in self.cfg()["rules"]}["r1"]["enabled"])
        self.ok("rules", "on", "r1")
        self.assertTrue({r["name"]: r for r in self.cfg()["rules"]}["r1"]["enabled"])
        self.assertEqual(json.loads(self.ok("rules", "show", "r2"))["action"], "block")
        self.ok("rules", "rm", "r2")
        self.assertEqual([r["name"] for r in self.cfg()["rules"]], ["r1"])
        self.bad("rules", "on", "ghost")
        self.bad("rules", "rm", "ghost")
        self.assertIn("r1", self.bash("rules", "list"))            # (file modes are NTFS ACLs on Windows; not asserted here)

    def test_rules_rm_deletes_only_unshared_project_mock(self):
        self.ok("rules", "list")
        mocks = os.path.join(self.state, "projects", "default", "mocks")
        own = os.path.join(mocks, "own.json")
        shared = os.path.join(mocks, "shared.json")
        for path in (shared,):
            open(path, "w").write("{}")
        self.bash("rules", "add", "own", "match=/own", "action=map_local", "body={}")
        own = next(r["file"] for r in self.cfg()["rules"] if r["name"] == "own")
        self.bash("rules", "add", "shared", "match=/shared", "action=map_local", "file=" + shared)
        cfg = self.cfg()
        cfg["rules"].append({"name": "reader", "action": "respond", "match": "/read", "body_file": shared})
        with open(self.rules_file(), "w") as fh:
            json.dump(cfg, fh)
        self.ok("rules", "rm", "own")
        self.assertFalse(os.path.exists(own))
        self.ok("rules", "rm", "shared")
        self.assertTrue(os.path.exists(shared))

    def test_throttle_restores_active_project_scope_with_rules_override(self):
        self.env["RIVIS_RULES"] = os.path.join(self.home, "override", "rules.json")
        os.makedirs(os.path.dirname(self.env["RIVIS_RULES"]))
        self.ok("rules", "list", "-Project", "neo")
        self.ok("throttle", "lte", "match=/old", "-Project", "neo")
        self.ok("throttle", "off", "-Project", "neo")
        with open(self.env["RIVIS_RULES"]) as fh:
            cfg = json.load(fh)
        self.assertEqual(cfg["throttle_match"], "neo\\.sa")
        self.assertEqual(cfg["loss"], 0)

    def test_rules_test_explains_like_the_bash_cli(self):
        self.bash("rules", "add", "post-500", "match=/api/pay", "action=status", "status=500", "method=POST")
        out = self.ok("rules", "test", "https://api.example.test/api/pay", "POST")
        self.assertRegex(out, r"FIRES\s+post-500")
        out = self.ok("rules", "test", "https://api.example.test/api/pay", "-Method", "GET")
        self.assertIn("only for POST", out)
        self.bad("rules", "test", msg="usage: rules test URL")

    def test_nocache_parity_with_the_bash_cli(self):
        self.assertIn("No caching: off", self.ok("nocache"))
        self.assertIn("No caching: on", self.ok("nocache", "on"))
        self.assertIs(self.cfg()["no_cache"], True)
        self.assertIn("No caching: on", self.ok("nocache", "status"))
        self.assertIn("No caching: off", self.ok("nocache", "off"))
        self.assertIs(self.cfg()["no_cache"], False)
        self.bad("nocache", "maybe", msg="on | off | status")
        self.bad("nocache", "on", "extra", msg="on | off | status")
        self.assertIn("nocache on|off|status", self.ok("help"))

    def test_throttle_profiles_options_and_validation(self):
        for profile in ("off", "3g-urban", "lte-congested", "high-latency-vpn", "packet-loss-8", "lte", "3g", "edge", "slow", "150ms", "300ms/500kbps"):
            self.ok("throttle", profile)
            self.assertEqual(self.cfg()["throttle"], profile)
        self.ok("throttle", "lte", "match=/api", "loss=5")
        c = self.cfg()
        self.assertEqual((c["throttle_match"], c["loss"]), ("/api", 5))
        self.ok("throttle", "off")
        self.assertEqual(self.cfg()["throttle_match"], "")
        self.ok("throttle", "lte", "match=/stale")
        self.ok("throttle", "slow")
        self.assertEqual(self.cfg()["throttle_match"], "")
        self.ok("throttle", "manual", "latency_ms=200", "jitter_ms=10", "down_kbps=900", "up_kbps=300", "loss_pct=1", "response_delay_ms=50")
        self.assertEqual(self.cfg()["manual"]["latency_ms"], 200)
        self.assertIn("throttle: manual", self.ok("throttle"))
        self.bad("throttle", "warp9")
        self.bad("throttle", "lte", "bogus=1")
        self.bad("throttle", "lte", "match=(unclosed")
        self.bad("throttle", "lte", "loss=abc")

    def test_throttle_rejects_out_of_range_and_non_finite_numbers(self):
        """FOUND-BUGS B14 (same in the bash CLI)."""
        for arg in ("loss=150", "loss=-1", "loss=NaN"):
            self.bad("throttle", "lte", arg)

    def test_tls_commands(self):
        self.assertIn("tls mode: all", self.ok("tls", "list"))
        self.ok("tls", "allow", "add", "*.Example.test")
        self.ok("tls", "ignore", "add", "pay.example.test:8443")
        self.ok("tls", "mode", "ignore")
        t = self.cfg()["tls"]
        self.assertEqual((t["mode"], t["allow"], t["ignore"]), ("ignore", ["*.example.test"], ["pay.example.test:8443"]))
        self.ok("tls", "allow", "rm", "*.example.test")
        self.assertEqual(self.cfg()["tls"]["allow"], [])
        for bad in ("http://x.test", "a b", "a/b", "x.test:99999"):
            self.bad("tls", "allow", "add", bad)
        self.bad("tls", "mode", "sideways")
        self.assertIn("tls mode: ignore", self.bash("tls", "list"))

    def test_scripts_new_list_on_off_rm(self):
        self.ok("scripts", "new", "hello", "-Lang", "py", "-Match", "/api")
        self.ok("scripts", "new", "jsone", "-Lang", "js")
        path = os.path.join(self.state, "projects", "default", "scripts", "hello.py")
        self.assertTrue(os.path.isfile(path))
        names = {s["name"]: s for s in self.cfg()["scripts"]}
        self.assertEqual((names["hello"]["match"], names["hello"]["lang"], names["jsone"]["lang"]), ("/api", "py", "js"))
        out = self.ok("scripts", "list")
        self.assertIn("hello", out)
        self.ok("scripts", "off", "hello")
        self.assertFalse({s["name"]: s for s in self.cfg()["scripts"]}["hello"]["enabled"])
        self.ok("scripts", "on", "hello")
        self.ok("scripts", "rm", "hello")
        self.assertNotIn("hello", [s["name"] for s in self.cfg()["scripts"]])
        self.bad("scripts", "new", "x", "-Lang", "rb")
        self.bad("scripts", "new", "../x", "-Lang", "py")
        self.bad("scripts", "new", "jsone", "-Lang", "js")             # already exists
        self.assertIn("jsone", self.bash("scripts", "list"))

    def fake_proxy(self, active):
        """A stand-in for the proxy UI: serves the login page and /proxy/api/state for the project it 'runs'."""
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps({"active_project": active}).encode() if self.path.startswith("/proxy/api/state") else b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        self.env["RIVIS_WEB_PORT"] = str(port)
        os.makedirs(self.state, exist_ok=True)
        with open(os.path.join(self.state, "web-token-%d" % port), "w") as fh:
            fh.write("tok-0123456789")

    def test_running_project_mismatch_warns_without_failing(self):
        self.fake_proxy("neo")
        warn = "running proxy serves project 'neo', not 'default'"
        for args in (("rules", "list"), ("scripts", "list"), ("throttle",), ("nocache", "status"), ("tls", "list"), ("breakpoint", "list")):
            cp = self.ps(*args)
            self.assertEqual(cp.returncode, 0, (args, cp.stdout, cp.stderr))
            self.assertIn(warn, cp.stderr, args)
            self.assertIn("stop, then start", cp.stderr, args)
            self.assertNotIn(warn, cp.stdout, args)

    def test_running_project_match_is_silent(self):
        self.fake_proxy("default")
        for args in (("rules", "list"), ("throttle",), ("nocache", "status"), ("tls", "list")):
            cp = self.ps(*args)
            self.assertEqual(cp.returncode, 0, (args, cp.stdout, cp.stderr))
            self.assertNotIn("running proxy", cp.stdout + cp.stderr, args)

    def test_proxy_not_running_or_token_missing_is_silent(self):
        for args in (("rules", "list"), ("nocache", "status")):
            cp = self.ps(*args)                                   # no token file at all
            self.assertEqual(cp.returncode, 0, (args, cp.stdout, cp.stderr))
            self.assertNotIn("running proxy", cp.stdout + cp.stderr, args)
        os.makedirs(self.state, exist_ok=True)
        with open(os.path.join(self.state, "web-token"), "w") as fh:   # token present but nothing listening
            fh.write("tok-0123456789")
        cp = self.ps("rules", "list")
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertNotIn("running proxy", cp.stdout + cp.stderr)

    def test_compose_list_and_errors_offline(self):
        self.assertIn("no saved requests", self.ok("compose", "list"))
        cdir = os.path.join(self.state, "projects", "default", "composer")
        os.makedirs(cdir, mode=0o700)
        with open(os.path.join(cdir, "saved.json"), "w") as fh:
            json.dump({"method": "GET", "url": "https://h.test/"}, fh)
        self.assertIn("saved", self.ok("compose", "list"))
        self.bad("compose", "send", "saved")                           # no proxy running → clear error, not a stack trace
        self.bad("compose", "send", "nope")

    def test_cert_prints_fingerprint(self):
        out = self.ok("cert")
        self.assertIn("sha256:", out)
        self.assertRegex(out, r"android:\s+[0-9a-f]{8}\.0")

    def test_neo_mitm_shim_defaults_to_project_neo(self):
        out = self.ok("projects", "show", bin="neo-mitm.ps1")
        self.assertEqual(json.loads(out)["id"], "neo")

    @unittest.skipUnless(IS_WIN, WINDOWS_ONLY)
    def test_status_and_net_reset_dry_run(self):
        out = self.ok("status")
        self.assertRegex(out, r"windows system proxy: ")
        self.assertIn("not listening", out)
        out = self.ok("net-reset", "-DryRun")
        self.assertIn("user proxy:", out)
        self.assertIn("winhttp:", out)
        self.assertIn("dry run: nothing changed", out)

    @unittest.skip("Android emulator / adb are not part of the hermetic suite")
    def test_android_on_off(self):
        pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
