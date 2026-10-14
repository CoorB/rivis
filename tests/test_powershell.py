"""PowerShell edition (rivis.ps1, neo-mitm.ps1, install.ps1) under the portable pwsh on macOS: parse checks, and the commands
that do not need Windows (projects, rules, throttle, scripts, tls, compose, cert, help) against a fake HOME.
Registry / netstat / Android parts are skipped with a reason."""
import json
import os
import stat
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import Suite

PWSH = harness.PWSH
HAVE_PWSH = os.path.isfile(PWSH) and os.access(PWSH, os.X_OK)
NO_PWSH = "portable pwsh not found at %s" % PWSH
WINDOWS_ONLY = "needs the Windows registry (HKCU:) / netstat, which do not exist in pwsh on macOS"


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


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

    def bash(self, *args):
        cp = self.suite.rivis(*args, home=self.home, env=self.env)
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        return cp.stdout

    def rules_file(self, project="default"):
        return os.path.join(self.state, "projects", project, "rules.json")

    def cfg(self, project="default"):
        with open(self.rules_file(project)) as fh:
            return json.load(fh)

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

    def test_throttle_profiles_options_and_validation(self):
        for profile in ("off", "3g-urban", "lte-congested", "high-latency-vpn", "packet-loss-8", "lte", "3g", "edge", "slow", "150ms", "300ms/500kbps"):
            self.ok("throttle", profile)
            self.assertEqual(self.cfg()["throttle"], profile)
        self.ok("throttle", "lte", "match=/api", "loss=5")
        c = self.cfg()
        self.assertEqual((c["throttle_match"], c["loss"]), ("/api", 5))
        self.ok("throttle", "manual", "latency_ms=200", "jitter_ms=10", "down_kbps=900", "up_kbps=300", "loss_pct=1", "response_delay_ms=50")
        self.assertEqual(self.cfg()["manual"]["latency_ms"], 200)
        self.assertIn("throttle: manual", self.ok("throttle"))
        self.bad("throttle", "warp9")
        self.bad("throttle", "lte", "bogus=1")
        self.bad("throttle", "lte", "match=(unclosed")
        self.bad("throttle", "lte", "loss=abc")

    @unittest.expectedFailure
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

    @unittest.skip(WINDOWS_ONLY)
    def test_status_and_net_reset_dry_run(self):
        pass

    @unittest.skip("Android emulator / adb are not part of the hermetic suite")
    def test_android_on_off(self):
        pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
