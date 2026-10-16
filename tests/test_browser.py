"""`rivis browser`: a separate Chrome/Edge window for web apps, pointed at the proxy and trusting only the Rivis CA.

The browser is found under ${RIVIS_BROWSER_APPS} (default /Applications), so these tests put a fake
"Google Chrome.app" there: a shim that logs its argv, or one that runs the real Chrome headless (skipped when
Chrome is not installed). Nothing here touches the user's browser, profile, keychain or system proxy.
"""
import os
import shlex
import sys
import shutil
import subprocess
import time
import unittest

from unittest import mock

import harness
from harness import Instance, Suite

sys.path.insert(0, os.path.join(harness.REPO, "addons"))
import devices  # noqa: E402

REAL_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def fake_app(root, name, script):
    path = os.path.join(root, "%s.app" % name, "Contents", "MacOS", name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(script)
    os.chmod(path, 0o755)
    return path


class Browser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()
        cls.up = cls.suite.upstream()
        cls.apps = os.path.join(cls.suite.root, "apps-browser")      # where this Rivis (and the panel's CLI) look
        # inst: started with the localhost allowance (harness default); plain: exactly as `rivis start` ships (review R8)
        cls.inst = Instance(cls.suite, "browser", extra_env={"RIVIS_BROWSER_APPS": cls.apps}).start()
        cls.plain = Instance(cls.suite, "browser-plain", extra_env={"RIVIS_BROWSER_APPS": cls.apps}, allow_private=False).start()

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()
        cls.plain.stop()

    def setUp(self):
        shutil.rmtree(self.apps, ignore_errors=True)
        os.makedirs(self.apps)
        self.argv_log = os.path.join(self.apps, "argv.log")
        self.env = dict(self.inst.env)
        for name in ("osascript-running", "osascript-out", "osascript-fail", "osascript.log"):
            try:
                os.remove(os.path.join(self.suite.shimlog, name))
            except FileNotFoundError:
                pass

    def front_tab(self, running, out="", fail=None):
        """What the osascript stand-in answers: the running browsers, and the front tab's URL (or an error)."""
        with open(os.path.join(self.suite.shimlog, "osascript-running"), "w") as fh:
            fh.write("".join(app + "\n" for app in running))
        with open(os.path.join(self.suite.shimlog, "osascript-out"), "w") as fh:
            fh.write(out + "\n")
        if fail:
            with open(os.path.join(self.suite.shimlog, "osascript-fail"), "w") as fh:
                fh.write(fail + "\n")

    def cli(self, *args, env=None, inst=None):
        inst = inst or self.inst
        return self.suite.run(["/bin/bash", harness.RIVIS, "browser"] + list(args), home=inst.home,
                              env=env or dict(inst.env), timeout=60)

    def logging_app(self, name="Google Chrome"):
        return fake_app(self.apps, name, '#!/bin/sh\nfor a in "$@"; do printf "%%s\\n" "$a"; done > %s\n'
                        % shlex.quote(self.argv_log))

    def logged_argv(self):
        harness.wait_for(lambda: os.path.exists(self.argv_log) and open(self.argv_log).read().strip(), 10,
                         desc="the browser to be started")
        return open(self.argv_log).read().splitlines()

    def spki(self):
        pem = os.path.join(self.inst.env["RIVIS_CONFDIR"], "mitmproxy-ca-cert.pem")
        pub = subprocess.run(["openssl", "x509", "-in", pem, "-pubkey", "-noout"], capture_output=True, check=True).stdout
        der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"], input=pub, capture_output=True, check=True).stdout
        return subprocess.run("openssl dgst -sha256 -binary | base64", shell=True, input=der, capture_output=True,
                              check=True).stdout.decode().strip()

    def test_opens_a_separate_profile_pointed_at_this_proxy_and_pinned_to_this_ca(self):
        self.logging_app()
        r = self.cli("example.test/login")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        argv = self.logged_argv()
        profile = os.path.join(self.inst.home, ".rivis", "browser", "chrome")
        self.assertIn("--user-data-dir=" + profile, argv)
        self.assertEqual(os.stat(profile).st_mode & 0o777, 0o700)
        self.assertIn("--proxy-server=127.0.0.1:%d" % self.inst.proxy_port, argv)
        self.assertIn("--ignore-certificate-errors-spki-list=" + self.spki(), argv)
        self.assertIn("--use-mock-keychain", argv)        # a fresh profile must not ask for the login keychain
        bypass = [a for a in argv if a.startswith("--proxy-bypass-list=")]
        self.assertEqual(bypass, ["--proxy-bypass-list=<-loopback>;127.0.0.1:%d;localhost:%d"
                                  % (self.inst.web_port, self.inst.web_port)])   # localhost apps captured, own UI not
        self.assertEqual(argv[-1], "https://example.test/login")
        self.assertIn("not touched", r.stdout)

    def test_a_default_rivis_leaves_localhost_direct_and_says_how_to_capture_it(self):
        """Review R8: `rivis start` refuses private destinations, so routing localhost through it gave the app a 403."""
        self.logging_app()
        r = self.cli("http://localhost:3000/", inst=self.plain)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        argv = self.logged_argv()
        self.assertIn("--proxy-bypass-list=127.0.0.1:%d;localhost:%d" % (self.plain.web_port, self.plain.web_port), argv)
        self.assertIn("opens directly", r.stdout)
        self.assertIn("--allow-private-hosts '^(localhost|127\\.0\\.0\\.1)$'", r.stdout)
        os.remove(self.argv_log)
        r = self.cli("http://localhost:3000/")                       # this Rivis allows localhost: captured, no note
        self.assertIn("--proxy-bypass-list=<-loopback>;", "\n".join(self.logged_argv()))
        self.assertNotIn("opens directly", r.stdout)

    def test_current_opens_the_page_of_the_front_tab(self):
        self.logging_app()
        self.front_tab(["Microsoft Edge"], "https://app.example.test/orders?id=7")
        r = self.cli("--current")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.logged_argv()[-1], "https://app.example.test/orders?id=7")
        self.assertIn("front tab of Microsoft Edge", r.stdout)
        script = self.suite.shim_log("osascript.log")
        self.assertIn('tell application "Microsoft Edge" to get URL of active tab of front window', script)
        self.assertNotIn("Google Chrome\" to get", script)            # only the running browser is asked
        os.remove(self.argv_log)
        self.front_tab(["Safari"], "https://safari.example.test/")
        self.assertEqual(self.cli("--current").returncode, 0)
        self.assertEqual(self.logged_argv()[-1], "https://safari.example.test/")
        self.assertIn('tell application "Safari" to get URL of front document', self.suite.shim_log("osascript.log"))

    def test_current_refusals_explain_what_to_do(self):
        self.logging_app()
        for running, out, fail, msg in (
                (["Google Chrome"], "chrome://newtab/", None, "is not a web page (chrome://newtab/)"),
                (["Google Chrome"], "", "execution error: Not authorized to send Apple events to Google Chrome. (-1743)",
                 "Privacy & Security → Automation"),
                (["Google Chrome"], "", "execution error: Can’t get window 1. Invalid index. (-1719)", "has no open window"),
                ([], "", None, "needs Chrome, Edge")):
            self.front_tab(running, out, fail)
            r = self.cli("--current")
            self.assertNotEqual(r.returncode, 0, msg)
            self.assertIn(msg, r.stderr)
            try:
                os.remove(os.path.join(self.suite.shimlog, "osascript-fail"))
            except FileNotFoundError:
                pass
        self.assertIn("not both", self.cli("--current", "https://a.test/").stderr)
        time.sleep(0.3)
        self.assertFalse(os.path.exists(self.argv_log), "a refused command started the browser")

    def test_python_and_cli_find_the_same_browsers(self):
        """The panel lists browsers without starting a process (review R1); it must agree with `rivis browser --list`."""
        self.logging_app("Brave Browser")
        self.logging_app("Microsoft Edge")
        with mock.patch.dict(os.environ, {"RIVIS_BROWSER_APPS": self.apps}):
            self.assertEqual([(b["id"], b["name"]) for b in devices.browsers()], [("edge", "Microsoft Edge"), ("brave", "Brave Browser")])
        self.assertEqual(self.cli("--list").stdout, "edge\tMicrosoft Edge\nbrave\tBrave Browser\n")

    def test_fresh_profile_is_temporary_and_edge_can_be_chosen(self):
        self.logging_app("Microsoft Edge")
        r = self.cli("--edge", "--fresh", "http://localhost:3000/")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        argv = self.logged_argv()
        profile = [a.split("=", 1)[1] for a in argv if a.startswith("--user-data-dir=")][0]
        self.assertNotIn(os.path.join(".rivis", "browser"), profile)
        self.assertTrue(os.path.basename(profile).startswith("rivis-browser."), profile)
        self.assertEqual(argv[-1], "http://localhost:3000/")

    def test_list_shows_only_installed_browsers(self):
        self.logging_app("Microsoft Edge")
        r = self.cli("--list")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, "edge\tMicrosoft Edge\n")

    def test_refusals_start_nothing(self):
        self.logging_app()
        for args, msg in ((("ftp://x",), "not an http(s) URL"), (("--browser", "opera"), "unknown browser"),
                          (("--edge",), "edge is not installed"), (("--frob",), "unknown option"),
                          (("a.test", "b.test"), "only one URL"), (("javascript:alert(1)",), "not an http(s) URL"),
                          (("file:///etc/passwd",), "not an http(s) URL"), (("--", "--user-data-dir=/x"), "unknown option")):
            r = self.cli(*args)
            self.assertNotEqual(r.returncode, 0, args)
            self.assertIn(msg, r.stderr, args)
        empty = dict(self.env, RIVIS_BROWSER_APPS=os.path.join(self.apps, "none"))
        self.assertIn("no Chrome, Edge", self.cli(env=empty).stderr)
        time.sleep(0.3)
        self.assertFalse(os.path.exists(self.argv_log), "a refused command started the browser")

    def test_refuses_when_this_rivis_is_not_the_one_listening(self):
        self.logging_app()
        other = self.suite.new_home("browser-other")      # same ports, another HOME: that mitmweb is not ours
        env = dict(self.suite.cli_env(other), RIVIS_BROWSER_APPS=self.apps,
                   RIVIS_PORT=str(self.inst.proxy_port), RIVIS_WEB_PORT=str(self.inst.web_port))
        r = self.suite.run(["/bin/bash", harness.RIVIS, "browser"], home=other, env=env, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not by this Rivis", r.stderr)
        env["RIVIS_PORT"] = str(harness.free_port())
        r = self.suite.run(["/bin/bash", harness.RIVIS, "browser"], home=other, env=env, timeout=60)
        self.assertIn("not running", r.stderr)
        self.assertFalse(os.path.exists(self.argv_log))

    def test_panel_lists_browsers_and_opens_one_through_the_cli(self):
        """Tools → Devices → Web browser: the same CLI command, for this proxy's port, URL never read as an option."""
        self.logging_app()
        st = self.inst.panel.ok("devices", {})
        self.assertEqual(st["browsers"], [{"id": "chrome", "name": "Google Chrome"}])
        self.inst.panel.ok("browser_open", {"browser": "chrome", "url": "https://app.example.test/"})
        job = self.browser_job()
        self.assertEqual(job["rc"], 0, job)
        self.assertIn("not touched", "\n".join(job["lines"]))
        argv = self.logged_argv()
        self.assertIn("--proxy-server=127.0.0.1:%d" % self.inst.proxy_port, argv)
        self.assertEqual(argv[-1], "https://app.example.test/")
        os.remove(self.argv_log)
        for body, msg in (({"browser": "opera"}, "browser must be"), ({"browser": "chrome", "url": "--user-data-dir=/x"}, "not a URL"),
                          ({"browser": "chrome", "url": "a b"}, "not a URL")):
            code, doc, raw = self.inst.panel.post("browser_open", body)
            self.assertNotEqual(code, 200, body)
            self.assertIn(msg, str(raw), body)
        for body, msg in (({"browser": "edge"}, "edge is not installed"),            # the CLI refuses: shown in the tab
                          ({"browser": "chrome", "url": "javascript:alert(1)"}, "not an http(s) URL")):
            self.inst.panel.ok("browser_open", body)
            job = self.browser_job()
            self.assertNotEqual(job["rc"], 0, body)
            self.assertIn(msg, "\n".join(job["lines"]), body)
        time.sleep(0.3)
        self.assertFalse(os.path.exists(self.argv_log), "a refused request started the browser")

    def test_opening_from_the_panel_never_blocks_the_proxy(self):
        """Review R1: the panel ran the CLI on mitmproxy's event loop, so capture stopped while a browser started."""
        started = os.path.join(self.apps, "started")
        fake_app(self.apps, "Google Chrome", "#!/bin/sh\ntouch %s\nsleep 4\n" % shlex.quote(started))
        self.inst.panel.ok("browser_open", {"browser": "chrome"})    # the CLI also asks this proxy for its options
        t = time.time()
        r = self.inst.fetch(self.up.url("/echo?while-browser-starts=1"))
        self.assertEqual(r.status, 200)
        self.assertLess(time.time() - t, 2.0, "a call through the proxy waited for the browser to start")
        self.assertEqual(self.browser_job(timeout=30)["rc"], 0)
        harness.wait_for(lambda: os.path.exists(started), 10, 0.1, "the fake browser to start")   # not into the next test
        self.kill_test_browsers()

    def browser_job(self, timeout=20):
        return harness.wait_for(lambda: (lambda j: j if j and not j["running"] else None)(self.inst.panel.ok("devices", {})["browser_job"]),
                                timeout, 0.2, "the browser job to finish")

    def ps(self, *args, inst=None):
        inst = inst or self.inst
        return self.suite.run([harness.PWSH, "-NoProfile", "-NonInteractive", "-File", os.path.join(harness.REPO, "rivis.ps1"),
                               "browser"] + list(args), home=inst.home, env=dict(inst.env), timeout=120)

    @unittest.skipUnless(os.access(harness.PWSH, os.X_OK), "portable pwsh not found")
    def test_powershell_edition_passes_the_same_flags_and_pin(self):
        """rivis.ps1 builds the SPKI pin by hand (Windows PowerShell 5.1 cannot export it): it must equal openssl's."""
        self.logging_app()
        r = self.ps("app.example.test/a b", "-Browser", "chrome")
        self.assertNotEqual(r.returncode, 0)                          # a space: not one URL
        r = self.ps("app.example.test/x", "-Browser", "chrome")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        argv = self.logged_argv()
        self.assertIn("--ignore-certificate-errors-spki-list=" + self.spki(), argv)
        self.assertIn("--user-data-dir=" + os.path.join(self.inst.home, ".rivis", "browser", "chrome"), argv)
        self.assertIn("--proxy-server=127.0.0.1:%d" % self.inst.proxy_port, argv)
        self.assertIn("--proxy-bypass-list=<-loopback>;127.0.0.1:%d;localhost:%d" % (self.inst.web_port, self.inst.web_port), argv)
        self.assertIn("--use-mock-keychain", argv)
        self.assertEqual(argv[-1], "https://app.example.test/x")
        os.remove(self.argv_log)
        for args, msg in ((("javascript:alert(1)",), "not an http(s) URL"), (("a.test", "b.test"), "unexpected argument"),
                          (("-Browser", "opera"), "opera"), (("-Browser", "edge"), "edge is not installed")):
            r = self.ps(*args)
            self.assertNotEqual(r.returncode, 0, args)
            self.assertIn(msg, r.stdout + r.stderr, args)
        r = self.ps("-List")
        self.assertEqual(r.stdout.strip(), "chrome\tGoogle Chrome")
        self.assertIn("not available on Windows", self.ps("-Current").stdout)
        r = self.ps("http://localhost:3000/", inst=self.plain)       # review R8, same as bash
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("--proxy-bypass-list=127.0.0.1:%d;localhost:%d" % (self.plain.web_port, self.plain.web_port), self.logged_argv())
        self.assertIn("opens directly", r.stdout)
        os.remove(self.argv_log)
        time.sleep(0.3)
        self.assertFalse(os.path.exists(self.argv_log), "a refused command started the browser")

    @unittest.skipUnless(os.path.exists(REAL_CHROME), "Google Chrome is not installed")
    def test_real_chrome_traffic_is_captured_decrypted(self):
        """The real thing: headless Chrome with exactly the flags the CLI passes, HTTPS to the suite upstream."""
        dom = os.path.join(self.apps, "dom.html")
        fake_app(self.apps, "Google Chrome", '#!/bin/sh\nexec %s --headless=new --disable-gpu --dump-dom "$@" > %s 2>/dev/null\n'
                 % (shlex.quote(REAL_CHROME), shlex.quote(dom)))
        marker = "/echo?web-app=%d" % time.time_ns()
        try:
            r = self.cli("--fresh", self.up.url(marker, tls=True))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            flows = harness.wait_for(lambda: [f for f in self.inst.panel.flows() if f["request"]["path"] == marker
                                              and f.get("response")], 60, 0.5, "Chrome's call in the call list")
            f = flows[0]
            self.assertEqual(f["request"]["scheme"], "https")      # decrypted, not a CONNECT tunnel
            self.assertEqual(f["response"]["status_code"], 200)
            self.assertTrue(self.up.hits_for(marker), "the upstream was not reached")
        finally:
            self.kill_test_browsers()

    def kill_test_browsers(self):
        # only processes under this test's own temp dirs (never a browser the user opened)
        for path in (self.inst.env["TMPDIR"], self.plain.env["TMPDIR"], self.apps):   # all under the suite's rivis-t-* root
            subprocess.run(["pkill", "-f", path], capture_output=True)

    @unittest.skipUnless(os.path.exists(REAL_CHROME), "Google Chrome is not installed")
    def test_real_chrome_with_a_default_rivis_still_loads_localhost(self):
        """Review R8, the real thing: a default Rivis answered a localhost web app with its private-address 403."""
        dom = os.path.join(self.apps, "dom.html")
        fake_app(self.apps, "Google Chrome", '#!/bin/sh\nexec %s --headless=new --disable-gpu --dump-dom "$@" > %s 2>/dev/null\n'
                 % (shlex.quote(REAL_CHROME), shlex.quote(dom)))
        marker = "/echo?local-app=%d" % time.time_ns()
        try:
            r = self.cli("--fresh", self.up.url(marker), inst=self.plain)    # http://127.0.0.1:<port>/…
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            harness.wait_for(lambda: self.up.hits_for(marker), 60, 0.5, "the local app reached by Chrome")
            harness.wait_for(lambda: os.path.exists(dom) and "local-app" in open(dom).read(), 30, 0.5, "the page drawn")
            self.assertNotIn("blocked by Rivis", open(dom).read())
            self.assertFalse([f for f in self.plain.panel.flows() if f["request"]["path"] == marker])
        finally:
            self.kill_test_browsers()


if __name__ == "__main__":
    unittest.main(verbosity=2)
