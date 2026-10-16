"""`rivis browser`: a separate Chrome/Edge window for web apps, pointed at the proxy and trusting only the Rivis CA.

The browser is found under ${RIVIS_BROWSER_APPS} (default /Applications), so these tests put a fake
"Google Chrome.app" there: a shim that logs its argv, or one that runs the real Chrome headless (skipped when
Chrome is not installed). Nothing here touches the user's browser, profile, keychain or system proxy.
"""
import os
import shlex
import shutil
import subprocess
import time
import unittest

import harness
from harness import Instance, Suite

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
        cls.inst = Instance(cls.suite, "browser", extra_env={"RIVIS_BROWSER_APPS": cls.apps}).start()

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()

    def setUp(self):
        shutil.rmtree(self.apps, ignore_errors=True)
        os.makedirs(self.apps)
        self.argv_log = os.path.join(self.apps, "argv.log")
        self.env = dict(self.inst.env)

    def cli(self, *args, env=None):
        return self.suite.run(["/bin/bash", harness.RIVIS, "browser"] + list(args), home=self.inst.home,
                              env=env or self.env, timeout=60)

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
        doc = self.inst.panel.ok("browser_open", {"browser": "chrome", "url": "https://app.example.test/"})
        self.assertIn("not touched", doc["output"])
        argv = self.logged_argv()
        self.assertIn("--proxy-server=127.0.0.1:%d" % self.inst.proxy_port, argv)
        self.assertEqual(argv[-1], "https://app.example.test/")
        os.remove(self.argv_log)
        for body, msg in (({"browser": "opera"}, "browser must be"), ({"browser": "chrome", "url": "--user-data-dir=/x"}, "not a URL"),
                          ({"browser": "chrome", "url": "a b"}, "not a URL"), ({"browser": "edge"}, "edge is not installed"),
                          ({"browser": "chrome", "url": "javascript:alert(1)"}, "not an http(s) URL")):
            code, doc, raw = self.inst.panel.post("browser_open", body)
            self.assertNotEqual(code, 200, body)
            self.assertIn(msg, str(raw), body)
        time.sleep(0.3)
        self.assertFalse(os.path.exists(self.argv_log), "a refused request started the browser")

    def ps(self, *args):
        return self.suite.run([harness.PWSH, "-NoProfile", "-NonInteractive", "-File", os.path.join(harness.REPO, "rivis.ps1"),
                               "browser"] + list(args), home=self.inst.home, env=self.env, timeout=120)

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
            # only processes under this test's own temp dirs (never a browser the user opened)
            for path in (self.inst.env["TMPDIR"], self.apps):   # both under the suite's rivis-t-* root
                subprocess.run(["pkill", "-f", path], capture_output=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
