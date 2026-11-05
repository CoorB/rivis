"""Upstream HTTPS is checked against what this Mac trusts, not only mitmproxy's bundled roots.

2026-10-16 night QA: on a network that inspects TLS (a corporate root pushed by IT/MDM, e.g. the bank's Sophos /
internal root), every HTTPS call through Rivis failed with "certificate verify failed" while Safari, curl and Proxyman
worked, because mitmproxy only knows certifi. The tests never change the keychain: a corporate root is stood in for
by RIVIS_EXTRA_TRUST (an explicit PEM, the documented escape hatch), and macOS's own trust verdict is checked on a
root it ships and on a certificate it has never seen."""
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness

sys.path.insert(0, os.path.join(harness.REPO, "addons"))
import system_trust  # noqa: E402
from upstream import _make_upstream_cert  # noqa: E402


class TrustedByThisMac(unittest.TestCase):
    def test_an_unknown_self_signed_root_is_not_trusted(self):
        # Apple's root store is taken as shipped; macOS's SSL verdict decides only for certificates added to the
        # System / user keychains (IT, MDM or the user marked them trusted). One it has never seen must not pass.
        with tempfile.TemporaryDirectory() as d:
            key, cert = os.path.join(d, "k.pem"), os.path.join(d, "c.pem")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                            "-days", "2", "-subj", "/CN=rivis-untrusted-test-root", "-addext",
                            "basicConstraints=critical,CA:TRUE"], check=True, capture_output=True)
            with open(cert) as fh:
                self.assertFalse(system_trust.trusted_for_ssl(fh.read().strip(), d))

    def test_the_bundle_has_the_macos_roots_and_the_explicit_extra(self):
        with tempfile.TemporaryDirectory() as d:
            extra = os.path.join(d, "corp.pem")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", os.path.join(d, "k"),
                            "-out", extra, "-days", "2", "-subj", "/CN=rivis-corp-test-root"], check=True, capture_output=True)
            out = os.path.join(d, "bundle.pem")
            cp = subprocess.run(["/usr/bin/python3", "-I", os.path.join(harness.REPO, "addons", "system_trust.py"),
                                 out, extra], capture_output=True, text=True, timeout=60)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            roots, added = map(int, cp.stdout.split())
            self.assertGreater(roots, 50)
            self.assertGreaterEqual(added, 1)
            with open(out) as fh, open(extra) as ex:
                body = fh.read()
                self.assertIn(ex.read().strip(), body)
            self.assertEqual(oct(os.stat(out).st_mode & 0o777), "0o600")

    def test_a_hung_security_command_cannot_stall_the_build(self):
        # /usr/bin/security waiting on a keychain or authorization dialog never returns. Without a short bound on
        # every call, `rivis start --verify-upstream` and this module's live build sit until the dialog is dismissed
        # (the full suite hung here for hours). A stuck binary must fail the build in seconds, not hang the runner.
        with tempfile.TemporaryDirectory() as d:
            fake = os.path.join(d, "security")
            with open(fake, "w") as fh:
                fh.write("#!/bin/sh\nexec sleep 120\n")
            os.chmod(fake, 0o755)
            out = os.path.join(d, "bundle.pem")
            with mock.patch.object(system_trust, "SECURITY", fake):
                t0 = time.time()
                rc = system_trust.main(["system_trust.py", out])
                elapsed = time.time() - t0
            self.assertEqual(rc, 1)
            self.assertFalse(os.path.exists(out))
            self.assertLess(elapsed, 15, "hung security blocked for %.1fs" % elapsed)


class RootStoreAsMacOSTrustsIt(unittest.TestCase):
    """Night QA lane C2: every certificate in SystemRootCertificates was trusted, including Apple's code-signing-only
    root, which macOS does not trust for SSL. Roots now follow the system trust settings and admin/user 'Never Trust'."""

    def test_roots_follow_system_settings_and_explicit_distrust(self):
        pems = {h: "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----" % h for h in ("AA", "BB", "CC", "DD")}
        listing = "".join("SHA-1 hash: %s\n%s\n" % (h, p) for h, p in pems.items())
        ssl_deny = [{"kSecTrustSettingsPolicyName": "sslServer", "kSecTrustSettingsResult": 3}]
        code_only = [{"kSecTrustSettingsPolicyName": "CodeSigning", "kSecTrustSettingsResult": 3}]
        domains = {"-s": {"AA": [], "BB": [], "CC": []},          # DD: not listed (like the code-signing root)
                   "-d": {"BB": ssl_deny}, "": {"CC": code_only}}
        fake = mock.Mock(return_value=mock.Mock(stdout=listing, returncode=0))
        with mock.patch.object(system_trust, "_security", fake), \
                mock.patch.object(system_trust, "_trust_settings", side_effect=lambda flag, wd: domains[flag]):
            got = system_trust.system_roots("/nonexistent")
        self.assertEqual(got, [pems["AA"], pems["CC"]])

    def test_unreadable_system_trust_settings_do_not_ship_every_root(self):
        # trust-settings-export -s failed: the old code kept every certificate in SystemRootCertificates
        # (including Apple's code-signing-only root) and build() still printed success counts. Without the
        # system list we cannot say which roots macOS trusts for SSL — refuse so the caller keeps mitmproxy's.
        pems = {("%040X" % i): "-----BEGIN CERTIFICATE-----\nR%d\n-----END CERTIFICATE-----" % i
                for i in range(25)}
        listing = "".join("SHA-1 hash: %s\n%s\n" % (h, p) for h, p in pems.items())
        fake = mock.Mock(return_value=mock.Mock(stdout=listing, returncode=0))
        with mock.patch.object(system_trust, "_security", fake), \
                mock.patch.object(system_trust, "_trust_settings", return_value=None):
            self.assertEqual(system_trust.system_roots("/nonexistent"), [])
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "bundle.pem")
            with mock.patch.object(system_trust, "_security", fake), \
                    mock.patch.object(system_trust, "_trust_settings", return_value=None), \
                    mock.patch.object(system_trust, "added_anchors", return_value=[]):
                self.assertIsNone(system_trust.build(out))
            self.assertFalse(os.path.exists(out))

    def test_build_reasserts_owner_only_on_the_output_directory(self):
        # makedirs(..., exist_ok=True) does not fix a directory that already exists as 0755. The trust bundle
        # parent must be re-chmod'd to 0700 so a looser mode from an earlier run does not stick.
        with tempfile.TemporaryDirectory() as d:
            parent = os.path.join(d, "nested")
            os.makedirs(parent, mode=0o755)
            os.chmod(parent, 0o755)
            out = os.path.join(parent, "bundle.pem")
            roots = ["-----BEGIN CERTIFICATE-----\nR%d\n-----END CERTIFICATE-----" % i for i in range(25)]
            with mock.patch.object(system_trust, "system_roots", return_value=roots), \
                    mock.patch.object(system_trust, "added_anchors", return_value=[]):
                self.assertEqual(system_trust.build(out), (25, 0))
            self.assertEqual(oct(os.stat(parent).st_mode & 0o777), "0o700")

    def test_build_does_not_write_through_a_shared_out_tmp(self):
        # Two `rivis start`s used out.tmp for the same path: one truncated while the other wrote, leaving a
        # mixed or empty trust bundle. Each build must use a private temp, then replace.
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "bundle.pem")
            opened = []
            real_open = os.open

            def spy(path, flags, mode=0o777):
                opened.append(os.path.abspath(path))
                return real_open(path, flags, mode)

            roots = ["-----BEGIN CERTIFICATE-----\nR%d\n-----END CERTIFICATE-----" % i for i in range(25)]
            with mock.patch.object(system_trust, "system_roots", return_value=roots), \
                    mock.patch.object(system_trust, "added_anchors", return_value=[]), \
                    mock.patch("os.open", spy):
                self.assertEqual(system_trust.build(out), (25, 0))
            self.assertTrue(os.path.isfile(out))
            self.assertNotIn(os.path.abspath(out + ".tmp"), opened,
                             "shared out.tmp is racy under concurrent builds")
            self.assertTrue(any(p.endswith(".tmp") for p in opened))

    def test_concurrent_builds_leave_a_complete_unmixed_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "bundle.pem")
            barrier = threading.Barrier(2, timeout=5)
            errors = []

            def roots(tag):
                return ["-----BEGIN CERTIFICATE-----\n%s%d\n-----END CERTIFICATE-----" % (tag, i)
                        for i in range(25)]

            original = system_trust.system_roots
            local = threading.local()

            def system_roots(_wd):
                barrier.wait()
                return roots(local.tag)

            def run(tag):
                local.tag = tag
                try:
                    system_trust.build(out)
                except Exception as exc:
                    errors.append(exc)

            # Patch once, here: mock.patch is not thread-safe. Two threads patching the same attribute could restore
            # each other's stand-in, leaving the barrier-waiting system_roots on the module, and the next test that
            # built a root store waited on that barrier for ever (the suite hung for hours in this module).
            # daemon: a stuck barrier must not keep the pytest process alive after join times out.
            threads = [threading.Thread(target=run, args=(tag,), daemon=True) for tag in ("AAA", "BBB")]
            with mock.patch.object(system_trust, "system_roots", system_roots), \
                    mock.patch.object(system_trust, "added_anchors", return_value=[]):
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(5.0)
            self.assertIs(system_trust.system_roots, original, "a stand-in system_roots leaked onto the module")
            self.assertEqual(errors, [])
            self.assertTrue(all(not t.is_alive() for t in threads))
            body = open(out).read()
            self.assertGreaterEqual(body.count("BEGIN CERTIFICATE"), 20)
            self.assertTrue(
                ("AAA0" in body and "BBB0" not in body) or ("BBB0" in body and "AAA0" not in body),
                "bundle mixed both writers: %r" % body[:200])


class UpstreamNotVerifiedByDefault(unittest.TestCase):
    """0.9.10, the owner's decision of 2026-10-25: a server certificate never blocks a call.

    Proxyman does not verify the upstream chain at all — its maintainers call that inherent to a capturing proxy —
    and the team hit refusals here that Proxyman had never shown them: non-prod hosts reached through /etc/hosts
    entries serve internal or long-expired certificates. Rivis now behaves the same way, and `--verify-upstream`
    (tested by CorporateRootTrusted below) puts the check back for anyone who wants it.
    """

    @classmethod
    def setUpClass(cls):
        cls.suite = harness.Suite.get()
        cls.untrusted = cls.suite.upstream()            # a self-signed server nothing trusts
        cls.inst = harness.Instance(cls.suite, "tlsdefault", start_args=()).start()   # no flags at all

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()

    def test_a_server_nothing_trusts_is_captured_instead_of_refused(self):
        r = self.inst.fetch("https://localhost:%d/json/small?dflt=1" % self.untrusted.https_port)
        self.assertEqual(r.status, 200, r.text[:300])
        self.assertIn("alice", r.text)                  # the real answer, not a Rivis error page
        paths = [f["request"]["path"] for f in self.inst.flows()]
        self.assertIn("/json/small?dflt=1", paths)      # and the call is in the list, decrypted

    def test_the_start_banner_says_certificates_are_not_verified(self):
        self.assertRegex(self.inst.log(), re.compile(r"not verified", re.I))


class CorporateRootTrusted(unittest.TestCase):
    """--verify-upstream: the upstream's certificate chains to a root only 'the Mac' trusts (RIVIS_EXTRA_TRUST)."""

    @classmethod
    def setUpClass(cls):
        cls.suite = harness.Suite.get()
        cls.up = cls.suite.upstream()                   # its self-signed cert stands in for the corporate root
        # Suite reuses one cert across upstreams; this case needs a second, untrusted identity.
        cls.other = cls.suite.upstream(cert_key=_make_upstream_cert(cls.suite.root))
        cls.inst = harness.Instance(cls.suite, cls.__name__.lower(), start_args=("--verify-upstream",),
                                    extra_env={"RIVIS_EXTRA_TRUST": cls.up.cert}).start()

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()

    def test_https_to_a_server_behind_the_corporate_root_works_without_insecure(self):
        r = self.inst.fetch("https://localhost:%d/json/small?ct=1" % self.up.https_port)
        self.assertEqual(r.status, 200, r.text[:200])

    def test_a_server_the_mac_does_not_trust_still_fails(self):
        r = self.inst.fetch("https://localhost:%d/json/small?ct=2" % self.other.https_port)
        self.assertEqual(r.status, 502, r.text[:200])
        self.assertRegex(r.text, re.compile("certificate", re.I))


if __name__ == "__main__":
    unittest.main()
