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
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness

sys.path.insert(0, os.path.join(harness.REPO, "addons"))
import system_trust  # noqa: E402


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
                                 out, extra], capture_output=True, text=True)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            roots, added = map(int, cp.stdout.split())
            self.assertGreater(roots, 50)
            self.assertGreaterEqual(added, 1)
            with open(out) as fh, open(extra) as ex:
                body = fh.read()
                self.assertIn(ex.read().strip(), body)
            self.assertEqual(oct(os.stat(out).st_mode & 0o777), "0o600")


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
        cls.other = cls.suite.upstream()                # a second server nobody trusts
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
