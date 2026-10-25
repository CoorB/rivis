"""Pilot 2026-10-21: "I can't log in to the app while the tool is running". Rivis captures every simulator from the
start, but one that has not been set up refuses the Rivis certificate: every HTTPS call failed, the app showed
"Network error" and the call list showed nothing. Now a refused host passes through undecrypted (the app keeps working)
and the panel state names it, until the device is set up or "Decrypt again" is chosen.

  bash tests/run.sh --fast -k test_untrusted_client_0910
"""
import unittest

from harness import LiveCase, wait_for


class UntrustedClient(LiveCase):
    def url(self, path):
        return "https://localhost:%d%s" % (self.up.https_port, path)   # a name: clients send no SNI for an IP address

    def untrusted(self):
        return [h["host"] for h in self.panel.state().get("untrusted") or []]

    def setUp(self):
        super().setUp()
        self.panel.ok("untrusted_retry", {})

    def test_a_refused_host_passes_through_and_the_panel_names_it(self):
        first = self.inst.fetch(self.url("/json/small?untrusted=1"), cacert=self.up.cert)
        self.assertNotEqual(first.rc, 0, "the client refuses the Rivis certificate")
        wait_for(lambda: "localhost" in self.untrusted(), 5, 0.2, "the refused host listed in the panel state")
        second = self.inst.fetch(self.url("/json/small?untrusted=2"), cacert=self.up.cert)
        self.assertEqual((second.rc, second.status), (0, 200), "the app works again: its HTTPS passes through")
        self.assertTrue(self.up.hits_for("/json/small?untrusted=2"), "the call reached the server")
        self.assertFalse([f for f in self.inst.flows() if "untrusted=2" in f["request"]["path"]],
                         "a passed-through call is not decrypted, so it is not listed")

    def test_decrypt_again_and_a_trusting_client_are_still_decrypted(self):
        self.inst.fetch(self.url("/json/small?again=1"), cacert=self.up.cert)
        wait_for(lambda: "localhost" in self.untrusted(), 5, 0.2, "listed")
        ok = self.fetch("/json/small?trusting=1", tls=True)           # 127.0.0.1, trusts the Rivis CA: unaffected
        self.assertEqual(ok.status, 200)
        self.assertTrue([f for f in self.inst.flows() if "trusting=1" in f["request"]["path"]])
        self.panel.ok("untrusted_retry", {})
        self.assertEqual(self.untrusted(), [])
        again = self.inst.fetch(self.url("/json/small?again=2"))     # now trusts the Rivis CA: decrypted and listed
        self.assertEqual(again.status, 200)
        wait_for(lambda: [f for f in self.inst.flows() if "again=2" in f["request"]["path"]], 5, 0.2, "decrypted again")


if __name__ == "__main__":
    unittest.main()
