"""TLS allow/ignore lists change what is actually decrypted — proven by which certificate the client sees:
decrypted → forged by the Rivis CA; tunnelled → the upstream's own certificate."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import LiveCase, wait_for


class TlsLive(LiveCase):
    def decrypted(self):
        """True when a client that trusts ONLY the Rivis CA succeeds (the cert was forged by the proxy)."""
        r = self.fetch("/echo", tls=True)
        return r.rc == 0 and r.status == 200

    def tunnelled(self):
        """True when a client that trusts ONLY the upstream's cert succeeds (the proxy did not touch TLS)."""
        r = self.fetch("/echo", tls=True, cacert=self.up.cert)
        return r.rc == 0 and r.status == 200

    def apply(self, tls, expect_decrypted):
        self.reset_state(tls=tls)
        wait_for(lambda: self.decrypted() == expect_decrypted, 10, 0.3, "tls policy %r" % (tls,))

    def test_default_all_decrypts(self):
        self.assertTrue(self.decrypted())
        self.assertFalse(self.tunnelled())
        self.assertEqual(self.fetch("/echo", tls=True).json()["tls"], True)

    def test_ignore_list_tunnels_the_host(self):
        self.apply({"mode": "ignore", "ignore": ["127.0.0.1"]}, False)
        self.up.reset_hits()
        self.assertTrue(self.tunnelled())
        self.assertEqual(len(self.up.hits_for("/echo")), 1)
        self.assertEqual(self.up.hits[-1]["tls"], True)

    def test_ignore_list_with_other_hosts_still_decrypts_this_one(self):
        self.apply({"mode": "ignore", "ignore": ["*.example.test", "other.test"]}, True)

    def test_ignored_host_bypasses_rules_mocks_and_scripts(self):
        self.reset_state(rules=[self.rule("m", "respond", "/echo", status=299, body="mock")],
                         tls={"mode": "ignore", "ignore": ["127.0.0.1"]})
        wait_for(lambda: not self.decrypted(), 10, 0.3, "ignore")
        r = self.fetch("/echo", tls=True, cacert=self.up.cert)
        self.assertEqual((r.rc, r.status), (0, 200))            # the rule did not fire: the call is not intercepted at all
        self.assertNotEqual(r.text, "mock")
        self.reset_state(rules=[self.rule("m", "respond", "/echo", status=299, body="mock")], tls={"mode": "all"})
        wait_for(lambda: self.fetch("/echo", tls=True).status == 299, 10, 0.3, "decrypted again")

    def test_allow_mode_with_empty_list_decrypts_nothing(self):
        self.apply({"mode": "allow", "allow": []}, False)
        self.assertTrue(self.tunnelled())

    def test_allow_mode_decrypts_only_listed_hosts(self):
        self.apply({"mode": "allow", "allow": ["127.0.0.1"]}, True)
        self.apply({"mode": "allow", "allow": ["somewhere.else.test"]}, False)
        self.apply({"mode": "allow", "allow": ["127.0.0.*"]}, True)          # wildcard

    def test_port_specific_pattern(self):
        self.apply({"mode": "ignore", "ignore": ["127.0.0.1:%d" % self.up.https_port]}, False)
        self.apply({"mode": "ignore", "ignore": ["127.0.0.1:%d" % (self.up.https_port + 1)]}, True)

    def test_panel_tls_host_toggles_the_list_without_touching_other_hosts(self):
        self.reset_state(tls={"mode": "ignore", "ignore": ["keep.example.test"]})
        self.panel.ok("tls_host", {"host": "127.0.0.1", "decrypt": False})
        wait_for(lambda: not self.decrypted(), 10, 0.3, "tunnel via panel")
        self.assertEqual(sorted(self.panel.state()["tls"]["ignore"]), ["127.0.0.1", "keep.example.test"])
        self.panel.ok("tls_host", {"host": "127.0.0.1", "decrypt": True})
        wait_for(self.decrypted, 10, 0.3, "decrypt via panel")
        self.assertEqual(self.panel.state()["tls"]["ignore"], ["keep.example.test"])

    def test_cli_tls_commands_reach_the_running_proxy(self):
        env = dict(self.inst.env)
        for args in (["tls", "ignore", "add", "127.0.0.1"], ["tls", "mode", "ignore"]):
            cp = self.suite.run(["/bin/bash", harness.RIVIS] + args, home=self.inst.home, env=env)
            self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        wait_for(lambda: not self.decrypted(), 12, 0.3, "CLI ignore reaches proxy")
        cp = self.suite.run(["/bin/bash", harness.RIVIS, "tls", "mode", "all"], home=self.inst.home, env=env)
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        wait_for(self.decrypted, 12, 0.3, "CLI all reaches proxy")

    def test_invalid_tls_block_keeps_the_previous_policy(self):
        self.apply({"mode": "ignore", "ignore": ["127.0.0.1"]}, False)
        self.inst.write_cfg({"tls": {"mode": "bogus"}}, sync=False)
        import time
        time.sleep(2.5)
        self.assertFalse(self.decrypted())                      # previous (valid) policy still in force
        self.assertTrue(self.panel.state()["tls"]["error"])      # and the panel says why


import harness  # noqa: E402  (RIVIS path for the CLI test)

if __name__ == "__main__":
    unittest.main(verbosity=2)
