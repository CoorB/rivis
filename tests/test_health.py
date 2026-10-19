"""`rivis health` against a live instance: healthy when it serves, and it must not leave its own test call in the
tester's call list."""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import LiveCase


class Health(LiveCase):
    def health(self):
        env = self.suite.cli_env(self.inst.home, RIVIS_PORT=str(self.inst.proxy_port), RIVIS_WEB_PORT=str(self.inst.web_port))
        return self.suite.rivis("health", home=self.inst.home, env=env)

    def test_healthy_instance_and_no_trace_in_the_call_list(self):
        before = len(self.inst.flows())
        r = self.health()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("healthy", r.stdout)
        time.sleep(1.0)
        self.assertEqual(len(self.inst.flows()), before,
                         "R8D-01: the health check's own probe shows up in the tester's call list")


if __name__ == "__main__":
    unittest.main(verbosity=2)
