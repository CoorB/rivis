"""W5 flow retention: bounded store, oldest-first trim, protected selected/paused calls, restart safety."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Background, Instance, LiveCase, Suite, wait_for


class Retention(LiveCase):
    INSTANCE_KW = {"extra_env": {"RIVIS_MAX_FLOWS": "25"}}

    def fill(self, n, stem="fill"):
        for i in range(n):
            self.fetch("/json/small?%s=%d" % (stem, i))
        return wait_for(lambda: (lambda f: f if len(f) <= 25 else None)(self.inst.flows()),
                        10, 0.1, "flow store trimmed to 25")

    def test_oldest_completed_calls_are_dropped_and_status_reports_the_limit(self):
        first = self.fetch("/echo?oldest=1")
        self.assertEqual(first.status, 200)
        oldest = self.inst.flow_for("oldest=1")["id"]
        flows = self.fill(35)
        self.assertEqual(len(flows), 25)
        self.assertNotIn(oldest, {f["id"] for f in flows})
        state = self.panel.state()
        self.assertEqual(state["retention"]["limit"], 25)
        self.assertGreaterEqual(state["retention"]["trimmed"], 11)

    def test_selected_call_is_never_trimmed(self):
        self.fetch("/echo?selected=1")
        selected = self.inst.flow_for("selected=1")["id"]
        self.panel.ok("flow_selected", {"id": selected})
        flows = self.fill(35, "selected-fill")
        self.assertIn(selected, {f["id"] for f in flows})
        self.panel.ok("flow_selected", {"id": None})

    def test_paused_call_is_never_trimmed(self):
        self.reset_state(breakpoints=[{"name": "hold", "match": r"/echo\?paused", "request": True,
                                       "response": False, "enabled": True}])
        call = Background(self.fetch, "/echo?paused=1", timeout=20)
        paused = wait_for(lambda: self.panel.state()["paused"], 10, 0.1, "paused flow")[0]
        flows = self.fill(35, "paused-fill")
        self.assertIn(paused["id"], {f["id"] for f in flows})
        self.panel.ok("paused_abort", {"id": paused["id"]})
        self.assertNotEqual(call.result().rc, 0)


class RestartSafety(unittest.TestCase):
    def test_restart_with_the_same_state_dir_is_clean_and_keeps_the_configured_cap(self):
        suite = Suite.get()
        up = suite.upstream()
        first = Instance(suite, "retention-restart-a", extra_env={"RIVIS_MAX_FLOWS": "10"}).start()
        home = first.home
        try:
            for i in range(18):
                first.fetch(up.url("/json/small?r=%d" % i))
            wait_for(lambda: len(first.flows()) <= 10, 10, 0.1, "first instance trimmed")
        finally:
            first.stop()
        second = Instance(suite, "retention-restart-b", extra_env={"RIVIS_MAX_FLOWS": "10"})
        second.home = home
        try:
            second.start()
            self.assertEqual(second.panel.state()["retention"]["limit"], 10)
            self.assertEqual(second.fetch(up.url("/json/small?after-restart=1")).status, 200)
            self.assertLessEqual(len(second.flows()), 10)
        finally:
            second.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
