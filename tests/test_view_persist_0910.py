"""Pilot 2026-10-21: "the project-only view also reset to all traffic after a restart". The choice made in the panel is
kept per project and applied again at the next start; `rivis start --all` / `--project-only` still decide for that start.

  bash tests/run.sh --fast -k test_view_persist_0910
"""
import unittest

from harness import Instance, Suite


class ViewSurvivesRestart(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()
        cls.inst = Instance(cls.suite, "viewpersist", project="neo").start()

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()

    def restart(self, *extra):
        self.inst.stop()
        self.inst.start_args = [a for a in self.inst.start_args if a != "--all"] + list(extra)
        self.inst.start()
        return self.inst.panel.state()

    def view_filter(self):
        return self.inst.panel.option("view_filter")

    def test_project_only_survives_a_restart_and_all_traffic_does_too(self):
        self.inst.panel.ok("view", {"project": "neo", "project_only": True})
        self.assertTrue(self.inst.panel.state()["project_only"])
        state = self.restart()
        self.assertTrue(state["project_only"], "the project-only view came back after the restart")
        self.assertIn("~d", self.view_filter())
        self.inst.panel.ok("view", {"project": "neo", "project_only": False})
        state = self.restart()
        self.assertFalse(state["project_only"], "All traffic is remembered as well")
        self.assertEqual(self.view_filter(), "~http")

    def test_start_all_still_shows_everything(self):
        self.inst.panel.ok("view", {"project": "neo", "project_only": True})
        state = self.restart("--all")
        self.assertFalse(state["project_only"], "--all asked for everything at this start")
        self.assertFalse(self.view_filter(), "no view filter: every call")
        self.restart()
        self.inst.panel.ok("view", {"project": "neo", "project_only": False})


if __name__ == "__main__":
    unittest.main()
