"""Rules tab, in a real browser: hit counts per rule, the "ON but never matched" warning, and
"Test against the selected call" explaining why a rule does or does not fire."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase, shot   # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class RuleHitsUi(UiBase):
    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def rules_tab(self):
        if not self.P("#drawer.open").count():
            self.P("#fab").click()
        self.P("button[data-t=rules]").click()
        self.page.wait_for_timeout(300)

    def test_hits_and_never_matched_warning_show_on_each_rule(self):
        self.reset_state(rules=[self.rule("force-503", "status", "/echo", status=503),
                                self.rule("typo", "status", "/ehco", status=500)])
        for _ in range(11):
            self.fetch("/echo")
        self.open()
        self.rules_tab()
        wait_for(lambda: "matched 1" in self.panel_text(), 10, 0.3, "hit count shown")
        text = self.panel_text()
        self.assertRegex(text, r"matched 1\d calls")
        self.assertIn("none of the", text)
        shot(self.page, "rule-hits")
        self.assertEqual(self.errors, [])

    def test_test_against_the_selected_call_explains_each_rule(self):
        self.reset_state(rules=[self.rule("post-only", "status", "/echo", status=500, method="POST"),
                                self.rule("slow", "delay", "/echo", ms=1)])
        self.open()
        row = self.page.locator(".flow-table tbody tr", has_text="/echo").first
        wait_for(lambda: row.count() > 0, 10, 0.2, "echo row")
        row.click()
        self.rules_tab()
        self.P("#ruletest").click()
        wait_for(lambda: "only for POST" in self.panel_text(), 10, 0.2, "explanation")
        text = self.panel_text()
        self.assertIn("slow fires", text)
        shot(self.page, "rule-test")
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
