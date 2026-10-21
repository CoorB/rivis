"""0.9.9 review batch B in a real browser: M1 (no call-list download while the Tools drawer is closed or the page is
hidden, at most one per poll when open) and m10 (leaving a new Map Local through another Tools tab discards it)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class ReviewBUi(UiBase):
    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def watch(self):
        self.polls, self.lists = [], []
        self.page.on("request", lambda r: self.lists.append(r.url) if r.url.split("?")[0].endswith(("/flows", "/proxy/api/flows_since")) else
                     self.polls.append(r.url) if r.url.split("?")[0].endswith("/proxy/api/state") else None)

    def window(self, ms):
        a, b = len(self.lists), len(self.polls)
        self.page.wait_for_timeout(ms)
        return len(self.lists) - a, len(self.polls) - b

    def test_M1_call_list_is_not_downloaded_while_closed_or_hidden_and_once_per_poll_when_open(self):
        self.open()
        self.watch()
        self.page.wait_for_timeout(1500)
        lists, polls = self.window(5000)
        self.assertGreaterEqual(polls, 3, "the panel is not polling")
        self.assertEqual(lists, 0, "call list fetched with the Tools drawer closed")
        self.page.evaluate("Object.defineProperty(document, 'hidden', {get: () => true, configurable: true})")
        self.P("#fab").click()
        self.page.wait_for_timeout(1500)
        lists, polls = self.window(5000)
        self.assertEqual(lists, 0, "call list fetched while the page is hidden")
        self.page.evaluate("Object.defineProperty(document, 'hidden', {get: () => false, configurable: true})")
        self.page.wait_for_timeout(2500)
        lists, polls = self.window(6000)
        self.assertGreaterEqual(lists, 1, "open drawer never refreshed the list")
        self.assertLessEqual(lists, polls, "more than one call-list download per poll (%d vs %d polls)" % (lists, polls))

    def test_m10_switching_tab_discards_an_unchanged_new_map_local(self):
        self.reset_state()
        self.open()
        row = self.page.locator(".flow-table tbody tr", has_text="/echo").first
        wait_for(lambda: row.count() > 0, 10, 0.2, "echo row")
        row.click()
        self.P("#fab").click()
        self.P("button[data-t=call]").click()
        self.P("#mock").click()
        wait_for(lambda: self.P("#back").count() > 0, 10, 0.2, "Map Local editor")
        drafts = [r for r in self.inst.cfg()["rules"] if r.get("draft")]
        self.assertEqual(len(drafts), 1, self.inst.cfg()["rules"])
        mock_file = drafts[0]["file"]
        self.assertTrue(os.path.exists(mock_file))
        self.P("button[data-t=rules]").click()                       # another Tools tab instead of Back
        wait_for(lambda: not [r for r in self.inst.cfg()["rules"] if r.get("draft")], 10, 0.2, "draft discarded")
        self.assertFalse(os.path.exists(mock_file), "mock file left behind")

    def test_m10_a_changed_draft_is_not_deleted_by_a_tab_switch(self):
        self.reset_state()
        self.open()
        row = self.page.locator(".flow-table tbody tr", has_text="/echo").first
        wait_for(lambda: row.count() > 0, 10, 0.2, "echo row")
        row.click()
        self.P("#fab").click()
        self.P("button[data-t=call]").click()
        self.P("#mock").click()
        wait_for(lambda: self.P("#body").count() > 0, 10, 0.2, "Map Local editor")
        self.P("#body").fill('{"typed": true}')
        self.P("button[data-t=rules]").click()
        self.page.wait_for_timeout(1000)
        self.assertEqual(len([r for r in self.inst.cfg()["rules"] if r.get("draft")]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
