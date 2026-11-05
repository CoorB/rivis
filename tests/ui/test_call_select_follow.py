"""The Tools → This call tab must follow the selected row by call id, never keep showing the previous call.

Under live traffic a QA engineer selects call B while the drawer still paints call A: Map Local / Breakpoint /
Repeat would then target the wrong endpoint. The gap was the async load (viewer + flows) leaving A's markup in
place, and up to 300 ms before a selection change even started a redraw.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402

HOLD_FILE = os.path.join(tempfile.mkdtemp(prefix="rivis-hold-"), "delay.json")


def hold(**ops):
    with open(HOLD_FILE, "w") as fh:
        json.dump(ops, fh)


@unittest.skipIf(PW_REASON, PW_REASON or "")
class CallTabFollowsSelection(UiBase):
    INSTANCE_KW = {"extra_env": {"RIVIS_TEST_PANEL_DELAY_FILE": HOLD_FILE}}

    def setUp(self):
        hold()
        self.addCleanup(hold)
        super().setUp()

    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def selected(self):
        h = self.page.evaluate("location.hash").replace("#/", "").split("?")[0].split("/")
        return h[1] if len(h) > 1 and h[0] == "flows" else None

    def call_text(self):
        return self.P("#main .call").inner_text() if self.P("#main .call").count() else self.P("#main").inner_text()

    def test_switching_rows_does_not_leave_the_previous_call_on_this_call_tab(self):
        self.fetch("/echo?follow=aaa")
        self.fetch("/echo?follow=bbb")
        self.open()
        self.page.locator(".flow-table tbody tr", has_text="follow=aaa").first.click()
        wait_for(lambda: self.selected() is not None, 5, 0.1, "aaa selected")
        self.P("#fab").click()
        wait_for(lambda: self.P("#drawer.open").count() > 0, 5, 0.1, "drawer open")
        self.P("button[data-t=call]").click()
        wait_for(lambda: "follow=aaa" in self.call_text(), 8, 0.1, "This call shows aaa")
        id_a = self.selected()

        hold(viewer=4)                                          # the next This-call draw waits on viewer
        self.page.locator(".flow-table tbody tr", has_text="follow=bbb").first.click()
        wait_for(lambda: self.selected() and self.selected() != id_a, 5, 0.05, "bbb selected in the hash")

        # Until bbb is drawn, the pane must not keep offering aaa's URL / Map Local / Breakpoint.
        for _ in range(20):
            text = self.call_text()
            self.assertNotIn("follow=aaa", text,
                             "This call still showed the previous row while another was selected: %r" % text[:200])
            if "follow=bbb" in text:
                break
            self.assertTrue("Loading" in text or self.P("#main .call").count() == 0,
                            "expected Loading… or empty, got: %r" % text[:200])
            self.page.wait_for_timeout(100)
        wait_for(lambda: "follow=bbb" in self.call_text(), 10, 0.2, "This call shows bbb")
        hold()
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main()
