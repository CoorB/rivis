"""Pilot 2026-10-21: "when I use a breakpoint to modify an API response, the edited response doesn't take effect".
A breakpoint from the call menu pauses the request first, and that sheet showed an editable "No body" box with nothing
saying it is what the app SENDS: the new response typed there went to the server as a request body. The sheet now says
which side it is, that the response pauses next, and offers to pause the response when it would not."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402
import test_workflows                   # noqa: E402  (not the class: the runner would collect its tests here)


@unittest.skipIf(PW_REASON, PW_REASON or "")
class BreakpointSheetSaysWhichSide(UiBase):
    # the workflow helpers only (inheriting Workflows would run all of its tests again)
    _W = test_workflows.Workflows
    P, row, select, tab, in_background, sheet, breakpoint_from_call = (
        _W.P, _W.row, _W.select, _W.tab, _W.in_background, _W.sheet, _W.breakpoint_from_call)

    def tearDown(self):
        for p in self.panel.state()["paused"]:                # never leak a held call into the next test
            self.panel.post("paused_abort", {"id": p["id"]})
        super().tearDown()

    def test_menu_breakpoint_says_the_response_pauses_next_and_the_edit_reaches_the_app(self):
        self.fetch("/json/small?bps=1")
        self.open()
        self.row("bps=1").click(button="right")
        self.P("#cmenu button[data-k=bp]").click()
        wait_for(lambda: any(b.get("response") for b in self.panel.state()["breakpoints"]), 5, 0.1, "breakpoint saved")
        self.page.wait_for_timeout(1200)
        t, box = self.in_background("/json/small?bps=2")
        sheet = self.sheet()
        self.assertIn("edit what the app sends", sheet.text_content())
        self.assertIn("the response pauses next", self.P("#pnext").text_content())
        self.assertEqual(self.P("button[data-psub=body]").text_content(), "Request body")
        self.P("#pcont").click()
        wait_for(lambda: "edit what the app receives" in self.P("#pause.open").text_content(), 10, 0.2, "the response sheet")
        self.assertEqual(self.P("button[data-psub=body]").text_content(), "Response body")
        self.P("#pb").fill('{"edited": true}')
        self.P("#pcont").click()
        t.join(20)
        self.assertEqual(box["r"].json(), {"edited": True})

    def test_a_request_only_breakpoint_offers_to_pause_the_response(self):
        self.fetch("/json/small?bpr=1")
        self.open()
        self.breakpoint_from_call("bpr=1", phase="request")
        t, box = self.in_background("/json/small?bpr=2")
        self.sheet()
        self.P("#presp").click()
        wait_for(lambda: "the response pauses next" in self.P("#pnext").text_content(), 5, 0.2, "response pauses next")
        self.page.wait_for_timeout(1200)                     # the proxy picks the filter up within a second
        self.P("#pcont").click()
        wait_for(lambda: "edit what the app receives" in self.P("#pause.open").text_content(), 10, 0.2, "the response sheet")
        self.P("#pb").fill('{"from_the_sheet": 1}')
        self.P("#pcont").click()
        t.join(20)
        self.assertEqual(box["r"].json(), {"from_the_sheet": 1})


if __name__ == "__main__":
    unittest.main()
