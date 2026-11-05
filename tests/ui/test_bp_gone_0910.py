"""A pause sheet whose call has already left the paused list must not vanish in silence.

The app timed out, the proxy restarted, or Abort ran from the CLI: the next poll used to close the sheet
with no toast, so a dirty edit disappeared and the window looked as if the user had cancelled.

Also: a polled auto-open that fails (call already released) must not retry every ~1.2 s and toast-spam.
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402
import test_workflows                   # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class PauseSheetWhenCallGone(UiBase):
    _W = test_workflows.Workflows
    P, row, select, tab, in_background, sheet, breakpoint_from_call = (
        _W.P, _W.row, _W.select, _W.tab, _W.in_background, _W.sheet, _W.breakpoint_from_call)

    def tearDown(self):
        try:
            self.page.unroute("**/proxy/api/paused_get")
        except Exception:
            pass
        for p in self.panel.state()["paused"]:
            self.panel.post("paused_abort", {"id": p["id"]})
        super().tearDown()

    def toast(self):
        return self.page.evaluate(
            "document.querySelector('#proxy-panel-host').shadowRoot.querySelector('#toast').innerText")

    def test_sheet_says_the_paused_call_is_gone_when_it_leaves_the_queue(self):
        self.fetch("/json/small?gone=1")
        self.open()
        self.breakpoint_from_call("gone=1", phase="request")
        t, box = self.in_background("/json/small?gone=2")
        self.sheet()
        self.P("#pu").fill(self.P("#pu").input_value() + "&edited=1")
        paused = self.panel.state()["paused"]
        self.assertTrue(paused)
        self.panel.ok("paused_abort", {"id": paused[0]["id"]})
        wait_for(lambda: "paused call is gone" in self.toast().lower(), 8, 0.2, "toast that the call left")
        wait_for(lambda: self.P("#pause.open").count() == 0, 5, 0.1, "sheet closed")
        self.assertIn("edits were not sent", self.toast().lower())
        t.join(5)
        self.assertEqual(self.errors, [])

    def test_failed_auto_open_does_not_retry_every_poll(self):
        # state still lists the paused id, but paused_get refuses: without dismissed.add the poll retried
        # openPaused every ~1.2 s and toast-spammed. wait_for_timeout (not bare sleep) so the route runs.
        self.fetch("/json/small?goneauto=1")
        self.open()
        self.breakpoint_from_call("goneauto=1", phase="request")
        hits = []

        def refuse(route):
            hits.append(time.time())
            route.fulfill(status=400, content_type="application/json",
                          body='{"error":"that call is not paused any more"}')

        self.page.route("**/proxy/api/paused_get", refuse)
        t, box = self.in_background("/json/small?goneauto=2")
        end = time.time() + 10
        while time.time() < end and len(hits) < 1:
            self.page.wait_for_timeout(200)
        self.assertGreaterEqual(len(hits), 1, "auto-open never called paused_get")
        wait_for(lambda: "not paused any more" in self.toast().lower(), 5, 0.2, "failure toast")
        self.page.wait_for_timeout(4000)          # ~3 state polls; pumps Playwright so further hits register
        self.assertLessEqual(len(hits), 2,
                             "auto-open kept retrying paused_get (hits=%d); should dismiss after one failure" % len(hits))
        self.assertEqual(self.P("#pause.open").count(), 0)
        self.page.unroute("**/proxy/api/paused_get")
        for p in self.panel.state()["paused"]:
            self.panel.post("paused_abort", {"id": p["id"]})
        t.join(5)
        # The refused paused_get is deliberate; Chromium logs it as console.error 400.
        self.assertEqual([e for e in self.errors
                          if not (e[0] == "requestfailed" and "paused_get" in e[1])
                          and not (e[0] == "console.error" and "status of 400" in e[1])], [])


if __name__ == "__main__":
    unittest.main()
