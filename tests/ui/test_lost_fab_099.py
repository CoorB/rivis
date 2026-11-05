"""When the proxy stops answering, the Tools button must not keep saying \"N paused\".

The last good state left the FAB amber with a waiting count; with the lost bar up that looked like the
pause sheet was still live. The count clears until a poll answers again.
"""
import json
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402
import test_workflows                   # noqa: E402

HOLD_FILE = os.path.join(tempfile.mkdtemp(prefix="rivis-hold-"), "delay.json")


def hold(**ops):
    with open(HOLD_FILE, "w") as fh:
        json.dump(ops, fh)


@unittest.skipIf(PW_REASON, PW_REASON or "")
class LostFabNotPaused(UiBase):
    INSTANCE_KW = {"extra_env": {"RIVIS_TEST_PANEL_DELAY_FILE": HOLD_FILE}}
    _W = test_workflows.Workflows
    P, row, select, tab, breakpoint_from_call, in_background, sheet = (
        _W.P, _W.row, _W.select, _W.tab, _W.breakpoint_from_call, _W.in_background, _W.sheet)

    def setUp(self):
        hold()
        self.addCleanup(hold)
        super().setUp()

    def tearDown(self):
        hold()
        for p in self.panel.state().get("paused") or []:
            self.panel.post("paused_abort", {"id": p["id"]})
        super().tearDown()

    def fab_label(self):
        return self.P("#fablabel").inner_text()

    def bar(self):
        return self.page.evaluate(
            "() => { const b = document.querySelector('#proxy-panel-host').shadowRoot.querySelector('#lostbar');"
            " return b.classList.contains('open') ? b.innerText : '' }")

    def test_tools_button_drops_paused_count_while_the_proxy_is_not_responding(self):
        self.fetch("/json/small?lostfab=1")
        self.open()
        self.breakpoint_from_call("lostfab=1", phase="request")
        t, box = self.in_background("/json/small?lostfab=2")
        self.sheet()
        wait_for(lambda: "paused" in self.fab_label().lower(), 5, 0.2, "FAB shows paused while waiting")
        # Dismiss the sheet so the call stays paused and Tools is clickable again.
        self.page.keyboard.press("Escape")
        wait_for(lambda: self.P("#pause.open").count() == 0, 5, 0.1, "sheet dismissed")
        wait_for(lambda: "paused" in self.fab_label().lower(), 5, 0.2, "FAB still counts the waiting call")
        hold(state=40)
        wait_for(lambda: "not responding" in self.bar(), 20, 0.25, "lost bar")
        self.assertNotIn("paused", self.fab_label().lower(), self.fab_label())
        self.assertFalse(self.P("#fab").evaluate("e => e.classList.contains('paused')"))
        # Stale paused ids must not reopen a sheet while the lost bar is up (evaluate click: the hung
        # state poll from opening the drawer must not block this assertion).
        self.page.evaluate("""() => document.querySelector('#proxy-panel-host').shadowRoot.querySelector('#fab').click()""")
        self.page.wait_for_timeout(400)
        self.assertEqual(self.P("#pause.open").count(), 0, "must not open a pause sheet from stale state")
        hold()
        wait_for(lambda: not self.bar(), 15, 0.25, "lost bar clears")
        wait_for(lambda: "paused" in self.fab_label().lower(), 8, 0.2, "paused count returns after answer")
        self.P("#fab").click()
        wait_for(lambda: self.P("#pause.open").count() > 0, 8, 0.2, "sheet reopens once the proxy answers")
        self.P("#pskip").click()
        t.join(10)
        # Aborted state polls while the proxy is held are expected (same class as PanelSilence).
        self.assertEqual([e for e in self.errors if not (e[0] == "requestfailed" and e[1].endswith("/proxy/api/state"))], [])


if __name__ == "__main__":
    unittest.main()
