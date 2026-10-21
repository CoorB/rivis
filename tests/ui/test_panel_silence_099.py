"""0.9.9: the panel must never go silent. Pilot report: right-click a call → Map Local / Repeat / Pause / Edit & Repeat closed the menu
and NOTHING happened — no drawer, no new call, no toast — because the /proxy/api request never completed (a stuck proxy, or the
browser's 6 connections per host used up) and the panel waited for ever. Now every panel request has a deadline and ends in a red
toast that names the command to run, a click on a still-running action says so, a slow action shows "Working…", at most one
poll is ever in flight, and a proxy that stops answering raises the not-responding bar until it answers again.

The server side is held with a test-only file (RIVIS_TEST_PANEL_DELAY_FILE → {"<op>": seconds}); without that variable it does nothing."""
import json
import os
import sys
import tempfile
import time
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
class PanelSilence(UiBase):
    INSTANCE_KW = {"extra_env": {"RIVIS_TEST_PANEL_DELAY_FILE": HOLD_FILE}}

    def setUp(self):
        hold()
        self.addCleanup(hold)
        super().setUp()
        self.inflight, self.peak = set(), [0]

        def started(r):
            if "/proxy/api/" in r.url:
                self.inflight.add(r)
                self.peak[0] = max(self.peak[0], len(self.inflight))

        def ended(r):
            self.inflight.discard(r)
        self.page.on("request", started)
        self.page.on("requestfinished", ended)
        self.page.on("requestfailed", ended)

    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def toast(self):
        return self.page.evaluate("document.querySelector('#proxy-panel-host').shadowRoot.querySelector('#toast').innerText")

    def bar(self, which="lostbar"):
        return self.page.evaluate("(w) => { const b = document.querySelector('#proxy-panel-host').shadowRoot.querySelector('#' + w);"
                                  " return b.classList.contains('open') ? b.innerText : '' }", which)

    def menu_press(self, k):
        self.page.locator(".flow-table tbody tr", has_text="a=1").first.click(button="right")
        wait_for(lambda: self.P("#cmenu.open").count() > 0, 5, 0.1, "menu open")
        self.page.wait_for_timeout(900)
        self.P("#cmenu button[data-k=%s]" % k).click()

    def test_action_that_gets_no_answer_ends_in_a_red_toast(self):
        self.open()
        hold(mock=19)                                      # the proxy takes the Map Local request and does not answer
        self.menu_press("map")
        wait_for(lambda: "Working" in self.toast(), 3, 0.1, "a slow action shows Working…")
        self.menu_press("map")                             # a second click on the same, still-running action
        wait_for(lambda: "Still waiting for the previous Map Local" in self.toast(), 3, 0.1, "a click on a running action says so")
        wait_for(lambda: "did not answer within 15 s" in self.toast(), 20, 0.25, "the deadline ends in a message")
        t = self.toast()
        self.assertIn("rivis status", t)
        self.assertIn("rivis restart", t)
        self.assertFalse(self.P("#drawer.open").count(), "no drawer for an action that did not complete")
        hold()                                             # the proxy answers again: the same click now works
        self.menu_press("map")
        wait_for(lambda: self.P("#drawer.open").count() > 0, 8, 0.2, "after the proxy answers, Map Local opens its editor")

    def test_unanswered_polls_do_not_pile_up_and_actions_still_work(self):
        self.open()
        hold(state=40)                                     # the heartbeat gets no answer
        t0 = time.time()
        wait_for(lambda: "not responding" in self.bar(), 20, 0.25, "banner after ~10 s without an answer")
        self.assertIn("rivis status", self.bar())
        self.assertGreater(time.time() - t0, 5, "not instantly")
        # a user action still has a free connection while polls are being refused
        self.menu_press("bp")
        wait_for(lambda: "Breakpoint on" in self.toast(), 6, 0.2, "an action completes while the heartbeat is stuck")
        self.page.wait_for_timeout(14000)                  # several poll periods: abandoned requests used to stack up
        self.assertLessEqual(len(self.inflight), 2, [r.url for r in self.inflight])
        self.assertLessEqual(self.peak[0], 3, "peak concurrent panel requests %d" % self.peak[0])
        hold()                                             # answers resume → the bar clears by itself
        wait_for(lambda: not self.bar(), 15, 0.25, "banner clears when the proxy answers")

    def test_menu_opens_at_once_while_the_call_list_is_not_answering(self):
        """Soak F3: the right-click menu waited for the call-list download (10 s) before it drew anything, so with a stuck proxy it
        looked dead. Everything it shows is on the row, so it opens straight away."""
        self.open()
        self.P("#fab").click()                             # the drawer's poll now fetches the call list
        wait_for(lambda: self.P("#drawer.open").count() > 0, 5, 0.1, "drawer open")
        hold(flows_since=19)
        self.page.wait_for_timeout(2600)                   # a poll is now in flight and will not be answered for 19 s
        t0 = time.time()
        self.page.locator(".flow-table tbody tr", has_text="a=1").first.click(button="right")
        wait_for(lambda: self.P("#cmenu.open").count() > 0, 2, 0.05, "the menu opens while the call list is stuck")
        self.assertLess(time.time() - t0, 2)
        self.assertIn("Copy URL", self.P("#cmenu").inner_text())
        self.assertIn("/echo", self.P("#cmenu .hd").inner_text())


if __name__ == "__main__":
    unittest.main()
