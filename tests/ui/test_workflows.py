"""Demo paths, in a real browser: what a QA engineer does in front of an audience, feature after feature, the way a
Proxyman user would. Each test is one workflow, clicked through the UI, with the effect checked on the wire.

Added 2026-10-15 after a breakpoint looked dead in a live demo: it was set after the app's only call, and Repeat
skipped breakpoints. Unit tests had covered each piece alone; these cover the pieces together.
"""
import json
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase, shot   # noqa: E402

KMOD = "Meta" if sys.platform == "darwin" else "Control"


@unittest.skipIf(PW_REASON, PW_REASON or "")
class Workflows(UiBase):
    # ── helpers ────────────────────────────────────────────────────────────────────────────────────
    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def row(self, text):
        return self.page.locator(".flow-table tbody tr", has_text=text).first

    def select(self, text):
        wait_for(lambda: self.row(text).count() > 0, 10, 0.2, "row %s" % text)
        self.row(text).click()
        self.page.wait_for_timeout(400)

    def tab(self, name):
        if not self.P("#drawer.open").count():
            self.P("#fab").click()
        self.P("button[data-t=%s]" % name).click()
        self.page.wait_for_timeout(300)

    def toast(self):
        return self.page.evaluate("document.querySelector('#proxy-panel-host').shadowRoot.querySelector('#toast').innerText")

    def in_background(self, path, **kw):
        """A call the 'app' makes; it may be held by a breakpoint, so it runs on a thread."""
        box = {}
        t = threading.Thread(target=lambda: box.update(r=self.fetch(path, **kw)), daemon=True)
        t.start()
        return t, box

    def sheet(self, timeout=10000):
        self.P("#pause.open").wait_for(timeout=timeout)
        return self.P("#pause.open")

    def breakpoint_from_call(self, path, phase="request"):
        self.select(path)
        self.tab("call")
        self.P("button[data-ph=%s]" % phase).click()
        wait_for(lambda: any(b.get(phase) for b in self.panel.state()["breakpoints"]), 5, 0.1, "breakpoint saved")
        self.page.wait_for_timeout(1200)                     # the proxy picks the filter up within a second

    def tearDown(self):
        for p in self.panel.state()["paused"]:                # never leak a held call into the next test
            self.panel.post("paused_abort", {"id": p["id"]})
        super().tearDown()

    # ── workflows ──────────────────────────────────────────────────────────────────────────────────
    def test_breakpoint_then_the_app_calls_again_edit_and_continue(self):
        self.fetch("/echo?wf=1", method="POST", data='{"amount": 10}', headers={"Content-Type": "application/json"})
        page = self.open()
        self.breakpoint_from_call("wf=1")
        self.assertRegex(self.toast().lower(), r"next", "turning a breakpoint on must say it pauses the NEXT call")
        t, box = self.in_background("/echo?wf=1", method="POST", data='{"amount": 10}', headers={"Content-Type": "application/json"})
        self.sheet()
        shot(page, "wf-paused-request")
        self.P("#pb").fill('{"amount": 999}')
        self.P("#pcont").click()
        t.join(20)
        self.assertEqual(box["r"].status, 200)
        self.assertIn("999", json.dumps(box["r"].json()), "the server must receive the edited body")
        self.assertEqual(self.errors, [])

    def test_breakpoint_then_repeat_pauses_too(self):
        """The demo bug: Repeat (right-click, Cmd+Enter) went straight through a breakpoint."""
        self.fetch("/json/small?wf=2")
        self.open()
        self.breakpoint_from_call("wf=2")
        self.row("wf=2").click(button="right")
        self.P("#cmenu button[data-k=repeat]").click()
        self.sheet()
        self.P("#pabort").click()
        wait_for(lambda: not self.panel.state()["paused"], 10, 0.2, "aborted")
        self.select("wf=2")
        self.page.keyboard.press(KMOD + "+Enter")
        self.sheet()
        self.P("#pcont").click()
        wait_for(lambda: not self.panel.state()["paused"], 10, 0.2, "continued")
        self.assertEqual(self.errors, [])

    def test_response_breakpoint_changes_what_the_app_receives(self):
        self.fetch("/json/small?wf=3")
        self.open()
        self.breakpoint_from_call("wf=3", phase="response")
        t, box = self.in_background("/json/small?wf=3")
        self.sheet()
        self.P("#pst").fill("418")
        self.P("#pb").fill('{"teapot": true}')
        self.P("#pcont").click()
        t.join(20)
        self.assertEqual((box["r"].status, box["r"].json()), (418, {"teapot": True}))

    def test_abort_gives_the_app_an_error_and_the_server_never_sees_it(self):
        self.fetch("/text?wf=4")
        self.open()
        self.breakpoint_from_call("wf=4")
        self.up.reset_hits()
        t, box = self.in_background("/text?wf=4")
        self.sheet()
        self.P("#pabort").click()
        t.join(20)
        self.assertNotEqual(box["r"].status, 200)
        self.assertEqual(self.up.hits_for("/text"), [])

    def test_two_paused_calls_are_both_handled(self):
        self.fetch("/text?wf=5")
        self.open()
        self.breakpoint_from_call("wf=5")
        (t1, b1), (t2, b2) = self.in_background("/text?wf=5&n=1"), self.in_background("/text?wf=5&n=2")
        wait_for(lambda: len(self.panel.state()["paused"]) == 2, 10, 0.2, "two paused")
        for _ in range(2):
            self.sheet()
            self.P("#pcont").click()
            self.page.wait_for_timeout(600)
        t1.join(20); t2.join(20)
        self.assertEqual((b1["r"].status, b2["r"].status), (200, 200))

    def test_pause_shows_even_when_a_filter_hides_the_call_and_the_drawer_is_closed(self):
        self.fetch("/text?wf=6")
        page = self.open()
        self.breakpoint_from_call("wf=6")
        self.P("#drawer .x, #drawer [aria-label=Close]").first.click() if self.P("#drawer.open").count() else None
        page.keyboard.press(KMOD + "+f"); page.keyboard.type("nothing-matches-this"); page.keyboard.press("Enter")
        page.wait_for_timeout(800)
        t, box = self.in_background("/text?wf=6")
        self.sheet()
        self.P("#pcont").click()
        t.join(20)
        self.assertEqual(box["r"].status, 200)

    def test_map_local_edit_then_repeat_serves_the_new_mock(self):
        self.fetch("/json/small?wf=7")
        self.open()
        self.select("wf=7")
        self.tab("call")
        self.P("#mock").click()
        self.P("#body").wait_for(timeout=10000)
        self.P("#body").fill('{"v": 1}')
        self.P("#save").click()
        self.page.wait_for_timeout(1200)
        self.assertEqual(self.fetch("/json/small?wf=7").json(), {"v": 1})
        self.P("#body").fill('{"v": 2}')
        self.P("#save").click()
        self.page.wait_for_timeout(1200)
        self.assertEqual(self.fetch("/json/small?wf=7").json(), {"v": 2})

    def test_breakpoint_and_map_local_on_one_endpoint_pause_first(self):
        """Proxyman order: the breakpoint stops the call before Map Local answers it."""
        self.fetch("/json/small?wf=8")
        self.open()
        self.select("wf=8")
        self.tab("call")
        self.P("#mock").click()
        self.P("#body").wait_for(timeout=10000)
        self.P("#body").fill('{"mocked": 8}')
        self.P("#save").click()
        self.page.wait_for_timeout(800)
        self.P("#back").click()
        self.breakpoint_from_call("wf=8")
        t, box = self.in_background("/json/small?wf=8")
        self.sheet()
        self.P("#pcont").click()
        t.join(20)
        self.assertEqual(box["r"].json(), {"mocked": 8})

    def test_breakpoint_off_lets_calls_through(self):
        self.fetch("/text?wf=9")
        self.open()
        self.breakpoint_from_call("wf=9")
        self.select("wf=9")
        self.tab("call")
        self.P("button[data-ph=request]").click()              # second click: off
        wait_for(lambda: not any(b.get("request") and b.get("enabled", True) for b in self.panel.state()["breakpoints"]),
                 5, 0.1, "breakpoint off")
        self.page.wait_for_timeout(1200)
        self.assertEqual(self.fetch("/text?wf=9", timeout=8).status, 200)
        self.assertEqual(self.panel.state()["paused"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
