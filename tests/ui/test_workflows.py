"""Demo paths, in a real browser: what a QA engineer does in front of an audience, feature after feature, the way a
Proxyman user would. Each test is one workflow, clicked through the UI, with the effect checked on the wire.

Added 2026-10-15 after a breakpoint looked dead in a live demo: it was set after the app's only call, and Repeat
skipped breakpoints. Unit tests had covered each piece alone; these cover the pieces together.
"""
import json
import os
import re
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
        try:
            self.row(text).click(timeout=8000)
        except Exception:
            shot(self.page, "wf-click-blocked-" + self._testMethodName)
            print("BLOCKER:", self.page.evaluate("""() => { const r = document.querySelector('.flow-table tbody tr').getBoundingClientRect();
                const sr = document.querySelector('#proxy-panel-host').shadowRoot;
                const el = sr.elementFromPoint(r.left + 40, r.top + r.height / 2);
                return el ? (el.id + ' ' + el.className + ' ' + (el.parentElement && el.parentElement.id)) : 'none'; }"""))
            raise
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
        try:
            self.P("#pause.open").wait_for(timeout=timeout)
        except Exception:
            st = self.panel.state()
            print("SHEETDEBUG paused=%r bps=%r" % (st["paused"], st["breakpoints"]))
            shot(self.page, "wf-no-sheet-" + self._testMethodName)
            raise
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
        self.fetch("/echo?wfa=1", method="POST", data='{"amount": 10}', headers={"Content-Type": "application/json"})
        page = self.open()
        self.breakpoint_from_call("wfa=1")
        self.assertRegex(self.toast().lower(), r"next", "turning a breakpoint on must say it pauses the NEXT call")
        t, box = self.in_background("/echo?wfa=1", method="POST", data='{"amount": 10}', headers={"Content-Type": "application/json"})
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
        self.fetch("/json/small?wfb=1")
        self.open()
        self.breakpoint_from_call("wfb=1")
        self.row("wfb=1").click(button="right")
        self.P("#cmenu button[data-k=repeat]").click()
        self.sheet()
        self.P("#pabort").click()
        wait_for(lambda: not self.panel.state()["paused"], 10, 0.2, "aborted")
        self.select("wfb=1")
        self.page.keyboard.press(KMOD + "+Enter")
        self.sheet()
        self.P("#pcont").click()
        wait_for(lambda: not self.panel.state()["paused"], 10, 0.2, "continued")
        self.assertEqual(self.errors, [])

    def test_plain_r_repeats_as_a_new_flow(self):
        self.fetch("/echo?rkey=1")
        self.open()
        self.select("rkey=1")
        original = self.inst.flow_for("rkey=1")["id"]
        self.page.keyboard.press("r")
        matching = lambda: [f for f in self.inst.flows()
                            if "rkey=1" in ((f.get("request") or {}).get("path") or "")]
        flows = wait_for(lambda: (lambda rows: rows if len(rows) >= 2 else None)(matching()),
                         10, 0.2, "plain r created a second flow")
        self.assertIn(original, [f["id"] for f in flows])
        self.assertGreaterEqual(len({f["id"] for f in flows}), 2)

    def test_toolbar_replay_keeps_original_and_adds_row(self):
        # R3A-09: stock toolbar Replay mutates the original instead of making a repeat row.
        self.fetch("/echo?toolbar-replay=1")
        self.open()
        self.select("toolbar-replay=1")
        original = self.inst.flow_for("toolbar-replay=1")["id"]
        self.page.locator("#container > header button", has_text="Replay").first.click()
        rows = wait_for(lambda: (lambda fs: fs if len(fs) >= 2 else None)([
            f for f in self.inst.flows() if "toolbar-replay=1" in ((f.get("request") or {}).get("path") or "")]),
            10, 0.2, "toolbar Replay made a second row")
        self.assertIn(original, [f["id"] for f in rows])
        self.assertTrue(any((f.get("comment") or "").startswith("repeat of") for f in rows))

    def test_map_local_back_warns_before_discarding_edits(self):
        # R3A-10: Back keeps the draft on screen until the in-panel choice is made.
        self.fetch("/json/small?back-warning=1")
        self.open()
        self.select("back-warning=1")
        self.tab("call")
        self.P("#mock").click()
        self.P("#body").fill('{"changed":true}')
        self.P("[data-sub=headers]").click()      # R3A-10: tab switches must not reset the dirty baseline
        self.P("#back").click()
        self.assertTrue(self.P("#discard").is_visible())
        self.assertEqual(self.P("#body").input_value(), '{"changed":true}')
        self.P("#keep").click()
        self.assertFalse(self.P("#discard").is_visible())
        self.P("#back").click()
        self.P("#discard-yes").click()
        wait_for(lambda: self.P("#body").count() == 0, 5, 0.1, "editor closed after discard")

    def test_response_breakpoint_changes_what_the_app_receives(self):
        self.fetch("/json/small?wfc=1")
        self.open()
        self.breakpoint_from_call("wfc=1", phase="response")
        t, box = self.in_background("/json/small?wfc=1")
        self.sheet()
        self.P("#pst").fill("418")
        self.P("#pb").fill('{"teapot": true}')
        self.P("#pcont").click()
        t.join(20)
        self.assertEqual((box["r"].status, box["r"].json()), (418, {"teapot": True}))

    def test_paused_get_offers_no_format_json_and_continue_says_unchanged(self):
        # L3: "Format JSON" was offered for "No body"; L1: an untouched Continue was labelled "edited"
        self.fetch("/text?wfnobody=1")
        self.open()
        self.breakpoint_from_call("wfnobody=1")
        t, box = self.in_background("/text?wfnobody=1")
        self.sheet()
        self.assertEqual(self.P("#pfmt").count(), 0, "Format JSON shown for a call with no body")
        self.P("#pcont").click()
        t.join(20)
        self.assertEqual(box["r"].status, 200)
        comment = wait_for(lambda: self.inst.flow_for("/text?wfnobody=1").get("comment"), 10, 0.2, "comment")
        self.assertIn("continued unchanged", comment)
        self.assertEqual(self.errors, [])

    def test_abort_gives_the_app_an_error_and_the_server_never_sees_it(self):
        self.fetch("/text?wfd=1")
        self.open()
        self.breakpoint_from_call("wfd=1")
        self.up.reset_hits()
        t, box = self.in_background("/text?wfd=1")
        self.sheet()
        self.P("#pabort").click()
        t.join(20)
        self.assertNotEqual(box["r"].status, 200)
        self.assertEqual(self.up.hits_for("/text"), [])

    def test_two_paused_calls_are_both_handled(self):
        self.fetch("/text?wfe=1")
        self.open()
        self.breakpoint_from_call("wfe=1")
        (t1, b1), (t2, b2) = self.in_background("/text?wfe=1&n=1"), self.in_background("/text?wfe=1&n=2")
        wait_for(lambda: len(self.panel.state()["paused"]) == 2, 10, 0.2, "two paused")
        for _ in range(2):
            self.sheet()
            self.P("#pcont").click()
            self.page.wait_for_timeout(600)
        t1.join(20); t2.join(20)
        self.assertEqual((b1["r"].status, b2["r"].status), (200, 200))

    def test_pause_shows_even_when_a_filter_hides_the_call_and_the_drawer_is_closed(self):
        self.fetch("/text?wff=1")
        page = self.open()
        self.breakpoint_from_call("wff=1")
        self.P("#drawer .x, #drawer [aria-label=Close]").first.click() if self.P("#drawer.open").count() else None
        page.keyboard.press(KMOD + "+f"); page.keyboard.type("nothing-matches-this"); page.keyboard.press("Enter")
        page.wait_for_timeout(800)
        t, box = self.in_background("/text?wff=1")
        self.sheet()
        self.P("#pcont").click()
        t.join(20)
        self.assertEqual(box["r"].status, 200)

    def test_map_local_edit_then_repeat_serves_the_new_mock(self):
        self.fetch("/json/small?wfg=1")
        self.open()
        self.select("wfg=1")
        self.tab("call")
        self.P("#mock").click()
        self.P("#body").wait_for(timeout=10000)
        self.P("#body").fill('{"v": 1}')
        self.P("#save").click()
        self.page.wait_for_timeout(1200)
        self.assertEqual(self.fetch("/json/small?wfg=1").json(), {"v": 1})
        self.P("#body").fill('{"v": 2}')
        self.P("#save").click()
        self.page.wait_for_timeout(1200)
        self.assertEqual(self.fetch("/json/small?wfg=1").json(), {"v": 2})

    def test_map_local_of_a_non_json_call_saves_without_a_json_warning(self):
        # F-02: Save asked "This is not valid JSON. Save anyway?" for an HTML / text mock; cancelling it (or a browser
        # that auto-dismisses dialogs) left the mock unsaved and the real page served
        self.fetch("/text?f02=1")
        self.open()
        self.select("f02=1")
        self.tab("call")
        self.P("#mock").click()
        self.P("#body").wait_for(timeout=10000)
        self.P("#body").fill("<h1>mocked page</h1>")
        self.P("#save").click()
        self.page.wait_for_timeout(1200)
        self.assertEqual(self.fetch("/text?f02=1").text, "<h1>mocked page</h1>")

    def test_map_local_back_discards_the_draft_and_next_call_is_live(self):
        # B-03: the visible Back path is the cancel path, including removal of the draft file.
        path = "/json/small?wf-draft-back=1"
        self.fetch(path)
        self.open()
        self.select("wf-draft-back=1")
        self.tab("call")
        self.P("#mock").click()
        self.P("#body").wait_for(timeout=10000)
        draft = next(r for r in self.inst.cfg()["rules"] if r.get("draft"))
        self.assertFalse(draft["enabled"])
        file = draft["file"]
        self.P("#back").click()
        wait_for(lambda: all(r["name"] != draft["name"] for r in self.inst.cfg()["rules"]), 5, 0.2, "draft discarded")
        self.assertFalse(os.path.exists(file))
        self.up.reset_hits()
        self.fetch(path)
        self.assertTrue(self.up.hits_for(path), "Back left an active mock on the next call")
        self.assertNotIn("mock:", self.inst.flow_for(path)["comment"] or "")

    def test_failed_map_local_save_keeps_the_draft_discardable(self):
        # B-03 review: the failed Save used to clear the editor's draft flag before the API replied.
        self.fetch("/json/small?wf-bad-save=1")
        self.open()
        self.select("wf-bad-save=1")
        self.tab("call")
        self.P("#mock").click()
        self.P("#st").fill("999")
        self.P("#save").click()
        wait_for(lambda: "status" in self.toast().lower(), 5, 0.2, "invalid status rejected")
        draft = next(r for r in self.inst.cfg()["rules"] if r.get("draft"))
        file = draft["file"]
        self.P("#back").click()
        self.assertTrue(self.P("#discard").is_visible())  # R3A-10: the rejected status is still an unsaved edit
        self.P("#discard-yes").click()
        wait_for(lambda: all(r["name"] != draft["name"] for r in self.inst.cfg()["rules"]), 5, 0.2, "failed save discarded")
        self.assertFalse(os.path.exists(file))

    def test_map_local_pasted_url_keeps_its_query(self):
        self.open()
        self.tab("map")
        exact = self.up.url("/echo?x=1")
        self.P("#mh").fill(exact)
        self.P("#madd").click()
        self.P("#body").wait_for(timeout=10000)
        rule = next(r for r in self.inst.cfg()["rules"] if r.get("action") == "map_local")
        self.assertTrue(re.search(rule["match"], exact), rule["match"])
        self.assertFalse(re.search(rule["match"], self.up.url("/echo?x=9")), rule["match"])

    def test_breakpoint_and_map_local_on_one_endpoint_pause_first(self):
        """Proxyman order: the breakpoint stops the call before Map Local answers it."""
        self.fetch("/json/small?wfh=1")
        self.open()
        self.select("wfh=1")
        self.tab("call")
        self.P("#mock").click()
        self.P("#body").wait_for(timeout=10000)
        self.P("#body").fill('{"mocked": 8}')
        self.P("#save").click()
        self.page.wait_for_timeout(800)
        self.P("#back").click()
        self.breakpoint_from_call("wfh=1")
        t, box = self.in_background("/json/small?wfh=1")
        self.sheet()
        self.P("#pcont").click()
        t.join(20)
        self.assertEqual(box["r"].json(), {"mocked": 8})

    def test_a_breakpoint_made_in_the_terminal_shows_as_on_for_its_call(self):
        """QA TXT-06: CLI breakpoints carry no label, so the This call tab said 'off' (and a click made a duplicate)."""
        self.fetch("/json/small?wfj=1")
        self.reset_state(breakpoints=[{"name": "cli", "match": "wfj=1", "request": True, "response": False, "enabled": True}])
        self.open()
        self.select("wfj=1")
        self.tab("call")
        btn = self.P("button[data-ph=request]")
        wait_for(lambda: "on" in (btn.get_attribute("class") or "").split(), 5, 0.2, "Request shown as on")
        self.assertIn("on for this endpoint", self.panel_text())

    def test_mock_editor_shows_what_was_saved(self):
        """Manual QA: after Save with status 200 the editor showed the old 500, so the save looked lost."""
        self.fetch("/json/small?wfk=1")
        self.open()
        self.select("wfk=1")
        self.tab("call")
        self.P("#mock").click()
        self.P("#st").wait_for(timeout=10000)
        self.P("#st").fill("299")
        self.P("#body").fill('{"saved": 1}')
        self.P("#save").click()
        self.page.wait_for_timeout(2500)                       # a poll re-render or two
        self.assertEqual(self.P("#st").input_value(), "299")
        self.assertEqual(self.fetch("/json/small?wfk=1").status, 299)

    def test_typing_a_status_code_finds_calls_with_that_status(self):
        """Manual QA: '503' only matched URLs containing 503, not a 503 returned by /text."""
        self.reset_state(rules=[self.rule("force", "respond", "/text", status=503, body={"down": True})])
        wait_for(lambda: self.fetch("/text?wfl=1").status == 503, 10, 0.3, "the 503 rule applies")
        self.fetch("/json/small?wfl=2")
        page = self.open()
        self.P("#sq").click(); page.keyboard.type("503"); page.keyboard.press("Enter")
        try:
            wait_for(lambda: self.row("wfl=1").count() == 1 and self.row("wfl=2").count() == 0, 10, 0.3, "only the 503 listed")
        except AssertionError:
            shot(page, "wf-status-filter")
            print("FILTERDEBUG", self.row("wfl=1").count(), self.row("wfl=2").count(),
                  page.evaluate("document.querySelector('#proxy-panel-host').shadowRoot.querySelector('#sq').value"),
                  page.evaluate("[...document.querySelectorAll('.flow-table tbody tr td.col-path')].slice(0,8).map(t=>t.textContent)"))
            raise

    def test_a_breakpoint_on_a_busy_endpoint_can_be_turned_off_from_the_paused_sheet(self):
        """Manual QA: a breakpoint on a call the app makes every few seconds queued sheet after sheet, covering the
        whole UI (incl. the Breakpoints tab). The sheet now offers 'Turn off this breakpoint'."""
        self.fetch("/text?wfm=1")
        self.open()
        self.breakpoint_from_call("wfm=1", phase="request")
        stop = threading.Event()
        def app():
            while not stop.is_set():
                self.fetch("/text?wfm=1", timeout=10)
        workers = [threading.Thread(target=app, daemon=True) for _ in range(3)]
        for w in workers:
            w.start()
        try:
            self.sheet()
            wait_for(lambda: len(self.panel.state()["paused"]) >= 2, 10, 0.2, "calls queue up")
            self.P("#pbpoff").click()
            wait_for(lambda: not any(b.get("enabled", True) for b in self.panel.state()["breakpoints"]), 10, 0.2, "breakpoint off")
            wait_for(lambda: not self.panel.state()["paused"] and not self.P("#pause.open").count(), 15, 0.3,
                     "nothing paused and the sheet closed while calls keep coming")
        finally:
            stop.set()
        self.assertEqual(self.errors, [])

    def test_breakpoint_off_lets_calls_through(self):
        self.fetch("/text?wfi=1")
        self.open()
        self.breakpoint_from_call("wfi=1")
        self.select("wfi=1")
        self.tab("call")
        self.P("button[data-ph=request]").click()              # second click: off
        wait_for(lambda: not any(b.get("request") and b.get("enabled", True) for b in self.panel.state()["breakpoints"]),
                 5, 0.1, "breakpoint off")
        self.page.wait_for_timeout(1200)
        self.assertEqual(self.fetch("/text?wfi=1", timeout=8).status, 200)
        self.assertEqual(self.panel.state()["paused"], [])

    def test_a_paused_propfind_continued_untouched_stays_propfind(self):
        # QA-05: the sheet's method list had 7 verbs; with PROPFIND missing the browser selected GET and Continue sent it
        self.fetch("/echo?qam=1", method="PROPFIND")
        self.open()
        self.breakpoint_from_call("qam=1")
        t, box = self.in_background("/echo?qam=1", method="PROPFIND")
        self.sheet()
        self.assertEqual(self.P("#pm").input_value(), "PROPFIND")
        self.P("#pcont").click()
        t.join(20)
        self.assertEqual(box["r"].json()["method"], "PROPFIND")

    def test_opening_a_session_with_replace_keeps_a_paused_call(self):
        # QA-03: Sessions -> Open (replace) cleared the paused call too; the app hung with nothing left to Continue
        self.fetch("/echo?qas=1")
        self.panel.ok("sess_save", {"name": "qa-ui-sess", "overwrite": True})
        self.open()
        self.breakpoint_from_call("qas=1")
        t, box = self.in_background("/echo?qas=1", timeout=45)
        self.sheet()
        self.panel.ok("sess_load", {"name": "qa-ui-sess", "replace": True})
        paused = wait_for(lambda: self.panel.state()["paused"], 5, 0.2, "paused call still listed")
        self.panel.ok("paused_continue", {"id": paused[0]["id"], "edits": {}})
        t.join(20)
        self.assertEqual(box["r"].status, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
