"""Keyboard-only use and heavy bodies, in a real browser (round 6, lane B: a keyboard-first tester with 5-20 MB bodies).

User-opened sheets, editors and the drawer take focus and keep Tab inside; an auto-opened pause leaves typing focus
alone. Esc preserves dirty drafts and closes clean surfaces; mitmweb's list shortcuts never fire inside the panel.
Big or non-ASCII bodies must show as readable text, and saving a big Map Local body must not freeze the page.
"""
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase, shot   # noqa: E402

KMOD = "Meta" if sys.platform == "darwin" else "Control"
# where keyboard focus really is: through the panel's shadow root, and which panel surface holds it
ACTIVE = """() => { let a = document.activeElement; while (a && a.shadowRoot && a.shadowRoot.activeElement) a = a.shadowRoot.activeElement;
  const sr = document.querySelector('#proxy-panel-host').shadowRoot, has = (id) => !!sr.getElementById(id) && sr.getElementById(id).contains(a);
  return { tag: a ? a.tagName : null, id: a ? a.id : null, cls: a ? String(a.className || '') : null,
           panel: sr.contains(a), drawer: has('drawer'), pause: has('pause') }; }"""


@unittest.skipIf(PW_REASON, PW_REASON or "")
class KeyboardAndHeavyBodies(UiBase):
    def setUp(self):
        super().setUp()
        self.page.set_viewport_size({"width": 900, "height": 700})     # the tester's narrow laptop window

    def tearDown(self):
        for p in self.panel.state()["paused"]:                         # never leak a held call into the next test
            self.panel.post("paused_abort", {"id": p["id"]})
        super().tearDown()

    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def active(self):
        return self.page.evaluate(ACTIVE)

    def select(self, text):
        row = self.page.locator(".flow-table tbody tr", has_text=text).first
        wait_for(lambda: row.count() > 0, 15, 0.2, "row %s" % text)
        row.click()
        self.page.wait_for_timeout(400)

    def calls(self, part):
        return len([f for f in self.inst.flows() if part in ((f.get("request") or {}).get("path") or "")])

    def tab_stays(self, where, presses=24, shift=False):
        seen = set()
        for _ in range(presses):
            self.page.keyboard.press("Shift+Tab" if shift else "Tab")
            a = self.active()
            self.assertTrue(a[where], "Tab left the %s: focus is on %r" % (where, a))
            seen.add(a["id"] or a["tag"])
        return seen

    def tab_to(self, ident, where, presses=40):
        for _ in range(presses):
            if self.active()["id"] == ident:
                return
            self.page.keyboard.press("Tab")
            self.assertTrue(self.active()[where])
        self.fail("Tab never reached #%s" % ident)

    def in_background(self, path, **kw):
        box = {}
        t = threading.Thread(target=lambda: box.update(r=self.fetch(path, **kw)), daemon=True)
        t.start()
        return t, box

    # ── R6B-01 ─────────────────────────────────────────────────────────────────────────────────────
    def test_compose_chord_takes_focus_so_typing_r_does_not_replay(self):
        self.fetch("/echo?kbc=1")
        page = self.open()
        self.select("kbc=1")
        before, calls = self.active(), self.calls("kbc=1")
        page.keyboard.press("Alt+Shift+C")
        wait_for(lambda: self.active()["id"] == "cu", 10, 0.1, "Compose URL field focused")
        page.keyboard.type("r")
        page.wait_for_timeout(800)
        self.assertEqual(self.P("#cu").input_value(), "r")
        self.assertEqual(self.calls("kbc=1"), calls, "typing r after the Compose chord replayed the selected call")
        self.tab_stays("drawer")
        self.tab_stays("drawer", 6, shift=True)
        page.keyboard.press("Escape")                                   # R6-03: a typed draft stays open on Esc
        self.assertEqual(self.P("#drawer.open").count(), 1)
        self.P("#close").click()
        wait_for(lambda: not self.P("#drawer.open").count(), 5, 0.1, "drawer closed with X")
        after = self.active()
        self.assertEqual((after["tag"], after["id"], after["panel"]), (before["tag"], before["id"], before["panel"]),
                         "focus must go back where it was")
        self.assertEqual(self.errors, [])

    def test_r_on_a_focused_panel_button_does_not_replay(self):
        self.fetch("/echo?kbr=1")
        page = self.open()
        self.select("kbr=1")
        calls = self.calls("kbr=1")
        page.keyboard.press("Alt+Shift+B")                                # focus on the Breakpoints tab button
        wait_for(lambda: self.active()["drawer"], 10, 0.1, "drawer focused")
        page.keyboard.press("r")
        page.wait_for_timeout(800)
        self.assertEqual(self.calls("kbr=1"), calls)
        self.assertEqual(self.errors, [])

    # ── R6B-02 ─────────────────────────────────────────────────────────────────────────────────────
    def test_auto_opened_breakpoint_sheet_keeps_typing_focus_traps_tab_and_esc_gives_it_back(self):
        self.reset_state(breakpoints=[{"name": "kb", "match": r"/echo\?kbp", "request": True, "response": False, "enabled": True}])
        page = self.open()
        page.locator("body").click(position={"x": 5, "y": 5})
        page.keyboard.press("Alt+Shift+C")                                # the tester is typing in Compose…
        wait_for(lambda: self.active()["id"] == "cu", 10, 0.1, "Compose URL focused")
        t, box = self.in_background("/echo?kbp=1", method="POST", data="orig")
        self.P("#pause.open").wait_for(timeout=15000)                    # …when the paused call's sheet opens by itself
        self.assertEqual(self.active()["id"], "cu", "R6-01: the auto-opened sheet must leave Compose typing alone")
        page.keyboard.press("Tab")                                        # the user chooses to enter the sheet
        self.assertTrue(self.active()["pause"])
        self.tab_stays("pause")
        self.tab_stays("pause", 8, shift=True)
        page.keyboard.press("Escape")                                   # = the backdrop click: hide, still paused
        wait_for(lambda: not self.P("#pause.open").count(), 5, 0.1, "sheet hidden on Esc")
        self.assertEqual(len(self.panel.state()["paused"]), 1)
        self.assertEqual(self.active()["id"], "cu", "focus must return to the field the sheet interrupted")
        self.P("#fab").click()                                           # reopen it, then finish from the keyboard only
        self.P("#pause.open").wait_for(timeout=10000)
        wait_for(lambda: self.active()["pause"], 5, 0.1, "reopened sheet focused")
        self.tab_to("pcont", "pause")
        page.keyboard.press("Enter")
        t.join(20)
        self.assertEqual(box["r"].status, 200, "Continue from the keyboard must release the call")
        self.assertEqual(self.errors, [])

    # ── R6B-04 ─────────────────────────────────────────────────────────────────────────────────────
    def test_edit_and_repeat_chord_takes_focus_and_esc_cancels(self):
        self.fetch("/echo?kbe=1")
        page = self.open()
        self.select("kbe=1")
        before, calls = self.active(), self.calls("kbe=1")
        page.keyboard.press("Alt+Shift+Enter")
        self.P("#pause.open").wait_for(timeout=10000)
        wait_for(lambda: self.active()["id"] == "ru", 5, 0.1, "Edit & Repeat URL focused")
        seen = self.tab_stays("pause")
        self.assertIn("rsend", seen, "Tab must reach Send")
        page.keyboard.press("Escape")
        wait_for(lambda: not self.P("#pause.open").count(), 5, 0.1, "Esc cancelled")
        self.assertEqual(self.calls("kbe=1"), calls, "Esc must not send")
        after = self.active()
        self.assertEqual((after["tag"], after["id"]), (before["tag"], before["id"]))
        page.keyboard.press("Alt+Shift+Enter")                            # and the keyboard can send an edited copy
        wait_for(lambda: self.active()["id"] == "ru", 5, 0.1, "focused again")
        page.keyboard.press("End")
        page.keyboard.type("&edited=1")
        self.tab_to("rsend", "pause")
        page.keyboard.press("Enter")
        wait_for(lambda: self.calls("edited=1") == 1, 10, 0.2, "edited copy sent")
        self.assertEqual(self.errors, [])

    # ── R6B-06 ─────────────────────────────────────────────────────────────────────────────────────
    def test_map_local_editor_takes_focus_saves_from_the_keyboard_and_esc_goes_back(self):
        self.fetch("/json/small?kbm=1")
        page = self.open()
        self.select("kbm=1")
        self.P("#fab").click()
        self.P("button[data-t=call]").click()
        self.P("#mock").click()
        self.P("#main #body").wait_for(timeout=10000)
        wait_for(lambda: self.active()["id"] == "body", 5, 0.1, "Map Local body focused")
        self.tab_to("save", "drawer")
        page.keyboard.press("Enter")
        wait_for(lambda: any(r.get("action") == "map_local" and r.get("enabled") for r in self.panel.state()["rules"]),
                 10, 0.2, "the Map Local saved and on")
        self.tab_stays("drawer")
        page.keyboard.press("Escape")                                   # = Back (nothing changed since Save)
        wait_for(lambda: self.P("#main #mock").count() > 0, 5, 0.1, "back on This call")
        wait_for(lambda: self.active()["id"] == "mock", 5, 0.1, "focus back on Map Local this call…")
        self.assertEqual(self.errors, [])

    # ── R6B-08 ─────────────────────────────────────────────────────────────────────────────────────
    def test_tools_chord_pressed_twice_quickly_ends_closed(self):
        page = self.open()
        for _ in range(3):
            page.locator("body").click(position={"x": 5, "y": 5})
            page.keyboard.press("Alt+Shift+P")
            page.keyboard.press("Alt+Shift+P")
            page.wait_for_timeout(700)
            self.assertEqual(self.P("#drawer.open").count(), 0, "two quick presses must open and close the drawer")
        page.keyboard.press("Alt+Shift+P")
        wait_for(lambda: self.P("#drawer.open").count() == 1, 5, 0.1, "a third press opens it")
        self.assertEqual(self.errors, [])

    # ── R6B-05 ─────────────────────────────────────────────────────────────────────────────────────
    def test_filter_box_stays_readable_beside_the_open_drawer_at_900(self):
        self.fetch("/json/small?kbf=1")
        page = self.open()
        self.select("kbf=1")                                  # the "Selected call" menu takes header room too
        page.keyboard.press("Alt+Shift+L")
        self.P("#drawer.open").wait_for(timeout=10000)
        page.keyboard.press(KMOD + "+f")
        wait_for(lambda: self.active()["id"] == "sq", 5, 0.1, "filter focused")
        value = "/json/small?kbf"
        page.keyboard.type(value)
        page.keyboard.press("Enter")
        page.wait_for_timeout(1500)                                     # a placement tick
        for scheme in ("light", "dark"):
            page.emulate_media(color_scheme=scheme)
            page.wait_for_timeout(200)
            g = self.page.evaluate("""() => { const sr = document.querySelector('#proxy-panel-host').shadowRoot, i = sr.getElementById('sq');
                const r = i.getBoundingClientRect(), d = sr.getElementById('drawer').getBoundingClientRect(), b = sr.getElementById('sbar').getBoundingClientRect();
                return { w: r.width, fits: i.scrollWidth <= i.clientWidth + 1, right: b.right, drawer: d.left, value: i.value }; }""")
            shot(page, "kb-filter-900-" + scheme)
            self.assertGreaterEqual(g["w"], 150, "filter input is %r px wide" % g["w"])
            self.assertTrue(g["fits"], "the active filter %r does not fit its box" % g["value"])
            self.assertLessEqual(g["right"], g["drawer"], "the filter bar runs under the drawer")
        self.assertEqual(self.errors, [])

    # ── R6B-03 ─────────────────────────────────────────────────────────────────────────────────────
    def response_view(self, path):
        page, fid = self.page, self.inst.flow_for(path)["id"]
        for _ in range(5):                                # the list may re-sort under the click: check what got selected
            self.select(path)
            if fid in page.evaluate("location.hash"):
                break
        self.assertIn(fid, page.evaluate("location.hash"))
        page.locator(".flow-detail nav a", has_text="Response").first.click()
        pre = page.locator(".contentview pre").first
        try:
            wait_for(lambda: pre.count() > 0 and "Loading" not in page.locator(".contentview h5").first.inner_text(),
                     30, 0.2, "response view of %s loaded" % path)
        except AssertionError:
            shot(page, "kb-response-view-" + self._testMethodName)
            print("DETAIL:", page.evaluate("(document.querySelector('.flow-detail') || document.body).outerHTML.slice(0, 3000)"))
            raise
        return pre

    def test_utf8_arabic_and_emoji_text_shows_as_text_right_to_left(self):
        self.fetch("/arabic")
        self.fetch("/emoji")
        self.open()
        for path, word in (("/arabic", "مرحبا بالعالم"), ("/emoji", "🚀")):
            pre = self.response_view(path)
            title = self.page.locator(".contentview h5").first.inner_text()
            self.assertNotIn("hex", title.lower(), "%s shown as %r" % (path, title))
            self.assertIn(word, pre.inner_text())
        line = self.page.evaluate("getComputedStyle(document.querySelector('.contentview pre > div')).unicodeBidi")
        self.assertEqual(line, "plaintext", "Arabic lines must take their direction from their own text")
        shot(self.page, "kb-arabic")
        self.assertEqual(self.errors, [])

    # ── R6B-07 ─────────────────────────────────────────────────────────────────────────────────────
    def test_one_line_5mb_script_and_20mb_json_show_their_beginning(self):
        self.page.set_viewport_size({"width": 1440, "height": 900})
        self.fetch("/bigline?mb=5&type=js&kb=js5", timeout=60)
        self.fetch("/bigline?mb=20&type=json&kb=json20", timeout=120)
        self.open()
        for path, start in (("kb=js5", 'var x="bbbbbbbb'), ("kb=json20", '"data"')):
            pre = self.response_view(path)
            g = self.page.evaluate("""() => { const p = document.querySelector('.contentview pre');
                return { len: p.innerText.length, sw: p.scrollWidth, h: p.getBoundingClientRect().height, text: p.innerText.slice(0, 200) }; }""")
            self.assertIn(start, g["text"])
            self.assertLess(g["len"], 1024 * 1024, "the whole body was put into the page")
            self.assertLess(g["sw"], 30000000, "a line wider than Chromium can paint")
            note = self.page.locator(".contentview .rv-clip")
            wait_for(lambda: note.count() > 0, 5, 0.1, "clipped-body note")
            self.assertRegex(note.inner_text(), r"showing first \d+ KB of (5\.0|20\.0) MB")
            href = note.locator("a", has_text="Download").get_attribute("href")
            self.assertTrue(href.endswith("/response/content.data"), href)
            shot(self.page, "kb-bigline-" + path[3:])
        if "json" in path:
            self.assertIn("aaaaaaaa", self.page.locator(".contentview pre").first.inner_text()[:2000],
                          "the JSON value itself must be visible, not just its key")
        self.assertEqual(self.errors, [])

    # ── R6B-09 ─────────────────────────────────────────────────────────────────────────────────────
    def test_saving_a_20mb_map_local_keeps_the_page_responsive(self):
        self.fetch("/bigline?mb=20&type=json&kbs=1", timeout=120)
        page = self.open()
        self.select("kbs=1")
        puts = []
        page.on("request", lambda r: puts.append(len(r.post_data_buffer or b"")) if r.url.endswith("/proxy/api/mockfile_put") else None)
        self.P("#fab").click()
        self.P("button[data-t=call]").click()
        self.P("#mock").click()
        self.P("#main #body").wait_for(timeout=30000)
        wait_for(lambda: self.P("#main #body").evaluate("t => t.value.length") > 20000000, 30, 0.2, "20 MB body loaded")
        for attempt in range(2):                                          # the first Save (turns it on) and a repeat Save
            gap = page.evaluate("""() => new Promise((done) => {
                const sr = document.querySelector('#proxy-panel-host').shadowRoot;
                let last = performance.now(), worst = 0, stop = false;
                const tick = () => { const n = performance.now(); worst = Math.max(worst, n - last); last = n; if (!stop) requestAnimationFrame(tick); };
                requestAnimationFrame(tick);
                const t0 = performance.now();
                sr.getElementById('save').click();
                const wait = () => /Saved/.test(sr.getElementById('toast').innerText) && sr.getElementById('toast').style.display !== 'none'
                    ? (stop = true, done({ worst, took: performance.now() - t0 })) : setTimeout(wait, 20);
                wait(); })""")
            self.assertLess(gap["worst"], 1000, "Save #%d froze the page for %d ms" % (attempt + 1, gap["worst"]))
            page.evaluate("document.querySelector('#proxy-panel-host').shadowRoot.getElementById('toast').style.display = 'none'")
        self.assertTrue(puts and max(puts) < 1024 * 1024, "an unchanged 20 MB body was sent again: %r bytes" % puts)
        self.assertTrue(any(r.get("action") == "map_local" and r.get("enabled") for r in self.panel.state()["rules"]))
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
