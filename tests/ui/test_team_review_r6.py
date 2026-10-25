"""Regression coverage for the seven panel review findings."""
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for
from test_ui import PW_REASON, UiBase

KMOD = "Meta" if sys.platform == "darwin" else "Control"


@unittest.skipIf(PW_REASON, PW_REASON or "")
class ReviewR6(UiBase):
    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def active(self):
        return self.page.evaluate("""() => { let a = document.activeElement;
            while (a && a.shadowRoot && a.shadowRoot.activeElement) a = a.shadowRoot.activeElement;
            return {id: a && a.id, tag: a && a.tagName, panel: document.querySelector('#proxy-panel-host').shadowRoot.contains(a)}; }""")

    def select(self, text):
        row = self.page.locator(".flow-table tbody tr", has_text=text).first
        row.wait_for(timeout=10000)
        row.click()
        self.page.wait_for_timeout(300)

    def calls(self, part):
        return len([f for f in self.inst.flows() if part in ((f.get("request") or {}).get("path") or "")])

    def paused_call(self, token):
        self.reset_state(breakpoints=[{"name": token, "match": r"/echo\?" + token, "request": True,
                                      "response": False, "enabled": True}])
        box = {}
        t = threading.Thread(target=lambda: box.update(r=self.fetch("/echo?" + token, method="POST", data="original")), daemon=True)
        t.start()
        self.P("#pause.open").wait_for(timeout=15000)
        return t, box

    def tearDown(self):
        for p in self.panel.state()["paused"]:
            self.panel.post("paused_abort", {"id": p["id"]})
        super().tearDown()

    def test_r6_01_auto_pause_keeps_external_typing_focus(self):
        self.page.add_init_script("localStorage.setItem('rivis-skin', 'off')")
        self.open()
        field = self.page.locator('.filter-input input[placeholder="Search"]').first
        field.wait_for(timeout=10000)
        field.focus()
        field.fill("before")
        self.assertEqual(self.active()["id"], field.evaluate("e => e.id"))
        t, _ = self.paused_call("r6focus=1")
        self.assertTrue(field.evaluate("e => document.activeElement === e"))
        self.page.keyboard.type("after")
        self.assertEqual(field.input_value(), "beforeafter")
        self.page.keyboard.press("Tab")
        self.assertTrue(self.P("#pause").evaluate("e => e.contains(e.getRootNode().activeElement)"))
        self.P("#pabort").click()
        t.join(20)
        self.assertEqual(self.errors, [])

    def test_r6_02_dirty_repeat_and_paused_escape_keep_edits(self):
        self.fetch("/echo?r6repeat=1", method="POST", data="original")
        self.open()
        self.select("r6repeat=1")
        self.page.keyboard.press("Alt+Shift+Enter")
        self.P("#ru").wait_for(timeout=10000)
        self.P("#ru").fill(self.P("#ru").input_value() + "&changed=1")
        self.page.keyboard.press("Escape")
        self.assertEqual(self.P("#pause.open").count(), 1)
        self.assertIn("changed=1", self.P("#ru").input_value())
        self.P("#rcancel").click()
        t, _ = self.paused_call("r6pause=1")
        self.P("#pb").fill("edited")
        self.page.keyboard.press("Escape")
        self.assertEqual(self.P("#pause.open").count(), 1)
        self.assertEqual(self.P("#pb").input_value(), "edited")
        self.P("#pabort").click()
        t.join(20)
        self.assertEqual(self.errors, [])

    def test_r6_03_dirty_compose_and_tools_escape_keep_drawer(self):
        self.open()
        self.page.keyboard.press("Alt+Shift+C")
        self.P("#cu").wait_for(timeout=10000)
        self.P("#cu").fill("https://example.test/draft")
        self.page.keyboard.press("Escape")
        self.assertEqual(self.P("#drawer.open").count(), 1)
        self.assertEqual(self.P("#cu").input_value(), "https://example.test/draft")
        self.P('button[data-t="net"]').click()
        self.P('input[data-tlsadd="allow"]').fill("draft.example.test")
        self.page.keyboard.press("Escape")
        self.assertEqual(self.P("#drawer.open").count(), 1)
        self.assertEqual(self.P('input[data-tlsadd="allow"]').input_value(), "draft.example.test")
        self.P("#close").click()
        self.assertEqual(self.errors, [])

    def test_r6_04_x_and_toggle_return_list_shortcuts(self):
        self.fetch("/echo?r6shortcut=1")
        self.open()
        self.select("r6shortcut=1")
        for closer, shortcut in (("#close", "r"), ("#fab", KMOD + "+Enter")):
            self.P("#fab").click()
            self.P("#drawer.open").wait_for(timeout=10000)
            self.P(closer).click()
            self.assertFalse(self.active()["panel"], (closer, self.active()))
            before = self.calls("r6shortcut=1")
            self.page.keyboard.press(shortcut)
            wait_for(lambda: self.calls("r6shortcut=1") > before, 10, 0.2, "list shortcut after drawer close")
        self.assertEqual(self.errors, [])

    def test_r6_05_json_timer_does_not_touch_detached_editor(self):
        self.fetch("/bigline?mb=5&type=json&r6timer=1", timeout=60)
        self.open()
        self.select("r6timer=1")
        self.P("#fab").click()
        self.P('button[data-t="call"]').click()
        self.P("#mock").click()
        self.P("#main #body").wait_for(timeout=30000)
        self.assertGreater(self.P("#main #body").evaluate("e => e.value.length"), 1024 * 1024)
        self.P("#save").click()
        wait_for(lambda: "Saved" in self.P("#toast").inner_text(), 10, 0.1, "Map Local saved")
        # R6-05: start a fresh debounce and leave in the same event turn, before the timer can fire.
        self.page.evaluate("""() => { const sr = document.querySelector('#proxy-panel-host').shadowRoot, ta = sr.getElementById('body');
            ta.dispatchEvent(new Event('input', {bubbles:true})); sr.getElementById('back').click(); }""")
        wait_for(lambda: self.P("#main #body").count() == 0, 5, 0.1, "editor left")
        self.page.wait_for_timeout(650)
        self.assertEqual(self.errors, [])

    def test_r6_06_protobuf_builtin_view_uses_full_body(self):
        payload = b"z" * (300 * 1024)
        n = len(payload)
        varint = bytearray()
        while n > 127:
            varint.append((n & 127) | 128)
            n >>= 7
        varint.append(n)
        self.fetch("/grpc/Full/Body?r6proto=1", method="POST", data=b"\x0a" + bytes(varint) + payload,
                   headers={"Content-Type": "application/x-protobuf"}, timeout=60)
        seen = []
        self.open()
        self.page.on("request", lambda r: seen.append(r.url) if "/content/" in r.url and "Protocol%20Buffer" in r.url else None)
        self.select("r6proto=1")
        self.P("#fab").click()
        self.P('button[data-t="call"]').click()
        # Playwright's sync API delivers page.on() events only while Python is inside a Playwright call: a plain
        # bool(seen) loop never saw requests sent after click() returned (failed ~1 in 6, even alone; 2026-10-23)
        wait_for(lambda: self.page.wait_for_timeout(50) or bool(seen), 20, 0.2, "built-in protobuf request")
        self.assertTrue(all("full=1" in url for url in seen), seen)
        fid = self.inst.flow_for("r6proto=1")["id"]
        path = "/flows/%s/request/content/Protocol%%20Buffer.json" % fid
        clipped = self.panel.get_json(path)
        full = self.panel.get_json(path + "?full=1")
        self.assertIn("showing first", clipped["text"])
        self.assertNotIn("showing first", full["text"])
        self.assertGreater(len(full["text"]), len(clipped["text"]))
        self.assertEqual(self.errors, [])

    def test_r6_07_close_clears_editor_return_target(self):
        self.fetch("/json/small?r6return=1")
        self.open()
        self.select("r6return=1")
        self.P("#fab").click()
        self.P('button[data-t="call"]').click()
        self.P("#mock").click()
        self.P("#main #body").wait_for(timeout=10000)
        self.P("#close").click()
        self.P("#fab").click()
        self.P('button[data-t="map"]').click()
        self.P("#mh").fill("example.test")
        self.P("#mp").fill("/r6-return")
        self.P("#madd").click()
        self.P("#main #body").wait_for(timeout=10000)
        self.P("#back").click()
        wait_for(lambda: self.P("#main #madd").count() == 1, 10, 0.1, "back in map tab")
        self.assertEqual(self.active()["id"], "madd")
        self.assertEqual(self.errors, [])
