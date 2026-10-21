"""0.9.9: the right-click menu on a call list that FOLLOWS new calls. The list scrolls itself on every new call, and the menu used to
close on any scroll event after 700 ms, so it vanished while the pointer travelled to an item and the click landed on nothing.
The menu must close only on user intent (outside press, wheel, scroll keys, Escape, window blur, real resize)."""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class CtxMenuFollow(UiBase):
    def setUp(self):
        super().setUp()
        try:
            self.context.grant_permissions(["clipboard-read", "clipboard-write"], origin="http://127.0.0.1:%d" % self.inst.web_port)
        except Exception:                                  # noqa: BLE001
            pass

    def tearDown(self):
        try:                                               # the Rivis is shared by the class: no breakpoint or host filter may leak on
            for b in self.panel.state().get("breakpoints") or []:
                self.panel.ok("bp_delete", {"name": b["name"]})
            self.panel.ok("focus_host", {"host": None})
        finally:
            super().tearDown()

    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def toast(self):
        return self.page.evaluate("document.querySelector('#proxy-panel-host').shadowRoot.querySelector('#toast').innerText")

    def menu_open(self):
        return self.P("#cmenu.open").count() > 0

    def prepare(self, where="end"):
        self.page.set_viewport_size({"width": 1512, "height": 837})
        for i in range(80):
            self.fetch("/echo?seed=%d" % i)
        self.open()
        stop = threading.Event()

        def pump():
            n = 0
            while not stop.is_set():
                try:
                    self.fetch("/echo?live=%d" % n)
                except Exception:                          # noqa: BLE001
                    pass
                n += 1
                time.sleep(0.3)
        t = threading.Thread(target=pump, daemon=True)
        t.start()
        self.addCleanup(lambda: (stop.set(), t.join(5)))
        self.page.wait_for_timeout(2000)
        self.page.evaluate("""() => { window.__scrolls = 0; document.querySelector('.flow-table').addEventListener('scroll', () => window.__scrolls++);
            const ft = document.querySelector('.flow-table'); ft.scrollTop = %s; }""" % ("ft.scrollHeight" if where == "end" else "ft.scrollHeight / 2"))
        self.page.wait_for_timeout(800)

    def open_menu(self, wait_ms):
        idx = self.page.evaluate("""() => { const ft = document.querySelector('.flow-table').getBoundingClientRect();
            const rs = [...document.querySelectorAll('.flow-table tbody tr')];
            const ok = rs.map((r, i) => [r, i]).filter(([r]) => { const b = r.getBoundingClientRect(); return /echo\\?/.test(r.innerText) && b.top > ft.top + 40 && b.bottom < ft.bottom - 10; });
            return ok.length ? ok[Math.floor(ok.length / 2)][1] : -1; }""")
        self.assertGreaterEqual(idx, 0, "no visible echo row")
        row = self.page.locator(".flow-table tbody tr").nth(idx)
        self.url = row.inner_text()
        row.click(button="right")
        wait_for(self.menu_open, 5, 0.1, "menu open")
        self.page.wait_for_timeout(wait_ms)
        self.assertTrue(self.menu_open(), "menu closed by itself after %d ms while the list followed new calls" % wait_ms)

    def click_item(self, k):
        b = self.P("#cmenu button[data-k=%s]" % k).bounding_box()
        self.assertTrue(b, "menu closed by itself before %s" % k)
        self.page.mouse.move(b["x"] + 30, b["y"] + 8, steps=8)
        self.page.mouse.down()
        self.page.wait_for_timeout(60)
        self.page.mouse.up()

    def wait_toast(self, text):
        try:
            wait_for(lambda: text in self.toast(), 5, 0.2, text)
        except AssertionError:
            self.fail("expected toast %r, got %r" % (text, self.toast()))

    def run_case(self, where, wait_ms):
        self.prepare(where)
        for k in ("url", "host", "map", "bp"):
            self.open_menu(wait_ms)
            self.click_item(k)
            if k == "url":
                self.wait_toast("URL copied")
            elif k == "host":
                self.wait_toast("Showing only")
            elif k == "bp":
                self.wait_toast("Breakpoint on")
            else:
                wait_for(lambda: self.P("#drawer.open").count() > 0, 5, 0.2, "Map Local editor")
                self.P("#fab").click()
            self.assertFalse(self.menu_open())
            self.page.wait_for_timeout(300)
        self.assertEqual(self.errors, [])

    def test_follow_at_end_1_5s(self):
        self.run_case("end", 1500)

    def test_follow_at_end_3s(self):
        self.run_case("end", 3000)

    def test_list_in_the_middle_3s(self):
        self.run_case("middle", 3000)

    def test_menu_targets_its_own_call_after_selection_moves(self):
        self.prepare("end")
        self.open_menu(1500)
        want = self.page.evaluate("""() => { const sr = document.querySelector('#proxy-panel-host').shadowRoot;
            return sr.querySelector('#cmenu .hd').innerText; }""")
        self.page.evaluate("""() => { const rows = [...document.querySelectorAll('.flow-table tbody tr')];
            rows[0].click(); }""")                         # the selection moves to another row; the menu stays
        self.page.wait_for_timeout(500)
        self.assertTrue(self.menu_open())
        self.click_item("url")
        self.wait_toast("URL copied")
        try:
            clip = self.page.evaluate("navigator.clipboard.readText()")
        except Exception:                                  # noqa: BLE001
            self.skipTest("no clipboard read")
        path = want.split(" ", 1)[1]
        self.assertTrue(self.url.split("\t")[2].strip() in clip or path.split("?")[0] in clip, "Copy URL used another call than the menu was opened on")
        self.assertIn(self.url.split("\t")[2].strip().split("?")[-1], clip)

    def test_real_wheel_scroll_still_closes_the_menu(self):
        self.prepare("end")
        self.open_menu(1500)
        self.page.mouse.move(600, 300)
        self.page.mouse.wheel(0, -300)
        wait_for(lambda: not self.menu_open(), 3, 0.1, "wheel closes")

    def test_escape_and_outside_press_still_close(self):
        self.prepare("end")
        self.open_menu(1000)
        self.page.keyboard.press("Escape")
        wait_for(lambda: not self.menu_open(), 3, 0.1, "Escape closes")
        self.open_menu(1000)
        self.page.mouse.click(5, 300)
        wait_for(lambda: not self.menu_open(), 3, 0.1, "outside press closes")
