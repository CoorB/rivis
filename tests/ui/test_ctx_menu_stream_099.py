"""0.9.9: the call-list right-click menu while calls stream in. Pilot report: clicking ANY item (Map Local, Pause, Copy URL,
Show only this host) closed the menu and did nothing. Cause: the menu's close listener (blur / scroll / resize, after 700 ms)
fired in the middle of the press — Safari / WebKit moves focus off the button on mousedown, and the streaming list scrolls — so
the button was hidden before mouseup and the click never happened."""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402

CHECKS = {"url": lambda t, d: "URL copied" in t, "map": lambda t, d: d, "bp": lambda t, d: "Breakpoint on" in t,
          "host": lambda t, d: "Showing only" in t}


@unittest.skipIf(PW_REASON, PW_REASON or "")
class CtxMenuStreaming(UiBase):
    ITEMS = ("url", "host", "bp", "map")

    def setUp(self):
        super().setUp()
        try:
            self.context.grant_permissions(["clipboard-read", "clipboard-write"], origin="http://127.0.0.1:%d" % self.inst.web_port)
        except Exception:                                  # noqa: BLE001 - WebKit has no clipboard permission
            pass

    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def toast(self):
        return self.page.evaluate("document.querySelector('#proxy-panel-host').shadowRoot.querySelector('#toast').innerText")

    def stream(self):
        stop = threading.Event()

        def run():
            n = 0
            while not stop.is_set():
                n += 1
                try:
                    self.fetch("/json/small?stream=%d" % n)
                except Exception:                          # noqa: BLE001
                    pass
                time.sleep(0.3)
        t = threading.Thread(target=run, daemon=True)
        t.start()
        self.addCleanup(lambda: (stop.set(), t.join(5)))

    def menu_on(self):
        self.page.locator(".flow-table tbody tr", has_text="a=1").first.click(button="right")
        wait_for(lambda: self.P("#cmenu.open").count() > 0, 5, 0.1, "menu open")
        self.page.wait_for_timeout(1200)       # past the 700 ms grace; several polls and new rows

    def pointer_press(self, k, between=None):
        b = self.P("#cmenu button[data-k=%s]" % k).bounding_box()
        self.page.mouse.move(b["x"] + 30, b["y"] + 8, steps=6)
        self.page.mouse.down()
        if between:
            between()
        self.page.wait_for_timeout(60)
        self.page.mouse.up()

    def assert_acts(self, k):
        try:
            wait_for(lambda: CHECKS[k](self.toast(), self.P("#drawer.open").count() > 0), 5, 0.2, k)
        except AssertionError:
            self.fail("menu item %r did nothing (toast=%r)" % (k, self.toast()))

    def test_every_item_acts_while_calls_stream_in(self):
        self.open()
        self.stream()
        self.page.wait_for_timeout(1500)
        for k in self.ITEMS:
            self.menu_on()
            self.pointer_press(k)
            self.assert_acts(k)
            self.assertFalse(self.P("#cmenu.open").count(), "menu stays open after %s" % k)
            if self.P("#drawer.open").count():
                self.P("#fab").click()
            self.page.wait_for_timeout(300)
        self.assertEqual(self.errors, [])

    def test_press_survives_focus_leaving_the_menu_button(self):
        """Safari/WebKit semantics in any browser: mousedown on a menu button blurs the focused button (focus goes to the page)."""
        self.open()
        self.menu_on()
        self.page.evaluate("""document.querySelector('#proxy-panel-host').shadowRoot.querySelector('#cmenu')
            .addEventListener('mousedown', () => { const a = document.querySelector('#proxy-panel-host').shadowRoot.activeElement; if (a) a.blur(); }, true)""")
        self.pointer_press("url")
        self.assert_acts("url")

    def test_press_survives_a_scroll_or_resize_mid_click(self):
        self.open()
        for ev in ("scroll", "resize"):
            self.menu_on()
            self.pointer_press("url", between=lambda: self.page.evaluate(
                "document.querySelector('.flow-table').dispatchEvent(new Event('scroll')); window.dispatchEvent(new Event('resize'))"))
            self.assert_acts("url")

    def test_outside_scroll_and_blur_still_close_the_menu(self):
        self.open()
        self.menu_on()
        self.page.evaluate("window.dispatchEvent(new Event('scroll'))")
        wait_for(lambda: not self.P("#cmenu.open").count(), 3, 0.1, "scroll closes")
        self.menu_on()
        self.page.mouse.click(5, 300)
        wait_for(lambda: not self.P("#cmenu.open").count(), 3, 0.1, "outside click closes")


@unittest.skipIf(PW_REASON, PW_REASON or "")
class CtxMenuWebKit(UiBase):
    """The same streaming scenario in WebKit (Safari's engine), where the bug showed on every item. Skips without WebKit."""
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            wk = cls.pw.webkit.launch()
        except Exception as exc:                           # noqa: BLE001
            super().tearDownClass()
            raise unittest.SkipTest("WebKit for Playwright is not installed (%s): python3 -m playwright install webkit" % str(exc).splitlines()[0])
        cls.browser.close()
        cls.browser = wk

    test_every_item_acts_while_calls_stream_in = CtxMenuStreaming.test_every_item_acts_while_calls_stream_in
    P, toast, stream, menu_on, pointer_press, assert_acts = (CtxMenuStreaming.P, CtxMenuStreaming.toast, CtxMenuStreaming.stream,
                                                             CtxMenuStreaming.menu_on, CtxMenuStreaming.pointer_press,
                                                             CtxMenuStreaming.assert_acts)
    ITEMS = ("host", "bp", "map")
