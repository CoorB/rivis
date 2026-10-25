"""The classic UI's hard-won list and menu cases, ported to the new main window (/rivis/): a click selects the pressed call
even when calls arrive during the press (0.9.9 F3), a drag is not a click, the right-click menu acts on its own call while
calls stream in and closes on an outside scroll, 5,000 calls stay quick, and a tool window gives focus back on Esc."""
import http.client
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402

MOD = "Meta" if sys.platform == "darwin" else "Control"


class NewUiBase(UiBase):
    def open_new(self, *paths):
        for p in paths:
            self.fetch(p)
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.goto("http://127.0.0.1:%d/rivis/" % self.inst.web_port)
        self.page.locator("#rv-app").wait_for(timeout=15000)
        # leaving the previous page (the classic login page polls state) aborts its poll: not this page's error
        self.errors[:] = [e for e in self.errors if not (e[0] == "requestfailed" and e[1].endswith("/proxy/api/state"))]
        wait_for(lambda: self.page.evaluate("!!(window.RivisApp && window.__rivisUI.state)"), 10, 0.1, "page ready")
        return self.page

    def rows(self, text=None):
        return self.page.locator(".rv-tr", has_text=text) if text else self.page.locator(".rv-tr")

    def selected_url(self):
        return self.page.evaluate("(() => { const S = window.__rivisUI, f = S.sel && S.byId.get(S.sel); return f ? f.request.path : null })()")

    def stream(self, every=0.3):
        stop = threading.Event()
        def run():
            n = 0
            while not stop.is_set():
                n += 1
                try:
                    self.fetch("/json/small?stream=%d" % n)
                except Exception:                          # noqa: BLE001
                    pass
                time.sleep(every)
        t = threading.Thread(target=run, daemon=True)
        t.start()
        self.addCleanup(lambda: (stop.set(), t.join(5)))


@unittest.skipIf(PW_REASON, PW_REASON or "")
class ListPressesDuringArrivals(NewUiBase):
    def prepare(self):
        self.open_new(*["/echo?seed=%02d" % i for i in range(30)])
        wait_for(lambda: self.rows("seed=29").count() == 1, 10, 0.1, "the calls listed")
        self.page.wait_for_timeout(400)

    def press_with_arrival(self, row, n):
        """Press on `row`, let call `n` arrive and the list redraw, then release at the same pixel."""
        box = row.bounding_box()
        x, y = box["x"] + box["width"] * 0.35, box["y"] + box["height"] / 2
        self.page.mouse.move(x, y, steps=4)
        self.page.mouse.down()
        self.fetch("/echo?arrive=%02d" % n)
        wait_for(lambda: self.page.evaluate("[...window.__rivisUI.byId.values()].some((f) => f.request.path.includes('arrive=%02d'))" % n),
                 10, 0.05, "call %d in the model" % n)
        self.page.wait_for_timeout(150)                    # the list has redrawn under the pointer
        self.page.mouse.up()

    def test_click_selects_the_pressed_call_even_if_a_call_arrives_during_the_press(self):
        self.prepare()
        for n in range(3):
            self.page.keyboard.press("Escape")
            row = self.rows("seed=%02d" % (27 - n))
            self.press_with_arrival(row, n)
            wait_for(lambda: (self.selected_url() or "").endswith("seed=%02d" % (27 - n)), 3, 0.1,
                     "seed=%02d selected (call %d arrived mid-press; selected: %s)" % (27 - n, n, self.selected_url()))
        self.assertEqual(self.errors, [])

    def test_the_pressed_call_is_selected_when_newest_first_shifts_the_rows(self):
        self.prepare()
        self.page.locator('.rv-th[data-col="seq"]').click()   # sort by #…
        self.page.locator('.rv-th[data-col="seq"]').click()   # …newest first
        self.page.wait_for_timeout(300)
        row = self.rows("seed=20")
        self.press_with_arrival(row, 9)
        wait_for(lambda: (self.selected_url() or "").endswith("seed=20"), 3, 0.1, "seed=20 selected, not the row shifted under the pointer")

    def test_newest_first_with_follow_shows_the_newest_at_the_top(self):
        self.prepare()
        self.page.locator('.rv-th[data-col="seq"]').click()
        self.page.locator('.rv-th[data-col="seq"]').click()
        wait_for(lambda: self.page.evaluate("document.getElementById('tscroll').scrollTop") == 0, 3, 0.1, "scrolled to the top")
        self.assertIn("seed=29", self.rows().first.inner_text())

    def test_a_drag_across_rows_is_not_a_click(self):
        self.prepare()
        before = self.selected_url()
        box = self.rows("seed=22").bounding_box()
        self.page.mouse.move(box["x"] + 40, box["y"] + box["height"] / 2, steps=4)
        self.page.mouse.down()
        self.page.mouse.move(box["x"] + 40, box["y"] + box["height"] * 3.5, steps=6)
        self.page.mouse.up()
        self.page.wait_for_timeout(400)
        self.assertEqual(self.selected_url(), before)

    def test_plain_click_still_selects(self):
        self.prepare()
        self.rows("seed=24").click()
        wait_for(lambda: (self.selected_url() or "").endswith("seed=24"), 3, 0.1, "selected")


@unittest.skipIf(PW_REASON, PW_REASON or "")
class MenuWhileStreaming(NewUiBase):
    def setUp(self):
        super().setUp()
        self.context.grant_permissions(["clipboard-read", "clipboard-write"])

    def tearDown(self):
        try:
            for b in self.panel.state().get("breakpoints") or []:
                self.panel.ok("bp_delete", {"name": b["name"]})
        finally:
            super().tearDown()

    def menu_on(self, text):
        self.rows(text).first.click(button="right")
        wait_for(lambda: self.page.locator("#menu:not([hidden])").count() == 1, 5, 0.1, "menu open")
        self.page.wait_for_timeout(1200)                   # several polls and new rows
        self.assertEqual(self.page.locator("#menu:not([hidden])").count(), 1, "menu closed by itself while calls stream in")

    def press(self, act):
        b = self.page.locator('#menu [data-act="%s"]' % act).bounding_box()
        self.page.mouse.move(b["x"] + 30, b["y"] + b["height"] / 2, steps=6)
        self.page.mouse.down()
        self.page.wait_for_timeout(60)
        self.page.mouse.up()

    def test_menu_items_act_on_their_own_call_while_calls_stream_in(self):
        self.open_new("/json/small?target=1")
        self.stream()
        self.page.wait_for_timeout(1000)
        self.menu_on("target=1")
        self.press("url")
        wait_for(lambda: "URL copied" in self.page.locator("#toast").inner_text(), 5, 0.1, "Copy URL acted")
        self.assertIn("target=1", self.page.evaluate("navigator.clipboard.readText()"))
        self.menu_on("target=1")
        self.press("bp")
        wait_for(lambda: any("target" in (b.get("match") or "") or "small" in (b.get("match") or "")
                             for b in self.panel.state().get("breakpoints") or []), 5, 0.1, "breakpoint added for the call")
        self.assertEqual(self.errors, [])

    def test_an_outside_scroll_or_click_closes_the_menu(self):
        self.open_new(*["/json/small?m=%d" % i for i in range(40)])
        wait_for(lambda: self.rows().count() > 10, 10, 0.1, "rows")
        self.menu_on("m=35")
        box = self.page.locator("#tscroll").bounding_box()
        self.page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
        self.page.mouse.wheel(0, 200)
        wait_for(lambda: self.page.locator("#menu:not([hidden])").count() == 0, 3, 0.1, "wheel scroll closes")
        self.menu_on("m=35")
        self.page.mouse.click(5, 300)
        wait_for(lambda: self.page.locator("#menu:not([hidden])").count() == 0, 3, 0.1, "outside click closes")


@unittest.skipIf(PW_REASON, PW_REASON or "")
class WindowFocus(NewUiBase):
    def test_a_tool_chord_takes_focus_and_esc_gives_it_back(self):
        self.open_new("/json/small?wf=1")
        self.rows("wf=1").click()
        self.page.keyboard.press(MOD + "+Alt+R")
        wait_for(lambda: self.page.evaluate("!!document.activeElement.closest('.rv-win[data-win=\"rules\"]')"), 5, 0.1, "focus in the window")
        self.page.keyboard.press("Escape")
        wait_for(lambda: self.page.locator('.rv-win[data-win="rules"]').is_hidden(), 5, 0.1, "window closed")
        wait_for(lambda: self.page.evaluate("document.activeElement && document.activeElement.id === 'tscroll'"), 5, 0.1,
                 "focus back on the list (%s)" % self.page.evaluate("document.activeElement && (document.activeElement.id || document.activeElement.tagName)"))
        self.page.keyboard.press("ArrowUp")                # the list keys work straight away
        self.assertEqual(self.errors, [])


@unittest.skipIf(PW_REASON, PW_REASON or "")
class Scale(NewUiBase):
    INSTANCE_KW = {"extra_env": {"RIVIS_MAX_FLOWS": "20000"}}
    N, BUDGET_S = 5000, 3.0

    def timed(self, label, action, done, results):
        t = time.perf_counter()
        action()
        wait_for(done, 30, 0.05, label)
        results[label] = round(time.perf_counter() - t, 2)

    def test_everyday_actions_stay_quick_with_5000_calls(self):
        host = "127.0.0.1:%d" % self.up.http_port
        conn = http.client.HTTPConnection("127.0.0.1", self.inst.proxy_port)
        for i in range(self.N):
            conn.request("GET", "http://%s/json/small?n=%d" % (host, i), headers={"Host": host})
            conn.getresponse().read()
        conn.request("GET", "http://%s/echo?needle=1" % host, headers={"Host": host})
        conn.getresponse().read()
        wait_for(lambda: len(self.inst.flows()) > self.N, 60, 0.5, "%d flows" % self.N)
        r = {}
        self.timed("open page", lambda: self.open_new(), lambda: self.page.evaluate("window.__rivisUI.order.length") > self.N, r)
        self.timed("select a call", lambda: self.rows("n=4995").first.click(), lambda: (self.selected_url() or "").endswith("n=4995"), r)
        self.timed("filter to one call", lambda: self.page.locator("#q").fill("needle"),
                   lambda: self.rows("needle").count() == 1 and self.rows("json/small").count() == 0, r)
        self.timed("open Map Remote & Rules", lambda: self.page.keyboard.press(MOD + "+Alt+R"),
                   lambda: self.page.locator('.rv-win[data-win="rules"]').is_visible(), r)
        self.page.keyboard.press("Escape")
        self.timed("back to the top", lambda: (self.page.locator("#q").fill(""), self.page.locator("#tscroll").focus(), self.page.keyboard.press("Home")),
                   lambda: self.rows("n=0").count() >= 1, r)
        for label, secs in r.items():
            self.assertLess(secs, self.BUDGET_S if label != "open page" else 2 * self.BUDGET_S,
                            "%s took %.2fs with %d calls: %s" % (label, secs, self.N, r))
        self.assertEqual(self.errors, [])


@unittest.skipIf(PW_REASON, PW_REASON or "")
class OpenAtTheFlowCap(NewUiBase):
    """QA cycle 5 reported 23 s to open the window over a capture of about 6,000 calls. It did not reproduce — the
    same measurement is a quarter of a second, including on the very commit it was reported against — but nothing
    guarded the case it described, which Scale above does not cover: the DEFAULT flow cap, so the trim path runs; a
    client that opens a connection per call, so every call is attributed; and calls still arriving while the window
    opens. Budgets are generous; this catches a regression into seconds, not a few hundred milliseconds.
    """
    PREFILL, PER_CONNECTION, BUDGET_S = 5200, 150, 6.0      # past the 5000 cap, so the trim path runs

    def prefill(self):
        host = "127.0.0.1:%d" % self.up.http_port
        conn = http.client.HTTPConnection("127.0.0.1", self.inst.proxy_port)
        for i in range(self.PREFILL):
            try:
                conn.request("GET", "http://%s/json/small?p=%d" % (host, i), headers={"Host": host})
                conn.getresponse().read()
            except OSError:
                conn = http.client.HTTPConnection("127.0.0.1", self.inst.proxy_port)
        for i in range(self.PER_CONNECTION):        # its own connection each time: one attribution per call
            self.fetch("/json/small?own=%d" % i)

    def test_the_window_opens_quickly_at_the_flow_cap_with_calls_still_arriving(self):
        self.prefill()
        trimmed = self.panel.state()["retention"]
        self.assertTrue(trimmed.get("trimmed"), "the capture must pass the flow cap, or this guards nothing: %s" % trimmed)
        stop = threading.Event()
        sent = []

        def stream():
            while not stop.is_set():
                try:
                    self.fetch("/json/small?live=%d" % len(sent))
                    sent.append(1)
                except Exception:                   # noqa: BLE001 - the stream is background noise, not the assertion
                    pass
                time.sleep(0.08)

        feed = threading.Thread(target=stream, daemon=True)
        feed.start()
        self.addCleanup(lambda: (stop.set(), feed.join(5)))
        try:
            t = time.perf_counter()
            self.page.add_init_script("try { localStorage.setItem('rivis-ui-welcome', 'done') } catch (e) {}")
            self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
            self.page.goto("http://127.0.0.1:%d/rivis/" % self.inst.web_port)
            self.page.locator("#rv-app").wait_for(timeout=30000)
            kept = len(self.inst.flows())
            wait_for(lambda: self.page.evaluate("window.__rivisUI.order.length") >= kept * 0.9, 60, 0.2, "the list")
            listed = time.perf_counter() - t
            wait_for(lambda: " calls" in (self.page.locator("#status").inner_text() or ""), 60, 0.2, "the footer count")
            footed = time.perf_counter() - t
            wait_for(lambda: self.page.locator(".rv-tr").count() > 0, 60, 0.2, "rows on screen")
            drawn = time.perf_counter() - t
        finally:
            stop.set()
            feed.join(5)
        self.assertLess(listed, self.BUDGET_S, "the list took %.1f s (footer %.1f s, rows %.1f s)" % (listed, footed, drawn))
        self.assertLess(drawn, self.BUDGET_S, "the rows took %.1f s" % drawn)
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main()
