"""UI smoke in a real browser (Playwright + Chromium): open the UI, open the panel, click every tab, type into editors
(mitmweb's single-key shortcuts must not fire), no console errors. Screenshots go to tests/.artifacts/.

Skips with a reason when Playwright or its Chromium is missing. To enable on a machine that has neither:
    pip3 install --user playwright && python3 -m playwright install chromium
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import harness
from harness import Background, LiveCase, wait_for

try:
    from playwright.sync_api import sync_playwright
    PW_REASON = None
except ImportError as exc:                       # pragma: no cover - environment dependent
    sync_playwright = None
    PW_REASON = ("Playwright is not importable (%s). Enable with: pip3 install --user playwright && "
                 "python3 -m playwright install chromium" % exc)

TABS = ["call", "compose", "map", "bp", "net", "coll", "cmp", "sess", "scripts", "rules"]


def shot(page, name):
    os.makedirs(harness.ARTIFACTS, exist_ok=True)
    path = os.path.join(harness.ARTIFACTS, "ui-%s.png" % name)
    page.screenshot(path=path)
    return path


@unittest.skipIf(PW_REASON, PW_REASON or "")
class UiSmoke(LiveCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.pw = sync_playwright().start()
        try:
            cls.browser = cls.pw.chromium.launch()
        except Exception as exc:                 # noqa: BLE001 - Chromium not downloaded
            cls.pw.stop()
            raise unittest.SkipTest("Chromium for Playwright is not installed (%s). Enable with: "
                                    "python3 -m playwright install chromium" % str(exc).splitlines()[0])

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls.pw.stop()
        finally:
            super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.errors = []
        self.context = self.browser.new_context(viewport={"width": 1400, "height": 900})
        self.page = self.context.new_page()
        self.page.on("console", lambda m: self.errors.append(("console.error", m.text)) if m.type == "error" else None)
        self.page.on("pageerror", lambda e: self.errors.append(("pageerror", str(e))))
        self.page.on("requestfailed", lambda r: self.errors.append(("requestfailed", r.url)) if "/proxy/" in r.url else None)

    def tearDown(self):
        self.context.close()

    def panel_text(self):
        return self.page.evaluate("document.querySelector('#proxy-panel-host').shadowRoot.textContent")

    def open(self, first_run=False):
        for path in ("/json/small", "/echo?a=1", "/text"):
            self.fetch(path)
        if not first_run:   # the "Coming from Proxyman?" welcome (and its backdrop) shows once per browser; most tests start past it
            self.page.add_init_script("try { localStorage.setItem('rivis-welcome', 'done') } catch (e) {}")
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.wait_for_selector("#fab", timeout=20000)
        return self.page

    def test_page_loads_with_flows_and_the_panel_button(self):
        page = self.open()
        wait_for(lambda: page.get_by_text("/json/small").count() > 0, 10, 0.2, "flow rows rendered")
        shot(page, "flows")
        self.assertEqual(self.errors, [])

    def test_first_run_welcome_shows_once_and_closes_on_escape(self):
        page = self.open(first_run=True)
        welcome = page.locator("#proxy-panel-host #welcome.open")
        welcome.wait_for(timeout=10000)
        page.keyboard.press("Escape")
        wait_for(lambda: welcome.count() == 0, 5, 0.1, "welcome closed on Esc")
        page.reload()
        page.wait_for_selector("#fab", timeout=20000)
        page.wait_for_timeout(500)
        self.assertEqual(welcome.count(), 0, "welcome must not come back after it was closed")
        self.assertEqual(self.errors, [])

    def test_open_the_panel_and_click_every_tab(self):
        page = self.open()
        page.locator("#fab").click()
        tabs = page.locator("button[data-t]")
        self.assertEqual([tabs.nth(i).get_attribute("data-t") for i in range(tabs.count())], TABS)
        for name in TABS:
            btn = page.locator("button[data-t=%s]" % name)
            btn.click()
            wait_for(lambda: "on" in (btn.get_attribute("class") or "").split(), 5, 0.1, "tab %s active" % name)
            page.wait_for_timeout(200)
            shot(page, "tab-" + name)
        self.assertEqual(self.errors, [])

    def test_this_call_tab_describes_the_selected_flow(self):
        page = self.open()
        page.get_by_text("/echo?a=1").first.click()
        page.locator("#fab").click()
        page.locator("button[data-t=call]").click()
        wait_for(lambda: "echo" in self.panel_text(), 8, 0.2, "call details")
        shot(page, "this-call")
        self.assertEqual(self.errors, [])

    def test_typing_into_a_panel_editor_does_not_trigger_mitmweb_shortcuts(self):
        self.reset_state(breakpoints=[{"name": "b", "match": r"/echo\?bp", "request": True, "response": False, "enabled": True}])
        page = self.open()
        before = len(self.inst.flows())
        call = Background(self.fetch, "/echo?bp=1", method="POST", data="orig", timeout=40)
        wait_for(lambda: self.panel.state()["paused"], 15, 0.2, "paused call")
        box = page.locator("#pb")
        box.wait_for(timeout=15000)
        box.click()
        box.fill("")
        text = "dar adx e r d a"            # d=delete a=resume r=replay in mitmweb's own key map
        box.press_sequentially(text, delay=15)
        self.assertEqual(box.input_value(), text)
        page.wait_for_timeout(500)
        self.assertEqual(len(self.panel.state()["paused"]), 1, "a shortcut resumed or removed the paused call")
        self.assertGreaterEqual(len(self.inst.flows()), before)
        shot(page, "editor-typing")
        page.locator("text=Continue").last.click()
        r = call.result(30)
        self.assertEqual(r.json()["body"], text)
        self.assertEqual(self.errors, [])

    def test_dark_and_reduced_motion_preferences_do_not_break_the_panel(self):
        page = self.open()
        page.emulate_media(color_scheme="dark", reduced_motion="reduce")
        page.locator("#fab").click()
        for name in ("rules", "net", "scripts"):
            page.locator("button[data-t=%s]" % name).click()
            page.wait_for_timeout(150)
        shot(page, "dark")
        self.assertEqual(self.errors, [])

    def test_rules_added_through_the_api_appear_in_the_rules_tab(self):
        page = self.open()
        page.locator("#fab").click()
        self.panel.ok("add", {"rule": {"name": "ui-rule", "action": "block", "match": "/x"}})
        wait_for(lambda: "Rules2" in self.panel_text().replace(" ", "").replace("\n", ""), 10, 0.3, "tab counter refreshed")
        page.locator("button[data-t=scripts]").click()
        page.locator("button[data-t=rules]").click()
        wait_for(lambda: "ui-rule" in self.panel_text(), 10, 0.3, "rule shown after re-opening the tab")
        self.assertEqual(self.errors, [])

    @unittest.expectedFailure
    def test_open_rules_tab_refreshes_when_a_rule_is_added_elsewhere(self):
        """FOUND-BUGS B15: the tab counter updates from the poll, the list of the OPEN tab stays stale."""
        page = self.open()
        page.locator("#fab").click()
        page.locator("button[data-t=rules]").click()
        self.panel.ok("add", {"rule": {"name": "elsewhere", "action": "block", "match": "/x"}})
        wait_for(lambda: "elsewhere" in self.panel_text(), 8, 0.3, "open list refreshed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
