"""Visual QA round before the 2026-10-16 pilot (visual QA FINDINGS ISSUE-01/05/19/20): what a tester sees on a
13-inch laptop, with the Tools drawer open, on binary and long-URL calls, and while the proxy is unreachable."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase, shot   # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class PilotVisual(UiBase):
    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def select(self, text):
        row = self.page.locator(".flow-table tbody tr", has_text=text).first
        wait_for(lambda: row.count() > 0, 10, 0.2, "row %s" % text)
        row.click()
        self.page.wait_for_timeout(400)

    def call_tab(self):
        if not self.P("#drawer.open").count():
            self.P("#fab").click()
        self.P("button[data-t=call]").click()
        self.page.wait_for_timeout(600)

    def test_this_call_renders_for_a_binary_post(self):
        self.open()
        self.fetch("/echo?pv=bin", method="POST", data=os.urandom(1024), headers={"Content-Type": "application/octet-stream"})
        self.select("pv=bin")
        self.call_tab()
        shot(self.page, "pv-binary")
        wait_for(lambda: self.P("#main #mock").count() > 0, 5, 0.2, "This call shows its actions for a binary call")
        self.assertEqual([e for e in self.errors if e[0] == "pageerror"], [])

    def test_narrow_list_shows_the_path_not_the_host(self):
        self.page.set_viewport_size({"width": 1024, "height": 800})
        self.open()
        self.fetch("/json/small?pv=narrow")
        self.select("pv=narrow")
        self.call_tab()
        # the narrow layout is applied by an observer after the drawer opens; a fixed 500 ms was flaky under a loaded run
        self.page.wait_for_function("document.documentElement.dataset.narrow === '1'", timeout=10000)
        shot(self.page, "pv-narrow")
        self.assertEqual(self.page.evaluate("document.documentElement.dataset.narrow"), "1")
        got = self.page.evaluate("""() => { const c = [...document.querySelectorAll('.flow-table tbody td.col-path')].find((x) => x.textContent.includes('pv=narrow'));
            const host = c.textContent.indexOf('/', c.textContent.indexOf('://') + 3);
            return { indent: parseFloat(getComputedStyle(c).textIndent), ch: parseFloat(getComputedStyle(c).fontSize), host, title: c.title }; }""")
        self.assertLess(got["indent"], -got["ch"] * got["host"] * 0.4, "scheme and host are shifted out of a narrow row: %r" % got)
        self.assertIn("://", got["title"])                               # the full URL is still one hover away

    def test_lost_banner_never_covers_the_filter_box(self):
        self.open()
        box = self.page.evaluate("""() => { const sr = document.querySelector('#proxy-panel-host').shadowRoot, b = sr.querySelector('#lostbar');
            b.classList.add('open'); b.textContent = 'x'; const r = b.getBoundingClientRect(); return { top: r.top, h: innerHeight }; }""")
        self.assertGreater(box["top"], box["h"] / 2, "the proxy-down banner sits at the bottom, away from the toolbar")

    def test_long_url_keeps_the_call_actions_on_screen(self):
        self.open()
        self.fetch("/echo?" + "&".join("k%d=%s" % (i, "v" * 60) for i in range(40)) + "&pv=long")
        self.select("pv=long")
        self.call_tab()
        shot(self.page, "pv-long")
        top = self.page.evaluate("document.querySelector('#proxy-panel-host').shadowRoot.querySelector('#mock').getBoundingClientRect().top")
        self.assertLess(top, 400, "Map Local this call… stays near the top even for a huge query string")
