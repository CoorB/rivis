"""A docked tool window must never cover the call list or the call's panes, at the widths laptops really use.
Found by the 0.9.11 release-candidate QA: fine at 1440, covered the selected row and both panes at 1280, 1024, 900."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402

MEASURE = """() => {
  const win = [...document.querySelectorAll('.rv-win')].find(w => !w.hidden && w.offsetWidth);
  if (!win) return {error: 'no tool window open'};
  const d = win.getBoundingClientRect(), out = {dock: [d.left, d.right], vw: innerWidth, covered: []};
  const sel = document.querySelector('.rv-tr[aria-selected="true"]');
  const parts = {row: sel, list: document.querySelector('.rv-list'), request: document.querySelector('.rv-pane'),
                 response: [...document.querySelectorAll('.rv-pane')].pop()};
  for (const [name, el] of Object.entries(parts)) {
    if (!el) { out.covered.push(name + ': missing'); continue; }
    const r = el.getBoundingClientRect();
    if (r.width && r.right > d.left + 1 && r.bottom > d.top && r.top < d.bottom) out.covered.push(name + ' right=' + Math.round(r.right));
  }
  out.past_viewport = Math.round(d.right - innerWidth);
  return out;
}"""


@unittest.skipIf(PW_REASON, PW_REASON or "")
class DockedToolAtLaptopWidths(UiBase):
    def open_with_call(self):
        self.fetch("/dock-1")
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.evaluate("() => { try { localStorage.clear(); } catch (e) {} }")
        self.page.goto("http://127.0.0.1:%d/rivis/" % self.inst.web_port)
        self.page.locator("#rv-app").wait_for(timeout=15000)
        wait_for(lambda: self.page.evaluate("!!(window.RivisTools && window.RivisApp && window.__rivisUI.state)"), 10, 0.1, "tools ready")
        self.page.locator(".rv-tr", has_text="dock-1").first.click()

    def check_width(self, width):
        self.page.set_viewport_size({"width": width, "height": 800})
        self.open_with_call()
        self.page.evaluate("() => window.RivisTools.open('compose')")
        self.page.wait_for_timeout(400)                               # the list makes room with a short transition
        m = self.page.evaluate(MEASURE)
        self.assertNotIn("error", m, m)
        self.assertEqual(m["covered"], [], "at %d px the docked tool covers: %s (dock x %s)" % (width, m["covered"], m["dock"]))
        self.assertLessEqual(m["past_viewport"], 0, "at %d px the docked tool sticks %d px out of the window" % (width, m["past_viewport"]))

    def test_docked_tool_clear_of_the_call_at_1440(self):
        self.check_width(1440)

    def test_docked_tool_clear_of_the_call_at_1280(self):
        self.check_width(1280)

    def test_docked_tool_clear_of_the_call_at_1024(self):
        self.check_width(1024)

    def test_docked_tool_clear_of_the_call_at_900(self):
        self.check_width(900)


if __name__ == "__main__":
    unittest.main()
