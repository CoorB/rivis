"""Unusual but legal values in the new main window: a Cookie pair with no '=', and switching Edit and Repeat
to another call while the form is dirty. Both used to show the wrong data or throw the user's edits away."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class EdgeBodies(UiBase):
    def setUp(self):
        super().setUp()
        self.context.grant_permissions(["clipboard-read", "clipboard-write"])

    def open_new(self, *paths):
        for p in paths or ("/json/small?nu=1", "/echo?nu=2", "/text?nu=3"):
            self.fetch(p)
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.goto("http://127.0.0.1:%d/rivis/" % self.inst.web_port)
        self.page.locator("#rv-app").wait_for(timeout=15000)
        self.errors[:] = [e for e in self.errors if not (e[0] == "requestfailed" and e[1].endswith("/proxy/api/state"))]
        return self.page

    def rows(self, text=None):
        loc = self.page.locator(".rv-tr")
        return loc.filter(has_text=text) if text else loc

    def wait_rows(self, text, n=1, timeout=10):
        wait_for(lambda: self.rows(text).count() >= n, timeout, 0.1, "row %s" % text)

    def win(self, wid):
        return self.page.locator('.rv-win[data-win="%s"]' % wid)

    def menu(self, text, act):
        self.wait_rows(text)
        self.rows(text).first.click(button="right")
        self.page.locator('#menu [data-act="%s"]' % act).click()

    def flow_id(self, text):
        return self.page.evaluate("""(t) => {
          const S = window.__rivisUI;
          for (const id of S.view) {
            const f = S.byId.get(id);
            if (f && ((f.request.path || '') + (f.request.pretty_host || '')).includes(t)) return id;
          }
          return null;
        }""", text)

    def test_cookie_without_equals_keeps_its_name(self):
        # A Cookie pair with no '=' is rare but legal on the wire. indexOf("=") === -1 made slice(0, -1) drop
        # the last character of the name and reuse the whole token as the value.
        self.open_new()
        self.fetch("/echo?edge=cookie", headers={"Cookie": "lonely; token=abc"})
        self.wait_rows("edge=cookie")
        self.rows("edge=cookie").first.click()
        self.page.locator("#pane-req [data-tab=cookies]").click()
        table = self.page.locator("#pane-req .rv-kv")
        wait_for(lambda: table.count() == 1 and "token" in table.inner_text(), 8, 0.1, "cookies")
        rows = table.locator("tr").evaluate_all(
            "els => els.map(r => [r.cells[0].textContent, r.cells[1].textContent])")
        self.assertIn(["lonely", ""], rows)
        self.assertIn(["token", "abc"], rows)
        self.assertNotIn(["lonel", "lonely"], rows)
        self.assertEqual(self.errors, [])

    def test_edit_and_repeat_asks_before_replacing_dirty_edits(self):
        # Opening Edit and Repeat for a second call used to load that call into the open window and wipe
        # whatever was typed for the first one, with no question. The right-click menu calls the same open().
        self.open_new("/echo?edge=rep1", "/echo?edge=rep2")
        self.wait_rows("edge=rep2")
        self.menu("edge=rep1", "edit")
        w = self.win("repeat")
        wait_for(lambda: w.is_visible() and w.locator("#rpu").count() == 1 and "edge=rep1" in w.locator("#rpu").input_value(),
                 10, 0.1, "first call loaded")
        edited = w.locator("#rpu").input_value() + "&kept=1"
        w.locator("#rpu").fill(edited)
        id2 = self.flow_id("edge=rep2")
        self.assertTrue(id2)
        self.page.evaluate("(id) => window.RivisTools.open('repeat', { fromFlow: id })", id2)
        dlg = self.page.locator("#dialog:not([hidden])")
        wait_for(lambda: dlg.count() == 1 and "different call" in dlg.inner_text().lower(), 5, 0.1, "ask first")
        self.page.locator("#dno").click()
        wait_for(lambda: dlg.count() == 0, 5, 0.1, "cancelled")
        self.assertEqual(w.locator("#rpu").input_value(), edited)
        self.page.evaluate("(id) => window.RivisTools.open('repeat', { fromFlow: id })", id2)
        wait_for(lambda: dlg.count() == 1, 5, 0.1, "ask again")
        self.page.locator("#dyes").click()
        wait_for(lambda: "edge=rep2" in w.locator("#rpu").input_value(), 10, 0.1, "second call loaded")
        self.assertNotIn("kept=1", w.locator("#rpu").input_value())
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main()
