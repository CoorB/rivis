"""Pilot 2026-10-21: "the delete/clear button doesn't work, so calls keep piling up". Both asked with the browser's
confirm(): once someone ticks "Prevent this page from creating additional dialogs", confirm() answers "no" at once and
shows nothing, so the buttons looked dead. The panel now asks inside the page; these tests run in a browser whose
confirm()/prompt() behave like that suppressed state."""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import REPO, wait_for      # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402

ROWS = ".flow-table tbody tr:has(td.col-path)"
SUPPRESSED = "window.confirm = () => false; window.prompt = () => null; window.alert = () => undefined;"


class NoBrowserDialogs(unittest.TestCase):
    def test_the_panel_never_uses_the_browsers_own_dialogs(self):
        src = open(os.path.join(REPO, "addons", "panel.js")).read()
        code = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("//"))
        self.assertEqual(re.findall(r"(?<![\w.])(?:window\.)?(confirm|prompt|alert)\(", code), [])


@unittest.skipIf(PW_REASON, PW_REASON or "")
class ClearList(UiBase):
    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def start(self):
        self.page.add_init_script(SUPPRESSED)
        page = self.open()
        rows = page.locator(ROWS)
        wait_for(lambda: rows.count() >= 3, 10, 0.2, "rows")
        return page, rows

    def test_trash_button_clears_the_list_after_yes(self):
        page, rows = self.start()
        self.P("#strash").click()
        dlg = self.P("#askdlg.open")
        dlg.wait_for(timeout=5000)
        self.assertIn("Clear all", dlg.text_content())
        self.P("#ask-yes").click()
        wait_for(lambda: len(self.inst.flows()) == 0, 10, 0.2, "the list emptied on the proxy")
        wait_for(lambda: rows.count() == 0, 10, 0.2, "the table emptied")
        wait_for(lambda: "List cleared" in self.P("#toast").text_content(), 5, 0.2, "toast")
        self.fetch("/json/small?after=1")
        wait_for(lambda: rows.count() == 1, 10, 0.2, "new calls show again after a clear")

    def test_cancel_and_escape_keep_the_list(self):
        page, rows = self.start()
        before = len(self.inst.flows())
        self.P("#strash").click()
        self.P("#askdlg.open").wait_for(timeout=5000)
        self.P("#ask-no").click()
        self.P("#strash").click()
        self.P("#askdlg.open").wait_for(timeout=5000)
        page.keyboard.press("Escape")
        page.wait_for_timeout(600)
        self.assertFalse(self.P("#askdlg.open").count())
        self.assertEqual(len(self.inst.flows()), before)

    def test_delete_one_call_from_its_menu(self):
        page, rows = self.start()
        self.fetch("/json/small?delme=1")
        row = page.locator(".flow-table tbody tr", has_text="delme=1").first
        wait_for(lambda: row.count() > 0, 10, 0.2, "row")
        before = len(self.inst.flows())
        row.click(button="right")
        self.P("#cmenu button[data-k=del]").click()
        self.P("#askdlg.open").wait_for(timeout=5000)
        self.P("#ask-yes").click()
        wait_for(lambda: len(self.inst.flows()) == before - 1, 10, 0.2, "the call deleted")
        self.assertFalse([f for f in self.inst.flows() if "delme=1" in f["request"]["path"]])

    def test_save_as_asks_for_the_name_in_the_panel(self):
        page, rows = self.start()
        self.P("#fab").click()
        self.P("button[data-t=compose]").click()
        self.P("#cu").fill(self.up.url("/echo?named=1"))
        self.P("#csaveas").click()
        self.P("#ask-in").wait_for(timeout=5000)
        self.P("#ask-in").fill("asked-in-panel")
        self.P("#ask-in").press("Enter")
        wait_for(lambda: self.panel.post("compose_load", {"name": "asked-in-panel"})[0] == 200, 8, 0.2, "saved under the typed name")
        self.panel.ok("compose_delete", {"name": "asked-in-panel"})


if __name__ == "__main__":
    unittest.main()
