"""Saved filter chips and Paste cURL in the browser panel."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for
from test_ui import PW_REASON, UiBase


@unittest.skipIf(PW_REASON, PW_REASON or "")
class FiltersCurlUi(UiBase):
    def test_cycle5_suggested_filter_name_can_be_saved(self):
        self.open()
        self.P("#sq").fill("~m POST")
        self.P("#ssave").click()
        self.P("#ask-in").wait_for()
        name = self.P("#ask-in").input_value()
        self.P("#ask-yes").click()
        wait_for(lambda: any(x["name"] == name for x in self.panel.state()["saved_filters"]),
                 5, 0.1, "suggested name saved")

    def test_cycle5_invalid_and_duplicate_filter_names_keep_the_dialog(self):
        self.open()
        self.panel.ok("filters_save", {"name": "Existing", "filter": "~m GET"})
        self.P("#sq").fill("~m POST")
        self.P("#ssave").click()
        for name, error in (("bad/name", "filter name:"), ("Existing", "already exists")):
            self.answer(name)
            self.page.wait_for_timeout(500)
            self.assertTrue(self.P("#askdlg.open").count(), "failed save must keep the dialog")
            self.assertEqual(self.P("#ask-in").input_value(), name)
            self.assertIn(error, self.P("#askdlg").inner_text())
        self.answer("Posts fixed")
        wait_for(lambda: any(x["name"] == "Posts fixed" for x in self.panel.state()["saved_filters"]),
                 5, 0.1, "corrected name saved")

    def test_cycle5_arabic_filter_name_is_saved(self):
        self.open()
        self.save("~m POST", "طلبات")
        self.assertTrue(any(x["name"] == "طلبات" for x in self.panel.state()["saved_filters"]))

    def test_invalid_filter_shows_parser_reason_in_classic_view(self):
        self.open()
        self.P("#sq").fill("~(")
        wait_for(lambda: "err" in (self.P("#spop").get_attribute("class") or ""), 5, 0.1, "filter error")
        self.assertIn("operator", self.P("#spop").inner_text().lower())

    def P(self, selector):
        return self.page.locator("#proxy-panel-host").locator(selector)

    def answer(self, value):
        self.P("#ask-in").wait_for(timeout=5000)
        self.P("#ask-in").fill(value)
        self.P("#ask-yes").click()

    def save(self, expression, name):
        self.P("#sq").fill(expression)
        self.P("#ssave").click()
        self.page.wait_for_timeout(400)
        self.assertTrue(self.P("#ask-in").count(), self.P("#toast").text_content())
        self.answer(name)
        wait_for(lambda: self.P("[data-saved]").count() >= 1, 8, 0.1, "saved chip")

    def test_saved_filter_chips_apply_rename_order_delete_shortcut_and_reload(self):
        self.open()
        self.save("~m POST", "Posts")
        self.save("~c 500", "Errors")
        wait_for(lambda: self.P("[data-saved]").count() == 2, 8, 0.1, "two chips")
        self.P("[data-saved='0']").click()
        wait_for(lambda: self.P("#sq").input_value() == "~m POST", 8, 0.1, "chip applied")
        self.P("[data-saved='0']").click()
        wait_for(lambda: self.P("#sq").input_value() == "", 8, 0.1, "chip cleared")
        self.P("[data-smenu='0']").click()
        self.P("[data-sact='rename']").click()
        self.answer("Post calls")
        wait_for(lambda: "Post calls" in self.P("[data-saved='0']").text_content(), 8, 0.1, "renamed")
        self.P("[data-smenu='0']").click()
        self.P("[data-sact='right']").click()
        wait_for(lambda: "Post calls" in self.P("[data-saved='1']").text_content(), 8, 0.1, "moved")
        self.page.reload()
        wait_for(lambda: self.P("[data-saved]").count() == 2, 10, 0.2, "chips after reload")
        self.assertIn("Post calls", self.P("[data-saved='1']").text_content())
        self.P("#sq").blur()
        self.page.keyboard.press("Alt+1")
        wait_for(lambda: self.P("#sq").input_value() == "~c 500", 8, 0.1, "Alt+1 applied")
        self.P("#sq").focus()
        self.page.keyboard.press("Alt+2")
        self.assertEqual(self.P("#sq").input_value(), "~c 500")
        self.P("[data-smenu='0']").click()
        self.P("[data-sact='delete']").click()
        self.P("#ask-yes").click()
        wait_for(lambda: self.P("[data-saved]").count() == 1, 8, 0.1, "deleted")
        self.assertEqual(self.errors, [])

    def test_paste_curl_populates_compose_without_sending(self):
        self.open()
        before = len(self.inst.flows())
        self.P("#fab").click()
        self.P("#drawer nav button[data-t=compose]").click()
        self.P("#cpaste").click()
        self.answer("curl -X PATCH 'https://example.test/a' -H 'X-Test: yes' -d 'hello=world' -k --unknown")
        wait_for(lambda: self.P("#cu").input_value() == "https://example.test/a", 8, 0.1, "URL imported")
        self.assertEqual(self.P("#cm").input_value(), "PATCH")
        self.P("[data-cs=headers]").click()
        self.assertEqual(self.P('[data-kv="headers"] .krow input[type=text]').first.input_value(), "X-Test")
        self.P("[data-cs=body]").click()
        self.assertIn("hello=world", self.P("#carea").text_content() + self.P("#carea").locator("textarea").first.input_value())
        self.assertEqual(len(self.inst.flows()), before)
        self.assertIn("--unknown", self.P("#toast").text_content())
        self.assertEqual(self.errors, [])
