"""Rules tab controls for a Map Local folder and Proxyman RuleTree import."""
import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import harness
from harness import wait_for
from test_ui import PW_REASON, UiBase


@unittest.skipIf(PW_REASON, PW_REASON or "")
class MapLocalControls0910(UiBase):
    def setUp(self):
        super().setUp()
        self.page.add_init_script(harness.PANEL_AUTO_ANSWER_JS)

    def panel_el(self, selector):
        return self.page.locator("#proxy-panel-host").locator(selector)

    def rules_tab(self):
        self.open()
        self.panel_el("#fab").click()
        self.panel_el("button[data-t=rules]").click()
        self.panel_el("#rfolderopen").wait_for()

    def test_add_toggle_delete_folder(self):
        folder = self.inst.path("mocks", "ui-folder")
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "one.json"), "w") as fh:
            fh.write('{"mocked":true}')
        self.rules_tab()
        self.panel_el("#rfolderopen").click()
        self.panel_el("#rfoldername").fill("ui-folder")
        self.panel_el("#rfolderbase").fill(self.up.url("/v1/"))
        self.panel_el("#rfolderpath").fill(folder)
        self.panel_el("#rfolderform button[type=submit]").click()
        wait_for(lambda: any(r.get("name") == "ui-folder" for r in self.inst.cfg()["rules"]), 8)
        row = self.panel_el(".row").filter(has_text="ui-folder").first
        self.assertIn("Map Local folder", row.text_content())
        self.assertEqual(self.inst.fetch(self.up.url("/v1/one")).json(), {"mocked": True})
        row.locator(".sw").click()
        wait_for(lambda: next(r for r in self.inst.cfg()["rules"] if r["name"] == "ui-folder")["enabled"] is False, 8)
        row.locator("[data-del]").click()
        wait_for(lambda: all(r.get("name") != "ui-folder" for r in self.inst.cfg()["rules"]), 8)

    def test_import_control(self):
        source = os.path.join(self.inst.home, "Library", "Application Support", "com.proxyman.NSProxy", "user-data")
        os.makedirs(os.path.dirname(source), exist_ok=True)
        shutil.copytree(os.path.join(harness.REPO, "tests", "fixtures", "proxyman"), source)
        self.rules_tab()
        self.panel_el("#rimport").click()
        wait_for(lambda: any(r.get("name") == "wild" for r in self.inst.cfg()["rules"]), 8)
        self.assertIn("imported 4, skipped 1", self.panel_el("#toast").text_content())
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main()
