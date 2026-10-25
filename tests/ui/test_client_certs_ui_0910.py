"""Network → Client certificates: add a .p12 for a host, see it listed, remove it (in-panel question). The tab redraws
on every poll, so a half-filled form (host, chosen file, password) must survive a redraw."""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import PANEL_AUTO_ANSWER_JS, wait_for     # noqa: E402
from test_client_certs_0910 import Pki                 # noqa: E402
from test_ui import PW_REASON, UiBase                  # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class ClientCertsUi(UiBase):
    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def toast(self):
        return self.page.evaluate("document.querySelector('#proxy-panel-host').shadowRoot.querySelector('#toast').innerText")

    def test_add_a_p12_from_the_network_tab_and_remove_it(self):
        pki = Pki(self.suite.new_home("pki-ui"))
        _, _, p12 = pki.client("carol", password="pw-ui")
        self.page.add_init_script(PANEL_AUTO_ANSWER_JS)
        self.open()
        self.P("#fab").click()
        self.P("#drawer nav button[data-t=net]").click()
        wait_for(lambda: self.P("#ccaddbtn").count() == 1, 8, 0.1, "the Client certificates section")
        self.P("#cchost").fill("API.Example.test")
        self.P("#ccfile").set_input_files(p12)
        self.P("#ccpass").fill("pw-ui")
        self.P("#ccsec").click()                    # focus leaves the fields: the next polls redraw the tab
        time.sleep(3)
        self.assertEqual(self.P("#cchost").input_value(), "API.Example.test", "the host survives a redraw")
        self.assertEqual(self.P("#ccpass").input_value(), "pw-ui", "the password survives a redraw")
        self.assertIn("carol.p12", self.P("#ccadd").text_content(), "the chosen file is still named")
        self.P("#ccaddbtn").click()
        wait_for(lambda: "Client certificate for api.example.test" in self.toast(), 10, 0.1, "the added toast")
        row = self.P("[data-cc='api.example.test']")
        wait_for(lambda: row.count() == 1, 8, 0.1, "the listed certificate")
        self.assertIn("carol", row.text_content())
        self.assertEqual(self.P("#cchost").input_value(), "", "the form is cleared after Add")
        self.assertEqual([r["host"] for r in self.panel.state()["client_certs"]], ["api.example.test"])
        self.P("[data-ccrm='api.example.test']").click()
        wait_for(lambda: row.count() == 0, 8, 0.1, "the certificate to go")
        self.assertEqual(self.panel.state()["client_certs"], [])
        self.assertEqual(self.errors, [])

    def test_a_wrong_password_says_so_and_keeps_the_form(self):
        pki = Pki(self.suite.new_home("pki-ui2"))
        _, _, p12 = pki.client("dave", password="right")
        self.open()
        self.P("#fab").click()
        self.P("#drawer nav button[data-t=net]").click()
        wait_for(lambda: self.P("#ccaddbtn").count() == 1, 8, 0.1, "the Client certificates section")
        self.P("#cchost").fill("pay.example.test")
        self.P("#ccfile").set_input_files(p12)
        self.P("#ccpass").fill("wrong")
        self.P("#ccaddbtn").click()
        wait_for(lambda: "password" in self.toast(), 10, 0.1, "the wrong-password message")
        self.assertEqual(self.P("#cchost").input_value(), "pay.example.test")
        self.assertEqual(self.panel.state()["client_certs"], [])


if __name__ == "__main__":
    unittest.main()
