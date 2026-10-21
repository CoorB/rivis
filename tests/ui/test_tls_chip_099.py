"""Soak F1 follow-up: removing a host chip from the HTTPS decryption lists says "Removed <host>", drops the chip and is saved. The
soak scenario that checks this failed only because its click landed below the window (see test_soak_click.py)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class TlsChipRemoval(UiBase):
    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def toast(self):
        return self.page.evaluate("document.querySelector('#proxy-panel-host').shadowRoot.querySelector('#toast').innerText")

    def test_removing_a_leave_alone_chip_confirms_and_is_saved(self):
        self.panel.ok("tls_set", {"mode": "ignore"})
        for h in ("one.example.test", "two.example.test"):
            self.panel.ok("tls_update", {"list": "ignore", "action": "add", "pattern": h})
        self.page.set_viewport_size({"width": 1512, "height": 500})            # the chips sit below the fold, as in the soak window
        self.open()
        self.P("#fab").click()
        self.P("#drawer nav button[data-t=net]").click()
        chip = self.P("[data-tlsrm][data-p='one.example.test']")
        wait_for(lambda: chip.count() == 1, 8, 0.1, "the chip")
        chip.scroll_into_view_if_needed()
        chip.click()
        wait_for(lambda: "Removed one.example.test" in self.toast(), 5, 0.1, "the Removed toast")
        wait_for(lambda: chip.count() == 0, 5, 0.1, "the chip to go")
        self.assertEqual(self.panel.state()["tls"]["ignore"], ["two.example.test"])
        self.assertEqual(self.errors, [])
        self.panel.ok("tls_set", {"mode": "all"})
        self.panel.ok("tls_update", {"list": "ignore", "action": "remove", "pattern": "two.example.test"})


if __name__ == "__main__":
    unittest.main()
