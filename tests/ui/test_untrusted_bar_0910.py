"""Pilot 2026-10-21 ("can't log in while the tool is running"): a device that does not trust the Rivis certificate is
now let through, and the panel must say so — which host, and a way to set the device up."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class UntrustedBar(UiBase):
    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def test_the_bar_names_the_host_and_opens_device_setup(self):
        self.panel.ok("untrusted_retry", {})
        page = self.open()
        self.inst.fetch("https://localhost:%d/json/small?bar=1" % self.up.https_port, cacert=self.up.cert)
        bar = self.P("#proxybar.open")
        wait_for(lambda: bar.count() and "localhost" in bar.text_content(), 10, 0.2, "the bar names the refused host")
        self.assertIn("does not trust", bar.text_content())
        self.P("#trust-setup").click()
        wait_for(lambda: self.P("#drawer.open").count() and self.P("button[data-t=dev].on").count(), 8, 0.2, "Tools → Devices opened")
        self.P("#trust-retry").click()
        wait_for(lambda: not self.P("#proxybar.open").count(), 8, 0.2, "the bar goes once Decrypt again is chosen")


if __name__ == "__main__":
    unittest.main()
