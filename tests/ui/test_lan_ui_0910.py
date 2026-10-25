"""Tools → Devices → Phones and tablets (`start --lan`): the QR code and address, a refused device waiting to be
allowed, Allow / Rename / Remove (in-panel questions)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import PANEL_AUTO_ANSWER_JS, wait_for     # noqa: E402
from test_lan_0910 import LAN, NO_LAN, curl            # noqa: E402
from test_ui import PW_REASON, UiBase                  # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
@unittest.skipUnless(LAN, NO_LAN)
class LanDevicesUi(UiBase):
    INSTANCE_KW = {"start_args": ("--insecure", "--lan")}

    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def phone(self, path):
        return curl(["--noproxy", "", "-x", "http://%s:%d" % (LAN[0], self.inst.proxy_port),
                     "-A", "Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/AP1A) Chrome/120", self.up.url(path)])

    def test_allow_rename_and_remove_a_phone(self):
        self.page.add_init_script(PANEL_AUTO_ANSWER_JS)
        self.open()
        self.P("#fab").click()
        self.P("#drawer nav button[data-t=dev]").click()
        wait_for(lambda: self.P("#lansec").count() == 1, 10, 0.2, "the Phones and tablets section")
        self.assertEqual(self.P("#lanip").text_content(), LAN[0])
        self.assertEqual(self.P("#lanport").text_content(), str(self.inst.proxy_port))
        self.assertEqual(self.P(".lanqr svg").count(), 1, "the QR code")
        self.assertEqual(self.phone("/echo?ui=1")[0], 403)
        waiting = self.P("[data-lanwait='%s']" % LAN[0])
        wait_for(lambda: waiting.count() == 1, 12, 0.2, "the refused phone waiting to be allowed")
        self.assertIn("Android Pixel 8", waiting.text_content())
        self.P("[data-lanallow='%s']" % LAN[0]).click()
        allowed = self.P("[data-lanok='%s']" % LAN[0])
        wait_for(lambda: allowed.count() == 1, 12, 0.2, "the phone in the Allowed list")
        self.assertEqual(waiting.count(), 0)
        wait_for(lambda: self.phone("/echo?ui=2")[0] == 200, 5, 0.2, "the allowed phone's call goes through")
        self.page.evaluate("window.__rivisAnswer = 'Lab Pixel'")
        self.P("[data-lanrename='%s']" % LAN[0]).click()
        wait_for(lambda: "Lab Pixel" in allowed.text_content(), 12, 0.2, "the new name")
        self.assertEqual([d["name"] for d in self.panel.state()["lan"]["devices"]], ["Lab Pixel"])
        self.P("[data-lanrm='%s']" % LAN[0]).click()
        wait_for(lambda: allowed.count() == 0, 12, 0.2, "the phone removed")
        self.assertEqual(self.phone("/echo?ui=3")[0], 403)
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main()
