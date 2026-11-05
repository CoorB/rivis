"""The Terms of Use cover in a real browser: both windows show it while the terms are not accepted, the Agree button
needs the box ticked and a typed name, and agreeing removes it and unlocks the proxy."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class TermsGateUi(UiBase):
    INSTANCE_KW = {"terms": False}

    def reset_state(self, **cfg):
        pass        # the reset proves reloads with a call through the proxy, which is locked until the terms are agreed

    def test_a_classic_window_is_covered_and_keys_stay_in_the_cover(self):
        page = self.page
        page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        cover = page.locator("#rivis-terms")
        cover.wait_for(timeout=15000)
        self.assertIn("Rivis Terms of Use", cover.inner_text())
        self.assertNotIn("RIVIS-PLACEHOLDER-TERMS", cover.inner_text())        # the build marker is not shown
        self.assertTrue(page.locator("#rivis-terms-accept").is_disabled())
        page.keyboard.press("Escape")                                         # does not dismiss it
        self.assertTrue(cover.is_visible())
        self.errors[:] = [e for e in self.errors if not (e[0] == "requestfailed" and e[1].endswith("/proxy/api/terms_status"))]
        self.assertEqual(self.errors, [])

    def test_b_agreeing_in_the_new_window_unlocks_rivis(self):
        page = self.page
        page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        page.goto("http://127.0.0.1:%d/rivis/" % self.inst.web_port)
        cover = page.locator("#rivis-terms")
        cover.wait_for(timeout=15000)
        self.assertEqual(self.fetch("/json/small").status, 403)
        page.locator("#rivis-terms-name").fill("Ada Lovelace")
        self.assertTrue(page.locator("#rivis-terms-accept").is_disabled())   # the box is not ticked yet
        page.locator("#rivis-terms-read").check()
        page.locator("#rivis-terms-accept").click()
        wait_for(lambda: page.locator("#rivis-terms").count() == 0, 10, 0.2, "cover gone after agreeing")
        self.assertEqual(self.panel.state()["terms"]["state"], "accepted")
        self.assertEqual(self.fetch("/json/small").status, 200)
        # polls still in flight when the cover closes or the page navigates are cut off by the browser
        self.errors[:] = [e for e in self.errors if not (e[0] == "requestfailed"
                                                         and e[1].endswith(("/proxy/api/state", "/proxy/api/terms_status")))]
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main()
