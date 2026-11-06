"""The IT-approval cover in a real browser: after the Terms of Use, both windows ask for a sign-in with the
organisation account, show the device code, and lift the cover (and the proxy lock) once Azure DevOps confirms the
account may read the Rivis feed. The fake Azure DevOps and Entra ID come from tests/test_access_gate.py."""
import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import Instance, wait_for          # noqa: E402
from test_access_gate import FakeDevOps, tree_copy   # noqa: E402
from test_ui import PW_REASON, UiBase           # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class AccessGateUi(UiBase):
    @classmethod
    def make_instance(cls):
        cls.fake = FakeDevOps()
        cls.root, tree = tree_copy(cls.fake.url)
        return Instance(cls.suite, "accessui", rivis_bin=os.path.join(tree, "rivis"),
                        extra_env={"RIVIS_TOKEN_FILE": os.path.join(cls.root, "token")})

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls.fake.close()
        shutil.rmtree(cls.root, ignore_errors=True)

    def reset_state(self, **cfg):
        pass        # the reset proves reloads with a call through the proxy, which is locked until approval

    def test_signing_in_from_the_new_window_confirms_approval_and_unlocks_rivis(self):
        page = self.page
        page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        page.goto("http://127.0.0.1:%d/rivis/" % self.inst.web_port)
        cover = page.locator("#rivis-terms")
        cover.wait_for(timeout=15000)
        self.assertIn("Confirm IT approval", cover.inner_text())
        self.assertEqual(self.fetch("/json/small").status, 403)
        page.keyboard.press("Escape")
        self.assertTrue(cover.is_visible())
        page.locator("#rivis-access-signin").click()
        page.locator("#rivis-access-code").wait_for(timeout=15000)
        self.assertEqual(page.locator("#rivis-access-code").inner_text(), "ABCD1234")
        self.assertIn("microsoft.com/devicelogin", cover.inner_text())
        self.fake.pending = 0                                   # the person finished the sign-in in the browser
        wait_for(lambda: page.locator("#rivis-terms").count() == 0, 30, 0.3, "cover gone once approval is confirmed")
        self.assertTrue(self.panel.state()["access"]["allowed"])
        wait_for(lambda: self.fetch("/json/small").status == 200, 70, 0.5, "traffic flows once approved")
        self.errors[:] = [e for e in self.errors if not (e[0] == "requestfailed"
                                                         and e[1].endswith(("/proxy/api/state", "/proxy/api/terms_status")))]
        self.assertEqual(self.errors, [])

    def test_z_a_refused_account_is_told_to_fill_in_the_form(self):
        self.fake.answer = (403, "application/json", b"{}", None)
        self.panel.ok("access_check", {})
        wait_for(lambda: self.panel.state()["access"]["state"] == "refused", 20, 0.3, "refusal recorded")
        page = self.page
        page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        cover = page.locator("#rivis-terms")
        cover.wait_for(timeout=15000)
        text = cover.inner_text()
        self.assertIn("is not approved", text)
        self.assertIn("confirmation form", text)
        self.assertTrue(page.locator("#rivis-access-check").is_visible())
        self.assertIn("another account", page.locator("#rivis-access-signin").inner_text())
        self.errors[:] = [e for e in self.errors if not (e[0] == "requestfailed"
                                                         and e[1].endswith(("/proxy/api/state", "/proxy/api/terms_status")))]
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main()
