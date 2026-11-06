"""The new window's Settings must let a person sign in for updates without a terminal: a plain sentence and a Sign in
button (not 'run rivis update login'), the device code and link while the sign-in runs, an honest failure, and the
Check for updates button once signed in. Found by the 0.9.11 release-candidate QA (the sentence) and by review (no
sign-in at all when the IT-approval card is off, which is how 0.9.11 ships)."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402

AZURE = {"configured": True, "installed": True, "repo": "", "signed_in": False, "available": None, "error": None,
         "login": None, "installing": None}


@unittest.skipIf(PW_REASON, PW_REASON or "")
class SettingsUpdateSignIn(UiBase):
    def fake_update(self, update):
        """Make the page see `update` as the panel's update state (a test instance is a source checkout: no feed)."""
        self.update = update
        calls = self.calls = []

        def handler(route, request):
            op = request.url.split("/proxy/api/")[-1].split("?")[0]
            if op == "state":
                resp = route.fetch()
                doc = resp.json()
                doc["update"] = self.update
                route.fulfill(response=resp, body=json.dumps(doc), headers=dict(resp.headers))
            elif op in ("update_login_start", "update_check"):
                calls.append(op)
                route.fulfill(status=200, content_type="application/json", body=json.dumps({"update": self.update}))
            else:
                route.continue_()
        self.page.route("**/proxy/api/**", handler)

    def open_settings(self):
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.goto("http://127.0.0.1:%d/rivis/" % self.inst.web_port)
        self.page.locator("#rv-app").wait_for(timeout=15000)
        wait_for(lambda: self.page.evaluate("!!(window.RivisApp && window.__rivisUI.state)"), 10, 0.1, "app ready")
        self.page.evaluate("() => localStorage.setItem('rivis-ui-welcome', 'done')")
        self.page.locator("#tb-settings").click()
        self.page.locator("#set-update-box").wait_for(timeout=10000)

    def box_text(self):
        return self.page.locator("#set-update-box").inner_text()

    def test_not_signed_in_says_so_plainly_and_offers_a_button(self):
        self.page.goto("about:blank")
        self.fake_update(dict(AZURE))
        self.open_settings()
        wait_for(lambda: self.page.locator("#set-update-signin").count() == 1, 10, 0.2, "Sign in button")
        text = self.box_text()
        self.assertIn("Sign in with your organisation account to check for updates", text)
        self.assertNotIn("rivis update login", text)
        self.assertEqual(self.page.locator("#set-update").count(), 0, "no Check button before signing in")

    def test_sign_in_shows_the_code_and_link_then_the_check_button(self):
        self.page.goto("about:blank")
        self.fake_update(dict(AZURE))
        self.open_settings()
        self.page.locator("#set-update-signin").click()
        wait_for(lambda: "update_login_start" in self.calls, 10, 0.1, "sign-in requested")
        self.update = dict(AZURE, login={"status": "waiting", "user_code": "ABCD-EFGH", "uri": "https://microsoft.com/devicelogin"})
        wait_for(lambda: self.page.locator("#set-update-code").count() == 1, 10, 0.2, "device code shown")
        self.assertEqual(self.page.locator("#set-update-code").inner_text(), "ABCD-EFGH")
        link = self.page.locator("#set-update-box a")
        self.assertEqual(link.get_attribute("href"), "https://microsoft.com/devicelogin")
        self.assertEqual(link.get_attribute("rel"), "noopener")
        self.update = dict(AZURE, signed_in=True, login={"status": "ok"})
        wait_for(lambda: self.page.locator("#set-update").count() == 1, 15, 0.3, "Check for updates button after sign-in")
        self.assertIn("update_check", self.calls, "signing in runs a check by itself")
        self.assertEqual(self.page.locator("#set-update-code").count(), 0)

    def test_a_failed_sign_in_says_why_and_can_be_retried(self):
        self.page.goto("about:blank")
        self.fake_update(dict(AZURE))
        self.open_settings()
        self.update = dict(AZURE, login={"status": "error", "error": "the code expired — sign in again"})
        self.page.locator("#set-update-signin").click()
        wait_for(lambda: "Sign-in failed: the code expired" in self.box_text(), 10, 0.2, "failure shown")
        self.assertEqual(self.page.locator("#set-update-signin").count(), 1, "the button is back")

    def test_an_unconfigured_copy_does_not_offer_a_sign_in(self):
        self.page.goto("about:blank")
        self.fake_update(dict(AZURE, configured=False))
        self.open_settings()
        wait_for(lambda: "not set up" in self.box_text(), 10, 0.2, "plain note")
        self.assertEqual(self.page.locator("#set-update-signin").count(), 0)


if __name__ == "__main__":
    unittest.main()
