"""The labels and messages around the call list, in a real browser: the project label after Show → All traffic,
the empty-list wording after Clear, and File → Open of a file that cannot be read."""
import os
import sys
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class ViewLabelsUi(UiBase):
    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def clear_list(self):
        """mitmweb's File → Clear All (POST /clear)."""
        req = urllib.request.Request(self.panel.base + "/clear", data=b"", method="POST",
                                     headers={"X-XSRFToken": self.panel.xsrf})
        code, raw = self.panel._do(req, 30)
        self.assertEqual(code, 200, raw[:200])

    def test_all_traffic_puts_the_project_label_back(self):
        # R9-02: after Show → NEO only → All traffic the header, status bar and empty state kept saying "NEO"
        self.addCleanup(lambda: self.panel.ok("view", {"project_only": False, "show_dns": True}))
        page = self.open()
        self.P("#fab").click()
        wait_for(lambda: self.P("#main").text_content().strip() != "", 8, 0.2, "Tools content loaded")
        start = self.P("#bproj").text_content().strip()
        self.assertNotEqual(start, "NEO")
        self.P("#project").select_option("neo")
        wait_for(lambda: self.P("#bproj").text_content().strip() == "NEO", 8, 0.2, "NEO label while NEO only")
        self.P("#project").select_option("__all")
        wait_for(lambda: self.panel.state()["project_only"] is False, 8, 0.2, "All traffic applied")
        page.reload()
        page.wait_for_selector("#fab", timeout=20000)
        wait_for(lambda: self.P("#bproj").text_content().strip() == start, 8, 0.2,
                 "header label back to %r after All traffic (was %r)" % (start, self.P("#bproj").text_content()))
        self.assertNotIn("NEO", page.title())
        self.assertNotEqual(self.panel.state()["project"].get("label"), "NEO")
        self.assertEqual(self.errors, [])

    def test_empty_list_after_clear_with_no_limit_does_not_talk_about_a_limit(self):
        # R9-03: "Showing . The calls are still captured — remove the limit to see them." with no limit on
        page = self.open()
        wait_for(lambda: page.locator(".flow-table tbody tr:has(td.col-path)").count() >= 3, 10, 0.2, "rows")
        self.clear_list()
        box = self.P("#emptylist.open")
        box.wait_for(timeout=10000)
        page.wait_for_timeout(600)
        text = box.text_content()
        self.assertNotIn("Showing .", text)
        self.assertNotIn("remove the limit", text)
        self.assertEqual(self.errors, [])

    def test_opening_a_broken_har_keeps_the_calls_and_shows_why(self):
        # R9-05: File → Open of a truncated HAR cleared every call, then failed with a bare 500 and no message
        page = self.open()
        rows = page.locator(".flow-table tbody tr:has(td.col-path)")
        wait_for(lambda: rows.count() >= 3, 10, 0.2, "rows")
        before = rows.count()
        page.get_by_text("File", exact=True).first.click()
        page.locator("input[type=file]").first.set_input_files(
            files=[{"name": "broken.har", "mimeType": "application/json", "buffer": b'{"log": {"entries": ['}])
        toast = self.P("#toast")
        wait_for(lambda: toast.is_visible() and "Could not open broken.har" in toast.text_content(), 10, 0.2,
                 "a toast saying the file could not be opened")
        self.assertIn("current calls were kept", toast.text_content())
        page.wait_for_timeout(500)
        self.assertEqual(rows.count(), before, "the list must keep its calls")
        # the refused upload is reported by the browser as a 400; that is the expected answer, not a page error
        self.assertEqual([e for e in self.errors if "400" not in e[1]], [])


if __name__ == "__main__":
    unittest.main()
