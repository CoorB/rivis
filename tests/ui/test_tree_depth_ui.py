"""A body nested past the tree worker's depth limit must say so — not "cannot be parsed as JSON".

The worker refuses structured-clone of ~5000-deep values (that hang never returns). Its error names the
limit; the classic panel used to swallow every SyntaxError into the generic parse line, so a QA engineer
with a pathological payload thought the body was invalid JSON rather than too deep for the tree.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class TreeDepthMessage(UiBase):
    def response(self, path):
        row = self.page.locator(".flow-table tbody tr", has_text=path).first
        wait_for(lambda: row.count() > 0, 15, 0.2, "call row")
        row.click()
        self.page.locator(".flow-detail nav a", has_text="Response").first.click()
        wait_for(lambda: self.page.locator(".contentview pre").count() > 0 and
                 "Loading" not in self.page.locator(".contentview h5").first.inner_text(), 15, 0.2, "response body")
        self.page.locator(".rv-body-find").wait_for()

    def test_over_deep_json_says_nested_not_cannot_be_parsed(self):
        self.fetch("/deep?n=3000&depth=ui")
        self.open()
        self.response("depth=ui")
        self.page.locator(".rv-tree-toggle").click()
        tree = self.page.locator(".rv-tree")
        wait_for(lambda: tree.inner_text().strip() not in ("", "Loading the tree…"), 15, 0.1, "tree finished")
        text = tree.inner_text()
        self.assertIn("nested more than", text.lower(), text)
        self.assertNotIn("cannot be parsed", text.lower(), text)
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main()
