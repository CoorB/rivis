"""Tree must appear when the painted body looks like JSON even if the view title does not say JSON.

APIs often send application/json behind text/plain (or mitmweb picks Auto / Raw). Hiding Tree then forced a
QA engineer to read a wall of text for a body the worker would have opened fine.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class TreeSniffsJsonLookingBodies(UiBase):
    def test_tree_toggle_shows_when_the_view_title_is_not_json_but_the_body_starts_with_brace(self):
        self.fetch("/json/small?sniff=1")
        self.open()
        row = self.page.locator(".flow-table tbody tr", has_text="sniff=1").first
        wait_for(lambda: row.count() > 0, 15, 0.2, "call")
        row.click()
        self.page.locator(".flow-detail nav a", has_text="Response").first.click()
        wait_for(lambda: self.page.locator(".contentview pre").count() > 0, 15, 0.2, "body")
        # Pretend mitmweb labelled it something other than JSON (Content-Type lied / Auto view).
        self.page.evaluate("""() => {
          const h = document.querySelector('.contentview > .controls h5');
          if (h) h.textContent = 'Raw';
        }""")
        wait_for(lambda: self.page.locator(".rv-tree-toggle").count() > 0 and
                 self.page.locator(".rv-tree-toggle").is_visible(), 5, 0.1, "Tree toggle despite Raw title")
        self.page.locator(".rv-tree-toggle").click()
        wait_for(lambda: self.page.locator(".rv-tree").get_attribute("data-ready") == "1", 10, 0.1, "tree")
        self.assertGreater(self.page.locator('.rv-tree-node[data-path="$.user"]').count(), 0)
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main()
