"""Body search and JSON tree in the call detail pane."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for  # noqa: E402
from test_ui import PW_REASON, UiBase  # noqa: E402

MOD = "Meta" if sys.platform == "darwin" else "Control"


@unittest.skipIf(PW_REASON, PW_REASON or "")
class BodyFindF2(UiBase):
    def response(self, path):
        row = self.page.locator(".flow-table tbody tr", has_text=path).first
        wait_for(lambda: row.count() > 0, 15, 0.2, "call row")
        row.click()
        self.page.locator(".flow-detail nav a", has_text="Response").first.click()
        wait_for(lambda: self.page.locator(".contentview pre").count() > 0 and
                 "Loading" not in self.page.locator(".contentview h5").first.inner_text(), 15, 0.2, "response body")
        self.page.locator(".rv-body-find").wait_for()

    def test_body_find_navigation_clear_and_call_switch(self):
        self.fetch("/json/find?f2=first")
        self.fetch("/json/find?f2=second")
        self.open()
        self.response("f2=first")
        field = self.page.locator(".rv-body-find")
        field.fill("findme")
        count = self.page.locator(".rv-find-count")
        wait_for(lambda: count.inner_text() == "1 of 12", 5, 0.1, "12 body matches")
        self.assertEqual(self.page.evaluate("CSS.highlights.get('rv-find').size"), 12)
        field.press("Enter")
        self.assertEqual(count.inner_text(), "2 of 12")
        field.press("Shift+Enter")
        self.assertEqual(count.inner_text(), "1 of 12")
        self.page.locator(".rv-find-prev").click()
        self.assertEqual(count.inner_text(), "12 of 12")
        self.page.locator(".rv-find-next").click()
        self.assertEqual(count.inner_text(), "1 of 12")
        self.response("f2=second")
        self.assertEqual(field.input_value(), "findme")
        wait_for(lambda: count.inner_text() == "1 of 12", 5, 0.1, "search on next call")
        self.page.locator(".flow-detail nav a", has_text="Request").first.click()
        wait_for(lambda: self.page.locator(".rv-body-find").count() == 1, 5, 0.1, "request body")
        self.assertEqual(self.page.locator(".rv-body-find").input_value(), "findme")
        self.page.locator(".flow-detail nav a", has_text="Response").first.click()
        wait_for(lambda: count.inner_text() == "1 of 12", 5, 0.1, "search on response tab")
        field.press("Escape")
        self.assertEqual(field.input_value(), "")
        self.assertEqual(count.inner_text(), "")
        self.assertFalse(self.page.evaluate("CSS.highlights.has('rv-find')"))
        self.assertEqual(self.errors, [])

    def test_detail_find_chord_and_list_filter(self):
        self.fetch("/json/find?f2=keys")
        self.open()
        self.response("f2=keys")
        self.page.locator(".flow-detail nav a", has_text="Response").first.focus()
        self.page.keyboard.press(MOD + "+f")
        self.assertTrue(self.page.locator(".rv-body-find").evaluate("e => e === document.activeElement"))
        self.page.locator(".flow-table").click(position={"x": 20, "y": 20})
        self.page.keyboard.press(MOD + "+f")
        self.assertTrue(self.page.evaluate("document.querySelector('#proxy-panel-host').shadowRoot.activeElement === document.querySelector('#proxy-panel-host').shadowRoot.querySelector('[data-sbar] input, #sq')") or
                        self.page.evaluate("document.querySelector('#proxy-panel-host').shadowRoot.activeElement?.closest('[data-sbar]') !== null"))
        self.assertEqual(self.errors, [])

    def test_folded_tree_rows_preview_their_contents_and_search_ignores_the_preview(self):
        self.fetch("/json/long?n=5&prev=1")
        self.open()
        self.response("prev=1")
        if self.page.locator(".rv-tree").count() == 0 or self.page.locator(".rv-tree").is_hidden():
            self.page.locator(".rv-tree-toggle").click()
        node = self.page.locator('.rv-tree-node[data-path="$.accounts[3]"]')
        wait_for(lambda: node.count() == 1, 5, 0.1, "folded row")
        row = node.locator("summary").first
        self.assertIn('id: 3, name: "account 3", balance: 9', row.inner_text())
        field = self.page.locator(".rv-body-find")
        field.fill("account 3")
        wait_for(lambda: self.page.locator(".rv-find-count").inner_text() == "1 of 1", 5, 0.1, "one match, not one per preview")
        self.assertFalse(row.locator(".rv-tree-prev").is_visible(), "the opened row hides its preview")
        self.assertEqual(self.errors, [])

    def test_truncated_body_notice_and_tree_limit(self):
        self.fetch("/bigline?mb=25&type=json&f2=clip", timeout=120)
        self.open()
        self.response("f2=clip")
        note = self.page.locator(".rv-body-note")
        wait_for(lambda: note.is_visible(), 5, 0.1, "truncated notice")
        self.assertIn("shown part", note.inner_text().lower())
        self.page.locator(".rv-tree-toggle").click()
        self.assertEqual(self.page.evaluate("localStorage.getItem('rivis-body-tree')"), "1")
        wait_for(lambda: "up to 24 MB" in self.page.locator(".rv-tree").inner_text(), 15, 0.1, "tree limit")
        self.assertTrue(self.page.locator(".contentview pre").is_visible())
        self.page.locator(".rv-body-find").fill("data")
        wait_for(lambda: self.page.locator(".rv-find-count").inner_text() == "1 of 1", 5, 0.05, "one match")   # typing waits 150 ms
        self.assertEqual(self.errors, [])

    def test_tree_fold_search_copy_and_dark_colours(self):
        self.fetch("/json/find?f2=tree")
        self.open()
        self.response("f2=tree")
        self.page.locator(".rv-tree-toggle").click()
        tree = self.page.locator(".rv-tree")
        wait_for(lambda: tree.locator('[data-path="$.products[0].id"]').count() == 1, 5, 0.1, "JSON tree")
        self.assertTrue(self.page.locator(".contentview pre").is_hidden())
        products = tree.locator('[data-path="$.products"]')
        self.assertIn("[12]", products.locator(":scope > summary").inner_text())
        products.locator(":scope > summary").click(position={"x": 10, "y": 10})
        self.assertFalse(products.evaluate("e => e.open"))
        self.page.locator(".rv-body-find").fill("FINDME")
        wait_for(lambda: products.evaluate("e => e.open"), 5, 0.1, "search expands parent")
        self.assertEqual(self.page.locator(".rv-find-count").inner_text(), "1 of 12")
        self.context.grant_permissions(["clipboard-read", "clipboard-write"])
        node = tree.locator('[data-path="$.products[0].id"]')
        node.hover()
        node.get_by_role("button", name="Copy path $.products[0].id").click()
        self.assertEqual(self.page.evaluate("navigator.clipboard.readText()"), "$.products[0].id")
        node.get_by_role("button", name="Copy JSON $.products[0].id").click()
        self.assertEqual(self.page.evaluate("navigator.clipboard.readText()"), "0")
        self.page.evaluate("document.documentElement.setAttribute('data-theme', 'dark')")
        colours = self.page.evaluate("""() => ({key: getComputedStyle(document.querySelector('.rv-tree-key')).color,
          text: getComputedStyle(document.querySelector('.rv-tree')).color,
          hit: getComputedStyle(document.documentElement, '::highlight(rv-find-now)').backgroundColor})""")
        self.assertNotEqual(colours["key"], colours["text"])
        self.assertNotIn(colours["hit"], ("rgba(0, 0, 0, 0)", "transparent"))
        self.assertEqual(self.errors, [])


@unittest.skipIf(PW_REASON, PW_REASON or "")
class BodyFindLongBody(UiBase):
    """mitmweb draws a long body behind "Show more": the tree is built from the whole body (it once tried to parse the
    shown part and said "cannot be parsed"), a match far down a big array is found, and neither freezes the page."""
    response = BodyFindF2.response

    def test_long_json_tree_reads_the_whole_body_and_finds_the_last_item_quickly(self):
        import time
        self.fetch("/json/long?n=12000&f2=long")
        self.page.add_init_script("try { localStorage.setItem('rivis-body-tree', '0') } catch (e) {}")
        self.open()
        self.response("f2=long")
        self.assertIn("Show more", self.page.locator(".contentview").inner_text(), "the fixture is long enough to be cut")
        t0 = time.time()
        self.page.locator(".rv-tree-toggle").click()
        wait_for(lambda: self.page.evaluate("(document.querySelector('.rv-tree') || {dataset: {}}).dataset.ready === '1'"), 10, 0.05, "tree")
        tree_s = time.time() - t0
        self.assertIn("accounts[12000]", self.page.locator(".rv-tree").inner_text().replace(" ", ""))
        t0 = time.time()
        self.page.locator(".rv-body-find").fill("account 11999")
        wait_for(lambda: self.page.locator(".rv-find-count").inner_text() == "1 of 1", 10, 0.05, "the last item found")
        find_s = time.time() - t0
        self.assertLess(tree_s, 1.5, "the tree took %.2fs" % tree_s)
        self.assertLess(find_s, 1.5, "the search took %.2fs" % find_s)
        self.assertLess(self.page.evaluate("document.querySelectorAll('.rv-tree *').length"), 20000, "only what is open is built")
        self.assertEqual(self.errors, [])
