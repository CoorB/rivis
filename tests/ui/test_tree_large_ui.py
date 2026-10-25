"""Large JSON trees in both browser views."""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for
from test_ui import PW_REASON, UiBase


def observe(page):
    page.evaluate("""() => { window.treeLongTasks = []; new PerformanceObserver(list => {
      for (const e of list.getEntries()) window.treeLongTasks.push(e.duration);
    }).observe({type: 'longtask', buffered: false}); }""")


@unittest.skipIf(PW_REASON, PW_REASON or "")
class LargeTreeUi(UiBase):
    def test_new_window_large_tree(self):
        self.fetch("/json/tree-large?mb=20&large=new", timeout=120)
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.goto("http://127.0.0.1:%d/rivis/" % self.inst.web_port)
        wait_for(lambda: self.page.locator(".rv-tr", has_text="large=new").count(), 15, 0.1, "call")
        self.page.locator(".rv-tr", has_text="large=new").first.click()
        observe(self.page)
        start = time.monotonic()
        self.page.locator("#pane-res [data-tab=tree]").click()
        tree = self.page.locator("#pane-res .rv-tree")
        wait_for(lambda: tree.get_attribute("data-ready") == "1", 12, 0.05, "large tree")
        self.assertLess(time.monotonic() - start, 3)
        self.page.locator("[data-find=res]").fill("last_key")
        wait_for(lambda: tree.locator('[data-path="$.tail.branch.last_key"]').count(), 8, 0.05, "deep key")
        self.assertGreater(self.page.locator("[data-fc=res]").inner_text().find("1 of"), -1)
        self.context.grant_permissions(["clipboard-read", "clipboard-write"])
        line = tree.locator('[data-path="$.tail.branch.last_key"]')
        line.hover()
        line.locator("[data-copy=path]").click()
        self.assertEqual(self.page.evaluate("navigator.clipboard.readText()"), "$.tail.branch.last_key")
        line.locator("[data-copy=value]").click()
        self.assertEqual(self.page.evaluate("navigator.clipboard.readText()"), '"end marker"')
        for _ in range(6):
            self.page.mouse.wheel(0, 500)
        self.assertLess(max(self.page.evaluate("window.treeLongTasks") or [0]), 1000)
        self.page.locator("#pane-res [data-tab=body]").click()
        self.assertIn("Showing the first 512 KB", self.page.locator("#pane-res").inner_text())

    def test_classic_large_tree(self):
        self.fetch("/json/tree-large?mb=20&large=classic", timeout=120)
        self.open()
        row = self.page.locator(".flow-table tbody tr", has_text="large=classic").first
        wait_for(lambda: row.count(), 15, 0.1, "call")
        row.click()
        self.page.locator(".flow-detail nav a", has_text="Response").first.click()
        wait_for(lambda: self.page.locator(".rv-tree-toggle").is_visible(), 20, 0.1, "tree toggle")
        observe(self.page)
        start = time.monotonic()
        self.page.locator(".rv-tree-toggle").click()
        tree = self.page.locator(".rv-tree")
        wait_for(lambda: tree.get_attribute("data-ready") == "1", 12, 0.05, "large tree")
        self.assertLess(time.monotonic() - start, 3)
        self.page.locator(".rv-body-find").fill("last_key")
        node = tree.locator('[data-path="$.tail.branch.last_key"]')
        wait_for(lambda: node.count(), 8, 0.05, "deep key")
        wait_for(lambda: "1 of" in self.page.locator(".rv-find-count").inner_text(), 8, 0.05, "search count")
        self.context.grant_permissions(["clipboard-read", "clipboard-write"])
        node.get_by_role("button", name="Copy path $.tail.branch.last_key").click()
        self.assertEqual(self.page.evaluate("navigator.clipboard.readText()"), "$.tail.branch.last_key")
        node.get_by_role("button", name="Copy JSON $.tail.branch.last_key").click()
        self.assertEqual(self.page.evaluate("navigator.clipboard.readText()"), '"end marker"')
        for _ in range(6):
            self.page.mouse.wheel(0, 500)
        self.assertLess(max(self.page.evaluate("window.treeLongTasks") or [0]), 1000)

    def test_new_window_request_tree(self):
        body = b'{"padding":"' + b"a" * (20 * 1048576) + b'","tail":{"branch":{"last_key":"request end"}}}'
        self.fetch("/echo?large=request", method="POST", headers={"Content-Type": "application/json"}, data=body, timeout=120)
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.goto("http://127.0.0.1:%d/rivis/" % self.inst.web_port)
        wait_for(lambda: self.page.locator(".rv-tr", has_text="large=request").count(), 15, 0.1, "request call")
        self.page.locator(".rv-tr", has_text="large=request").first.click()
        observe(self.page)
        start = time.monotonic()
        self.page.locator("#pane-req [data-tab=tree]").click()
        tree = self.page.locator("#pane-req .rv-tree")
        wait_for(lambda: tree.get_attribute("data-ready") == "1", 12, 0.05, "request tree")
        self.assertLess(time.monotonic() - start, 3)
        self.page.locator("[data-find=req]").fill("last_key")
        wait_for(lambda: tree.locator('[data-path="$.tail.branch.last_key"]').count(), 8, 0.05, "request key")
        self.assertLess(max(self.page.evaluate("window.treeLongTasks") or [0]), 1000)


if __name__ == "__main__":
    unittest.main()
