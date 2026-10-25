"""Customize the mitmweb call list in a real browser."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for
from test_ui import PW_REASON, UiBase


@unittest.skipIf(PW_REASON, PW_REASON or "")
class ColumnsUI(UiBase):
    def test_columns_picker_adds_request_header_and_reorders_the_list(self):
        self.inst.fetch(self.up.url("/echo?columns=1"), headers={"X-Request-ID": "column-value-77"})
        page = self.open()
        picker = page.locator("#proxy-panel-host")
        page.locator("#rivis-columns").click()
        picker.locator('[data-ask="2"]').click()       # Add header
        picker.locator('[data-ask="0"]').click()       # Request
        picker.locator("#ask-in").fill("x-request-id")
        picker.locator("#ask-yes").click()
        wait_for(lambda: "request:x-request-id" in self.panel.state()["columns"], 10, 0.2, "header saved")
        row = page.locator(".flow-table tbody tr", has_text="columns=1").first
        wait_for(lambda: row.locator('td[data-rv-column="request:x-request-id"]').text_content() == "column-value-77",
                 10, 0.2, "header value")
        page.locator("#rivis-columns").click()
        picker.locator('[data-ask="1"]').click()       # Reorder
        picker.locator('[data-ask="1"]').click()       # Method
        picker.locator('[data-ask="0"]').click()       # Earlier
        wait_for(lambda: self.panel.state()["columns"][0] == "method", 10, 0.2, "order saved")
        page.locator("#rivis-columns").click()
        picker.locator('[data-ask="0"]').click()       # Show or hide
        picker.locator('[data-ask="2"]').click()       # Status
        wait_for(lambda: "status" not in self.panel.state()["columns"], 10, 0.2, "status hidden")
        wait_for(lambda: page.locator(".flow-table th.col-status").count() == 0, 10, 0.2, "status removed from list")
        self.panel.ok("columns_set", {"columns": ["method", "request:x-request-id"]})
        wait_for(lambda: page.evaluate("""() => getComputedStyle(document.querySelector('.flow-table td.col-path')).display""") == "none",
                 10, 0.2, "path hidden")
        self.panel.ok("columns_set", {"columns": ["method", "path", "request:x-request-id", "duration", "content_type",
                                                   "source_app", "response:content-type"]})
        wait_for(lambda: page.evaluate("""() => [...document.querySelectorAll('.flow-table thead th')]
            .map(x => x.dataset.rvColumn || x.className.match(/col-([a-z_]+)/)?.[1]).join(',')""").find("method,path,request:x-request-id,duration,content_type,source_app,response:content-type") >= 0,
            10, 0.2, "reordered columns")
        wait_for(lambda: row.locator('td[data-rv-column="response:content-type"]').text_content() == "application/json",
                 10, 0.2, "response header")
        self.assertEqual(row.locator('td[data-rv-column="content_type"]').text_content(), "application/json")
        self.assertRegex(row.locator('td[data-rv-column="duration"]').text_content(), r"\d+ ms")
        self.assertTrue(row.locator('td[data-rv-column="source_app"]').text_content())
        self.assertEqual(self.errors, [])

    def test_extra_columns_survive_scrolling_selection_and_a_reload(self):
        """The cells are added to a table React owns: rows it recycles while scrolling, a selection and a page reload must
        neither lose them nor leave a stale value from a recycled row."""
        self.panel.ok("columns_set", {"columns": ["path", "request:x-echo-n", "status", "duration"]})
        for i in range(120):
            self.inst.fetch(self.up.url("/echo?n=%d" % i), headers={"X-Echo-N": str(i)})
        page = self.open()
        wait_for(lambda: page.locator(".flow-table tbody tr").count() > 5, 15, 0.2, "rows")

        def mismatches():
            return page.evaluate("""() => [...document.querySelectorAll('.flow-table tbody tr')].filter(r => /n=\\d+$/.test((r.querySelector('td.col-path') || {}).textContent || '')).map(r => {   // not the list's spacer rows
                const c = r.querySelector('td[data-rv-column="request:x-echo-n"]');
                const m = r.querySelector('td.col-path').textContent.match(/n=(\\d+)$/)[1];
                return !c ? 'missing:' + m : (c.textContent === m ? '' : c.textContent + '!=' + m);
              }).filter(Boolean)""")
        wait_for(lambda: mismatches() == [], 10, 0.2, "every visible row shows its own header value")
        page.evaluate("document.querySelector('.flow-table').scrollTo(0, 99999)" )
        page.wait_for_timeout(500)
        wait_for(lambda: mismatches() == [], 10, 0.2, "every visible row shows its own header value")
        page.locator(".flow-table tbody tr").nth(3).click()
        page.keyboard.press("ArrowDown")
        page.wait_for_timeout(300)
        wait_for(lambda: mismatches() == [], 10, 0.2, "every visible row shows its own header value")
        order = "() => [...document.querySelectorAll('.flow-table thead th')].map(x => x.dataset.rvColumn || x.className.match(/col-([a-z_]+)/)?.[1]).filter(Boolean).join(',')"
        self.assertEqual(page.locator(".flow-table thead th.col-quickactions").count(), 1)      # not doubled
        self.assertIn("path,request:x-echo-n,status,duration", page.evaluate(order).replace("tls,icon,", ""))
        page.reload()
        wait_for(lambda: page.locator('.flow-table th[data-rv-column="request:x-echo-n"]').count() == 1, 15, 0.2, "restored after reload")
        wait_for(lambda: mismatches() == [], 10, 0.2, "every visible row shows its own header value")
        self.assertEqual(self.errors, [])

    def test_hiding_start_time_keeps_the_newest_call_first(self):
        self.panel.ok("columns_set", {"columns": ["path", "status"]})
        for i in range(4):
            self.inst.fetch(self.up.url("/echo?order=%d" % i))
        page = self.open()
        wait_for(lambda: page.locator(".flow-table tbody tr", has_text="order=3").count() == 1, 15, 0.2, "rows")
        self.assertEqual(page.evaluate("getComputedStyle(document.querySelector('.flow-table th.col-timestamp')).display"), "none")
        def position(n):
            return page.evaluate("""(n) => [...document.querySelectorAll('.flow-table tbody tr')]
              .filter(x => x.querySelector('td.col-path')).findIndex(x => x.textContent.includes('order=' + n))""", n)
        wait_for(lambda: position(0) >= 0 and position(3) >= 0, 10, 0.2, "all four rows rendered")
        self.assertLess(position(3), position(0))      # newest above oldest: still sorted by the hidden start time
        self.assertEqual(self.errors, [])
