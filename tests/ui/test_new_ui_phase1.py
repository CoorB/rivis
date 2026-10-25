"""UI overhaul phase 1 — the new main window at /rivis/ (Proxyman's arrangement): live call list, filter chips,
sources, request and response side by side, search in a body, JSON tree, Proxyman's shortcuts, in-page questions."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402

MOD = "Meta" if sys.platform == "darwin" else "Control"


@unittest.skipIf(PW_REASON, PW_REASON or "")
class NewMainWindow(UiBase):
    def setUp(self):
        super().setUp()
        self.context.grant_permissions(["clipboard-read", "clipboard-write"])

    def open_new(self, *paths):
        for p in paths or ("/json/small?nu=1", "/echo?nu=2", "/text?nu=3"):
            self.fetch(p)
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.goto("http://127.0.0.1:%d/rivis/" % self.inst.web_port)
        self.page.locator("#rv-app").wait_for(timeout=15000)
        return self.page

    def rows(self, text=None):
        loc = self.page.locator(".rv-tr")
        return loc.filter(has_text=text) if text else loc

    def wait_rows(self, text, n=1, timeout=10):
        wait_for(lambda: self.rows(text).count() >= n, timeout, 0.1, "row %s" % text)

    def visible_ids(self):
        return self.page.evaluate("window.__rivisUI.view.slice()")

    def shown(self, text):
        """Is a call whose URL contains text in the list now (the list is virtual: off-screen rows are not in the DOM)."""
        return self.page.evaluate("(t) => window.__rivisUI.view.some((id) => { const r = window.__rivisUI.byId.get(id).request; return (r.path || '').includes(t); })", text)

    def toast(self):
        return self.page.locator("#toast").inner_text()

    # ── list and live feed ────────────────────────────────────────────────────────────────────────────────────────────
    def test_calls_show_live_without_a_reload_and_the_status_bar_counts_them(self):
        self.open_new()
        self.wait_rows("nu=3")
        count = lambda: self.page.evaluate("window.__rivisUI.view.length")   # the list is virtual: rows ≠ calls
        wait_for(lambda: self.page.wait_for_timeout(300) or count() == count(), 5, 0.1, "list settled")
        before = count()
        self.fetch("/json/small?live=1")
        self.wait_rows("live=1")
        self.assertEqual(count(), before + 1)
        wait_for(lambda: "Live" in self.page.locator("#status").inner_text(), 5, 0.1, "live indicator")
        self.assertIn("%d of %d calls" % (before + 1, before + 1), self.page.locator("#status").inner_text())
        self.assertEqual(self.errors, [])

    def test_url_with_markup_is_shown_as_text(self):
        import harness
        self.open_new()
        # a raw request line: curl would percent-encode the markup and prove nothing
        harness.raw_http(self.inst.proxy_port, "GET", "http://127.0.0.1:%d/echo?x=<img/src=x/onerror=window.__pwned=1>" % self.up.http_port)
        self.wait_rows("onerror")
        self.assertIsNone(self.page.evaluate("window.__pwned || null"))
        self.assertEqual(self.page.locator(".rv-tr img").count(), 0)

    def test_follow_selects_the_newest_and_a_click_stops_following(self):
        self.open_new()
        self.wait_rows("nu=3")
        self.assertEqual(self.page.locator("#tb-follow").get_attribute("aria-pressed"), "true")
        self.fetch("/json/small?follow=1")
        wait_for(lambda: self.rows("follow=1").count() and self.rows("follow=1").first.get_attribute("aria-selected") == "true", 8, 0.1, "newest selected")
        self.rows("nu=1").first.click()
        self.assertEqual(self.page.locator("#tb-follow").get_attribute("aria-pressed"), "false")
        self.fetch("/json/small?follow=2")
        self.wait_rows("follow=2")
        self.assertEqual(self.rows("nu=1").first.get_attribute("aria-selected"), "true", "a click stops following")
        self.page.keyboard.press(MOD + "+Shift+L")
        wait_for(lambda: self.rows("follow=2").first.get_attribute("aria-selected") == "true", 5, 0.1, "Shift+Cmd+L follows again")

    def test_record_off_holds_new_calls_until_it_is_on_again(self):
        self.open_new()
        self.wait_rows("nu=3")
        self.page.locator("#tb-record").click()
        self.fetch("/json/small?held=1")
        wait_for(lambda: "waiting" in self.page.locator("#status").inner_text(), 8, 0.1, "held count")
        self.assertEqual(self.rows("held=1").count(), 0)
        self.page.locator("#tb-record").click()
        self.wait_rows("held=1")

    # ── filters ───────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_type_and_status_chips(self):
        self.open_new("/json/small?c=1", "/text?c=2", "/status/404?c=3")
        self.wait_rows("c=3")
        self.page.locator("[data-chip=json]").click()
        wait_for(lambda: not self.shown("c=2") and self.shown("c=1"), 5, 0.1, "JSON only")
        self.page.locator("[data-chip=all]").click()
        self.page.locator("[data-status='4xx']").click()
        wait_for(lambda: self.shown("c=3") and not self.shown("c=1"), 5, 0.1, "4xx only")
        self.page.locator("[data-status='4xx']").click()
        wait_for(lambda: self.shown("c=1") and self.shown("c=2"), 5, 0.1, "all again")

    def test_text_filter_and_a_mitmproxy_filter(self):
        self.open_new("/json/small?f=one", "/text?f=two")
        self.wait_rows("f=two")
        self.page.keyboard.press(MOD + "+Alt+f")
        self.assertTrue(self.page.locator("#q").evaluate("e => e === document.activeElement"))
        self.page.keyboard.type("f=one")
        wait_for(lambda: not self.shown("f=two") and self.shown("f=one"), 5, 0.1, "text filter")
        self.page.locator("#q").fill("~u text")
        self.page.locator("#q").press("Enter")
        wait_for(lambda: self.shown("f=two") and not self.shown("f=one"), 8, 0.1, "~u filter from mitmproxy")
        self.fetch("/text?f=three")
        self.wait_rows("f=three")                 # new calls are matched by the live filter too

    def test_an_invalid_filter_says_so_and_never_drops_the_live_feed(self):
        self.open_new()
        self.wait_rows("nu=3")
        self.page.locator("#q").fill("~u (")
        self.page.locator("#q").press("Enter")
        wait_for(lambda: "Not a valid filter" in self.page.locator("#qerr").inner_text(), 5, 0.1, "error shown")
        self.fetch("/json/small?after-bad=1")
        self.wait_rows("after-bad=1")
        self.assertIn("Live", self.page.locator("#status").inner_text())

    def test_saved_filter_chip_and_alt_1(self):
        self.panel.ok("filters_save", {"name": "Only echo", "filter": "~u echo"})
        try:
            self.open_new("/echo?s=1", "/text?s=2")
            self.wait_rows("s=2")
            chip = self.page.locator("[data-saved='0']")
            wait_for(lambda: chip.count() == 1, 6, 0.1, "saved chip")
            self.page.locator("#tscroll").focus()
            self.page.keyboard.press("Alt+1")
            wait_for(lambda: not self.shown("s=2") and self.shown("s=1"), 8, 0.1, "saved filter applied")
            self.assertEqual(self.page.locator("#q").input_value(), "~u echo")
        finally:
            self.panel.ok("filters_delete", {"name": "Only echo"})

    def test_domain_in_the_sidebar_shows_only_that_host(self):
        self.open_new()
        self.inst.fetch("http://localhost:%d/json/small?other=1" % self.up2.http_port)
        wait_for(lambda: self.shown("other=1"), 10, 0.1, "the call to localhost")
        self.page.locator("#sq").fill("localhost")
        dom = self.page.locator("[data-src-host='localhost']")
        wait_for(lambda: dom.count() == 1, 8, 0.1, "domain listed")
        dom.click()
        wait_for(lambda: self.shown("other=1") and not self.shown("nu=1"), 5, 0.1, "only localhost")
        self.page.locator("[data-src-all]").click()
        wait_for(lambda: self.shown("nu=1"), 5, 0.1, "all again")

    # ── detail ────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_request_and_response_side_by_side(self):
        self.open_new("/json/small?side=1")
        self.wait_rows("side=1")
        self.rows("side=1").first.click()
        req, res = self.page.locator("#pane-req"), self.page.locator("#pane-res")
        wait_for(lambda: "GET" in req.inner_text() and "200" in res.inner_text(), 8, 0.1, "both panes")
        rb, sb = req.bounding_box(), res.bounding_box()
        self.assertLess(rb["x"] + rb["width"], sb["x"] + 6, "response sits to the right of the request")
        self.assertAlmostEqual(rb["y"], sb["y"], delta=2)
        wait_for(lambda: "alice" in res.inner_text(), 8, 0.1, "response body")
        self.page.locator("#pane-req [data-tab=query]").click()
        wait_for(lambda: "side" in req.inner_text() and "1" in req.inner_text(), 5, 0.1, "query row")
        self.page.locator("#pane-res [data-tab=header]").click()
        wait_for(lambda: "application/json" in res.inner_text().lower(), 5, 0.1, "response headers")
        self.page.locator("#pane-res [data-tab=body]").click()

    def test_search_in_a_body_counts_and_steps(self):
        self.open_new("/json/find?b=1")
        self.wait_rows("b=1")
        self.rows("b=1").first.click()
        self.page.locator("#pane-res [data-tab=body]").click()
        wait_for(lambda: "FINDME" in self.page.locator("#pane-res").inner_text(), 8, 0.1, "body")
        self.page.locator("#pane-res .rv-pb").click()
        self.page.keyboard.press(MOD + "+f")          # the pane clicked last
        field = self.page.locator("[data-find=res]")
        self.assertTrue(field.evaluate("e => e === document.activeElement"))
        field.fill("findme")
        count = self.page.locator("[data-fc=res]")
        wait_for(lambda: count.inner_text() == "1 of 12", 5, 0.1, "12 matches")
        field.press("Enter")
        self.assertEqual(count.inner_text(), "2 of 12")
        field.press("Shift+Enter")
        self.assertEqual(count.inner_text(), "1 of 12")
        self.assertEqual(self.page.evaluate("CSS.highlights.get('rv-find').size"), 12)

    def test_json_tree_search_opens_branches_and_copies_a_path(self):
        self.open_new("/json/long?n=600&tree=1")
        self.wait_rows("tree=1")
        self.rows("tree=1").first.click()
        self.page.locator("#pane-res [data-tab=tree]").click()
        tree = self.page.locator("#pane-res .rv-tree")
        wait_for(lambda: tree.count() == 1 and tree.get_attribute("data-ready") == "1", 10, 0.1, "tree")
        self.assertIn("[600]", tree.inner_text())
        self.assertLess(self.page.evaluate("document.querySelectorAll('.rv-tree .rv-tl').length"), 260, "only what is open is built")
        field = self.page.locator("[data-find=res]")
        field.fill("account 512")
        wait_for(lambda: self.page.locator("[data-fc=res]").inner_text().startswith("1 of"), 5, 0.1, "match in a closed branch")
        node = tree.locator('[data-path="$.accounts[512].name"]')
        self.assertEqual(node.count(), 1, "the branch with the match was opened")
        node.hover()
        node.locator("[data-copy=path]").click()
        wait_for(lambda: self.page.evaluate("navigator.clipboard.readText()") == "$.accounts[512].name", 5, 0.1, "path copied")

    def test_a_body_over_2_mb_gets_no_tree_and_a_clipped_text_view(self):
        self.open_new("/big?mb=3&big=1")
        self.wait_rows("big=1")
        self.rows("big=1").first.click()
        self.page.locator("#pane-res [data-tab=tree]").click()
        wait_for(lambda: "up to 2 MB" in self.page.locator("#pane-res").inner_text(), 15, 0.1, "no tree")
        self.page.locator("#pane-res [data-tab=body]").click()
        wait_for(lambda: "Binary body, 3.0 MB" in self.page.locator("#pane-res").inner_text(), 15, 0.1, "binary shown as hex")
        self.assertIn("00000000  ", self.page.locator("#pane-res pre").inner_text())

    def test_a_long_text_body_is_clipped_with_a_note(self):
        self.open_new("/json/long?n=30000&clip=1")
        self.wait_rows("clip=1")
        self.rows("clip=1").first.click()
        self.page.locator("#pane-res [data-tab=body]").click()
        wait_for(lambda: "Showing the first 512 KB" in self.page.locator("#pane-res").inner_text(), 15, 0.1, "clipped")

    # ── review fixes ──────────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_list_keeps_drawing_while_calls_keep_arriving(self):
        import threading
        import time
        self.open_new()
        self.wait_rows("nu=3")
        stop = time.time() + 6
        def burst():
            i = 0
            while time.time() < stop:
                i += 1
                self.fetch("/json/small?burst=%d" % i)
        threads = [threading.Thread(target=burst) for _ in range(4)]
        for t in threads:
            t.start()
        try:
            # a debounce drew nothing until the traffic stopped; a throttle draws during it
            wait_for(lambda: self.rows("burst=").count() > 0, 4, 0.05, "rows drawn while the burst runs")
            self.assertLess(time.time(), stop, "drawn before the burst ended")
        finally:
            for t in threads:
                t.join()

    def test_a_call_that_arrives_while_the_list_loads_is_not_lost(self):
        import time
        self.fetch("/json/small?old=1")
        seen = []
        def slow_snapshot(route):
            resp = route.fetch()               # the snapshot as it was before the new call
            if not seen:
                seen.append(1)
                self.fetch("/json/small?during=1")
                time.sleep(1.5)                # the feed delivers the new call meanwhile
            route.fulfill(response=resp)
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.route("**/flows", slow_snapshot)
        self.page.goto("http://127.0.0.1:%d/rivis/" % self.inst.web_port)
        self.page.locator("#rv-app").wait_for(timeout=15000)
        self.wait_rows("old=1")
        wait_for(lambda: self.page.wait_for_timeout(50) or bool(seen), 10, 0.05, "snapshot served")
        self.page.wait_for_timeout(800)
        self.assertTrue(self.shown("during=1"), "the older snapshot did not erase the newer call")

    def test_a_held_call_counts_once(self):
        self.open_new()
        self.wait_rows("nu=3")
        self.page.locator("#tb-record").click()
        self.fetch("/json/small?once=1")
        wait_for(lambda: "waiting" in self.page.locator("#status").inner_text(), 8, 0.1, "held count")
        self.page.wait_for_timeout(600)              # its response event too
        self.assertIn("1 waiting", self.page.locator("#status").inner_text())

    def test_tree_search_finds_a_match_past_20000_entries(self):
        self.open_new("/json/long?n=22000&far=1")
        self.wait_rows("far=1")
        self.rows("far=1").first.click()
        self.page.locator("#pane-res [data-tab=tree]").click()
        tree = self.page.locator("#pane-res .rv-tree")
        wait_for(lambda: tree.count() == 1 and tree.get_attribute("data-ready") == "1", 15, 0.1, "tree")
        self.page.locator("[data-find=res]").fill("account 21500")
        wait_for(lambda: self.page.locator("[data-fc=res]").inner_text().startswith("1 of"), 10, 0.1, "match past 20000")
        self.assertEqual(tree.locator('[data-path="$.accounts[21500].name"]').count(), 1)

    def test_shortcuts_leave_a_text_field_alone(self):
        self.open_new()
        self.wait_rows("nu=3")
        self.assertEqual(self.page.locator("#tb-follow").get_attribute("aria-pressed"), "true")
        self.page.locator("#q").click()
        self.page.keyboard.press(MOD + "+Shift+L")
        self.page.wait_for_timeout(200)
        self.assertEqual(self.page.locator("#tb-follow").get_attribute("aria-pressed"), "true", "typing keeps follow as it was")
        self.page.evaluate("document.activeElement.blur()")     # (a click in the list would itself stop following)
        self.page.keyboard.press(MOD + "+Shift+L")
        wait_for(lambda: self.page.locator("#tb-follow").get_attribute("aria-pressed") == "false", 5, 0.1, "the list still takes it")

    def test_a_large_body_reports_its_real_size_from_a_bounded_read(self):
        self.open_new("/big?mb=40&huge=1")
        self.wait_rows("huge=1")
        self.rows("huge=1").first.click()
        self.page.locator("#pane-res [data-tab=body]").click()
        wait_for(lambda: "Binary body, 40.0 MB" in self.page.locator("#pane-res").inner_text(), 15, 0.1, "size from the message")

    # ── actions ───────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_clear_asks_in_the_page_then_empties_the_list(self):
        self.open_new()
        self.wait_rows("nu=3")
        self.page.keyboard.press(MOD + "+Shift+Backspace")
        dlg = self.page.locator("#dialog")
        wait_for(lambda: dlg.is_visible(), 5, 0.1, "question")
        self.assertIn("Clear all", dlg.inner_text())
        self.page.locator("#dno").click()
        self.assertGreater(self.rows().count(), 0)
        self.page.locator("#tb-clear").click()
        self.page.locator("#dyes").click()
        wait_for(lambda: self.rows().count() == 0, 8, 0.1, "cleared")
        wait_for(lambda: len(self.inst.flows()) == 0, 8, 0.2, "cleared in Rivis too")
        self.fetch("/json/small?after-clear=1")
        self.wait_rows("after-clear=1")

    def test_right_click_copies_curl_and_deletes_a_call(self):
        self.open_new("/json/small?ctx=1", "/json/small?ctx=2")
        self.wait_rows("ctx=2")
        self.rows("ctx=1").first.click(button="right")
        menu = self.page.locator("#menu")
        wait_for(lambda: menu.is_visible(), 5, 0.1, "menu")
        menu.locator("[data-act=curl]").click()
        wait_for(lambda: self.page.evaluate("navigator.clipboard.readText()").startswith("curl"), 5, 0.1, "cURL copied")
        self.assertIn("ctx=1", self.page.evaluate("navigator.clipboard.readText()"))
        self.rows("ctx=2").first.click(button="right")
        menu.locator("[data-act=delete]").click()
        wait_for(lambda: self.rows("ctx=2").count() == 0, 5, 0.1, "deleted")
        wait_for(lambda: not any("ctx=2" in f["request"]["path"] for f in self.inst.flows()), 5, 0.2, "deleted in Rivis")

    def test_keyboard_moves_through_the_list(self):
        self.open_new("/json/small?k=1", "/json/small?k=2", "/json/small?k=3")
        self.wait_rows("k=3")
        self.rows("k=1").first.click()
        self.page.keyboard.press("ArrowDown")
        wait_for(lambda: self.rows("k=2").first.get_attribute("aria-selected") == "true", 5, 0.1, "down")
        self.page.keyboard.press("ArrowUp")
        wait_for(lambda: self.rows("k=1").first.get_attribute("aria-selected") == "true", 5, 0.1, "up")

    def test_sorting_by_a_column(self):
        self.open_new("/status/500?st=1", "/json/small?st=2", "/status/404?st=3")
        self.wait_rows("st=3")
        self.page.locator(".rv-th[data-col=status]").click()
        self.assertEqual(self.page.locator(".rv-th[data-col=status]").get_attribute("aria-sort"), "ascending")
        statuses = [int(s) for s in self.page.locator(".rv-tr .rv-td:nth-child(4)").all_inner_texts() if s.strip().isdigit()]
        self.assertEqual(statuses, sorted(statuses))
        self.page.locator(".rv-th[data-col=status]").click()
        statuses = [int(s) for s in self.page.locator(".rv-tr .rv-td:nth-child(4)").all_inner_texts() if s.strip().isdigit()]
        self.assertEqual(statuses, sorted(statuses, reverse=True))

    def test_column_picker_adds_a_header_column_for_the_project(self):
        self.open_new("/json/small?col=1")
        self.wait_rows("col=1")
        try:
            self.page.locator("#colpick").click()
            self.page.locator("#hcol").fill("Content-Type")
            self.page.locator("#dyes").click()
            head = self.page.locator(".rv-th[data-col='response:Content-Type']")
            wait_for(lambda: head.count() == 1, 5, 0.1, "new column")
            wait_for(lambda: "application/json" in self.rows("col=1").first.inner_text(), 5, 0.1, "cell value")
            self.assertIn("response:Content-Type", self.panel.state()["columns"])
        finally:
            self.panel.ok("columns_set", {"columns": ["path", "method", "status", "size", "time", "timestamp"]})

    def test_tool_switches_light_up_and_no_caching_toggles_by_shortcut(self):
        self.reset_state(rules=[self.rule("ml", "respond", "/json/small", status=200, body="{}")])
        self.open_new()
        btn = self.page.locator("[data-tool=map]")
        wait_for(lambda: btn.get_attribute("aria-pressed") == "true", 6, 0.1, "Map Local lit")
        enabled = sum(1 for r in self.inst.cfg()["rules"] if r.get("enabled") and r.get("action") in ("respond", "map_local"))
        self.assertIn(str(enabled), btn.inner_text())
        nc = self.page.locator("[data-tool=nocache]")
        self.assertEqual(nc.get_attribute("aria-pressed"), "false")
        self.page.keyboard.press(MOD + "+Alt+n")
        wait_for(lambda: self.panel.state()["no_cache"] is True, 6, 0.2, "No Caching on")
        wait_for(lambda: nc.get_attribute("aria-pressed") == "true", 6, 0.1, "switch lit")
        nc.click()
        wait_for(lambda: self.panel.state()["no_cache"] is False, 6, 0.2, "No Caching off")

    def test_classic_view_opens_a_tool_from_the_new_window(self):
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.goto("http://127.0.0.1:%d/#rivis-tool=bp" % self.inst.web_port)
        self.page.wait_for_selector("#fab", timeout=20000)
        drawer = self.page.locator("#proxy-panel-host").locator("#drawer.open")
        wait_for(lambda: drawer.count() == 1, 8, 0.1, "drawer open")
        self.assertEqual(self.page.locator("#proxy-panel-host").locator("nav button.on").first.get_attribute("data-t"), "bp")
        self.assertNotIn("rivis-tool", self.page.evaluate("location.hash"))


if __name__ == "__main__":
    unittest.main()
