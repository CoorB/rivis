"""UI overhaul phase 2 — tool windows in the new main window (/rivis/): Breakpoint (rules and the paused call),
Map Local, Map Remote and the other rules, Scripting, Network, Edit and Repeat, plus the right-click menu's Pin,
Highlight and Comment. Each test is a workflow clicked through the page, with its effect checked on the wire."""
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402

MOD = "Meta" if sys.platform == "darwin" else "Control"


@unittest.skipIf(PW_REASON, PW_REASON or "")
class ToolWindows(UiBase):
    def setUp(self):
        super().setUp()
        self.context.grant_permissions(["clipboard-read", "clipboard-write"])

    def tearDown(self):
        for p in self.panel.state()["paused"]:                # never leak a held call into the next test
            self.panel.post("paused_abort", {"id": p["id"]})
        super().tearDown()

    # ── helpers ─────────────────────────────────────────────────────────────────────────────────────────────────────
    def open_new(self, *paths):
        for p in paths:
            self.fetch(p)
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.goto("http://127.0.0.1:%d/rivis/" % self.inst.web_port)
        self.page.locator("#rv-app").wait_for(timeout=15000)
        # leaving the previous page (the classic login page polls state) aborts its poll: not this page's error
        self.errors[:] = [e for e in self.errors if not (e[0] == "requestfailed" and e[1].endswith("/proxy/api/state"))]
        wait_for(lambda: self.page.evaluate("!!(window.RivisTools && window.RivisApp && window.__rivisUI.state)"), 10, 0.1, "tools ready")
        return self.page

    def row(self, text):
        return self.page.locator(".rv-tr", has_text=text).first

    def wait_row(self, text, timeout=10):
        wait_for(lambda: self.page.locator(".rv-tr", has_text=text).count() > 0, timeout, 0.1, "row %s" % text)

    def win(self, wid):
        return self.page.locator('.rv-win[data-win="%s"]' % wid)

    def win_open(self, wid, timeout=10):
        wait_for(lambda: self.win(wid).count() == 1 and self.win(wid).is_visible(), timeout, 0.1, "window %s" % wid)
        return self.win(wid)

    def menu(self, text, act):
        self.wait_row(text)
        self.row(text).click(button="right")
        self.page.locator('#menu [data-act="%s"]' % act).click()

    def in_background(self, path, **kw):
        box = {}
        t = threading.Thread(target=lambda: box.update(r=self.fetch(path, **kw)), daemon=True)
        t.start()
        return t, box

    def toast(self):
        return self.page.locator("#toast").inner_text()

    def test_allow_list_shortcut_opens_network_at_decrypt_hosts(self):
        self.open_new()
        self.page.locator('#q').focus()
        self.page.keyboard.press(MOD + "+Alt+A")
        w = self.win_open("net")
        field = w.locator('[data-net-tls-add="allow"]')
        self.assertTrue(field.is_visible())
        self.assertTrue(field.evaluate("e => document.activeElement === e"))
        self.assertTrue(field.evaluate("e => { const r=e.getBoundingClientRect(); return r.top>=0 && r.bottom<=innerHeight }"))
        self.page.keyboard.press("Escape")
        self.page.locator('#tscroll').focus()
        self.page.keyboard.press("?")
        self.assertIn("Allow List", self.page.locator("#dialog").inner_text())

    # ── Breakpoint ──────────────────────────────────────────────────────────────────────────────────────────────────
    def test_breakpoint_from_the_menu_then_the_paused_call_opens_by_itself_and_its_edit_reaches_the_app(self):
        self.open_new("/json/small?nbp=1")
        self.menu("nbp=1", "bp")
        w = self.win_open("bp")
        wait_for(lambda: "nbp" in w.inner_text() or "small" in w.inner_text(), 5, 0.1, "rule listed")
        self.page.wait_for_timeout(1200)                     # the proxy picks the filter up within a second
        t, box = self.in_background("/json/small?nbp=1")
        p = self.win_open("paused", 15)
        wait_for(lambda: "Paused at the request" in p.inner_text(), 10, 0.1, "request phase")
        p.locator("[data-pcont]").click()                    # request untouched → the response pauses next
        wait_for(lambda: "Paused at the response" in p.inner_text(), 15, 0.1, "response phase")
        p.locator("#pst").fill("418")
        p.locator("#pb").fill('{"teapot": true}')
        p.locator("[data-pcont]").click()
        t.join(20)
        self.assertEqual((box["r"].status, box["r"].json()), (418, {"teapot": True}))
        wait_for(lambda: not self.win("paused").is_visible(), 5, 0.1, "window closes when nothing else waits")
        self.assertEqual(self.errors, [])

    def test_a_paused_row_is_marked_and_a_click_opens_it_and_abort_fails_the_call(self):
        self.open_new("/text?nab=1")
        self.panel.ok("bp_add", {"host": "127.0.0.1", "path": "/text*", "request": True, "response": False})
        self.page.wait_for_timeout(1200)
        t, box = self.in_background("/text?nab=2")
        p = self.win_open("paused", 15)
        self.page.locator('.rv-win[data-win="paused"] .rv-win-x').click()   # dismissed: it stays paused in the list
        wait_for(lambda: self.page.locator(".rv-tr.rv-is-paused", has_text="nab=2").count() == 1, 10, 0.1, "paused row")
        self.assertIn("paused", self.row("nab=2").inner_text())
        self.row("nab=2").click()
        p = self.win_open("paused")
        p.locator("[data-pabort]").click()
        t.join(20)
        self.assertNotEqual(getattr(box.get("r"), "status", None), 200, "the app gets an error, not the server's answer")

    def test_add_edit_turn_off_and_delete_a_breakpoint_rule(self):
        self.open_new("/json/small?nrule=1")
        self.page.keyboard.press(MOD + "+Alt+B")
        w = self.win_open("bp")
        w.locator("[data-bp-new]").click()
        w.locator("#bpu").fill("127.0.0.1/json/small*")
        w.locator("#bpr").check()
        w.locator("[data-bp-save]").click()
        wait_for(lambda: len(self.panel.state()["breakpoints"]) == 1, 5, 0.1, "added")
        b = self.panel.state()["breakpoints"][0]
        self.assertEqual((b["request"], b["response"]), (True, True))
        wait_for(lambda: w.locator("[data-bp-on]").count() == 1, 5, 0.1, "listed")
        w.locator("[data-bp-on]").uncheck()
        wait_for(lambda: self.panel.state()["breakpoints"][0]["enabled"] is False, 5, 0.1, "off")
        w.locator("[data-bp-del]").click()
        self.page.locator("#dyes").click()
        wait_for(lambda: self.panel.state()["breakpoints"] == [], 5, 0.1, "deleted")
        self.page.keyboard.press("Escape")
        wait_for(lambda: not w.is_visible(), 5, 0.1, "Esc closes the window")

    # ── Map Local ───────────────────────────────────────────────────────────────────────────────────────────────────
    def test_map_local_from_the_menu_edit_save_and_the_next_call_gets_it(self):
        self.open_new("/json/small?nml=1")
        self.menu("nml=1", "map")
        w = self.win_open("map")
        ta = w.locator("#mlbody")
        wait_for(lambda: ta.count() == 1 and ta.input_value() != "", 10, 0.1, "editor with the call's response")
        self.assertIn("discarded", w.inner_text(), "a draft says it is discarded unless saved")
        ta.fill('{"mocked": 1}')
        w.locator("#mlst").fill("201")
        ta.press(MOD + "+s")
        wait_for(lambda: "Saved" in self.toast(), 5, 0.1, "saved")
        r = self.fetch("/json/small?nml=1")
        self.assertEqual((r.status, r.json()), (201, {"mocked": 1}))

    def test_closing_an_unsaved_map_local_draft_discards_it_and_the_next_call_is_live(self):
        self.open_new("/json/small?ndraft=1")
        self.menu("ndraft=1", "map")
        w = self.win_open("map")
        wait_for(lambda: w.locator("#mlbody").count() == 1, 10, 0.1, "editor")
        w.locator(".rv-win-x").click()
        wait_for(lambda: not [r for r in self.panel.state()["rules"] if r["action"] == "map_local"], 5, 0.1, "draft deleted")
        self.assertEqual(self.fetch("/json/small?ndraft=1").status, 200)

    def test_changed_map_local_asks_before_closing(self):
        self.open_new("/json/small?nask=1")
        self.menu("nask=1", "map")
        w = self.win_open("map")
        wait_for(lambda: w.locator("#mlbody").count() == 1, 10, 0.1, "editor")
        w.locator("#mlbody").fill("changed")
        self.page.keyboard.press("Escape")
        self.page.locator("#dialog").wait_for(state="visible", timeout=5000)
        self.page.locator("#dno").click()
        self.assertTrue(w.is_visible(), "Cancel keeps the window and the edit")
        self.assertEqual(w.locator("#mlbody").input_value(), "changed")

    def test_add_a_rule_by_url_and_toggle_it_from_the_list(self):
        self.open_new("/json/small?nadd=1")
        self.page.locator('[data-tool="map"]').click()
        w = self.win_open("map")
        w.locator("[data-ml-new]").click()
        w.locator(".rv-sheet input[name=url]").fill("127.0.0.1/json/small*")
        w.locator(".rv-sheet input[name=status]").fill("202")
        w.locator(".rv-sheet button[type=submit]").click()
        wait_for(lambda: w.locator("#mlbody").count() == 1, 10, 0.1, "editor for the new rule")
        w.locator("#mlbody").fill('{"by":"url"}')
        w.locator("[data-mlsave]").click()
        wait_for(lambda: self.fetch("/json/small?nadd=2").status == 202, 5, 0.2, "mock answers")
        w.locator("[data-ml-on]").first.uncheck()
        wait_for(lambda: self.fetch("/json/small?nadd=3").status == 200, 5, 0.2, "off → live again")

    # ── Map Remote, Block List and the other rules ──────────────────────────────────────────────────────────────────
    def test_block_from_the_menu_then_the_call_fails(self):
        self.open_new("/json/small?nblk=1")
        self.menu("nblk=1", "block")
        w = self.win_open("rules")
        ed = w.locator("[data-r-ed]")
        wait_for(lambda: ed.is_visible(), 5, 0.1, "editor prefilled from the call")
        self.assertIn("json", w.locator("#rf-match").input_value())
        w.locator("[data-r-save]").click()
        wait_for(lambda: any(r["action"] == "block" for r in self.panel.state()["rules"]), 5, 0.1, "block rule")
        self.page.wait_for_timeout(1200)
        r = self.fetch("/json/small?nblk=2")
        self.assertNotEqual(getattr(r, "status", 0), 200)

    def test_map_remote_rule_sends_the_call_elsewhere_and_test_explains_it(self):
        self.open_new("/json/small?nmr=1")
        self.page.keyboard.press(MOD + "+Alt+R")
        w = self.win_open("rules")
        w.locator("[data-r-new]").click()
        w.locator("#rf-name").fill("to-text")
        w.locator("#rf-match").fill("json/small\\?nmr")
        w.locator("#rf-replace").fill("/json/small")
        w.locator("#rf-with").fill("/text")
        w.locator("[data-r-save]").click()
        wait_for(lambda: any(r["name"] == "to-text" for r in self.panel.state()["rules"]), 5, 0.1, "rule")
        self.page.wait_for_timeout(1200)
        r = self.fetch("/json/small?nmr=2")
        self.assertNotIn("json", dict((k.lower(), v) for k, v in r.headers).get("content-type", ""), "answered by /text")
        self.wait_row("nmr=2")
        rb = self.row("nmr=2").bounding_box()                # the window floats over the table: click the row's visible end
        self.row("nmr=2").click(position={"x": rb["width"] - 16, "y": rb["height"] / 2})
        w.locator("[data-r-test]").click()
        wait_for(lambda: "to-text" in w.locator("[data-r-testout]").inner_text() and "fires" in w.locator("[data-r-testout]").inner_text(), 5, 0.1, "explained")

    # ── Scripting, Network, Edit and Repeat ─────────────────────────────────────────────────────────────────────────
    def test_network_no_caching_and_a_throttle_profile(self):
        self.open_new("/json/small?nnet=1")
        self.page.locator('[data-tool="net"]').click()
        w = self.win_open("net")
        w.locator("[data-net-nocache]").check()
        wait_for(lambda: self.panel.state()["no_cache"], 5, 0.1, "no caching on")
        prof = [p for p in self.panel.state()["profiles"] if p["id"] not in ("off", "manual")][0]
        w.locator("[data-net-profile]").select_option(prof["id"])
        wait_for(lambda: self.panel.state()["throttle"] == prof["id"], 5, 0.1, "throttle")
        w.locator("[data-net-profile]").select_option("off")
        wait_for(lambda: self.panel.state()["throttle"] == "off", 5, 0.1, "throttle off")

    def test_scripting_window_creates_and_switches_a_script(self):
        self.open_new("/json/small?nsc=1")
        self.page.locator('[data-tool="scripts"]').click()
        w = self.win_open("scripts")
        before = len(self.panel.state()["scripts"])
        w.locator("[data-script-new]").click()
        w.locator('[data-script-field="name"]').fill("ui-script")
        w.locator("[data-script-save]").click()
        wait_for(lambda: len(self.panel.state()["scripts"]) == before + 1, 10, 0.2, "script created")
        s = [x for x in self.panel.state()["scripts"] if "ui-script" in x["name"] or "ui-script" in x["file"]][0]
        wait_for(lambda: w.locator('[data-script-field="content"]').count() == 1, 10, 0.1, "opened in the editor")
        w.locator('[data-script-on="%s"]' % s["file"]).click()
        wait_for(lambda: [x for x in self.panel.state()["scripts"] if x["file"] == s["file"]][0]["enabled"] != s["enabled"], 5, 0.1, "toggled")

    def test_edit_and_repeat_sends_a_changed_copy(self):
        self.open_new("/echo?ner=1")
        self.menu("ner=1", "edit")
        w = self.win_open("repeat")
        u = w.locator("#rpu")
        wait_for(lambda: u.count() == 1 and "ner=1" in u.input_value(), 10, 0.1, "loaded")
        u.fill(u.input_value().replace("ner=1", "ner=2"))
        w.locator("[data-rpsend]").click()
        self.wait_row("ner=2")
        self.assertTrue(self.row("ner=1").count(), "the original stays")

    # ── right-click: highlight, comment, pin ────────────────────────────────────────────────────────────────────────
    def test_highlight_and_comment_live_on_the_call(self):
        self.open_new("/json/small?nhl=1")
        self.menu("nhl=1", "mark")
        self.page.locator('#menu [data-mark="green"]').click()
        wait_for(lambda: self.page.locator(".rv-tr.rv-mark-green", has_text="nhl=1").count() == 1, 5, 0.1, "row highlighted")
        wait_for(lambda: self.inst.flow_for("/json/small?nhl=1").get("marked") == "🟢", 5, 0.2, "stored on the call (mitmweb's marker)")
        self.menu("nhl=1", "comment")
        self.page.locator("#dtext").fill("look at this")
        self.page.locator("#dialog button[type=submit]").click()
        wait_for(lambda: self.inst.flow_for("/json/small?nhl=1").get("comment") == "look at this", 5, 0.2, "comment stored")
        wait_for(lambda: self.row("nhl=1").locator(".rv-cmt").count() == 1, 5, 0.1, "comment marker")

    def test_pin_a_domain_with_cmd_k_and_enter(self):
        self.open_new("/json/small?npin=1")
        self.page.keyboard.press(MOD + "+K")
        self.page.keyboard.type("127.0.0.1")
        self.page.keyboard.press("Enter")
        wait_for(lambda: "pinned" in self.page.locator("#sources").inner_text().lower(), 5, 0.1, "pinned section")
        self.page.reload()
        self.page.locator("#rv-app").wait_for(timeout=15000)
        # leaving the previous page (the classic login page polls state) aborts its poll: not this page's error
        self.errors[:] = [e for e in self.errors if not (e[0] == "requestfailed" and e[1].endswith("/proxy/api/state"))]
        wait_for(lambda: "pinned" in self.page.locator("#sources").inner_text().lower(), 5, 0.1, "kept after a reload")
        self.page.locator("[data-unpin]").first.click(force=True)
        wait_for(lambda: "pinned" not in self.page.locator("#sources").inner_text().lower(), 5, 0.1, "unpinned")

    # ── notices, help, first run ────────────────────────────────────────────────────────────────────────────────────
    def test_another_proxy_app_and_an_untrusted_certificate_are_noticed_without_covering_anything(self):
        import json as _json
        def patch(route):
            resp = route.fetch()
            doc = resp.json()
            doc["system_proxy"] = {"host": "127.0.0.1", "port": "9091", "owner": "Proxyman", "ours": False, "stale": False}
            doc["untrusted"] = [{"host": "api.example.test"}]
            route.fulfill(response=resp, body=_json.dumps(doc), headers={**resp.headers, "content-type": "application/json"})
        self.page.route("**/proxy/api/state", patch)
        self.open_new("/json/small?nbn=1")
        bar = self.page.locator('[data-banner="proxy"]')
        wait_for(lambda: bar.is_visible(), 10, 0.1, "banner")
        self.assertIn("Quit Proxyman", bar.inner_text())
        self.assertIn("api.example.test", self.page.locator('[data-banner="untrusted"]').inner_text())
        b, lst = self.page.locator("#banners").bounding_box(), self.page.locator("#list").bounding_box()
        self.assertLessEqual(b["y"] + b["height"], lst["y"] + 1, "the notices sit above the list, never over it")
        self.page.locator("#tb-record").click(timeout=3000)          # nothing covers the toolbar
        self.assertEqual(self.page.locator("#tb-record").get_attribute("aria-pressed"), "false")

    def test_question_mark_shows_the_shortcuts_and_esc_closes_them(self):
        self.open_new("/json/small?nhelp=1")
        self.page.locator("#tscroll").focus()
        self.page.keyboard.press("?")
        d = self.page.locator("#dialog")
        wait_for(lambda: d.is_visible() and "Map Local" in d.inner_text(), 5, 0.1, "shortcuts")
        self.page.keyboard.press("Escape")
        wait_for(lambda: not d.is_visible(), 5, 0.1, "closed")

    def test_first_run_welcome_shows_once(self):
        ctx = self.browser.new_context()
        self.addCleanup(ctx.close)
        page = ctx.new_page()
        page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        page.goto("http://127.0.0.1:%d/rivis/" % self.inst.web_port)
        d = page.locator("#dialog")
        wait_for(lambda: d.is_visible() and "Welcome" in d.inner_text(), 10, 0.1, "welcome")
        page.keyboard.press("Escape")
        wait_for(lambda: not d.is_visible(), 5, 0.1, "closed")
        page.reload()
        page.locator("#rv-app").wait_for(timeout=15000)
        page.wait_for_timeout(1500)
        self.assertFalse(d.is_visible(), "shown once per browser")


if __name__ == "__main__":
    import harness
    harness.main()
