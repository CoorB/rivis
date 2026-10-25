"""Workflows for the additional windows in the new main page."""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for  # noqa: E402
from test_ui import PW_REASON, UiBase  # noqa: E402

MOD = "Meta" if sys.platform == "darwin" else "Control"


@unittest.skipIf(PW_REASON, PW_REASON or "")
class MoreWindows(UiBase):
    def setUp(self):
        super().setUp()
        for saved in self.panel.state().get('sessions') or []:
            self.panel.ok('sess_delete', {'name': saved['name']})
        self.context.grant_permissions(["clipboard-read", "clipboard-write"])
        self.page.on("dialog", lambda d: (self.errors.append(("browser dialog", d.type, d.message)), d.dismiss()))

    def open_new(self, *paths):
        for path in paths:
            self.fetch(path)
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.locator("#fab").wait_for(timeout=15000)
        self.page.goto("http://127.0.0.1:%d/rivis/" % self.inst.web_port)
        self.page.locator("#rv-app").wait_for(timeout=15000)
        # leaving the previous page (the classic login page polls state) aborts its poll: not this page's error
        self.errors[:] = [e for e in self.errors if not (e[0] == "requestfailed" and e[1].endswith("/proxy/api/state"))]
        wait_for(lambda: self.page.evaluate("!!(window.RivisTools && window.RivisApp && window.__rivisUI.state)"), 10, 0.1, "windows ready")
        return self.page

    def row(self, text):
        return self.page.locator(".rv-tr", has_text=text).first

    def wait_row(self, text):
        wait_for(lambda: self.row(text).count() > 0, 10, 0.1, "row " + text)

    def win(self, wid):
        return self.page.locator('.rv-win[data-win="%s"]' % wid)

    def win_open(self, wid):
        wait_for(lambda: self.win(wid).count() == 1 and self.win(wid).is_visible(), 10, 0.1, "window " + wid)
        return self.win(wid)

    def menu(self, text, act):
        self.wait_row(text)
        self.row(text).click(button="right")
        self.page.locator('#menu [data-act="%s"]' % act).click()

    def more(self, wid):
        self.page.locator("#tb-more").click()
        self.page.locator('#menu [data-more="%s"]' % wid).click()
        return self.win_open(wid)

    def test_more_menu_keyboard_and_windows(self):
        self.open_new("/echo?more=1")
        button = self.page.locator("#tb-more")
        button.click()
        self.assertEqual(self.page.evaluate("document.activeElement.dataset.more"), "compose")
        self.page.keyboard.press("ArrowDown")
        self.assertEqual(self.page.evaluate("document.activeElement.dataset.more"), "devices")
        self.page.keyboard.press("ArrowUp")
        self.assertEqual(self.page.evaluate("document.activeElement.dataset.more"), "compose")
        self.page.keyboard.press("Escape")
        self.assertEqual(self.page.evaluate("document.activeElement.id"), "tb-more")
        self.assertEqual(button.get_attribute("aria-expanded"), "false")
        for wid in ("compose", "devices", "collections", "sessions", "compare"):
            self.more(wid)
        self.assertEqual(self.errors, [])

    def test_compose_typing_survives_live_calls_and_keeps_focus(self):
        self.open_new()
        stop = threading.Event()
        def traffic():
            i = 0
            while not stop.is_set():
                i += 1
                try:
                    self.fetch("/echo?stream=%d" % i)
                except Exception:
                    pass
                time.sleep(0.05)
        thread = threading.Thread(target=traffic, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(stop.set)
        url = "http://backbase-edge-sit.localhost:50890/api/user-manager/client-api/v2/users/me?compose=123"
        field = self.more("compose").locator("[data-compose-url]")
        field.fill("")
        field.focus()
        self.page.keyboard.type(url, delay=60)
        self.assertEqual(field.input_value(), url)
        self.page.wait_for_timeout(2600)
        self.assertEqual(field.input_value(), url)
        self.assertTrue(field.evaluate("e => document.activeElement === e"))
        stop.set()
        thread.join(5)
        self.assertEqual(self.errors, [])

    def test_compose_paste_curl_and_send_answer(self):
        self.open_new()
        w = self.more("compose")
        before = len(self.inst.flows())
        w.locator('[data-compose-action="paste"]').click()
        editor = w.locator('textarea[aria-label="Paste cURL command"]')
        editor.fill("curl '" + self.up.url("/echo?curl=1") + "' -X PATCH -H $'X-Test: yes' -d 'hello=world'")
        w.locator("[data-done]").click()
        wait_for(lambda: "curl=1" in w.locator("[data-compose-url]").input_value(), 8, 0.1, "imported")
        self.assertEqual(w.locator("[data-compose-method]").input_value(), "PATCH")
        w.locator('[data-compose-tab="headers"]').click()
        self.assertEqual(w.locator('[data-compose-kv="headers"] .rv-kvr input[type=text]').first.input_value(), "X-Test")
        w.locator('[data-compose-tab="body"]').click()
        self.assertIn("hello=world", w.locator("[data-compose-body]").input_value())
        self.assertEqual(len(self.inst.flows()), before)
        w.locator('[data-compose-action="send"]').click()
        self.wait_row("curl=1")
        flow = self.inst.flow_for("curl=1")
        self.assertEqual(flow["request"]["method"], "PATCH")
        self.assertIn(["X-Test", "yes"], flow["request"]["headers"])
        wait_for(lambda: "hello=world" in w.inner_text(), 8, 0.1, "answer in Compose")
        self.assertEqual(self.errors, [])

    def test_compose_save_reload_load_variables_and_masked_copy(self):
        self.open_new()
        w = self.more("compose")
        w.locator('[data-compose-tab="vars"]').click()
        w.locator('[data-compose-add="vars"]').click()
        inputs = w.locator('[data-compose-kv="vars"] .rv-kvr input[type=text]')
        inputs.nth(0).fill("base")
        inputs.nth(1).fill(self.up.url(""))
        w.locator("[data-compose-vars]").click()
        wait_for(lambda: self.panel.state()["composer"]["vars"].get("base") == self.up.url(""), 8, 0.1, "variable saved")
        w.locator("[data-compose-url]").fill("{{base}}/echo?variable=1")
        w.locator('[data-compose-tab="headers"]').click()
        w.locator('[data-compose-add="headers"]').click()
        headers = w.locator('[data-compose-kv="headers"] .rv-kvr input[type=text]')
        headers.nth(0).fill("Authorization")
        headers.nth(1).fill("Bearer secret-value")
        w.locator('[data-compose-action="saveas"]').click()
        w.locator('.rv-editor input[aria-label="Name"]').fill("saved-request")
        w.locator('.rv-editor button[type=submit]').click()
        wait_for(lambda: "saved-request" in self.panel.state()["composer"]["names"], 8, 0.1, "request saved")
        w.locator('[data-compose-action="copy"]').click()
        wait_for(lambda: "secret-value" not in self.page.evaluate("navigator.clipboard.readText()"), 5, 0.1, "masked copy")
        self.assertNotIn("secret-value", self.page.evaluate("navigator.clipboard.readText()"))
        w.locator('[data-compose-action="send"]').click()
        self.wait_row("variable=1")
        self.page.reload()
        self.page.locator("#rv-app").wait_for(timeout=15000)
        # leaving the previous page (the classic login page polls state) aborts its poll: not this page's error
        self.errors[:] = [e for e in self.errors if not (e[0] == "requestfailed" and e[1].endswith("/proxy/api/state"))]
        w = self.more("compose")
        w.locator("[data-compose-saved]").select_option("saved-request")
        w.locator('[data-compose-action="load"]').click()
        wait_for(lambda: "variable=1" in w.locator("[data-compose-url]").input_value(), 8, 0.1, "loaded")
        self.assertEqual(self.errors, [])

    def test_sessions_open_choices_note_har_and_delete(self):
        self.open_new("/echo?session=one")
        w = self.more("sessions")
        w.locator("[data-sess-name]").fill("capture-one")
        w.locator('[data-action="save"]').click()
        wait_for(lambda: any(x["name"] == "capture-one" for x in self.panel.state()["sessions"]), 8, 0.1, "saved")
        self.fetch("/echo?session=two")
        w.locator('[data-action="load"]').click()
        w.locator('[data-choice="cancel"]').click()
        self.assertTrue(self.inst.flow_for("session=two"))
        w.locator('[data-action="load"]').click()
        w.locator('[data-choice="add"]').click()
        wait_for(lambda: bool(self.inst.flow_for("session=one")) and bool(self.inst.flow_for("session=two")), 8, 0.1, "kept and opened")
        self.assertTrue(self.inst.flow_for("session=two"))
        w.locator('[data-action="note"]').click()
        w.locator('.rv-editor input').fill("capture note")
        w.locator('.rv-editor button[type=submit]').click()
        wait_for(lambda: self.panel.state()["sessions"][0]["note"] == "capture note", 8, 0.1, "note")
        with self.page.expect_download() as download:
            w.locator('[data-action="har"]').click()
        self.assertTrue(download.value.suggested_filename.endswith(".har"))
        w.locator('[data-action="load"]').click()
        w.locator('[data-choice="replace"]').click()
        wait_for(lambda: not any("session=two" in f["request"]["path"] for f in self.inst.flows()), 8, 0.1, "replaced")
        w.locator('[data-action="delete"]').click()
        self.page.locator("#dyes").click()
        wait_for(lambda: not self.panel.state()["sessions"], 8, 0.1, "deleted")
        self.assertEqual(self.errors, [])

    def test_sessions_visible_save_treats_regex_characters_literally(self):
        self.open_new("/echo?needle=a.b(1)", "/echo?needle=axb(1)", "/echo?needle=a.b11")
        self.page.locator("#q").fill("a.b(1)")
        wait_for(lambda: self.page.evaluate("window.RivisApp.currentFilter()") != "", 8, 0.1, "search applied")
        w = self.more("sessions")
        w.locator("[data-sess-name]").fill("visible-only")
        w.locator("[data-sess-visible]").check()
        w.locator('[data-action="save"]').click()
        wait_for(lambda: any(x["name"] == "visible-only" for x in self.panel.state()["sessions"]), 8, 0.1, "visible session")
        entries = self.panel.ok("sess_har", {"name": "visible-only"})["har"]["log"]["entries"]
        self.assertEqual([e["request"]["url"] for e in entries], [self.up.url("/echo?needle=a.b%281%29")])
        self.assertEqual(self.errors, [])

    def test_collections_record_replay_strict_and_delete(self):
        self.open_new()
        w = self.more("collections")
        w.locator('[data-field="name"]').fill("journey")
        w.locator('[data-field="match"]').fill("/echo")
        w.locator('[data-action="record"]').click()
        wait_for(lambda: self.panel.state()["collections"]["recording"] == "journey", 8, 0.1, "recording")
        self.fetch("/echo?coll=one")
        self.fetch("/echo?coll=two")
        w.locator('[data-action="stop"]').click()
        wait_for(lambda: self.panel.state()["collections"]["items"][0]["count"] >= 2, 8, 0.1, "recorded")
        w.locator('[data-action="entries"]').click()
        wait_for(lambda: w.locator('[data-action="entry-delete"]').count() >= 2, 8, 0.1, "entries")
        w.locator('[data-action="entry-delete"]').first.click()
        wait_for(lambda: self.panel.state()["collections"]["items"][0]["count"] == 1, 8, 0.1, "entry removed")
        w.locator('[data-action="replay"]').check()
        wait_for(lambda: self.panel.state()["collections"]["items"][0]["replay"], 8, 0.1, "replay on")
        w.locator('[data-action="strict"]').check()
        wait_for(lambda: self.panel.state()["collections"]["strict"], 8, 0.1, "strict on")
        self.assertEqual(self.fetch("/echo?coll=missing").status, 404)
        w.locator('[data-action="strict"]').uncheck()
        wait_for(lambda: not self.panel.state()["collections"]["strict"], 8, 0.1, "strict off")
        wait_for(lambda: self.fetch("/echo?coll=missing").status == 200, 8, 0.2, "strict no longer rejects")
        w.locator('[data-action="replay"]').uncheck()
        w.locator('[data-action="delete"]').click()
        self.page.locator("#dyes").click()
        wait_for(lambda: not self.panel.state()["collections"]["items"], 8, 0.1, "deleted")
        self.assertEqual(self.errors, [])

    def test_compare_from_call_shows_header_and_body_changes(self):
        self.open_new()
        self.fetch("/echo?diff=1", method="POST", headers={"X-Compare": "alpha"}, data=b"before")
        self.fetch("/echo?diff=2", method="POST", headers={"X-Compare": "beta"}, data=b"after")
        self.menu("diff=1", "compare")
        w = self.win_open("compare")
        options = w.locator('[data-compare="right"] option').evaluate_all("els => els.map(e => ({value:e.value, text:e.textContent}))")
        w.locator('[data-compare="right"]').select_option(next(x["value"] for x in options if "diff=2" in x["text"]))
        w.locator('[data-action="compare"]').click()
        wait_for(lambda: w.locator("[data-compare-result]").inner_text() != "", 8, 0.1, "comparison")
        self.assertIn("x-compare", w.locator("[data-compare-result]").inner_text())
        self.assertIn("before", w.locator("[data-compare-result]").inner_text())
        self.assertIn("after", w.locator("[data-compare-result]").inner_text())
        self.assertEqual(self.errors, [])

    def test_compare_result_keeps_its_scroll_while_calls_arrive(self):
        self.open_new()
        self.fetch("/echo?diff=scroll-a")
        self.fetch("/echo?diff=scroll-b")
        w = self.more("compare")
        options = w.locator('[data-compare="left"] option').evaluate_all("els => els.map(e => ({value:e.value, text:e.textContent}))")
        w.locator('[data-compare="left"]').select_option(next(x["value"] for x in options if "scroll-a" in x["text"]))
        w.locator('[data-compare="right"]').select_option(next(x["value"] for x in options if "scroll-b" in x["text"]))
        w.locator('[data-action="compare"]').click()
        result = w.locator("[data-compare-result]")
        wait_for(lambda: "Summary" in result.inner_text(), 8, 0.1, "comparison")
        result.evaluate("e => { window.__compareResultNode = e.firstElementChild }")
        self.fetch("/echo?diff=stream")
        wait_for(lambda: "stream" in w.locator('[data-compare="right"]').inner_text(), 8, 0.1, "new option")
        self.assertTrue(result.evaluate("e => e.firstElementChild === window.__compareResultNode"))

    def test_session_note_form_survives_state_refresh_with_submit_focused(self):
        self.open_new()
        w = self.more("sessions")
        w.locator("[data-sess-name]").fill("note-focus")
        w.locator('[data-action="save"]').click()
        wait_for(lambda: bool(self.panel.state()["sessions"]), 8, 0.1, "saved")
        w.locator('[data-action="note"]').click()
        w.locator('.rv-editor input').fill("typing survives")
        w.locator('.rv-editor button[type=submit]').focus()
        self.panel.ok("sess_note", {"name": "note-focus", "note": "server refresh"})
        self.page.evaluate("window.RivisApp.refresh()")
        self.page.wait_for_timeout(700)
        self.assertEqual(w.locator('.rv-editor input').input_value(), "typing survives")

    def test_collections_import_file_hint_says_it_is_kept_after_redraw(self):
        self.open_new()
        w = self.more("collections")
        w.locator("[data-import-file]").set_input_files({"name": "chosen.har", "mimeType": "application/json", "buffer": b"{}"})
        w.locator('[data-action="import"]').focus()
        self.panel.ok("coll_record", {"name": "refresh", "record_match": "."})
        self.page.evaluate("window.RivisApp.refresh()")
        wait_for(lambda: "Chosen: chosen.har" in w.inner_text(), 8, 0.1, "retained file hint")

    def test_open_capture_file_asks_before_keep_replace_or_cancel(self):
        import json
        self.open_new("/echo?capture=file")
        self.panel.ok("sess_save", {"name": "file-source", "overwrite": True})
        har = self.panel.ok("sess_har", {"name": "file-source"})["har"]
        data = json.dumps(har).encode()
        self.fetch("/echo?capture=after")
        before = len(self.inst.flows())
        w = self.more("sessions")
        w.locator("[data-sess-file]").set_input_files({"name": "capture.har", "mimeType": "application/json", "buffer": data})
        wait_for(lambda: w.locator('[data-choice="add"]').count() == 1, 8, 0.1, "open choice")
        self.assertEqual(len(self.inst.flows()), before)
        w.locator('[data-choice="cancel"]').click()
        self.assertEqual(len(self.inst.flows()), before)
        w.locator("[data-sess-file]").set_input_files({"name": "capture.har", "mimeType": "application/json", "buffer": data})
        w.locator('[data-choice="add"]').click()
        wait_for(lambda: len(self.inst.flows()) > before, 8, 0.1, "added capture")
        w.locator("[data-sess-file]").set_input_files({"name": "capture.har", "mimeType": "application/json", "buffer": data})
        w.locator('[data-choice="replace"]').click()
        wait_for(lambda: len(self.inst.flows()) == len(har["log"]["entries"]), 8, 0.1, "replaced capture")

    def test_devices_shortcut_absent_devices_and_consent(self):
        import json
        fake = {"ios": [], "android": [{"id": "emulator-5590", "name": "Pixel Play", "os": "Android 15", "ready": False,
                                         "ca_ok": False, "proxy_ok": False, "play": True}], "magisk": False, "job": None}
        requested = []
        self.page.route("**/proxy/api/devices", lambda r: r.fulfill(status=200, content_type="application/json", body=json.dumps(fake)))
        self.page.route("**/proxy/api/device_setup", lambda r: (requested.append(r.request.post_data), r.fulfill(status=200, content_type="application/json", body='{"id": 1}')))
        self.open_new()
        self.page.keyboard.press("Alt+" + MOD + "+D")
        w = self.win_open("devices")
        wait_for(lambda: "Pixel Play" in w.inner_text(), 8, 0.1, "device")
        self.assertIn("No simulator is booted", w.inner_text())
        w.locator('[data-device="emulator-5590"]').click()
        self.assertIn("Settings screens", w.inner_text())
        self.assertEqual(requested, [])
        w.locator('[data-consent="no"]').click()
        self.assertEqual(requested, [])
        self.assertEqual(self.errors, [])

    def test_devices_absent_emulator_explained(self):
        self.open_new()
        self.page.keyboard.press("Alt+" + MOD + "+D")
        w = self.win_open("devices")
        wait_for(lambda: "iOS Simulators" in w.inner_text(), 10, 0.1, "device probe")
        self.assertIn("No simulator is booted", w.inner_text())
        self.assertIn("adb was not found", w.inner_text())
        self.assertIn("rivis setup", w.inner_text())
        self.assertEqual(self.errors, [])

    def test_device_rename_form_survives_a_probe_with_submit_focused(self):
        self.open_new()
        self.page.evaluate("""() => { window.RivisApp.state().lan = {on:true, devices:[{ip:'192.168.1.9', name:'Phone'}], pending:[], addresses:['192.168.1.2:8080']}; }""")
        self.page.keyboard.press("Alt+" + MOD + "+D")
        w = self.win_open("devices")
        wait_for(lambda: w.locator('[data-lan="rename"]').count() == 1, 8, 0.1, "phone")
        w.locator('[data-lan="rename"]').click()
        w.locator('.rv-editor input').fill("New phone")
        w.locator('.rv-editor button[type=submit]').focus()
        self.page.evaluate("""() => { window.RivisApp.state().lan.pending = [{ip:'192.168.1.10', name:'Waiting', count:1}]; }""")
        self.page.wait_for_timeout(4700)
        self.assertEqual(w.locator('.rv-editor input').input_value(), "New phone")


if __name__ == "__main__":
    import harness
    harness.main()
