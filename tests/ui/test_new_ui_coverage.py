"""New main window checks for classic flows that had no matching browser check."""
import os
import sys
import threading
import unittest
import json
import time
import socket
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import harness  # noqa: E402
from harness import wait_for  # noqa: E402
from test_client_certs_0910 import Pki  # noqa: E402
from test_lan_0910 import LAN, NO_LAN, curl  # noqa: E402
from test_traffic_r10 import _RawServer  # noqa: E402
from test_ui import PW_REASON, UiBase  # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class NewWindowCoverage(UiBase):
    def open_new(self, *paths):
        for path in paths:
            self.fetch(path)
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.goto("http://127.0.0.1:%d/rivis/" % self.inst.web_port)
        wait_for(lambda: self.page.evaluate("!!(window.RivisTools && window.__rivisUI.state)"), 10, 0.1, "new window")
        return self.page

    def win(self, name):
        return self.page.locator('.rv-win[data-win="%s"]' % name)

    def test_failed_refused_and_cut_short_calls_show_a_failure(self):
        cut = _RawServer([b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100000\r\n\r\n" + b"x" * 1000])
        self.addCleanup(cut.close)
        self.inst.fetch("http://127.0.0.1:1/x?refused=1", timeout=10)
        self.inst.fetch("http://127.0.0.1:%d/midclose?cut=1" % cut.port, timeout=10)
        self.open_new()
        for key in ("refused=1", "cut=1"):
            row = self.page.locator(".rv-tr", has_text=key).first
            wait_for(lambda: row.count() == 1, 10, 0.1, "failed call")
            self.assertIn("failed", row.inner_text().lower())

    def test_client_certificate_wrong_password_and_add_remove(self):
        pki = Pki(self.suite.new_home("pki-new-ui"))
        _, _, p12 = pki.client("fixture", password="right")
        self.open_new()
        self.page.locator('[data-tool="net"]').click()
        w = self.win("net")
        host = w.locator("[data-net-cc-host]")
        host.fill("API.example.test")
        w.locator("[data-net-cc-file]").set_input_files(p12)
        w.locator("[data-net-cc-pass]").fill("wrong")
        w.locator("[data-net-cc-add]").click()
        wait_for(lambda: "password" in self.page.locator("#toast").inner_text().lower(), 8, 0.1, "wrong password")
        self.assertEqual(host.input_value(), "API.example.test")
        self.assertEqual(self.panel.state()["client_certs"], [])
        w.locator("[data-net-cc-pass]").fill("right")
        w.locator("[data-net-cc-add]").click()
        wait_for(lambda: len(self.panel.state()["client_certs"]) == 1, 8, 0.1, "certificate added")
        w.locator('[data-net-cc-rm="api.example.test"]').click()
        self.page.locator("#dyes").click()
        wait_for(lambda: self.panel.state()["client_certs"] == [], 8, 0.1, "certificate removed")

    def test_tls_leave_alone_host_can_be_removed(self):
        self.open_new()
        self.page.locator('[data-tool="net"]').click()
        w = self.win("net")
        w.locator('[data-net-tls-add="ignore"]').fill("api.example.test")
        w.locator('[data-net-tls-addbtn="ignore"]').click()
        wait_for(lambda: "api.example.test" in self.panel.state()["tls"]["ignore"], 8, 0.1, "host listed")
        w.locator('[data-net-tls-rm="ignore"][data-pattern="api.example.test"]').click()
        wait_for(lambda: "api.example.test" not in self.panel.state()["tls"]["ignore"], 8, 0.1, "host removed")

    def test_rule_hit_count_and_never_matched_warning(self):
        self.reset_state(rules=[self.rule("found", "status", "/echo", status=503),
                                self.rule("missing", "status", "/ehco", status=500)])
        for _ in range(11):
            self.fetch("/echo")
        self.open_new()
        self.page.locator('[data-tool="remote"]').click()
        w = self.win("rules")
        w.locator('[data-rtype="all"]').click()
        wait_for(lambda: "matched 11" in w.inner_text(), 8, 0.1, "hit count")
        self.assertIn("none of the", w.inner_text())

    def test_map_local_folder_add_toggle_and_delete(self):
        folder = self.inst.path("mocks", "new-ui-folder")
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "one.json"), "w") as stream:
            stream.write('{"mocked":true}')
        self.open_new()
        self.page.locator('[data-tool="map"]').click()
        w = self.win("map")
        w.locator("[data-ml-folder]").click()
        w.locator('input[name="name"]').fill("new-ui-folder")
        w.locator('input[name="base"]').fill(self.up.url("/v1/"))
        w.locator('input[name="folder"]').fill(folder)
        w.locator(".rv-sheet button[type=submit]").click()
        wait_for(lambda: any(r.get("name") == "new-ui-folder" for r in self.inst.cfg()["rules"]), 8, 0.1, "folder rule")
        self.assertEqual(self.inst.fetch(self.up.url("/v1/one")).json(), {"mocked": True})
        w.locator('[data-ml-on="new-ui-folder"]').uncheck()
        wait_for(lambda: next(r for r in self.inst.cfg()["rules"] if r["name"] == "new-ui-folder")["enabled"] is False, 8, 0.1, "rule off")
        w.locator('[data-ml-name="new-ui-folder"]').focus()
        w.locator('[data-ml-name="new-ui-folder"]').press('Delete')
        self.page.locator("#dyes").click()
        wait_for(lambda: not any(r.get("name") == "new-ui-folder" for r in self.inst.cfg()["rules"]), 8, 0.1, "rule deleted")

    def test_saved_rule_import_from_the_map_local_window(self):
        source = os.path.join(self.inst.home, 'Library', 'Application Support', 'com.proxyman.NSProxy', 'user-data')
        os.makedirs(os.path.dirname(source), exist_ok=True)
        if os.path.exists(source):
            shutil.rmtree(source)
        shutil.copytree(os.path.join(harness.REPO, 'tests', 'fixtures', 'proxyman'), source)
        self.open_new()
        self.page.locator('[data-tool="map"]').click()
        w = self.win('map')
        w.locator('[data-ml-import]').click()
        self.page.locator('#dyes').click()
        wait_for(lambda: any(r.get('name') == 'wild' for r in self.inst.cfg()['rules']), 8, 0.1, 'rules imported')
        self.assertIn('imported 4, skipped 1', self.page.locator('#toast').inner_text())

    def test_paused_request_form_keeps_json_types_and_query_edits(self):
        body = '{"amount":10,"ready":true}'
        self.open_new()
        self.panel.ok("bp_add", {"host": "127.0.0.1", "path": "/echo*", "request": True, "response": False})
        time.sleep(1.2)
        answer = {}
        thread = threading.Thread(target=lambda: answer.update(result=self.fetch(
            "/echo?form=1", method="POST", data=body, headers={"Content-Type": "application/json"})), daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        w = self.win("paused")
        wait_for(lambda: w.is_visible() and w.locator('[data-psub="form"]').count() == 1, 15, 0.1, "paused call")
        w.locator('[data-psub="form"]').click()
        fields = w.locator("#pfj .rv-kvr")
        fields.nth(0).locator('input[aria-label="JSON value"]').fill("25")
        fields.nth(1).locator('input[aria-label="JSON value"]').fill("false")
        w.locator('[data-kvadd="pfq"]').click()
        query = w.locator('#pfq .rv-kvr').last.locator("input")
        query.nth(0).fill("extra")
        query.nth(1).fill("a b")
        w.locator('[data-pcont]').click()
        thread.join(20)
        got = answer["result"].json()
        self.assertEqual(json.loads(got["body"]), {"amount": 25, "ready": False})
        self.assertEqual(got["query"]["extra"], ["a b"])

    def test_paused_urlencoded_form_can_change_method_path_and_fields(self):
        self.open_new()
        self.panel.ok('bp_add', {'host': '127.0.0.1', 'path': '/echo*', 'request': True, 'response': False})
        time.sleep(1.2)
        answer = {}
        thread = threading.Thread(target=lambda: answer.update(result=self.fetch(
            '/echo?encoded=1', method='POST', data='one=1',
            headers={'Content-Type': 'application/x-www-form-urlencoded'})), daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        w = self.win('paused')
        wait_for(lambda: w.is_visible() and w.locator('[data-psub="form"]').count() == 1, 15, 0.1, 'paused form')
        w.locator('#pm').select_option('PATCH')
        w.locator('#pu').fill(self.up.url('/echo?encoded=2'))
        w.locator('[data-psub="form"]').click()
        w.locator('[data-kvadd="pff"]').click()
        fields = w.locator('#pff .rv-kvr').last.locator('input')
        fields.nth(0).fill('two')
        fields.nth(1).fill('a b')
        w.locator('[data-pcont]').click()
        thread.join(20)
        got = answer['result'].json()
        self.assertEqual((got['method'], got['path'], got['body']), ('PATCH', '/echo', 'one=1&two=a+b'))
        self.assertEqual(got['query']['encoded'], ['2'])

    def test_paused_response_form_changes_status_and_json_field(self):
        self.open_new()
        self.panel.ok('bp_add', {'host': '127.0.0.1', 'path': '/json/small*', 'request': False, 'response': True})
        time.sleep(1.2)
        answer = {}
        thread = threading.Thread(target=lambda: answer.update(result=self.fetch('/json/small?response-form=1')), daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        w = self.win('paused')
        wait_for(lambda: w.is_visible() and w.locator('[data-psub="form"]').count() == 1, 15, 0.1, 'paused response')
        w.locator('#pst').fill('202')
        w.locator('[data-psub="form"]').click()
        w.locator('#pfj .rv-kvr').first.locator('input[aria-label="JSON value"]').fill('{"name":"changed"}')
        w.locator('[data-pcont]').click()
        thread.join(20)
        self.assertEqual(answer['result'].status, 202)
        self.assertEqual(answer['result'].json()['user'], {'name': 'changed'})

    def test_broken_capture_keeps_calls_and_explains_failure(self):
        self.open_new("/echo?before=broken")
        before = len(self.inst.flows())
        self.page.locator("#tb-more").click()
        self.page.locator('[data-more="sessions"]').click()
        w = self.win("sessions")
        w.locator("[data-sess-file]").set_input_files({"name": "broken.har", "mimeType": "application/json", "buffer": b'{"log":{"entries":['})
        w.locator('[data-choice="add"]').click()
        wait_for(lambda: "Could not open" in self.page.locator("#toast").inner_text(), 10, 0.1, "upload error")
        self.assertEqual(len(self.inst.flows()), before)
        self.assertIn("broken.har", self.page.locator("#toast").inner_text())

    def test_settings_and_update_notice(self):
        def patch(route):
            response = route.fetch()
            data = response.json()
            data["update"] = {"available": {"version": "99.1", "notes": "Update ready"}}
            route.fulfill(response=response, body=json.dumps(data), headers={**response.headers, "content-type": "application/json"})
        self.page.route("**/proxy/api/state", patch)
        self.open_new()
        notice = self.page.locator('[data-banner="update"]')
        wait_for(lambda: notice.is_visible(), 8, 0.1, "update notice")
        self.assertIn("99.1", notice.inner_text())
        notice.locator('[data-bn="later"]').click()
        wait_for(lambda: not notice.is_visible(), 5, 0.1, "notice postponed")
        self.page.locator("#tb-settings").click()
        dialog = self.page.locator("#dialog")
        self.assertIn("Appearance", dialog.inner_text())
        dialog.locator('input[value="dark"]').check()
        self.assertEqual(self.page.evaluate("localStorage.getItem('rivis-theme')"), "dark")
        dialog.locator('[data-close]').click()
        self.page.locator('[data-tool="net"]').click()
        self.win('net').locator('[data-net-settings]').click()
        wait_for(lambda: self.page.locator('#dialog').is_visible() and 'Appearance' in self.page.locator('#dialog').inner_text(),
                 5, 0.1, 'settings from Network')

    def test_source_choice_filters_calls_and_empty_state_names_it(self):
        self.fetch("/echo?src=python")
        sock = socket.create_connection(("127.0.0.1", self.inst.proxy_port), 10)
        try:
            sock.sendall(("GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n"
                          % (self.up.url("/echo?src=curl"), self.up.http_port)).encode())
            while sock.recv(65536):
                pass
        finally:
            sock.close()
        self.open_new()
        flow = self.inst.flow_for('src=curl')
        key = self.panel.state()['sources']['by_conn'][flow['client_conn']['id']]
        src = self.page.locator('[data-src-key="%s"]' % key)
        wait_for(lambda: src.count() == 1, 10, 0.1, "source shown")
        wait_for(lambda: self.page.locator('.rv-tr', has_text='src=curl').count() == 1, 10, 0.1, "source call loaded")
        wait_for(lambda: self.page.locator('.rv-tr', has_text='src=python').count() == 1, 10, 0.1, "other source loaded")
        src.click()
        wait_for(lambda: self.page.locator('.rv-tr', has_text='src=curl').count() == 1, 10, 0.1, "chosen source call")
        self.assertEqual(self.page.locator('.rv-tr', has_text='src=python').count(), 0)
        self.page.locator('#q').fill('no-such-call')
        wait_for(lambda: self.page.locator('#empty').is_visible(), 5, 0.1, "source empty state")
        self.assertIn(key.split('|')[-1], self.page.locator('#empty').inner_text())
        self.page.locator('[data-src-all]').click()
        self.page.locator('#q').fill('')
        wait_for(lambda: self.page.evaluate('window.__rivisUI.source === null && window.__rivisUI.text === ""'),
                 10, 0.1, 'source and search cleared')

    def test_every_rules_window_type_can_be_added_edited_and_deleted(self):
        self.open_new()
        self.page.locator('[data-tool="remote"]').click()
        w = self.win('rules')
        kinds = {
            'respond': ('rf-status', '201', '202'),
            'status': ('rf-status', '501', '502'),
            'json_patch': ('rf-set', '{"user.name":"before"}', '{"user.name":"after"}'),
            'delay': ('rf-ms', '10', '20'),
            'set_header': ('rf-header', 'X-First', 'X-Second'),
        }
        for kind, (field, first, second) in kinds.items():
            with self.subTest(kind=kind):
                name = 'coverage-' + kind
                w.locator('[data-r-new]').click()
                w.locator('#rf-type').select_option(kind)
                w.locator('#rf-name').fill(name)
                w.locator('#rf-match').fill('/echo')
                w.locator('#' + field).fill(first)
                w.locator('[data-r-save]').click()
                wait_for(lambda: any(r['name'] == name for r in self.panel.state()['rules']), 8, 0.1, name + ' added')
                w.locator('[data-rtype="all"]').click()
                w.locator('[data-r-edit="%s"]' % name).click()
                w.locator('#' + field).fill(second)
                w.locator('[data-r-save]').click()
                def updated():
                    rule = next((r for r in self.panel.state()['rules'] if r['name'] == name), {})
                    value = rule.get({'rf-status': 'status', 'rf-set': 'set', 'rf-ms': 'ms', 'rf-header': 'header'}[field])
                    return value == (json.loads(second) if field == 'rf-set' else int(second) if field in ('rf-status', 'rf-ms') else second)
                wait_for(updated, 8, 0.1, name + ' edited')
                w.locator('[data-r-del="%s"]' % name).click()
                self.page.locator('#dyes').click()
                wait_for(lambda: not any(r['name'] == name for r in self.panel.state()['rules']), 8, 0.1, name + ' deleted')

    def test_failed_action_toasts_and_state_polls_do_not_overlap(self):
        active = [0, 0]
        def delayed_state(route):
            active[0] += 1
            active[1] = max(active)
            try:
                time.sleep(2.5)
                route.fulfill(response=route.fetch())
            finally:
                active[0] -= 1
        self.page.route('**/proxy/api/state', delayed_state)
        self.open_new()
        self.page.route('**/proxy/api/nocache', lambda route: route.abort())
        self.page.keyboard.press('Meta+Alt+N' if sys.platform == 'darwin' else 'Control+Alt+N')
        wait_for(lambda: self.page.locator('#toast').is_visible(), 8, 0.1, 'failed action message')
        self.assertTrue(self.page.locator('#toast').evaluate('e => e.classList.contains("err")'))
        self.page.wait_for_timeout(5500)
        self.assertEqual(active[1], 1)

    def test_binary_post_and_long_url_keep_the_detail_readable(self):
        self.fetch('/echo?long=' + 'x' * 450, method='POST', data=b'\x00\x01\xff',
                   headers={'Content-Type': 'application/octet-stream'})
        self.open_new()
        row = self.page.locator('.rv-tr', has_text='long=').first
        wait_for(lambda: row.count() == 1, 8, 0.1, 'long call')
        row.click()
        self.assertTrue(self.page.locator('#pane-req').is_visible())
        self.assertTrue(self.page.locator('#pane-res').is_visible())
        self.assertLessEqual(self.page.locator('#list').evaluate('e => e.scrollWidth'),
                             self.page.locator('#list').evaluate('e => e.clientWidth') + 1)

    def test_map_local_variant_picker_changes_the_response(self):
        self.open_new('/json/small?variant=1')
        self.page.locator('.rv-tr', has_text='variant=1').first.click(button='right')
        self.page.locator('#menu [data-act="map"]').click()
        w = self.win('map')
        wait_for(lambda: w.locator('#mlbody').count() == 1, 8, 0.1, 'response editor')
        w.locator('[data-mlsave]').click()
        wait_for(lambda: 'Saved' in self.page.locator('#toast').inner_text(), 8, 0.1, 'default saved')
        w.locator('[data-mlv="add"]').click()
        self.page.locator('#pv').fill('alternate')
        self.page.locator('#dialog button[type=submit]').click()
        wait_for(lambda: w.locator('#mlvar').input_value() == 'alternate', 8, 0.1, 'variant selected')
        w.locator('#mlbody').fill('{"variant":true}')
        w.locator('[data-mlsave]').click()
        wait_for(lambda: self.fetch('/json/small?variant=1').json() == {'variant': True}, 8, 0.1, 'alternate response')
        w.locator('#mlvar').select_option('Default')
        wait_for(lambda: self.fetch('/json/small?variant=1').json() != {'variant': True}, 8, 0.1, 'default response')

    def test_classic_view_has_a_visible_link_to_the_main_window(self):
        self.page.goto('http://127.0.0.1:%d/?token=%s' % (self.inst.web_port, self.inst.password))
        self.page.locator('#fab').click()
        link = self.page.locator('#proxy-panel-host a[href="/rivis/"]')
        wait_for(lambda: link.count() == 1 and link.is_visible(), 8, 0.1, 'main window link')
        link.click()
        self.assertTrue(self.page.url.endswith('/rivis/'))

    def test_project_label_returns_after_showing_all_calls(self):
        self.open_new()
        original = self.panel.state()['project']['label']
        self.panel.ok('view', {'project': 'neo', 'project_only': True, 'show_dns': False})
        self.page.evaluate('window.RivisApp.refresh()')
        wait_for(lambda: 'NEO' in self.page.locator('#tb-project').inner_text(), 8, 0.1, 'project view label')
        self.panel.ok('view', {'project_only': False, 'show_dns': True})
        self.page.evaluate('window.RivisApp.refresh()')
        wait_for(lambda: original in self.page.locator('#tb-project').inner_text(), 8, 0.1, 'all-calls label')
        self.assertNotIn('NEO', self.page.locator('#status').inner_text())

    def test_dirty_compose_window_keeps_its_draft_on_escape(self):
        self.open_new()
        self.page.locator('#tb-more').click()
        self.page.locator('[data-more="compose"]').click()
        w = self.win('compose')
        field = w.locator('[data-compose-url]')
        field.fill(self.up.url('/echo?draft=1'))
        field.press('Escape')
        wait_for(lambda: self.page.locator('#dialog').is_visible(), 5, 0.1, 'dirty window question')
        self.page.locator('#dno').click()
        self.assertTrue(w.is_visible())
        self.assertIn('draft=1', field.input_value())


@unittest.skipIf(PW_REASON, PW_REASON or '')
@unittest.skipUnless(LAN, NO_LAN)
class NewWindowLan(UiBase):
    INSTANCE_KW = {'start_args': ('--insecure', '--lan')}

    def phone(self, path):
        return curl(['--noproxy', '', '-x', 'http://%s:%d' % (LAN[0], self.inst.proxy_port),
                     '-A', 'Mozilla/5.0 (Linux; Android 14; Mobile) Chrome/120', self.up.url(path)])

    def test_allow_rename_and_remove_phone(self):
        self.page.goto('http://127.0.0.1:%d/?token=%s' % (self.inst.web_port, self.inst.password))
        self.page.goto('http://127.0.0.1:%d/rivis/' % self.inst.web_port)
        self.page.locator('[data-tool="net"]').click()
        w = self.page.locator('.rv-win[data-win="net"]')
        self.assertEqual(self.phone('/echo?lan=new')[0], 403)
        wait_for(lambda: w.locator('[data-net-lan-allow="%s"]' % LAN[0]).count() == 1, 12, 0.1, 'waiting phone')
        w.locator('[data-net-lan-allow="%s"]' % LAN[0]).click()
        wait_for(lambda: w.locator('[data-net-lan-rm="%s"]' % LAN[0]).count() == 1, 12, 0.1, 'allowed phone')
        self.assertEqual(self.phone('/echo?lan=allowed')[0], 200)
        w.locator('[data-net-lan-name="%s"]' % LAN[0]).fill('Test phone')
        w.locator('[data-net-lan-rename="%s"]' % LAN[0]).click()
        wait_for(lambda: self.panel.state()['lan']['devices'][0]['name'] == 'Test phone', 12, 0.1, 'renamed phone')
        w.locator('[data-net-lan-rm="%s"]' % LAN[0]).click()
        self.page.locator('#dyes').click()
        wait_for(lambda: not self.panel.state()['lan']['devices'], 12, 0.1, 'removed phone')
        self.assertEqual(self.phone('/echo?lan=removed')[0], 403)


if __name__ == "__main__":
    unittest.main()
