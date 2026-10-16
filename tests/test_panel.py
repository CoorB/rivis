"""Panel API (/proxy/api/<op>): auth, XSRF, Host check, every op with valid + invalid input, path confinement."""
import json
import os
import re
import stat
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import LiveCase, raw_http, wait_for
from upstream import JWT_FRESH, SMALL_JSON

ADDONS = os.path.join(harness.REPO, "addons")
EXPECTED = "expected failure — see tests/FOUND-BUGS.md#B1"


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class Auth(LiveCase):
    def test_no_token_is_403_everywhere(self):
        port = self.inst.web_port
        for method, path, body in (("GET", "/proxy/api/state", None), ("GET", "/proxy/panel.js", None),
                                   ("POST", "/proxy/api/add", "{}"), ("GET", "/flows", None), ("GET", "/options", None)):
            status = raw_http(port, method, path, {"Content-Type": "application/json"}, body)[0]
            self.assertEqual(status, 403, "%s %s" % (method, path))

    def test_wrong_token_is_refused(self):
        status = raw_http(self.inst.web_port, "GET", "/?token=" + "x" * 12)[0]
        self.assertEqual(status, 403)
        self.assertEqual(raw_http(self.inst.web_port, "GET", "/proxy/api/state")[0], 403)

    def test_missing_or_wrong_xsrf_is_403_even_with_a_valid_session(self):
        import urllib.request
        for headers in ({"Content-Type": "application/json"}, {"Content-Type": "application/json", "X-XSRFToken": "nope"}):
            req = urllib.request.Request(self.panel.base + "/proxy/api/view", data=b"{}", method="POST", headers=headers)
            self.assertEqual(self.panel._do(req)[0], 403, headers)
        self.assertEqual(self.panel.post("view", {})[0], 200)       # control: the right pair works

    def test_session_cookie_is_http_only_and_scoped_to_the_port(self):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.inst.web_port, timeout=10)
        c.request("GET", "/?token=" + self.inst.password)
        r = c.getresponse()
        r.read()
        cookies = [v for k, v in r.getheaders() if k.lower() == "set-cookie"]
        auth = [x for x in cookies if x.startswith("mitmproxy-auth-%d=" % self.inst.web_port)]
        self.assertTrue(auth, cookies)
        self.assertIn("httponly", auth[0].lower())
        self.assertNotIn("expires", auth[0].lower())      # F-19: a browser-session cookie, not ~13 months
        self.assertNotIn("max-age", auth[0].lower())

    def test_dns_rebinding_host_header_is_refused(self):
        """FOUND-BUGS B2 (fixed): every UI route refuses a Host that is not a loopback name for this port (STANDARDS §2)."""
        cookie = "; ".join("%s=%s" % (c.name, c.value) for c in self.panel.jar)
        for path in ("/proxy/api/state", "/flows", "/", "/proxy/panel.js"):
            for host in ("evil.example", "evil.example:%d" % self.inst.web_port, "127.0.0.1.evil.example",
                         "127.0.0.1:%d" % (self.inst.web_port + 1)):
                status = raw_http(self.inst.web_port, "GET", path, {"Host": host, "Cookie": cookie})[0]
                self.assertEqual(status, 403, (path, host))
        for host in ("127.0.0.1:%d" % self.inst.web_port, "localhost:%d" % self.inst.web_port):   # control
            self.assertEqual(raw_http(self.inst.web_port, "GET", "/proxy/api/state", {"Host": host, "Cookie": cookie})[0],
                             200, host)

    def test_panel_api_refuses_cross_site_writes(self):
        """F-04: a page on another local port can plant the xsrf cookie; the API must still refuse its writes."""
        import urllib.request
        good = {"Content-Type": "application/json", "X-XSRFToken": self.panel.xsrf}
        port = self.inst.web_port
        cases = [
            ("text/plain body", "/proxy/api/view", {**good, "Content-Type": "text/plain"}),
            ("foreign Origin", "/proxy/api/view", {**good, "Origin": "http://127.0.0.1:%d" % (port + 1)}),
            ("evil Origin", "/proxy/api/view", {**good, "Origin": "http://evil.example"}),
            ("cross-site fetch", "/proxy/api/view", {**good, "Sec-Fetch-Site": "cross-site"}),
            ("same-site fetch", "/proxy/api/view", {**good, "Sec-Fetch-Site": "same-site"}),
            ("_xsrf query form", "/proxy/api/view?_xsrf=" + self.panel.xsrf, {"Content-Type": "application/json"}),
        ]
        for label, path, headers in cases:
            req = urllib.request.Request(self.panel.base + path, data=b"{}", method="POST", headers=headers)
            self.assertEqual(self.panel._do(req)[0], 403, label)
        own = {**good, "Origin": "http://127.0.0.1:%d" % port, "Sec-Fetch-Site": "same-origin"}
        req = urllib.request.Request(self.panel.base + "/proxy/api/view", data=b"{}", method="POST", headers=own)
        self.assertEqual(self.panel._do(req)[0], 200)   # control: what the real page sends

    def test_security_headers_on_the_page(self):
        status, body, headers = raw_http(self.inst.web_port, "GET", "/?token=" + self.inst.password)
        h = {k.lower(): v for k, v in headers}
        self.assertEqual(h.get("x-frame-options"), "DENY")
        self.assertEqual(h.get("x-content-type-options"), "nosniff")
        self.assertIn("default-src 'self'", h.get("content-security-policy", ""))
        self.assertIn("samesite=strict", (h.get("set-cookie") or "").lower())

    def test_panel_js_is_served_and_injected(self):
        code, body = self.panel.get("/proxy/panel.js")
        self.assertEqual(code, 200)
        with open(os.path.join(ADDONS, "panel.js"), "rb") as fh:
            self.assertEqual(body, fh.read())
        code, page = self.panel.get("/")
        self.assertIn(b"proxy/panel.js", page)

    def test_unknown_get_op_and_unknown_post_op(self):
        self.assertEqual(self.panel.get("/proxy/api/nope")[0], 404)
        code, doc, _ = self.panel.post("no_such_op", {})
        self.assertEqual(code, 400)
        self.assertIn("unknown op", doc["error"])


class Ops(LiveCase):
    def setUp(self):
        super().setUp()
        self.inst.clear_dir("mocks")

    def flow_id(self, path):
        return self.inst.flow_for(path)["id"]

    def rules(self):
        return [r for r in self.panel.state()["rules"] if not r["name"].startswith("sync-")]

    def widen_match(self, name, match):
        """Rules built from a call anchor on host+path and drop the :port (FOUND-BUGS B3); the suite's upstream is
        on a random port, so point the rule at the path to keep exercising everything else."""
        cfg = self.inst.cfg()
        for r in cfg["rules"]:
            if r["name"] == name:
                r["match"] = match
        self.inst.write_cfg(cfg)

    def bad(self, op, body, fragment=None):
        code, doc, raw = self.panel.post(op, body)
        self.assertEqual(code, 400, "%s %s -> %s %r" % (op, body, code, raw[:150]))
        self.assertIn("error", doc)
        if fragment:
            self.assertIn(fragment, doc["error"].lower())

    # -- rules ----------------------------------------------------------------------------------------
    def test_add_toggle_delete_rule(self):
        rule = {"name": "p1", "action": "respond", "match": "/echo", "status": 202, "body": "panel"}
        self.panel.ok("add", {"rule": rule})
        self.assertEqual([r["name"] for r in self.rules()], ["p1"])
        r = wait_for(lambda: (lambda x: x if x.status == 202 else None)(self.fetch("/echo")), 8, 0.3, "rule applied")
        self.assertEqual(r.text, "panel")
        self.panel.ok("toggle", {"name": "p1", "enabled": False})
        self.assertFalse(self.rules()[0]["enabled"])
        wait_for(lambda: self.fetch("/echo").status == 200, 8, 0.3, "rule off")
        self.panel.ok("delete", {"name": "p1"})
        self.assertEqual(self.rules(), [])

    def test_add_validation(self):
        self.bad("add", {"rule": {"name": "bad name!", "action": "respond"}}, "name")
        self.bad("add", {"rule": {"name": "x", "action": "explode"}}, "action")
        self.bad("add", {"rule": {"name": "x", "action": "respond", "match": "("}}, "regex")
        self.bad("add", {"rule": {"name": "x", "action": "status", "status": "abc"}}, "status")
        self.bad("add", {"rule": {"name": "x", "action": "map_local", "file": "/etc/hosts"}}, "file-backed")
        self.bad("add", {"rule": {"name": "x", "action": "respond", "body_file": "/etc/hosts"}}, "file-backed")
        self.bad("add", {"rule": {"name": "x" * 65, "action": "respond"}})
        self.bad("add", {})
        self.bad("add", {"rule": {"name": "x", "action": "block"}}, "match is required")
        self.bad("add", {"rule": {"name": "x", "match": "/a", "action": "set_header"}}, "needs: header")
        self.bad("add", {"rule": {"name": "x", "match": "/a", "action": "delay", "ms": -5}}, "0..600000")
        self.bad("add", {"rule": {"name": "x", "match": "/a", "action": "delay", "ms": "abc"}}, "number")
        self.bad("add", {"rule": {"name": "x", "match": "/a", "action": "status", "status": 99999}}, "100..599")
        self.panel.ok("add", {"rule": {"name": "dup", "match": "/dup", "action": "block"}})
        self.bad("add", {"rule": {"name": "dup", "match": "/dup", "action": "block"}}, "exists")
        self.bad("toggle", {"name": "ghost", "enabled": True}, "no rule")
        self.bad("delete", {"name": "ghost"}, "no rule")

    def test_quick_actions_from_a_call(self):
        self.fetch("/json/small")
        fid = self.flow_id("/json/small")
        name = self.panel.ok("quick", {"flow_id": fid, "kind": "status", "status": 503})["name"]
        self.assertEqual(self.panel.ok("quick", {"flow_id": fid, "kind": "status", "status": 503})["name"], name)   # no stacking
        self.assertEqual(len([r for r in self.rules() if r["action"] == "respond"]), 1)
        self.widen_match(name, "/json/small")
        wait_for(lambda: self.fetch("/json/small").status == 503, 8, 0.3, "forced status")
        blk = self.panel.ok("quick", {"flow_id": fid, "kind": "block"})["name"]
        self.widen_match(blk, "/json/small")
        wait_for(lambda: self.fetch("/json/small").rc != 0, 8, 0.3, "block")
        dly = self.panel.ok("quick", {"flow_id": fid, "kind": "delay", "ms": 300})
        self.assertEqual(sorted(r["action"] for r in self.rules()), ["block", "delay", "respond"])
        self.bad("quick", {"flow_id": fid, "kind": "explode"}, "unknown")
        self.bad("quick", {"flow_id": "nope", "kind": "block"}, "no longer")

    def test_mock_from_a_call_then_edit_the_mock_file(self):
        self.fetch("/json/small")
        fid = self.flow_id("/json/small")
        doc = self.panel.ok("mock", {"flow_id": fid})
        name = doc["name"]
        rule = next(r for r in self.rules() if r["name"] == name)
        self.assertEqual(rule["action"], "map_local")
        self.assertEqual(mode(rule["file"]), 0o600)
        self.assertEqual(os.path.dirname(os.path.realpath(rule["file"])), os.path.realpath(self.inst.path("mocks")))
        self.assertTrue(self.panel.ok("mock", {"flow_id": fid})["existing"])
        self.widen_match(name, "/json/small")
        self.up.reset_hits()
        wait_for(lambda: "mock:" in self.comment_after("/json/small"), 8, 0.3, "mock served")
        self.up.reset_hits()
        self.assertEqual(self.fetch("/json/small").json(), SMALL_JSON)
        self.assertEqual(self.up.hits_for("/json/small"), [])
        got = self.panel.ok("mockfile_get", {"name": name})
        self.assertEqual(json.loads(got["content"]), SMALL_JSON)
        self.assertTrue(got["editable"])
        self.panel.ok("mockfile_put", {"name": name, "content": '{"edited": true}', "status": 202,
                                       "headers": [["X-M", "1"]]})
        r = wait_for(lambda: (lambda x: x if x.status == 202 else None)(self.fetch("/json/small")), 8, 0.3, "edited mock")
        self.assertEqual((r.json(), r.header("x-m")), ({"edited": True}, "1"))
        self.bad("mockfile_get", {"name": "ghost"}, "no rule")
        self.bad("mock", {"flow_id": "nope"}, "no longer")

    def test_mock_from_a_call_that_never_got_a_response(self):
        """An unreachable server is exactly when you want Map Local: start from a 200 {} template."""
        url = "http://127.0.0.1:9/unreachable-mock"          # discard port: nothing listens, the call errors
        self.inst.fetch(url, timeout=5)
        f = self.inst.flow_for("/unreachable-mock")
        self.assertIsNone(f.get("response"))
        name = self.panel.ok("mock", {"flow_id": f["id"]})["name"]
        rule = next(r for r in self.rules() if r["name"] == name)
        self.assertEqual((rule["action"], rule["status"]), ("map_local", 200))
        self.assertEqual(json.loads(self.panel.ok("mockfile_get", {"name": name})["content"]), {})
        self.widen_match(name, "/unreachable-mock")
        r = wait_for(lambda: (lambda x: x if x.status == 200 else None)(self.inst.fetch(url, timeout=5)), 8, 0.3,
                     "mock served for an unreachable host")
        self.assertEqual(r.json(), {})

    def test_a_call_with_absurdly_deep_json_breaks_no_feature(self):
        """QA 2026-10-15: /deep (nesting past Python's recursion limit) made Compare and the redacted HAR 500."""
        self.fetch("/deep")
        self.fetch("/json/small")
        deep, small = self.flow_id("/deep"), self.flow_id("/json/small")
        self.panel.ok("diff", {"a": deep, "b": small})
        self.panel.ok("diff", {"a": deep, "b": deep})
        self.panel.ok("sess_save", {"name": "deep-qa"})
        har = self.panel.ok("sess_har", {"name": "deep-qa", "include_secrets": False})
        self.assertTrue(har["redacted"])
        self.assertTrue(any(e["request"]["url"].endswith("/deep") for e in har["har"]["log"]["entries"]))

    def test_mitmwebs_own_export_menu_masks_secrets(self):
        """Manual QA: the toolbar's Export ▾ → Copy as cURL / HTTPie / raw copied the Bearer token and cookies in clear."""
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJxYSJ9.c2lnbmF0dXJl"
        self.fetch("/echo?exp=1", headers={"Authorization": "Bearer " + token, "Cookie": "session=abc123"})
        fid = self.flow_id("exp=1")
        import urllib.request
        for fmt in ("curl", "httpie", "raw_request", "raw_response", "raw"):
            req = urllib.request.Request("http://127.0.0.1:%d/commands/export" % self.inst.web_port, method="POST",
                                         data=json.dumps({"arguments": [fmt, "@" + fid]}).encode(),
                                         headers={"Content-Type": "application/json", "X-XSRFToken": self.panel.xsrf})
            doc = json.load(self.panel.opener.open(req, timeout=10))
            text = doc.get("value") or ""
            self.assertTrue(text, (fmt, doc))
            self.assertNotIn(token, text, fmt)
            if fmt not in ("raw_response", "raw"):   # /echo returns the request headers inside its JSON body, as [name, value] pairs
                self.assertNotIn("abc123", text, fmt)
            if fmt in ("curl", "httpie", "raw_request", "raw"):
                self.assertIn("exp=1", text, fmt)

    def test_devices_tab_lists_and_runs_the_cli_as_one_background_job(self):
        st = self.panel.ok("devices", {})
        self.assertIn("ios", st)
        self.assertIsNone(st["android"])                                  # hermetic env: no adb
        self.bad("device_setup", {"platform": "ios", "target": "../x"}, "udid")
        self.bad("device_setup", {"platform": "android", "target": "R58M1"}, "serial")
        self.bad("device_setup", {"platform": "nope", "target": "all"}, "platform")
        self.panel.ok("device_setup", {"platform": "ios", "target": "all", "name": "all"})
        job = wait_for(lambda: (lambda j: j if j and not j["running"] else None)(self.panel.ok("device_job", {})["job"]),
                       20, 0.3, "setup job finished")
        self.assertNotEqual(job["rc"], 0)
        self.assertIn("no booted simulator", "\n".join(job["lines"]))      # the CLI's own message, streamed back

    def test_rules_built_from_a_call_match_that_call_on_a_non_default_port(self):
        """FOUND-BUGS B3: flow_regex drops ':port', so mock/quick/breakpoint-from-call never match a call to host:port."""
        self.fetch("/json/small")
        f = self.inst.flow_for("/json/small")
        url = self.up.url("/json/small")
        self.panel.ok("quick", {"flow_id": f["id"], "kind": "block"})
        rule = self.rules()[0]
        self.assertTrue(re.search(rule["match"], url), "%r does not match %s" % (rule["match"], url))

    def test_maplocal_add_wildcards(self):
        self.panel.ok("maplocal_add", {"name": "ml", "host": "127.0.0.1", "path": "/ech?", "body": '{"m":1}', "status": 203,
                                       "method": "get"})
        rule = self.rules()[0]
        self.assertEqual((rule["action"], rule["method"], rule["status"]), ("map_local", "GET", 203))
        r = wait_for(lambda: (lambda x: x if x.status == 203 else None)(self.fetch("/echo")), 8, 0.3, "map local")
        self.assertEqual(r.json(), {"m": 1})
        self.assertEqual(self.fetch("/echoo").status, 404)
        self.bad("maplocal_add", {"path": "/x"}, "host")
        self.assertEqual(self.panel.post("maplocal_add", {"host": "h", "status": "abc"})[0], 400)
        for bad_status in (0, -1, 70000, 999):                          # MQ-16: these gave the app an empty reply
            self.bad("maplocal_add", {"host": "h", "path": "/s", "status": bad_status}, "100 to 599")
        self.panel.ok("add", {"rule": {"name": "plain", "match": ".", "action": "block"}})
        self.bad("mockfile_get", {"name": "plain"}, "not a map local")
        self.bad("mockfile_put", {"name": "plain", "content": "x"}, "not a map local")

    # -- view / filters -------------------------------------------------------------------------------
    def test_focus_host_refuses_filter_injection(self):
        """F-16: the host becomes part of a ~d '...' filter; quotes and spaces must never reach it."""
        for host in ("a' | ~all | ~d 'b", "x y", "evil$", 7):
            self.assertEqual(self.panel.post("focus_host", {"host": host})[0], 400, host)
        self.assertIsNone(self.panel.state()["focus_host"])

    def test_view_focus_host_and_graphql_filter_drive_mitmweb_view_filter(self):
        self.panel.ok("view", {"project_only": False, "show_dns": True})
        self.assertEqual(self.panel.option("view_filter") or "", "")
        self.panel.ok("view", {"project_only": False, "show_dns": False})
        self.assertIn("~http", self.panel.option("view_filter"))
        self.panel.ok("focus_host", {"host": "127.0.0.1"})
        self.assertIn("127", self.panel.option("view_filter"))
        self.assertEqual(self.panel.state()["focus_host"], "127.0.0.1")
        self.panel.ok("focus_host", {})
        self.assertIsNone(self.panel.state()["focus_host"])
        self.panel.ok("graphql_filter", {"name": "GetViewer"})
        self.assertIn("GetViewer", self.panel.option("view_filter"))
        self.panel.ok("graphql_filter", {})
        self.assertNotIn("GetViewer", self.panel.option("view_filter"))
        self.bad("view", {"project": "no-such-project"}, "unknown")
        self.bad("view", {"project": "../x"}, "bad project")

    def test_filter_check_accepts_valid_filters_and_explains_invalid_ones(self):
        # the search bar asks first: an invalid filter sent straight to mitmweb would close its websocket
        for good in ("postman-echo.com", "~d example.com & ~m POST", "", "!~s"):
            self.assertTrue(self.panel.ok("filter_check", {"filter": good}).get("ok"), good)
        doc = self.panel.ok("filter_check", {"filter": "~d ("})
        self.assertFalse(doc.get("ok"))
        self.assertTrue(doc.get("error"))

    # -- export / codegen / compose --------------------------------------------------------------------
    def test_export_url_and_curl_mask_secrets_by_default(self):
        self.fetch("/echo?a=1", headers={"Authorization": "Bearer " + JWT_FRESH, "Cookie": "s=secretvalue"})
        fid = self.flow_id("/echo")
        self.assertEqual(self.panel.ok("export", {"flow_id": fid, "fmt": "url"})["text"], self.up.url("/echo?a=1"))
        masked = self.panel.ok("export", {"flow_id": fid, "fmt": "curl"})["text"]
        self.assertNotIn(JWT_FRESH, masked)
        self.assertNotIn("secretvalue", masked)
        self.assertIn("<redacted>", masked)
        plain = self.panel.ok("export", {"flow_id": fid, "fmt": "curl", "mask": False})["text"]
        self.assertIn(JWT_FRESH, plain)
        self.bad("export", {"flow_id": "nope"}, "no longer")

    def test_codegen_every_target_from_a_call_and_from_a_spec(self):
        self.fetch("/echo", method="POST", data='{"k": "v"}', headers={"Content-Type": "application/json",
                                                                    "Authorization": "Bearer tok123"})
        fid = self.flow_id("/echo")
        targets = [t["id"] for t in self.panel.state()["codegen_targets"]]
        self.assertEqual(len(targets), 12)
        for t in targets:
            doc = self.panel.ok("codegen", {"flow_id": fid, "target": t})
            self.assertTrue(doc["masked"])
            self.assertIn("/echo", doc["text"], t)
            self.assertNotIn("tok123", doc["text"], t)
        spec = {"method": "GET", "url": "https://h.test/x", "headers": [["Authorization", "Bearer T"]]}
        self.assertNotIn("Bearer T", self.panel.ok("codegen", {"spec": spec, "target": "curl"})["text"])
        self.assertIn("Bearer T", self.panel.ok("codegen", {"spec": spec, "target": "curl", "mask": False})["text"])
        self.bad("codegen", {"flow_id": fid, "target": "cobol"}, "unknown")
        self.bad("codegen", {"spec": "nope", "target": "curl"})

    def test_compose_save_load_rename_delete_vars_and_get(self):
        spec = {"method": "POST", "url": "{{base}}/echo", "headers": [["X-A", "1"]], "body_mode": "json", "body": '{"a":1}'}
        self.panel.ok("compose_vars", {"vars": {"base": self.up.url("")}})
        self.assertEqual(self.panel.ok("compose_save", {"name": "c1", "spec": spec})["name"], "c1")
        self.assertEqual(self.panel.state()["composer"]["names"], ["c1"])
        self.assertEqual(self.panel.state()["composer"]["vars"], {"base": self.up.url("")})
        self.assertEqual(self.panel.ok("compose_load", {"name": "c1"})["spec"]["url"], "{{base}}/echo")
        self.panel.ok("compose_rename", {"old": "c1", "new": "c2"})
        self.assertEqual(self.panel.state()["composer"]["names"], ["c2"])
        for d in (self.inst.path("composer"), self.inst.path("composer", "c2.json")):
            self.assertEqual(mode(d), 0o700 if os.path.isdir(d) else 0o600, d)
        self.panel.ok("compose_delete", {"name": "c2"})
        self.assertEqual(self.panel.state()["composer"]["names"], [])
        self.fetch("/echo?q=1", method="POST", data='{"z": 1}', headers={"Content-Type": "application/json"})
        got = self.panel.ok("compose_get", {"flow_id": self.flow_id("/echo")})["spec"]
        self.assertEqual((got["method"], got["body_mode"]), ("POST", "json"))
        self.assertEqual(got["query"], [["q", "1", True]])
        for op, body in (("compose_load", {"name": "ghost"}), ("compose_save", {"name": "../x", "spec": {}}),
                         ("compose_save", {"name": "ok", "spec": "nope"}), ("compose_rename", {"old": "ghost", "new": "x"}),
                         ("compose_delete", {"name": "../x"}), ("compose_vars", {"vars": "nope"}),
                         ("compose_get", {"flow_id": "nope"})):
            self.bad(op, body)

    def test_compose_send_goes_through_rules_and_is_listed(self):
        self.reset_state(rules=[self.rule("mockecho", "respond", "/echo", status=207, body={"mocked": True},
                                          headers={"X-Via": "rule"})])
        doc = self.panel.ok("compose_send", {"spec": {"method": "GET", "url": self.up.url("/echo?c=1")}})
        fl = wait_for(lambda: (lambda f: f if f and f.get("response") else None)(self.find_flow(doc["id"])), 10, 0.2, "composed flow")
        self.assertEqual(fl["response"]["status_code"], 207)
        self.assertIn("mock:mockecho", fl["comment"])
        self.assertIn("composed", fl["comment"])
        self.assertEqual(self.up.hits_for("/echo"), [])
        self.bad("compose_send", {"spec": {"url": "ftp://x"}})
        self.bad("compose_send", {"spec": {"url": "https://h/{{undefined}}"}})

    def test_cli_compose_send_reaches_the_running_proxy(self):
        """QA RIVIS-QA-01: `rivis compose send` died with 'mitmweb gave no XSRF cookie' against a running proxy."""
        self.panel.ok("compose_save", {"name": "clisend", "spec": {"method": "GET", "url": self.up.url("/json/small?cli=1")}})
        r = harness.subprocess.run(["/bin/bash", harness.RIVIS, "compose", "send", "clisend", "--no-wait"], env=self.inst.env,
                                   capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("sent GET", r.stdout)
        wait_for(lambda: self.up.hits_for("/json/small"), 10, 0.2, "upstream hit by the CLI send")
        self.panel.ok("compose_delete", {"name": "clisend"})          # the instance is shared by this class

    def test_compose_send_a_saved_request_with_variable_override(self):
        self.panel.ok("compose_save", {"name": "saved", "spec": {"method": "GET", "url": "{{base}}/json/small"}})
        doc = self.panel.ok("compose_send", {"name": "saved", "vars": {"base": self.up.url("")}})
        fl = wait_for(lambda: (lambda f: f if f and f.get("response") else None)(self.find_flow(doc["id"])), 10, 0.2, "saved send")
        self.assertEqual(fl["response"]["status_code"], 200)
        self.assertEqual(len(self.up.hits_for("/json/small")), 1)

    def test_compose_send_infers_body_and_does_not_replace_unicode_header_bytes(self):
        doc = self.panel.ok("compose_send", {"spec": {"method": "POST", "url": self.up.url("/echo"),
                                                       "headers": [["X-Name", "Jalapeño"]],
                                                       "body": "plain body"}})
        wait_for(lambda: self.find_flow(doc["id"]) and self.find_flow(doc["id"]).get("response"),
                 10, 0.2, "composed response")
        hit = self.up.hits_for("/echo")[-1]
        self.assertEqual(hit["body"], b"plain body")
        value = next(v for k, v in hit["headers"] if k.lower() == "x-name")
        self.assertEqual(value.encode("latin-1"), "Jalapeño".encode("utf-8"))

    def comment_after(self, path):
        self.fetch(path)
        return self.inst.flow_for(path)["comment"] or ""

    def find_flow(self, flow_id):
        return next((f for f in self.inst.flows() if f["id"] == flow_id), None)

    def test_compose_token_finds_the_latest_bearer_jwt(self):
        self.bad("compose_token", {"host": "127.0.0.1"}, "no authorization")
        self.fetch("/echo", headers={"Authorization": "Bearer " + JWT_FRESH})
        doc = self.panel.ok("compose_token", {"host": "127.0.0.1"})
        self.assertEqual((doc["token"], doc["sub"]), (JWT_FRESH, "alice"))

    def test_retry_edit_and_retry_sends_a_new_call(self):
        self.fetch("/echo?r=1", method="POST", data="one")
        fid = self.flow_id("/echo")
        info = self.panel.ok("retry_get", {"flow_id": fid})
        self.assertEqual((info["method"], info["req_body"]), ("POST", "one"))
        before = len(self.up.hits_for("/echo"))
        doc = self.panel.ok("retry", {"flow_id": fid, "edits": {"body": "two", "url": self.up.url("/echo?r=2")}})
        wait_for(lambda: len(self.up.hits_for("/echo")) == before + 1, 10, 0.2, "retry hit")
        self.assertEqual(self.up.hits_for("/echo")[-1]["body"], b"two")
        self.assertIn("edit & retry", (self.find_flow(doc["id"]) or {}).get("comment", "edit & retry"))
        self.bad("retry_get", {"flow_id": "nope"}, "no longer")
        self.bad("retry", {"flow_id": "nope"}, "no longer")

    def test_diff_two_calls(self):
        self.fetch("/echo?a=1", headers={"X-One": "1"})
        a = self.flow_id("/echo?a=1")
        self.fetch("/json/small")
        b = self.flow_id("/json/small")
        d = self.panel.ok("diff", {"a": a, "b": b})
        self.assertEqual(d["a"]["status"], 200)
        self.assertEqual(d["resp_body"]["kind"], "json")
        self.assertTrue(d["resp_body"]["rows"])
        self.assertTrue(any(r[0] == "x-one" for r in d["req_headers"]))
        self.bad("diff", {"a": a, "b": "nope"}, "no longer")

    # -- tls ------------------------------------------------------------------------------------------
    def test_tls_set_and_tls_host(self):
        self.panel.ok("tls_set", {"mode": "ignore", "ignore": ["*.example.test", "A.Example.Test"]})
        tls = self.panel.state()["tls"]
        self.assertEqual((tls["mode"], tls["ignore"]), ("ignore", ["*.example.test", "a.example.test"]))
        self.fetch("/json/small")
        fid = self.flow_id("/json/small")
        doc = self.panel.ok("tls_host", {"flow_id": fid, "decrypt": False})
        self.assertEqual(doc["host"], "127.0.0.1")
        self.assertIn("127.0.0.1", self.panel.state()["tls"]["ignore"])
        self.panel.ok("tls_host", {"host": "127.0.0.1", "decrypt": True})
        self.assertNotIn("127.0.0.1", self.panel.state()["tls"]["ignore"])
        self.bad("tls_set", {"mode": "sometimes"})
        self.bad("tls_set", {"ignore": ["http://x"]})
        self.bad("tls_host", {"host": "", "flow_id": "nope"}, "no longer")
        self.panel.ok("tls_set", {"mode": "all", "ignore": [], "allow": []})
        self.assertIn("already decrypted", self.panel.ok("tls_host", {"host": "h.test", "decrypt": True})["message"])

    def test_tls_incremental_update_preserves_concurrent_cli_changes(self):
        self.panel.ok("tls_set", {"mode": "allow", "allow": ["initial.example"]})
        cfg = self.inst.cfg()
        cfg["tls"]["allow"].append("cli.example")
        self.inst.write_cfg(cfg)
        self.panel.ok("tls_update", {"list": "allow", "action": "add", "pattern": "UI.Example"})
        self.assertEqual(self.panel.state()["tls"]["allow"],
                         ["initial.example", "cli.example", "ui.example"])
        self.panel.ok("tls_update", {"list": "allow", "action": "remove", "pattern": "initial.example"})
        self.assertEqual(self.panel.state()["tls"]["allow"], ["cli.example", "ui.example"])
        self.bad("tls_update", {"list": "other", "action": "add", "pattern": "x.test"}, "list must")
        self.bad("tls_update", {"list": "allow", "action": "replace", "pattern": "x.test"}, "action must")

    # -- viewers -------------------------------------------------------------------------------------
    def test_viewer_ops(self):
        self.fetch("/jwt/body")
        v = self.panel.ok("viewer", {"flow_id": self.flow_id("/jwt/body")})
        self.assertGreaterEqual(len(v["tokens"]), 2)
        self.assertEqual({t["payload"]["sub"] for t in v["tokens"]}, {"alice", "bob"})
        s = wait_for(lambda: (lambda d: d if d["complete"] else None)(self.panel.ok("viewer_summaries", {"limit": 50})["viewers"]),
                     20, 0.1, "incremental summaries complete")        # work is bounded per call (<= 50 flows)
        self.assertEqual(s["total"], len(self.inst.flows()))
        self.assertTrue(s["tokens"])
        self.bad("viewer", {"flow_id": "nope"}, "no longer")

    # -- scripts ----------------------------------------------------------------------------------------
    def test_script_ops(self):
        self.inst.clear_dir("scripts")
        for lang in ("py", "js"):
            for tpl in ("header", "json", "mock", "latency", "token"):
                name = "s-%s-%s" % (lang, tpl)
                self.assertEqual(self.panel.ok("script_new", {"name": name, "lang": lang, "template": tpl,
                                                              "match": "/never", "method": "get"})["file"], name + "." + lang)
        scripts = self.panel.state()["scripts"]
        self.assertEqual(len(scripts), 10)
        self.assertTrue(all(s["exists"] for s in scripts))
        got = self.panel.ok("script_get", {"file": "s-py-header.py"})
        self.assertIn("def on_request", got["content"])
        self.assertEqual(got["script"]["method"], "GET")
        self.assertEqual(mode(got["file"]), 0o600)
        self.panel.ok("script_put", {"file": "s-py-header.py", "content": "def on_request(context, url, request):\n    return None\n",
                                     "match": "/other", "method": ""})
        self.assertEqual(self.panel.ok("script_get", {"file": "s-py-header.py"})["script"]["match"], "/other")
        bad = self.panel.ok("script_put", {"file": "s-py-header.py", "content": "def on_request(context, url, request)\n    return None\n"})
        self.assertIn("line 1", bad["syntax_error"])                    # flagged on Save, not on the next matching call
        self.assertIn("s-py-header.py", bad["state"]["script_status"]["errors"])
        js = next(s["file"] for s in self.panel.state()["scripts"] if s["file"].endswith(".js"))
        bad = self.panel.ok("script_put", {"file": js, "content": "async function onRequest(c, u, request) {\n  request.x = ;\n  return request\n}\n"})
        self.assertIn("line 2", bad.get("syntax_error") or "")
        good = self.panel.ok("script_put", {"file": js, "content": "async function onRequest(c, u, request) { return request }\n"})
        self.assertNotIn("syntax_error", good)
        self.assertNotIn(js, good["state"]["script_status"]["errors"])
        self.panel.ok("script_put", {"file": "s-py-header.py", "content": "def on_request(context, url, request):\n    return None\n",
                                     "match": "/other", "method": ""})
        self.assertEqual(mode(self.inst.path("scripts", "s-py-header.py")), 0o600)
        self.panel.ok("script_toggle", {"file": "s-py-header.py", "enabled": False})
        self.assertFalse(next(s for s in self.panel.state()["scripts"] if s["file"] == "s-py-header.py")["enabled"])
        self.panel.ok("script_delete", {"file": "s-py-header.py"})
        self.assertFalse(os.path.exists(self.inst.path("scripts", "s-py-header.py")))
        for op, body in (("script_new", {"name": "s-js-json", "lang": "js"}), ("script_new", {"name": "x", "lang": "rb"}),
                         ("script_new", {"name": "../x", "lang": "py"}),
                         ("script_new", {"name": "y", "lang": "py", "match": "("}), ("script_get", {"file": "ghost.py"}),
                         ("script_get", {"file": "../../etc/passwd"}), ("script_get", {"file": "x.txt"}),
                         ("script_put", {"file": "ghost.py", "content": ""}), ("script_toggle", {"file": "ghost.py"}),
                         ("script_delete", {"file": "ghost.py"}), ("script_delete", {"file": "/etc/hosts"})):
            self.bad(op, body)
        self.assertFalse(os.path.exists(self.inst.path("scripts", "x.py")))
        self.assertFalse(os.path.exists(self.inst.path("scripts", "y.py")))

    def test_failed_script_new_leaves_no_orphan_file(self):
        """FOUND-BUGS B4: an unknown template raises after the file was created → empty orphan blocks the name."""
        self.inst.clear_dir("scripts")
        self.bad("script_new", {"name": "orph", "lang": "py", "template": "nope"})
        self.assertFalse(os.path.exists(self.inst.path("scripts", "orph.py")))
        self.panel.ok("script_new", {"name": "orph", "lang": "py"})       # the name must still be usable

    # -- coverage guard -----------------------------------------------------------------------------------
    def test_every_op_in_the_source_is_exercised_by_some_test(self):
        """Adding a panel op without a test fails this one."""
        src = open(os.path.join(ADDONS, "proxy_panel.py")).read()
        ops = set(re.findall(r'op (?:==|in) \(?"([a-z_]+)"', src)) | set(re.findall(r'"(paused_[a-z]+)"', src))
        text = ""
        for fn in os.listdir(harness.TESTS):
            if fn.startswith("test_") and fn.endswith(".py") and fn != "test_panel_coverage.py":
                text += open(os.path.join(harness.TESTS, fn)).read()
        missing = sorted(op for op in ops if ('"%s"' % op) not in text and ("'%s'" % op) not in text)
        self.assertEqual(missing, [], "panel ops with no test")
        self.assertGreaterEqual(len(ops), 55)


class Confinement(LiveCase):
    """Names with ../, absolute paths and symlink tricks never leave the project's state dir."""
    TRAVERSAL = ("../x", "../../x", "/etc/hosts", "/tmp/x", "a/b", "x\x00y", "x%2e%2e%2fy", "a b", "~/x", "C:\\x", "",
                 "CON", "nul.json", "com1", ".hidden", "trailing.", "..")   # F-18: Windows device names, dot edges

    def test_names_are_refused_by_every_name_taking_op(self):
        for name in self.TRAVERSAL:
            for op, key in (("sess_save", "name"), ("sess_load", "name"), ("sess_delete", "name"), ("sess_note", "name"),
                            ("sess_har", "name"), ("coll_record", "name"), ("coll_delete", "name"), ("coll_entries", "name"),
                            ("coll_export", "name"), ("coll_import", "name"), ("coll_replay", "name"),
                            ("compose_save", "name"), ("compose_load", "name"), ("compose_delete", "name"),
                            ("script_new", "name"), ("script_get", "file"), ("script_delete", "file"),
                            ("script_put", "file"), ("script_toggle", "file")):
                body = {key: name, "spec": {}, "har": {}, "enabled": True, "content": "x", "lang": "py"}
                code, doc, raw = self.panel.post(op, body)
                self.assertEqual(code, 400, "%s %r -> %s %r" % (op, name, code, raw[:100]))

    def test_nothing_was_created_outside_the_state_dir(self):
        parent = os.path.dirname(self.inst.state_dir)
        before = set(os.listdir(parent))
        self.panel.post("sess_save", {"name": "../escape"})
        self.panel.post("coll_record", {"name": "../escape"})
        self.panel.post("script_new", {"name": "../escape", "lang": "py"})
        self.assertEqual(set(os.listdir(parent)), before)
        self.assertEqual([f for f in os.listdir(self.inst.state_dir) if "escape" in f], [])

    def test_mockfile_ops_refuse_files_outside_the_mock_dir_including_symlinks(self):
        outside = os.path.join(self.suite.root, "outside-secret.txt")
        with open(outside, "w") as fh:
            fh.write("TOP-SECRET")
        mocks = self.inst.path("mocks")
        os.makedirs(mocks, exist_ok=True)
        link = os.path.join(mocks, "link.json")
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(outside, link)
        rules = [self.rule("abs", "map_local", "/x", file=outside), self.rule("lnk", "map_local", "/y", file=link),
                 self.rule("dotdot", "map_local", "/z", file=os.path.join(mocks, "..", "..", "..", os.path.relpath(outside, "/")))]
        self.reset_state(rules=rules)
        for name in ("abs", "lnk", "dotdot"):
            for op in ("mockfile_get", "mockfile_put"):
                code, doc, raw = self.panel.post(op, {"name": name, "content": "OVERWRITTEN"})
                self.assertEqual(code, 400, "%s %s -> %s %r" % (op, name, code, raw[:120]))
                self.assertNotIn("TOP-SECRET", json.dumps(doc))
        with open(outside) as fh:
            self.assertEqual(fh.read(), "TOP-SECRET")

    def test_symlinked_script_is_not_read_through_the_panel(self):
        """FOUND-BUGS B5."""
        outside = os.path.join(self.suite.root, "outside-script.txt")
        with open(outside, "w") as fh:
            fh.write("TOP-SECRET-SCRIPT")
        sdir = self.inst.path("scripts")
        os.makedirs(sdir, exist_ok=True)
        link = os.path.join(sdir, "evil.py")
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(outside, link)
        self.reset_state(scripts=[{"name": "evil", "file": "evil.py", "lang": "py", "enabled": False, "match": "."}])
        code, doc, raw = self.panel.post("script_get", {"file": "evil.py"})
        self.assertFalse(code == 200 and "TOP-SECRET-SCRIPT" in raw.decode(), "script_get followed a symlink out of the project")

    def test_symlinked_collection_is_not_read_through_the_panel(self):
        """FOUND-BUGS B5."""
        outside = os.path.join(self.suite.root, "outside-coll.json")
        with open(outside, "w") as fh:
            json.dump({"name": "evil", "entries": [{"method": "GET", "host": "TOP-SECRET-HOST", "path": "/", "status": 200}]}, fh)
        cdir = self.inst.path("collections")
        os.makedirs(cdir, exist_ok=True)
        link = os.path.join(cdir, "evil.json")
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(outside, link)
        code, doc, raw = self.panel.post("coll_entries", {"name": "evil"})
        self.assertFalse(code == 200 and b"TOP-SECRET-HOST" in raw, "coll_entries followed a symlink out of the project")

    def test_map_local_rule_pointing_outside_the_project_is_not_served(self):
        """FOUND-BUGS B6."""
        outside = os.path.join(self.suite.root, "outside-map.txt")
        with open(outside, "w") as fh:
            fh.write("TOP-SECRET-MAPLOCAL")
        self.reset_state(rules=[self.rule("m", "map_local", "/echo", file=outside)])
        self.assertNotIn("TOP-SECRET-MAPLOCAL", self.fetch("/echo").text)

    def test_respond_body_file_outside_the_project_is_not_served(self):
        """FOUND-BUGS B6."""
        outside = os.path.join(self.suite.root, "outside-body.txt")
        with open(outside, "w") as fh:
            fh.write("TOP-SECRET-BODYFILE")
        self.reset_state(rules=[self.rule("b", "respond", "/echo", body_file=outside)])
        self.assertNotIn("TOP-SECRET-BODYFILE", self.fetch("/echo").text)

    def _trust(self, *paths):
        with open(self.inst.path("trusted-files.json"), "w") as fh:
            json.dump({"files": [os.path.realpath(p) for p in paths]}, fh)
        self.addCleanup(lambda: os.path.exists(self.inst.path("trusted-files.json"))
                        and os.unlink(self.inst.path("trusted-files.json")))

    def test_a_file_the_user_trusted_on_this_machine_is_served_and_flagged(self):
        """Item 0: users map their OWN files anywhere, as in Proxyman — once trusted locally."""
        mine = os.path.join(self.suite.root, "my-mock.json")
        with open(mine, "w") as fh:
            fh.write('{"mine": true}')
        self._trust(mine)
        self.reset_state(rules=[self.rule("mine", "map_local", "/echo", file=mine),
                                self.rule("body", "respond", "/text", body_file=mine)])
        self.assertEqual(self.fetch("/echo").json(), {"mine": True})
        self.assertIn('"mine"', self.fetch("/text").text)
        self.assertEqual(sorted(self.panel.state()["rules_outside"]), ["body", "mine"])

    def test_a_rules_file_cannot_trust_itself(self):
        """A shared rules.json may carry any flag it likes; only the separate local trust list counts."""
        outside = os.path.join(self.suite.root, "outside-selftrust.txt")
        with open(outside, "w") as fh:
            fh.write("TOP-SECRET-SELFTRUST")
        self.reset_state(rules=[self.rule("x", "map_local", "/echo", file=outside, allow_outside=True, trusted=True)],
                         trusted_files=[outside])
        self.assertNotIn("TOP-SECRET-SELFTRUST", self.fetch("/echo").text)
        self.assertIn("allow-file", json.dumps(self.panel.state()))   # the skipped-rule error says how to trust it

    def test_keys_and_rivis_secrets_are_refused_even_when_trusted(self):
        fake_ssh = os.path.join(self.inst.home, ".ssh")    # the instance's fake HOME, never the real one
        os.makedirs(fake_ssh, exist_ok=True)
        key = os.path.join(fake_ssh, "id_test")
        pem = os.path.join(self.suite.root, "client.pem")
        for path, text in ((key, "TOP-SECRET-SSH"), (pem, "TOP-SECRET-PEM")):
            with open(path, "w") as fh:
                fh.write(text)
        token = self.inst.path("web-token") if os.path.exists(self.inst.path("web-token")) else None
        trusted = [key, pem] + ([token] if token else [])
        self._trust(*trusted)
        self.reset_state(rules=[self.rule("ssh", "map_local", "/echo", file=key),
                                self.rule("pem", "map_local", "/text", file=pem)])
        self.assertNotIn("TOP-SECRET-SSH", self.fetch("/echo").text)
        self.assertNotIn("TOP-SECRET-PEM", self.fetch("/text").text)


class MalformedInput(LiveCase):
    """Invalid input must come back as a JSON error, never a 500 (brief §8)."""

    def test_non_json_and_empty_bodies(self):
        for raw in (b"{bad", b"\xff\xfe", b"not json"):
            code, doc, _ = self.panel.post("view", raw=raw)
            self.assertEqual(code, 400)
            self.assertIn("error", doc)
        self.assertEqual(self.panel.post("view", raw=b"")[0], 200)       # empty body == {}

    def test_non_object_json_bodies_give_json_error_not_500(self):
        """FOUND-BUGS B1: [] / null / 123 / "x" as the request body → HTTP 500 HTML page."""
        for raw in (b"[]", b"null", b"123", b'"str"', b"true"):
            for op in ("add", "view", "bp_add", "sess_save", "tls_set"):
                code, doc, _ = self.panel.post(op, raw=raw)
                self.assertEqual(code, 400, "%s %r -> %s" % (op, raw, code))

    def test_panel_operations_have_request_and_field_size_limits(self):
        code, doc, _ = self.panel.post("view", raw=b" " * (8 * 1024 * 1024 + 1), timeout=30)
        self.assertEqual(code, 413)
        code, doc, _ = self.panel.post("view", {"oversized": "x" * (2 * 1024 * 1024 + 1)}, timeout=30)
        self.assertEqual(code, 400)
        self.assertIn("2 MiB", doc["error"])

    def test_wrongly_typed_names_give_json_error_not_500(self):
        """FOUND-BUGS B1: name/host given as number, list, object or bool → HTTP 500."""
        for op, key in (("sess_save", "name"), ("coll_record", "name"), ("coll_import", "name"),
                        ("maplocal_add", "name"), ("script_new", "name"), ("bp_add", "host")):
            for value in (5, ["x"], {"a": 1}, True):
                code, doc, _ = self.panel.post(op, {key: value, "request": True})
                self.assertEqual(code, 400, "%s %s=%r -> %s" % (op, key, value, code))


if __name__ == "__main__":
    unittest.main(verbosity=2)
