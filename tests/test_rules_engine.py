"""Rules engine, live through the proxy: every action, first-match semantics, tags, skipped rules, hot reload,
broken rules.json handling."""
import gzip
import hashlib
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import LiveCase, wait_for
from upstream import SMALL_JSON, big_body


class Actions(LiveCase):
    def test_respond_json_headers_and_never_hits_upstream(self):
        self.reset_state(rules=[self.rule("r", "respond", "/echo", status=201, body={"hello": "world"},
                                          headers={"X-Mock": "1"})])
        r = self.fetch("/echo")
        self.assertEqual((r.status, r.json(), r.header("x-mock")), (201, {"hello": "world"}, "1"))
        self.assertEqual(r.header("content-type"), "application/json")
        self.assertEqual(self.up.hits_for("/echo"), [])

    def test_respond_text_body_and_content_type_override(self):
        self.reset_state(rules=[self.rule("r", "respond", "/echo", body="plain", headers={"Content-Type": "text/plain"})])
        r = self.fetch("/echo")
        self.assertEqual((r.status, r.text, r.header("content-type")), (200, "plain", "text/plain"))

    def test_respond_body_file_and_binary_exact(self):
        blob = bytes(range(256)) * 40
        path = self.inst.path("blob.bin")          # inside the project: file rules are confined (F-09)
        open(path, "wb").write(blob)
        self.reset_state(rules=[self.rule("r", "respond", "/echo", body_file=path)])
        self.assertEqual(self.fetch("/echo").body, blob)

    def test_map_local_content_type_from_extension(self):
        jf, tf, bf = (self.inst.path(n) for n in ("a.json", "a.txt", "a.zzz"))
        open(jf, "w").write('{"j": 1}')
        open(tf, "w").write("text")
        open(bf, "wb").write(b"\x00\x01\x02")
        self.reset_state(rules=[self.rule("j", "map_local", "/m/j", file=jf, status=202),
                                self.rule("t", "map_local", "/m/t", file=tf),
                                self.rule("b", "map_local", "/m/b", file=bf)])
        r = self.fetch("/m/j")
        self.assertEqual((r.status, r.json(), r.header("content-type")), (202, {"j": 1}, "application/json"))
        self.assertTrue(self.fetch("/m/t").header("content-type").startswith("text/plain"))
        r = self.fetch("/m/b")
        self.assertEqual((r.body, r.header("content-type")), (b"\x00\x01\x02", "application/octet-stream"))
        self.assertEqual(self.up.hits, [])

    def test_map_local_missing_file_falls_through_and_is_tagged(self):
        self.reset_state(rules=[self.rule("ml", "map_local", "/json/small", file=self.inst.path("missing.json"))])
        r = self.fetch("/json/small")
        self.assertEqual(r.json(), SMALL_JSON)                 # the real server answered
        self.assertIn("rule:ml FAILED", self.comment("/json/small"))

    def test_status_rewrites_real_response(self):
        self.reset_state(rules=[self.rule("s", "status", "/json/small", status=503)])
        r = self.fetch("/json/small")
        self.assertEqual((r.status, r.json()), (503, SMALL_JSON))     # body kept
        self.assertEqual(len(self.up.hits_for("/json/small")), 1)
        self.reset_state(rules=[self.rule("s", "status", "/json/small", status=418, body={"x": 1})])
        r = self.fetch("/json/small")
        self.assertEqual((r.status, r.json()), (418, {"x": 1}))

    def test_json_patch_dot_paths_and_list_index(self):
        self.reset_state(rules=[self.rule("p", "json_patch", "/json/small",
                                          set={"user.name": "bob", "items[1].id": 99, "flag": True, "user.roles[0]": "z"})])
        d = self.fetch("/json/small").json()
        self.assertEqual((d["user"]["name"], d["items"][1]["id"], d["flag"], d["user"]["roles"]), ("bob", 99, True, ["z", "b"]))
        self.assertIn("rule:p", self.comment("/json/small"))

    def test_json_patch_missing_path_is_reported_not_invented(self):
        self.reset_state(rules=[self.rule("p", "json_patch", "/json/small", set={"user.nope.deep": 1, "user.name": "x"})])
        d = self.fetch("/json/small").json()
        self.assertEqual(d["user"]["name"], "x")
        self.assertNotIn("nope", d["user"])
        self.assertIn("missing: user.nope.deep", self.comment("/json/small"))

    def test_json_patch_empty_and_non_json_body_unchanged(self):
        self.reset_state(rules=[self.rule("p", "json_patch", "/(empty|text)", set={"a": 1})])
        r = self.fetch("/empty")
        self.assertEqual((r.status, r.body), (200, b""))
        r = self.fetch("/text")
        self.assertEqual((r.status, r.body), (200, b"not json at all"))
        self.assertIn("skipped", self.comment("/text"))

    def test_json_patch_on_gzip_response(self):
        self.reset_state(rules=[self.rule("p", "json_patch", "/json/gzip", set={"name": "patched"})])
        r = self.fetch("/json/gzip", extra=["--compressed"])
        self.assertEqual(r.json()["name"], "patched")
        self.assertEqual(len(r.json()["items"]), 50)

    def test_delay(self):
        self.reset_state(rules=[self.rule("d", "delay", "/json/small", ms=700)])
        t = time.time()
        self.fetch("/json/small")
        self.assertGreaterEqual(time.time() - t, 0.65)
        t = time.time()
        self.fetch("/echo")
        self.assertLess(time.time() - t, 0.6)                  # other URLs are not delayed
        self.assertIn("+700", self.comment("/json/small"))

    def test_set_header_request_side_add_replace_remove(self):
        self.reset_state(rules=[self.rule("a", "set_header", "/echo", header="X-Added", value="yes"),
                                self.rule("b", "set_header", "/echo", header="X-Replace", value="new"),
                                self.rule("c", "set_header", "/echo", header="X-Drop", value=None)])
        r = self.fetch("/echo", headers={"X-Replace": "old", "X-Drop": "bye"})
        hdrs = {k.lower(): v for k, v in r.json()["headers"]}
        self.assertEqual((hdrs.get("x-added"), hdrs.get("x-replace")), ("yes", "new"))
        self.assertNotIn("x-drop", hdrs)

    def test_set_header_response_side(self):
        self.reset_state(rules=[self.rule("a", "set_header", "/echo", side="response", header="X-Resp", value="1"),
                                self.rule("b", "set_header", "/echo", side="response", header="Content-Type", value=None)])
        r = self.fetch("/echo")
        self.assertEqual(r.header("x-resp"), "1")
        self.assertIsNone(r.header("content-type"))
        hdrs = {k.lower() for k, v in self.up.hits[0]["headers"]}
        self.assertNotIn("x-resp", hdrs)                       # response-side rule must not leak to the server

    def test_map_remote_rewrites_url_before_sending(self):
        self.reset_state(rules=[self.rule("m", "map_remote", "/json/small", replace=r":%d/" % self.up.http_port,
                                          **{"with": ":%d/" % self.up2.http_port + "echo?via=remote&orig="})])
        r = self.fetch("/json/small")
        self.assertEqual(self.up.hits, [])
        self.assertEqual(len(self.up2.hits), 1)
        self.assertIn("via=remote", self.up2.hits[0]["path"])
        self.assertIn("rule:m", self.comment("/echo"))

    def test_block_kills_connection_and_is_method_scoped(self):
        self.reset_state(rules=[self.rule("b", "block", "/echo", method="POST")])
        r = self.fetch("/echo", method="POST", data="x")
        self.assertNotEqual(r.rc, 0)
        self.assertEqual(r.status, 0)
        self.assertEqual(self.up.hits, [])
        r = self.fetch("/echo", method="GET")
        self.assertEqual((r.rc, r.status), (0, 200))

    def test_method_filter_is_case_insensitive_and_exact(self):
        self.reset_state(rules=[self.rule("r", "respond", "/echo", method="post", body="mocked")])
        self.assertEqual(self.fetch("/echo", method="POST", data="x").text, "mocked")
        self.assertEqual(self.fetch("/echo").json()["method"], "GET")

    def test_match_is_a_regex_on_the_full_url_including_query(self):
        self.reset_state(rules=[self.rule("r", "respond", r"\?mode=special$", body="special")])
        self.assertEqual(self.fetch("/echo?mode=special").text, "special")
        self.assertNotEqual(self.fetch("/echo?mode=normal").text, "special")

    def test_rules_apply_to_decrypted_https(self):
        self.reset_state(rules=[self.rule("r", "respond", "/echo", body="tls-mock"),
                                self.rule("p", "json_patch", "/json/small", set={"flag": True})])
        self.assertEqual(self.fetch("/echo", tls=True).text, "tls-mock")
        self.assertTrue(self.fetch("/json/small", tls=True).json()["flag"])

    def test_redirects_and_untouched_traffic_pass_through(self):
        self.reset_state(rules=[self.rule("never", "respond", "/nothing-matches", body="x")])
        r = self.fetch("/redirect")
        self.assertEqual((r.status, r.header("location")), (302, "/json/small"))
        r = self.fetch("/big?mb=3")
        self.assertEqual(hashlib.sha256(r.body).hexdigest(), hashlib.sha256(big_body(3)).hexdigest())

    def test_set_cookie_headers_survive(self):
        self.reset_state(rules=[self.rule("h", "set_header", "/cookies", side="response", header="X-Z", value="1")])
        r = self.fetch("/cookies")
        self.assertEqual(sorted(r.header_all("set-cookie")), ["a=1; Path=/", "b=2; Path=/; HttpOnly"])


class Semantics(LiveCase):
    def test_first_match_wins_for_local_answers(self):
        self.reset_state(rules=[self.rule("first", "respond", "/echo", body="one"),
                                self.rule("second", "respond", "/echo", body="two"),
                                self.rule("third", "map_local", "/echo", file=self.inst.path("nonexistent.json"))])
        self.assertEqual(self.fetch("/echo").text, "one")
        c = self.comment("/echo")
        self.assertIn("mock:first", c)
        self.assertNotIn("mock:second", c)
        self.assertNotIn("mock:third", c)

    def test_disabled_rule_is_skipped(self):
        self.reset_state(rules=[self.rule("off", "respond", "/echo", body="one", enabled=False),
                                self.rule("on", "respond", "/echo", body="two")])
        self.assertEqual(self.fetch("/echo").text, "two")

    def test_rule_comment_tag_lists_every_rule_that_fired(self):
        self.reset_state(rules=[self.rule("hdr", "set_header", "/json/small", header="X-A", value="1"),
                                self.rule("pat", "json_patch", "/json/small", set={"flag": True}),
                                self.rule("st", "status", "/json/small", status=202)])
        self.fetch("/json/small")
        c = self.comment("/json/small")
        for name in ("rule:hdr", "rule:pat", "rule:st"):
            self.assertIn(name, c)

    def test_unnamed_rule_gets_a_fallback_name(self):
        self.reset_state(rules=[{"enabled": True, "match": "/echo", "action": "respond", "body": "anon"}])
        self.assertEqual(self.fetch("/echo").text, "anon")
        self.assertIn("mock:rule #2", self.comment("/echo"))   # #1 is the harness sync-marker rule

    def test_bad_rules_are_skipped_and_listed_while_the_rest_still_apply(self):
        self.reset_state(rules=[
            {"name": "bad-action", "enabled": True, "match": ".", "action": "explode"},
            {"name": "bad-regex", "enabled": True, "match": "(unclosed", "action": "respond"},
            {"name": "missing-field", "enabled": True, "match": ".", "action": "status"},
            {"name": "bad-status", "enabled": True, "match": ".", "action": "respond", "status": "abc"},
            {"name": "bad-delay", "enabled": True, "match": ".", "action": "delay", "ms": -5},
            {"name": "bad-patch", "enabled": True, "match": ".", "action": "json_patch", "set": ["x"]},
            {"name": "bad-side", "enabled": True, "match": ".", "action": "set_header", "header": "X", "side": "sideways"},
            "not even an object",
            {"name": "good", "enabled": True, "match": "/echo", "action": "respond", "body": "still-works"}])
        self.assertEqual(self.fetch("/echo").text, "still-works")
        skipped = {x["name"]: x["error"] for x in self.panel.state()["skipped_rules"]}
        for name in ("bad-action", "bad-regex", "missing-field", "bad-status", "bad-delay", "bad-patch", "bad-side"):
            self.assertIn(name, skipped)
            self.assertTrue(skipped[name])
        self.assertEqual(len(skipped), 8)             # the non-object entry is listed too, under a positional name
        self.assertNotIn("good", skipped)
        self.assertIn("unknown action", skipped["bad-action"])
        self.assertIn("needs: status", skipped["missing-field"])

    def test_skipped_list_clears_when_the_file_is_fixed(self):
        self.reset_state(rules=[{"name": "bad", "enabled": True, "match": ".", "action": "explode"}])
        self.assertEqual(len(self.panel.state()["skipped_rules"]), 1)
        self.reset_state(rules=[])
        self.assertEqual(self.panel.state()["skipped_rules"], [])


class HotReload(LiveCase):
    def test_edit_toggle_and_remove_take_effect_without_restart(self):
        self.reset_state(rules=[self.rule("r", "respond", "/echo", body="v1")])
        self.assertEqual(self.fetch("/echo").text, "v1")
        self.inst.write_cfg({"rules": [self.rule("r", "respond", "/echo", body="v2")]})
        self.assertEqual(self.fetch("/echo").text, "v2")
        self.inst.write_cfg({"rules": [self.rule("r", "respond", "/echo", body="v2", enabled=False)]})
        self.assertEqual(self.fetch("/echo").json()["method"], "GET")
        self.inst.write_cfg({"rules": []})
        self.assertEqual(self.fetch("/echo").json()["method"], "GET")

    def test_cli_rule_changes_reach_the_running_proxy(self):
        self.reset_state()
        r = self.suite.rivis("rules", "add", "viacli", "match=/echo", "action=respond", "body=from-cli",
                             home=self.inst.home, env=self.inst.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        wait_for(lambda: self.fetch("/echo").text == "from-cli", 8, 0.3, "CLI rule applied")
        self.suite.rivis("rules", "off", "viacli", home=self.inst.home, env=self.inst.env)
        wait_for(lambda: self.fetch("/echo").text != "from-cli", 8, 0.3, "CLI rule off")

    def test_broken_rules_json_keeps_previous_rules_and_never_kills_mitmweb(self):
        self.reset_state(rules=[self.rule("r", "respond", "/echo", body="keep")])
        for broken in ("{ not json", "", "[]", '{"rules": 5}', '{"rules": [1, 2]}', '{"throttle": "warp"}',
                       '{"rules": [], "throttle_match": "(unclosed"}', '{"tls": {"mode": "sideways"}}'):
            with open(self.inst.rules_path, "w") as fh:
                fh.write(broken)
            time.sleep(2.2)
            self.assertEqual(self.fetch("/echo").text, "keep", "after rules.json = %r" % broken)
            self.assertIsNone(self.inst.proc.poll(), "mitmweb died on %r" % broken)
            code, body = self.panel.get("/proxy/api/state")
            state = json.loads(body)
            self.assertEqual(code, 200)                                    # panel still serves
            self.assertTrue(state["rules_error"])
            self.assertIn("r", [rule["name"] for rule in state["rules"]]) # last good state stays visible
        self.inst.write_cfg({"rules": [self.rule("r", "respond", "/echo", body="fixed")]})
        self.assertEqual(self.fetch("/echo").text, "fixed")                 # recovers once the file is valid again

    def test_deleting_rules_json_turns_rules_off_and_restoring_turns_them_on(self):
        self.reset_state(rules=[self.rule("r", "respond", "/echo", body="here")])
        self.assertEqual(self.fetch("/echo").text, "here")
        os.unlink(self.inst.rules_path)
        wait_for(lambda: self.fetch("/echo").text != "here", 8, 0.3, "rules off after delete")
        self.assertIsNone(self.inst.proc.poll())
        self.inst.write_cfg({"rules": [self.rule("r", "respond", "/echo", body="back")]})
        self.assertEqual(self.fetch("/echo").text, "back")

    def test_rules_reload_does_not_need_traffic(self):
        """The poller re-reads the file every second even when idle: breakpoints must be armed BEFORE the next call."""
        self.reset_state()
        self.inst.write_cfg({"breakpoints": [{"name": "idle", "match": "/never-called", "request": True,
                                              "response": False, "enabled": True}]}, sync=False)
        o = wait_for(lambda: json.loads(self.panel.get("/options")[1])["intercept"]["value"], 6, 0.3, "intercept armed while idle")
        self.assertIn("/never-called", o)
        self.inst.write_cfg({})
        wait_for(lambda: json.loads(self.panel.get("/options")[1])["intercept"]["value"] is None, 6, 0.3, "intercept released")


if __name__ == "__main__":
    unittest.main(verbosity=2)
