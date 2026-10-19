"""Rules engine, live through the proxy: every action, first-match semantics, tags, skipped rules, hot reload,
broken rules.json handling."""
import gzip
import hashlib
import json
import os
import select
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import LiveCase, wait_for
from upstream import SMALL_JSON, big_body


class Actions(LiveCase):
    def test_event_stream_arrives_before_upstream_finishes(self):
        # R4B-01: curl must see the first event while later events are still sleeping upstream.
        self.reset_state(rules=[self.rule("patch", "json_patch", "/sse", set={"x": 1}),
                                self.rule("status", "status", "/sse", status=503)],
                         breakpoints=[{"name": "sse-response", "match": "/sse", "response": True}])
        cmd = ["curl", "-sS", "-N", "--noproxy", "", "-x", "http://127.0.0.1:%d" % self.inst.proxy_port,
               "--max-time", "10", self.up.url("/sse?ms=800")]
        start = time.monotonic()
        proc = subprocess.Popen(cmd, env=self.suite.env(self.inst.home), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            ready, _, _ = select.select([proc.stdout], [], [], 1.5)
            self.assertTrue(ready, "first event was buffered until upstream completion")
            first = os.read(proc.stdout.fileno(), 1024)
            self.assertIn(b"data: tick0\n\n", first)
            self.assertLess(time.monotonic() - start, 1.5)
            rest, err = proc.communicate(timeout=6)
            self.assertEqual(proc.returncode, 0, err.decode())
            self.assertIn(b"data: tick2\n\n", first + rest)
            self.assertGreater(time.monotonic() - start, 2.0)
            self.assertEqual(self.fetch("/sse?ms=10").status, 200)   # response rules and breakpoints cannot edit it
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)

    def test_non_event_stream_response_stays_buffered(self):
        # R4B-01: the streaming exception must stay limited to text/event-stream.
        cmd = ["curl", "-sS", "-N", "--noproxy", "", "-x", "http://127.0.0.1:%d" % self.inst.proxy_port,
               "--max-time", "10", self.up.url("/sse?ms=800&type=text/plain")]
        proc = subprocess.Popen(cmd, env=self.suite.env(self.inst.home), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            ready, _, _ = select.select([proc.stdout], [], [], 1.2)
            self.assertFalse(ready, "a non-event-stream response was streamed")
            body, err = proc.communicate(timeout=6)
            self.assertEqual(proc.returncode, 0, err.decode())
            self.assertIn(b"data: tick2\n\n", body)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)

    def test_local_mock_cors_defaults_preserve_explicit_origin(self):
        # R4B-02: both local actions echo the request Origin unless the rule supplied its own policy.
        path = self.inst.path("cors.json")
        open(path, "w").write('{"ok":true}')
        self.reset_state(rules=[self.rule("map", "map_local", "/cors/map", file=path,
                                          headers={"Vary": "Accept-Language", "Access-Control-Allow-Credentials": "false"}),
                                self.rule("respond", "respond", "/cors/respond", body={"ok": True}),
                                self.rule("explicit", "respond", "/cors/explicit", body="x",
                                          headers={"Access-Control-Allow-Origin": "*"})])
        origin = "http://app.example:53721"
        for endpoint in ("map", "respond"):
            r = self.fetch("/cors/" + endpoint, headers={"Origin": origin})
            self.assertEqual(r.header("access-control-allow-origin"), origin)
            self.assertEqual(r.header("access-control-allow-credentials"), "true")
            self.assertEqual(r.header_all("access-control-allow-credentials"), ["true"])
            self.assertIn("Origin", r.header("vary"))
            if endpoint == "map":
                self.assertIn("Accept-Language", r.header("vary"))
        r = self.fetch("/cors/explicit", headers={"Origin": origin})
        self.assertEqual(r.header_all("access-control-allow-origin"), ["*"])
        self.assertIsNone(r.header("access-control-allow-credentials"))
        self.assertIsNone(self.fetch("/cors/respond").header("access-control-allow-origin"))

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

    def test_status_204_and_304_carry_no_body(self):
        # R7B-01: the old body and Content-Length stayed after the status line said 204/304: a keep-alive client then
        # read those bytes as the next response
        self.reset_state(rules=[self.rule("nc", "status", "/json/small", status=204),
                                self.rule("nm", "respond", "/echo", status=304, body={"x": 1})])
        for path, code in (("/json/small", 204), ("/echo", 304)):
            r = self.fetch(path)
            self.assertEqual((r.status, r.body, r.header("content-length")), (code, b"", None), path)

    def test_interim_status_and_bad_set_header_are_skipped_not_applied(self):
        # R7B-01: a 1xx "final" answer left the client waiting; R7B-04: an invalid header name made the server answer
        # 400 to every matching call, and a line break in the value added a header line
        self.reset_state(rules=[self.rule("s100", "status", "/echo", status=100),
                                self.rule("hname", "set_header", "/echo", header="X Bad Name", value="v"),
                                self.rule("hcrlf", "set_header", "/echo", header="X-Ok", value="a\r\nX-Evil: injected")])
        skipped = {x["name"]: x["error"] for x in self.panel.state()["skipped_rules"]}
        self.assertIn("200 to 599", skipped.get("s100", ""))
        self.assertIn("not a valid header name", skipped.get("hname", ""))
        self.assertIn("one line", skipped.get("hcrlf", ""))
        r = self.fetch("/echo")
        self.assertEqual(r.status, 200)
        self.assertNotIn("x-evil", [k.lower() for k, _v in r.json()["headers"]])

    def test_status_warns_about_rules_skipped_by_the_stricter_validation(self):
        # review 0.9.7 #11: a rule that 0.9.6 accepted is skipped after the upgrade; `rivis status` must say so
        self.reset_state(rules=[self.rule("slow", "delay", "/echo", ms=900000), self.rule("ok", "status", "/never", status=503)])
        wait_for(lambda: [x for x in self.panel.state()["skipped_rules"] if x["name"] == "slow"], 5, 0.1, "slow skipped")
        out = self.suite.rivis("status", home=self.inst.home, env=self.inst.env).stdout
        line = [ln for ln in out.splitlines() if ln.startswith("WARNING:") and "skipped" in ln]
        self.assertTrue(line, out)
        self.assertIn("1 rule(s) skipped", line[0])
        self.assertIn("slow (", line[0])
        self.assertIn("rules list", line[0])

    def test_a_just_saved_block_rule_applies_to_the_very_next_call(self):
        # R7B-02: the file was stat-ed at most once a second, so the first calls after `rules add` reached the server
        self.reset_state(rules=[])
        time.sleep(0.05)
        self.inst.write_cfg({"rules": [self.rule("blk", "block", "/json/small")]}, sync=False)
        self.assertNotEqual(self.fetch("/json/small").status, 200)          # block kills the connection
        self.assertEqual(self.up.hits_for("/json/small"), [])

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

    def test_map_local_missing_file_fails_closed_and_is_flagged(self):
        # R2A-02: a mock whose file is gone must NOT reach the real server; 502 naming rule+file, flagged in state
        self.reset_state(rules=[self.rule("ml", "map_local", "/json/small", file=self.inst.path("missing.json"))])
        r = self.fetch("/json/small")
        self.assertEqual(r.status, 502)
        self.assertIn("'ml'", r.text)
        self.assertIn("missing.json", r.text)
        self.assertEqual(self.up.hits_for("/json/small"), [])          # never forwarded upstream
        self.assertIn("rule:ml FAILED", self.comment("/json/small"))
        self.assertIn("ml", [s["name"] for s in self.panel.state()["skipped_rules"]])

    def test_removed_broken_map_local_clears_warning(self):
        # R3A-01: deleting a broken rule must clear its old runtime failure from doctor/panel state.
        self.reset_state(rules=[self.rule("gone", "map_local", "/json/small", file=self.inst.path("missing.json"))])
        self.assertEqual(self.fetch("/json/small").status, 502)
        self.assertIn("gone", [s["name"] for s in self.panel.state()["skipped_rules"]])
        self.reset_state(rules=[])
        wait_for(lambda: not any(s["name"] == "gone" for s in self.panel.state()["skipped_rules"]),
                 5, 0.2, "deleted rule warning cleared")

    def test_respond_missing_body_file_fails_closed(self):
        self.reset_state(rules=[self.rule("rb", "respond", "/json/small", body_file=self.inst.path("nope.json"))])
        r = self.fetch("/json/small")
        self.assertEqual(r.status, 502)
        self.assertEqual(self.up.hits_for("/json/small"), [])

    def test_status_rewrites_real_response(self):
        self.reset_state(rules=[self.rule("s", "status", "/json/small", status=503)])
        r = self.fetch("/json/small")
        self.assertEqual((r.status, r.json()), (503, SMALL_JSON))     # body kept
        self.assertEqual(self.inst.flow_for("/json/small")["response"]["reason"], "Service Unavailable")   # not "503 OK"
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

    def test_map_remote_to_an_unusable_target_answers_502_not_a_traceback(self):
        # R2A-11: with=not-a-url forwarded unchanged (log: ValueError); ftp:// gave a bare 502 with no hint
        self.reset_state(rules=[self.rule("bad", "map_remote", "/json/small", replace="^.*$", **{"with": "ftp://x.example/y"})])
        r = self.fetch("/json/small")
        self.assertEqual(r.status, 502)
        self.assertIn("'bad'", r.text)
        self.assertEqual(self.up.hits_for("/json/small"), [])
        self.assertIn("rule:bad FAILED", self.comment("/json/small"))

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

    def test_semantically_bad_rule_is_reported_as_skipped_not_structural_corruption(self):
        self.inst.write_cfg({"rules": [{"action": "respond", "match": "/echo", "body": "unnamed"},
                                        {"name": "missing-with", "action": "map_remote", "match": "/x"}]})
        state = wait_for(lambda: self.panel.state(), 5, 0.2, "panel state")
        self.assertIsNone(state["rules_error"])
        self.assertTrue(any(s.get("name") == "missing-with" for s in state["skipped_rules"]))

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
