"""Network profiles (latency, loss, throttle_match) and breakpoints (request/response pause, edit, skip, abort,
the ? wildcard, ownership of mitmweb's intercept filter), live through the proxy."""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Background, LiveCase, wait_for


def timed(fn, *a, **kw):
    t = time.time()
    r = fn(*a, **kw)
    return r, time.time() - t


class Profiles(LiveCase):
    def test_baseline_is_fast(self):
        r, dt = timed(self.fetch, "/json/small")
        self.assertEqual(r.status, 200)
        self.assertLess(dt, 0.8)

    def test_latency_spec_adds_the_requested_delay(self):
        self.reset_state(throttle="400ms")
        r, dt = timed(self.fetch, "/json/small")
        self.assertEqual(r.status, 200)
        self.assertGreaterEqual(dt, 0.38)          # 200 ms before the request + 200 ms after the response
        self.assertLess(dt, 2.5)
        self.assertIn("throttle +", self.comment("/json/small"))

    def test_named_profile_3g_adds_300ms_and_bandwidth_cost(self):
        self.reset_state(throttle="3g")
        r, dt = timed(self.fetch, "/json/small")
        self.assertEqual(r.status, 200)
        self.assertGreaterEqual(dt, 0.28)
        self.assertLess(dt, 2.5)

    def test_bandwidth_shapes_big_downloads(self):
        self.reset_state(throttle="10ms/8000kbps")       # 1 MB at 8 Mbit/s = ~1 s
        r, dt = timed(self.fetch, "/big?mb=1", timeout=30)
        self.assertEqual(len(r.body), 1024 * 1024)
        self.assertGreaterEqual(dt, 0.9)

    def test_manual_profile_via_panel(self):
        self.panel.ok("profile", {"id": "manual", "manual": {"latency_ms": 500}})
        self.assertEqual(self.panel.state()["throttle"], "manual")
        wait_for(lambda: timed(self.fetch, "/json/small")[1] >= 0.45, 12, 0.3, "manual latency applied")

    def test_scope_is_trimmed(self):
        self.panel.ok("profile", {"id": "3g-urban", "match": "  /json/small \n"})
        self.assertEqual(self.panel.state()["throttle_match"], "/json/small")

    def test_off_removes_the_delay(self):
        self.reset_state(throttle="600ms")
        self.reset_state(throttle="off")
        _, dt = timed(self.fetch, "/json/small")
        self.assertLess(dt, 0.5)

    def test_loss_100_kills_the_connection(self):
        self.reset_state(loss=100)
        r = self.fetch("/json/small")
        self.assertNotEqual(r.rc, 0, r)
        self.assertNotEqual(r.status, 200)
        self.assertEqual(self.up.hits_for("/json/small"), [])      # never reached the server
        self.assertIn("loss 100%", self.comment("/json/small"))

    def test_loss_0_never_drops(self):
        self.reset_state(loss=0, throttle="off")
        self.assertTrue(all(self.fetch("/json/small").status == 200 for _ in range(10)))

    def test_throttle_match_scopes_the_profile(self):
        self.reset_state(throttle="700ms", throttle_match="/slowme")
        _, dt_other = timed(self.fetch, "/json/small")
        _, dt_match = timed(self.fetch, "/slowme/x")
        self.assertLess(dt_other, 0.5)
        self.assertGreaterEqual(dt_match, 0.65)
        self.assertNotIn("throttle", self.comment("/json/small") or "")

    def test_loss_is_scoped_by_throttle_match(self):
        self.reset_state(loss=100, throttle_match="/lossy")
        self.assertEqual(self.fetch("/json/small").status, 200)
        self.assertNotEqual(self.fetch("/lossy/x").rc, 0)

    def test_invalid_panel_input_is_a_json_error(self):
        for body in ({"id": "nope"}, {"id": "manual", "manual": {"latency_ms": -5}},
                     {"id": "manual", "manual": {"loss_pct": 101}}, {"id": "3g", "match": "("}):
            code, doc, _ = self.panel.post("profile", body)
            self.assertEqual(code, 400, body)
            self.assertIn("error", doc)


def bp(name="b", match="/echo", request=True, response=False, method=None, enabled=True):
    d = {"name": name, "match": match, "request": request, "response": response, "enabled": enabled}
    if method:
        d["method"] = method
    return d


class Breakpoints(LiveCase):
    def tearDown(self):
        for p in self.panel.state()["paused"]:        # a failed test must not leak a held call into the next one
            self.panel.post("paused_abort", {"id": p["id"]})

    def paused(self, n=1, timeout=10):
        return wait_for(lambda: (lambda p: p if len(p) >= n else None)(self.panel.state()["paused"]), timeout, 0.1, "paused call")

    def bg(self, path, **kw):
        return Background(self.fetch, path, **kw)

    def retry(self, path, breakpoint):
        self.fetch(path)
        flow_id = self.inst.flow_for(path)["id"]
        self.reset_state(breakpoints=[breakpoint])
        replay_id = self.panel.ok("retry", {"flow_id": flow_id, "edits": {}})["id"]
        return flow_id, replay_id

    def paused_id(self, flow_id, phase=None):
        return wait_for(lambda: next((p for p in self.panel.state()["paused"]
                                     if p["id"] == flow_id and (phase is None or p["phase"] == phase)), None),
                        10, 0.1, "replayed call paused")

    def test_a_breakpoint_set_in_the_panel_catches_the_very_next_call(self):
        """Live NEO app, 2026-10-15: a breakpoint set and then triggered at once missed the call, because the proxy
        re-read rules at most once a second. No sleep between setting it and the call, for each phase."""
        for phase in ("request", "response"):
            self.reset_state()
            self.fetch("/json/small")                                  # the proxy has just checked the rules file
            self.panel.ok("bp_add", {"host": "127.0.0.1", "path": "/echo", phase: True, "name": "now-" + phase})
            call = self.bg("/echo?now=" + phase)
            got = self.paused()[0]
            self.assertEqual(got["phase"], phase)
            self.panel.ok("paused_skip", {"id": got["id"]})
            self.assertEqual(call.result().status, 200)

    def test_request_pause_continue_with_edits(self):
        self.reset_state(breakpoints=[bp()])
        call = self.bg("/echo?q=1", method="POST", data="orig")
        p = self.paused()[0]
        self.assertEqual((p["phase"], p["method"]), ("request", "POST"))
        self.assertEqual(self.up.hits_for("/echo"), [])               # held: upstream has not seen it
        info = self.panel.ok("paused_get", {"id": p["id"]})
        self.assertEqual(info["req_body"], "orig")
        self.panel.ok("paused_continue", {"id": p["id"], "edits": {
            "method": "PUT", "headers": [["Host", info["req_headers"][0][1]], ["X-Edited", "yes"]], "body": "changed"}})
        r = call.result()
        doc = r.json()
        self.assertEqual((doc["method"], doc["body"]), ("PUT", "changed"))
        self.assertIn(["X-Edited", "yes"], doc["headers"])
        self.assertEqual(self.panel.state()["paused"], [])
        self.assertIn("edited at breakpoint", self.comment("/echo"))

    def test_continue_with_edited_url_host_updates_the_host_header(self):
        # R2A-01: the sheet sends every header back; the stale Host must not undo the URL host edit
        self.reset_state(breakpoints=[bp()])
        call = self.bg("/echo?hostedit=1")
        p = self.paused()[0]
        info = self.panel.ok("paused_get", {"id": p["id"]})
        self.panel.ok("paused_continue", {"id": p["id"], "edits": {
            "url": info["url"].replace("127.0.0.1", "localhost"), "headers": info["req_headers"]}})
        host = [v for k, v in call.result().json()["headers"] if k.lower() == "host"]
        self.assertEqual(host, ["localhost:%d" % self.up.http_port])

    def test_continue_keeps_an_explicitly_edited_host_header(self):
        self.reset_state(breakpoints=[bp()])
        call = self.bg("/echo?hostedit=2")
        p = self.paused()[0]
        info = self.panel.ok("paused_get", {"id": p["id"]})
        hdrs = [[k, v] for k, v in info["req_headers"] if k.lower() != "host"] + [["Host", "vhost.example"]]
        self.panel.ok("paused_continue", {"id": p["id"], "edits": {
            "url": info["url"].replace("127.0.0.1", "localhost"), "headers": hdrs}})
        host = [v for k, v in call.result().json()["headers"] if k.lower() == "host"]
        self.assertEqual(host, ["vhost.example"])

    def test_edit_and_repeat_with_edited_url_host_updates_the_host_header(self):
        self.reset_state()
        self.fetch("/echo?rep=1")
        f = self.inst.flow_for("rep=1")
        info = self.panel.ok("retry_get", {"flow_id": f["id"]})
        self.panel.ok("retry", {"flow_id": f["id"], "edits": {
            "url": info["url"].replace("127.0.0.1", "localhost"), "headers": info["req_headers"]}})
        hit = wait_for(lambda: next((h for h in self.up.hits_for("/echo?rep=1")[1:]), None), 10, 0.2, "replayed hit")
        self.assertEqual([v for k, v in hit["headers"] if k.lower() == "host"], ["localhost:%d" % self.up.http_port])

    def test_request_pause_skip_sends_unchanged(self):
        self.reset_state(breakpoints=[bp()])
        call = self.bg("/echo", method="POST", data="same")
        p = self.paused()[0]
        self.panel.ok("paused_skip", {"id": p["id"]})
        self.assertEqual(call.result().json()["body"], "same")
        self.assertIn("breakpoint: skipped", self.comment("/echo"))

    def test_continue_without_changes_is_not_labelled_edited(self):
        # L1: the paused sheet sends every field back on Continue; untouched it must not say "edited"
        for phase, path in (("request", "/echo"), ("response", "/json/small")):
            self.reset_state(breakpoints=[bp(match=path, request=phase == "request", response=phase == "response")])
            call = self.bg(path + "?same=" + phase, method="POST" if phase == "request" else "GET",
                           data="same" if phase == "request" else None)
            p = self.paused()[0]
            info = self.panel.ok("paused_get", {"id": p["id"]})
            edits = ({"method": info["method"], "url": info["url"], "headers": info["req_headers"], "body": info["req_body"]}
                     if phase == "request" else
                     {"status": info["status"], "headers": info["resp_headers"], "body": info["resp_body"]})
            self.panel.ok("paused_continue", {"id": p["id"], "edits": edits})
            self.assertEqual(call.result().status, 200)
            comment = self.comment(path + "?same=" + phase)
            self.assertIn("continued unchanged", comment, phase)
            self.assertNotIn("edited at breakpoint", comment, phase)

    def test_request_pause_abort_kills_the_call(self):
        self.reset_state(breakpoints=[bp()])
        call = self.bg("/echo")
        p = self.paused()[0]
        self.panel.ok("paused_abort", {"id": p["id"]})
        r = call.result()
        self.assertNotEqual(r.rc, 0, r)
        self.assertEqual(self.up.hits_for("/echo"), [])

    def test_response_pause_edit_status_headers_body(self):
        self.reset_state(breakpoints=[bp(match="/json/small", request=False, response=True)])
        call = self.bg("/json/small")
        p = self.paused()[0]
        self.assertEqual((p["phase"], p["status"]), ("response", 200))
        self.assertEqual(len(self.up.hits_for("/json/small")), 1)      # the real response is what is held
        self.panel.ok("paused_continue", {"id": p["id"], "edits": {
            "status": 418, "headers": [["Content-Type", "text/plain"], ["X-Resp", "1"]], "body": "teapot"}})
        r = call.result()
        self.assertEqual((r.status, r.text, r.header("x-resp")), (418, "teapot", "1"))

    def test_both_phases_pause_twice(self):
        self.reset_state(breakpoints=[bp(match="/json/small", request=True, response=True)])
        call = self.bg("/json/small")
        p = self.paused()[0]
        self.assertEqual(p["phase"], "request")
        self.panel.ok("paused_continue", {"id": p["id"]})
        p2 = wait_for(lambda: [x for x in self.panel.state()["paused"] if x["phase"] == "response"], 10, 0.1, "response pause")[0]
        self.panel.ok("paused_skip", {"id": p2["id"]})
        self.assertEqual(call.result().status, 200)

    def test_replayed_matching_request_pauses_and_can_continue_and_abort(self):
        source_id, replay_id = self.retry("/echo?replay=request", bp())
        p = self.paused_id(replay_id, "request")
        self.assertEqual(self.panel.ok("paused_get", {"id": replay_id})["phase"], "request")
        self.assertEqual(self.up.hits_for("/echo"), [])
        self.panel.ok("paused_continue", {"id": p["id"]})
        wait_for(lambda: len(self.up.hits_for("/echo")) == 1, 10, 0.1, "continued replay hit")

        replay_id = self.panel.ok("retry", {"flow_id": source_id, "edits": {}})["id"]
        p = self.paused_id(replay_id, "request")
        self.panel.ok("paused_abort", {"id": p["id"]})
        wait_for(lambda: next((f.get("error") for f in self.inst.flows() if f["id"] == replay_id), None),
                 10, 0.1, "aborted replay completed")
        self.assertEqual(len(self.up.hits_for("/echo")), 1)

    def test_replayed_matching_response_pauses_at_response(self):
        _, replay_id = self.retry("/json/small?replay=response",
                                  bp(match="/json/small", request=False, response=True))
        p = self.paused_id(replay_id, "response")
        info = self.panel.ok("paused_get", {"id": p["id"]})
        self.assertEqual((info["phase"], info["status"]), ("response", 200))
        self.assertEqual(len(self.up.hits_for("/json/small")), 1)
        self.panel.ok("paused_continue", {"id": p["id"]})

    def test_replayed_nonmatching_call_is_not_paused(self):
        _, replay_id = self.retry("/json/small?replay=nonmatch", bp(match="/echo"))
        wait_for(lambda: next((f.get("response") for f in self.inst.flows() if f["id"] == replay_id), None),
                 10, 0.1, "nonmatching replay response")
        self.assertNotIn(replay_id, {p["id"] for p in self.panel.state()["paused"]})
        self.assertEqual(len(self.up.hits_for("/json/small")), 1)

    def test_breakpoint_on_a_mocked_endpoint_pauses_once_then_the_mock_answers(self):
        """Demo path: Map Local + breakpoint on one endpoint. The breakpoint used to never fire (the mock answered first)."""
        self.reset_state(rules=[self.rule("m", "respond", "/echo", status=201, body={"mocked": True})],
                         breakpoints=[bp(match="/echo", request=True, response=True)])
        call = self.bg("/echo?mocked=1")
        p = self.paused()[0]
        self.assertEqual(p["phase"], "request")
        self.panel.ok("paused_continue", {"id": p["id"]})
        r = wait_for(lambda: [x for x in self.panel.state()["paused"] if x["phase"] == "response"], 10, 0.1, "response pause")[0]
        self.panel.ok("paused_continue", {"id": r["id"]})
        res = call.result()
        self.assertEqual((res.status, res.json()), (201, {"mocked": True}))
        self.assertEqual(self.panel.state()["paused"], [], "exactly one request pause and one response pause")
        self.assertEqual(self.up.hits_for("/echo"), [])

    def test_response_breakpoint_on_a_mocked_endpoint_can_edit_the_mock(self):
        self.reset_state(rules=[self.rule("m", "respond", "/echo", status=201, body={"mocked": True})],
                         breakpoints=[bp(match="/echo", request=False, response=True)])
        call = self.bg("/echo?mocked=3")
        r = self.paused()[0]
        self.assertEqual((r["phase"], r["status"]), ("response", 201))
        self.panel.ok("paused_continue", {"id": r["id"], "edits": {"status": 409, "body": '{"edited": true}'}})
        res = call.result()
        self.assertEqual((res.status, res.json()), (409, {"edited": True}))

    def test_abort_at_a_breakpoint_on_a_mocked_endpoint_gives_an_error_not_the_mock(self):
        self.reset_state(rules=[self.rule("m", "respond", "/echo", status=201, body={"mocked": True})],
                         breakpoints=[bp(match="/echo")])
        call = self.bg("/echo?mocked=2")
        self.panel.ok("paused_abort", {"id": self.paused()[0]["id"]})
        self.assertNotEqual(call.result().status, 201)

    def test_resume_all_releases_every_paused_call_unchanged(self):
        """The paused sheet's 'Resume all' / 'Turn off this breakpoint' way out of a busy breakpoint."""
        self.reset_state(breakpoints=[bp(match="/echo")])
        calls = [self.bg("/echo?all=%d" % i) for i in range(3)]
        self.paused(3)
        self.assertEqual(self.panel.ok("paused_resume_all", {})["resumed"], 3)
        self.assertEqual([c.result().status for c in calls], [200, 200, 200])
        self.assertEqual(self.panel.state()["paused"], [])
        self.assertEqual(self.panel.ok("paused_resume_all", {})["resumed"], 0)

    def test_deleting_or_switching_off_a_breakpoint_lets_go_of_its_calls(self):
        """MQ-22: delete used to leave the call paused until the app timed out; another breakpoint still holds its own."""
        self.reset_state(breakpoints=[bp("a", "/echo"), bp("b", "/json")])
        held, other = self.bg("/echo?del=1"), self.bg("/json/small?del=2")
        self.paused(2)
        self.assertEqual(self.panel.ok("bp_delete", {"name": "a"})["resumed"], 1)
        self.assertEqual(held.result().status, 200)
        self.assertEqual(len(self.panel.state()["paused"]), 1)
        self.assertEqual(self.panel.ok("bp_update", {"name": "b", "enabled": False})["resumed"], 1)
        self.assertEqual(other.result().status, 200)
        self.assertEqual(self.panel.state()["paused"], [])

    def test_method_filter_and_disabled(self):
        self.reset_state(breakpoints=[bp(method="DELETE"), bp("off", "/json", enabled=False)])
        self.assertEqual(self.fetch("/echo").status, 200)             # GET, not paused
        self.assertEqual(self.fetch("/json/small").status, 200)       # disabled
        self.assertEqual(self.panel.state()["paused"], [])

    def test_panel_bp_add_wildcard_question_mark(self):
        self.reset_state()
        host = "127.0.0.1"
        doc = self.panel.ok("bp_add", {"host": host, "path": "/ec?o", "request": True})
        self.assertTrue(doc["name"])
        wait_for(lambda: self.panel.option("intercept"), 8, 0.2, "intercept armed")
        call = self.bg("/echo")
        p = self.paused()[0]
        self.panel.ok("paused_skip", {"id": p["id"]})
        self.assertEqual(call.result().status, 200)
        self.assertEqual(self.fetch("/ecxxo").status, 404)            # "?" is exactly one character: not paused
        self.assertEqual(self.panel.state()["paused"], [])

    def test_panel_bp_update_delete_and_validation(self):
        self.reset_state()
        name = self.panel.ok("bp_add", {"host": "127.0.0.1", "path": "/echo", "request": True})["name"]
        again = self.panel.ok("bp_add", {"host": "127.0.0.1", "path": "/echo", "request": True, "response": True})["name"]
        self.assertEqual(name, again)                                  # same endpoint: updated, not stacked
        st = self.panel.state()["breakpoints"]
        self.assertEqual(len(st), 1)
        self.assertTrue(st[0]["response"])
        self.panel.ok("bp_update", {"name": name, "enabled": False})
        self.assertFalse(self.panel.state()["breakpoints"][0]["enabled"])
        self.assertEqual(self.panel.post("bp_add", {"host": "127.0.0.1", "path": "/x"})[0], 400)     # no phase
        self.assertEqual(self.panel.post("bp_update", {"name": "ghost"})[0], 400)
        self.panel.ok("bp_delete", {"name": name})
        self.assertEqual(self.panel.state()["breakpoints"], [])

    def test_paused_calls_that_vanished_give_json_errors(self):
        for op in ("paused_get", "paused_continue", "paused_skip", "paused_abort"):
            code, doc, _ = self.panel.post(op, {"id": "does-not-exist"})
            self.assertEqual(code, 400, op)
            self.assertIn("error", doc)

    def test_breakpoint_arms_before_traffic_and_clears_when_removed(self):
        self.reset_state(breakpoints=[bp()])
        self.assertIn("/echo", self.panel.option("intercept") or "")
        self.reset_state(breakpoints=[])
        self.assertFalse(self.panel.option("intercept"))


class InterceptOwnership(LiveCase):
    """proxy_rules only replaces the intercept filter while it still owns it."""

    def tearDown(self):
        try:
            self.panel.set_option("intercept", "")
        except AssertionError:
            pass

    def test_user_filter_set_in_the_ui_is_preserved_then_reclaimed(self):
        self.reset_state()
        self.panel.set_option("intercept", "~u /user-filter")
        self.reset_state(breakpoints=[bp()])
        time.sleep(1.5)
        self.assertEqual(self.panel.option("intercept"), "~u /user-filter")       # not clobbered
        self.assertEqual(self.fetch("/echo").status, 200)                           # our breakpoint is NOT armed
        self.panel.set_option("intercept", "")                                      # user clears it
        self.reset_state(breakpoints=[bp(name="b2", match="/echo2")])               # next reload reclaims
        wait_for(lambda: "/echo2" in (self.panel.option("intercept") or ""), 10, 0.3, "intercept reclaimed")

    def test_filter_changed_in_the_ui_while_we_own_it_is_left_alone(self):
        self.reset_state(breakpoints=[bp()])
        self.assertIn("/echo", self.panel.option("intercept") or "")
        self.panel.set_option("intercept", "~u /mine")
        self.reset_state(breakpoints=[bp(name="b3", match="/other")])
        time.sleep(1.2)
        self.assertEqual(self.panel.option("intercept"), "~u /mine")


if __name__ == "__main__":
    unittest.main(verbosity=2)
