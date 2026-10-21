"""F2 (cloud review M1): with the Tools drawer open the panel downloaded the whole call list every 1.2 s (megabytes at a few
thousand calls). GET /proxy/api/flows_since?epoch=E&cursor=N answers only what is new or changed since the last answer, plus
the ids that left the list; no cursor, another epoch or a cursor the proxy cannot serve gives the whole list ("full").
The list a client builds from deltas must always equal /flows."""
import json
import os
import sys
import unittest
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import LiveCase, wait_for  # noqa: E402


OP = "flows_since"      # the panel op name (the coverage guard in test_panel looks for it quoted)


class Mirror:
    """What panel.js keeps: a map id -> flow JSON, updated from flows_since answers."""

    def __init__(self, panel):
        self.panel, self.epoch, self.cursor, self.flows = panel, None, 0, {}
        self.last_raw = b""
        self.answers = []

    def poll(self, **extra):
        q = {} if self.epoch is None else {"epoch": self.epoch, "cursor": self.cursor}
        q.update(extra)
        code, raw = self.panel.get("/proxy/api/" + OP + ("?" + urllib.parse.urlencode(q) if q else ""))
        assert code == 200, (code, raw[:200])
        self.last_raw = raw
        doc = json.loads(raw)
        self.answers.append(doc)
        if doc["full"]:
            self.flows = {}
        for f in doc["flows"]:
            self.flows[f["id"]] = f
        for i in doc["removed"]:
            self.flows.pop(i, None)
        self.epoch, self.cursor = doc["epoch"], doc["cursor"]
        return doc


class FlowFeed(LiveCase):
    def setUp(self):
        super().setUp()
        req = urllib.request.Request(self.panel.base + "/clear", data=b"", method="POST", headers={"X-XSRFToken": self.panel.xsrf})
        self.assertEqual(self.panel._do(req)[0], 200)
        wait_for(lambda: not self.panel.flows(), 10, 0.1, "list cleared")
        self.m = Mirror(self.panel)

    def calls(self, n, tag):
        for i in range(n):
            self.fetch("/json/small?%s=%d" % (tag, i))
        wait_for(lambda: len(self.panel.flows()) >= n, 10, 0.2, "%d calls" % n)

    def same_as_full(self):
        full = {f["id"]: f for f in self.panel.flows()}
        self.assertEqual(sorted(self.m.flows), sorted(full))
        for i, f in full.items():
            self.assertEqual(self.m.flows[i], f, "flow %s differs from /flows" % i)

    def test_first_answer_is_the_whole_list_then_polls_carry_only_the_delta(self):
        self.calls(12, "f2a")
        first = self.m.poll()
        self.assertTrue(first["full"])
        self.assertEqual(len(first["flows"]), 12)
        big = len(self.m.last_raw)
        again = self.m.poll()                                        # nothing happened
        self.assertEqual((again["full"], again["flows"], again["removed"]), (False, [], []))
        self.assertLess(len(self.m.last_raw), 200, "an idle poll must not carry the list")
        self.assertGreater(big, 10 * len(self.m.last_raw))
        self.fetch("/json/small?f2a=new")
        wait_for(lambda: len(self.panel.flows()) == 13, 10, 0.2, "new call")
        one = self.m.poll()
        self.assertEqual([f["request"]["path"] for f in one["flows"]], ["/json/small?f2a=new"])
        self.assertLess(len(self.m.last_raw), big / 4)
        self.same_as_full()

    def test_a_modified_call_comes_again_and_only_that_one(self):
        self.calls(5, "f2b")
        self.m.poll()
        target = self.panel.flows()[2]
        req = urllib.request.Request(self.panel.base + "/flows/" + target["id"], data=json.dumps({"comment": "edited-by-test"}).encode(),
                                     method="PUT", headers={"Content-Type": "application/json", "X-XSRFToken": self.panel.xsrf})
        self.assertEqual(self.panel._do(req)[0], 200)
        doc = self.m.poll()
        self.assertEqual([f["id"] for f in doc["flows"]], [target["id"]])
        self.assertEqual(doc["flows"][0]["comment"], "edited-by-test")
        self.same_as_full()

    def test_a_removed_call_is_reported_by_id(self):
        self.calls(5, "f2c")
        self.m.poll()
        gone = self.panel.flows()[1]["id"]
        req = urllib.request.Request(self.panel.base + "/flows/" + gone, method="DELETE", headers={"X-XSRFToken": self.panel.xsrf})
        self.assertEqual(self.panel._do(req)[0], 200)
        doc = self.m.poll()
        self.assertEqual((doc["full"], doc["flows"], doc["removed"]), (False, [], [gone]))
        self.assertEqual(len(self.m.flows), 4)
        self.same_as_full()

    def test_clearing_the_list_makes_the_next_answer_a_full_one(self):
        self.calls(4, "f2d")
        self.m.poll()
        old_epoch = self.m.epoch
        req = urllib.request.Request(self.panel.base + "/clear", data=b"", method="POST", headers={"X-XSRFToken": self.panel.xsrf})
        self.assertEqual(self.panel._do(req)[0], 200)
        doc = self.m.poll()
        self.assertTrue(doc["full"])
        self.assertNotEqual(doc["epoch"], old_epoch)
        self.assertEqual(self.m.flows, {})
        self.calls(2, "f2d2")
        self.m.poll()
        self.same_as_full()

    def test_a_call_that_finishes_comes_again_with_its_response(self):
        self.reset_state(breakpoints=[{"name": "b", "match": "/echo", "request": True, "response": False, "enabled": True}])
        from harness import Background
        call = Background(self.fetch, "/echo?f2e=1")
        wait_for(lambda: self.panel.state()["paused"], 10, 0.1, "paused")
        self.m.poll()
        waiting = [f for f in self.m.flows.values() if f.get("intercepted")]
        self.assertEqual(len(waiting), 1)
        self.panel.ok("paused_skip", {"id": self.panel.state()["paused"][0]["id"]})
        self.assertEqual(call.result().status, 200)
        wait_for(lambda: self.m.poll()["flows"] or None, 10, 0.2, "the finished call arrives as a change")
        wait_for(lambda: (self.m.poll(), self.m.flows[waiting[0]["id"]].get("response"))[1], 10, 0.2, "with its response")
        self.same_as_full()

    def test_unknown_epoch_or_a_cursor_from_the_future_gives_the_full_list(self):
        self.calls(3, "f2f")
        self.m.poll()
        for bad in ({"epoch": "nope", "cursor": 1}, {"epoch": self.m.epoch, "cursor": 10 ** 9}):
            doc = self.m.poll(**bad)
            self.assertTrue(doc["full"], bad)
            self.assertEqual(len(doc["flows"]), 3)

    def test_the_answer_needs_the_panel_login(self):
        from harness import raw_http
        self.assertEqual(raw_http(self.inst.web_port, "GET", "/proxy/api/flows_since")[0], 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
