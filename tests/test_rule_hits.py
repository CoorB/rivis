"""Rule hit counts and "what would each rule do to this call": an ON rule that never fires (wrong match, reversed
map_remote keys, wrong method, shadowed by an earlier mock) must be visible in the panel and `rules list`, not silent."""
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import LiveCase, wait_for
from test_cli import CliBase


def hits(state, name):
    return ((state.get("rule_hits") or {}).get("rules") or {}).get(name)


class RuleHits(LiveCase):
    def test_matching_calls_are_counted_with_last_time(self):
        self.reset_state(rules=[self.rule("force-503", "status", "/echo", status=503)])
        for _ in range(2):
            self.assertEqual(self.fetch("/echo").status, 503)
        h = wait_for(lambda: (lambda x: x if x and x["count"] == 2 else None)(hits(self.panel.state(), "force-503")), 5, 0.2, "2 hits")
        self.assertEqual(h["noop"], 0)
        self.assertLess(abs(time.time() - h["last"]), 30)

    def test_map_remote_that_changes_nothing_is_reported_as_inert(self):
        # R7A-02 shape: replace does not occur in the URL, so the rule matched and silently did nothing
        self.reset_state(rules=[self.rule("reversed", "map_remote", "/remote", replace="/does-not-occur",
                                          **{"with": self.up2.url("/echo")})])
        self.fetch("/remote")
        h = wait_for(lambda: (lambda x: x if x and x["noop"] else None)(hits(self.panel.state(), "reversed")), 5, 0.2, "noop")
        self.assertEqual(h["count"], 0)
        self.assertIn("changed nothing", h["noop_reason"])

    def test_rule_that_never_matches_is_flagged_in_rules_list(self):
        self.reset_state(rules=[self.rule("typo", "status", "/ehco", status=500)])
        for _ in range(12):
            self.fetch("/echo")
        h = hits(self.panel.state(), "typo")
        self.assertEqual(h["count"], 0)
        self.assertGreaterEqual(h["calls_since"], 10)
        def listed():
            r = self.suite.rivis("rules", "list", home=self.inst.home, env=self.suite.cli_env(self.inst.home))
            return r.stdout if "none of the" in r.stdout else None
        out = wait_for(listed, 8, 0.4, "rules list shows the never-matched warning")
        self.assertIn("rules test URL", out)

    def test_rules_list_shows_new_hits_within_about_a_second(self):
        # R8D-07: `rules list` right after 3 calls said "no matching call yet"; it caught up only ~5 s later
        self.reset_state(rules=[self.rule("quick", "status", "/echo", status=503)])
        time.sleep(1.2)                                   # let the reload's own write pass
        for _ in range(3):
            self.fetch("/echo")
        t = time.monotonic()
        def listed():
            r = self.suite.rivis("rules", "list", home=self.inst.home, env=self.suite.cli_env(self.inst.home))
            return r.stdout if "matched 3 calls · last" in r.stdout else None
        wait_for(listed, 6, 0.2, "rules list shows the 3 hits")
        self.assertLess(time.monotonic() - t, 2.0)

    def test_rules_list_counts_rapid_matching_calls_before_next_poll(self):
        # R8-02: a status rule can fire twice before the once-per-second hit-file poll.
        # The CLI must reflect the calls as soon as their responses finish.
        for index in range(5):
            name = "rapid-%d" % index
            self.inst.write_cfg({"rules": [self.rule(name, "status", "/echo", status=429)]})
            wait_for(lambda: name in (self.panel.state().get("rule_hits") or {}).get("rules", {}),
                     3, 0.05, "new rule loaded")
            for _ in range(2):
                self.assertEqual(self.fetch("/echo").status, 429)
            listed = self.suite.rivis("rules", "list", home=self.inst.home,
                                     env=self.suite.cli_env(self.inst.home)).stdout
            self.assertIn("matched 2 calls", listed, listed)

    def test_editing_a_rule_restarts_its_count_but_toggling_off_and_on_keeps_identity(self):
        self.reset_state(rules=[self.rule("r", "status", "/echo", status=503)])
        self.fetch("/echo")
        wait_for(lambda: (hits(self.panel.state(), "r") or {}).get("count") == 1, 5, 0.2, "1 hit")
        self.inst.write_cfg({"rules": [self.rule("r", "status", "/echo", status=504)]})
        self.assertEqual(hits(self.panel.state(), "r")["count"], 0)

    def test_switching_a_rule_off_and_on_keeps_its_hit_count(self):
        # R9-01: the reference says counts restart on edit, "not when it is only switched off and on"
        rule = self.rule("onoff", "status", "/echo", status=418)
        self.reset_state(rules=[rule])
        for _ in range(3):
            self.fetch("/echo")
        wait_for(lambda: (hits(self.panel.state(), "onoff") or {}).get("count") == 3, 5, 0.2, "3 hits")
        self.inst.write_cfg({"rules": [dict(rule, enabled=False)]})
        wait_for(lambda: hits(self.panel.state(), "onoff") is None, 5, 0.2, "rule off")
        self.inst.write_cfg({"rules": [dict(rule, enabled=True)]})
        wait_for(lambda: hits(self.panel.state(), "onoff") is not None, 5, 0.2, "rule back on")
        self.assertEqual(self.fetch("/echo").status, 418)
        h = wait_for(lambda: (lambda x: x if x and x["count"] >= 4 else None)(hits(self.panel.state(), "onoff")), 5, 0.2,
                     "count kept across off/on (expected 4)")
        self.assertEqual(h["count"], 4)

    def test_rule_test_explains_every_rule_for_the_selected_call(self):
        self.reset_state(rules=[self.rule("mock-a", "respond", "/echo", body="a"),
                                self.rule("mock-b", "respond", "/echo", body="b"),
                                self.rule("post-only", "status", "/echo", status=500, method="POST"),
                                self.rule("other", "delay", "/elsewhere", ms=5),
                                self.rule("reversed", "map_remote", "/echo", replace="/nope", **{"with": "http://x.test/"})])
        self.fetch("/echo")
        flow = self.inst.flow_for("/echo")
        doc = self.panel.ok("rule_test", {"flow_id": flow["id"]})
        rows = {r["name"]: r for r in doc["rules"]}
        self.assertTrue(rows["mock-a"]["fires"])
        self.assertIn("answered locally", rows["mock-a"]["effect"])
        self.assertFalse(rows["mock-b"]["fires"])
        self.assertIn("already answers", rows["mock-b"]["reason"])
        self.assertIn("only for POST", rows["post-only"]["reason"])
        self.assertIn("does not match", rows["other"]["reason"])
        self.assertTrue(rows["reversed"].get("inert"))
        self.assertEqual(doc["method"], "GET")

    def test_rule_test_explains_a_map_remote_against_the_url_the_app_asked_for(self):
        # the call in the list shows where Map Remote sent it; the test must still explain the rule that sent it there
        self.reset_state(rules=[self.rule("to-echo", "map_remote", "/remote", replace="/remote", **{"with": "/echo"})])
        self.fetch("/remote?mr=1")
        flow = wait_for(lambda: self.inst.flow_for("/echo?mr=1"), 5, 0.2, "rewritten call listed")
        doc = self.panel.ok("rule_test", {"flow_id": flow["id"]})
        rows = {r["name"]: r for r in doc["rules"]}
        self.assertTrue(rows["to-echo"]["fires"], rows["to-echo"])
        self.assertIn("/remote?mr=1", doc["url"])
        self.assertIn("/echo?mr=1", doc.get("sent_to", ""))

    def test_rule_test_on_an_unknown_call_is_a_clear_400(self):
        code, doc, raw = self.panel.post("rule_test", {"flow_id": "no-such-flow"})
        self.assertEqual(code, 400, raw)
        self.assertIn("no longer in the list", raw.decode())


# Review 0.9.7 #3: the hit file is rewritten for every call that fires a rule. It must not fsync, and from the proxy's
# async hooks the write must run off the event loop. Checked in a child process with a minimal mitmproxy stand-in
# (the frozen mitmproxy app has no importable Python), driving the real ProxyRules hit-file code.
_HIT_WRITE_PROBE = r"""
import asyncio, json, os, sys, tempfile, threading, types
sys.path.insert(0, sys.argv[1])
m = types.ModuleType("mitmproxy"); net = types.ModuleType("mitmproxy.net"); nh = types.ModuleType("mitmproxy.net.http")
nh.status_codes = types.SimpleNamespace(RESPONSES={})
m.ctx = types.SimpleNamespace(log=types.SimpleNamespace(debug=print, info=print, warn=print, warning=print, error=print),
                              options=types.SimpleNamespace())
m.flowfilter = types.SimpleNamespace(); m.http = types.SimpleNamespace(HTTPFlow=object)
sys.modules.update({"mitmproxy": m, "mitmproxy.net": net, "mitmproxy.net.http": nh})
import proxy_rules
fsyncs, writers = [], []
real_fsync, real_replace = os.fsync, os.replace
os.fsync = lambda fd: (fsyncs.append(fd), real_fsync(fd))[1]
os.replace = lambda a, b: (writers.append(threading.get_ident()), real_replace(a, b))[1]
d = tempfile.mkdtemp()
r = proxy_rules.ProxyRules()
r.path = os.path.join(d, "rules.json")
def hit():
    r.hits["x"] = {"fp": "f", "count": r.hits.get("x", {}).get("count", 0) + 1, "noop": 0, "noop_reason": None,
                   "last": 0, "since": 0, "seen_at_since": 0}
    r._hits_dirty = r._hits_unflushed = True
out = {}
hit(); r._write_hits(force=True)
out["sync_fsyncs"] = len(fsyncs)
async def main():
    loop_thread = threading.get_ident()
    if not hasattr(r, "_flush_hits"):
        out["async"] = "missing"
        return
    del fsyncs[:], writers[:]
    hit()
    await r._flush_hits(force=True)
    out["async_fsyncs"] = len(fsyncs)
    out["async_on_loop"] = loop_thread in writers
    out["async_written"] = len(writers)
asyncio.run(main())
with open(r.hits_path) as fh:
    out["count"] = json.load(fh)["rules"]["x"]["count"]
print(json.dumps(out))
"""


class HitFileWrite(unittest.TestCase):
    def test_hit_file_write_does_not_fsync_or_block_the_event_loop(self):
        import subprocess
        addons = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "addons")
        r = subprocess.run([sys.executable, "-I", "-c", _HIT_WRITE_PROBE, addons], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertEqual(out.get("sync_fsyncs"), 0, out)
        self.assertNotEqual(out.get("async"), "missing", out)
        self.assertEqual(out.get("async_fsyncs"), 0, out)
        self.assertEqual(out.get("async_written"), 1, out)
        self.assertFalse(out.get("async_on_loop"), "the hit file was written on the event loop thread: %s" % out)
        self.assertEqual(out.get("count"), 2, out)


class RulesTestCli(CliBase):
    def test_rules_test_explains_without_sending_traffic(self):
        self.ok("rules", "add", "slow", "match=/api/", "action=delay", "ms=200")
        self.ok("rules", "add", "post-500", "match=/api/pay", "action=status", "status=500", "method=POST")
        out = self.ok("rules", "test", "https://api.example.test/api/pay", "post").stdout
        self.assertIn("POST https://api.example.test/api/pay", out)
        self.assertRegex(out, r"FIRES\s+slow\s+held 200 ms")
        self.assertRegex(out, r"FIRES\s+post-500\s+the server's status becomes 500")
        out = self.ok("rules", "test", "https://api.example.test/home").stdout
        self.assertIn("does not match this URL", out)
        self.assertIn("no rule changes this call", out)

    def test_rules_test_needs_a_full_url(self):
        r = self.cli("rules", "test", "api.example.test/x")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("full URL", r.stderr + r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
