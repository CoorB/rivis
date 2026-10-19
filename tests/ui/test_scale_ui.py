"""The panel in a real browser with 5,000 calls in the list: what a tester does all day must stay quick — open the
page, open Tools, select a call, type a filter, open the Rules tab. Budgets are generous (seconds, not ms): this
guards against the list or a tab freezing, as large bodies once did (R6B-08/09)."""
import http.client
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import harness                           # noqa: E402
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase, shot   # noqa: E402

N = 5000
BUDGET_S = 3.0


@unittest.skipIf(PW_REASON, PW_REASON or "")
class ScaleUi(UiBase):
    INSTANCE_KW = {"extra_env": {"RIVIS_MAX_FLOWS": "20000"}}

    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def timed(self, label, action, done, results):
        t = time.perf_counter()
        action()
        wait_for(done, 30, 0.05, label)
        results[label] = round(time.perf_counter() - t, 2)

    def test_everyday_actions_stay_quick_with_5000_calls(self):
        self.reset_state(rules=[self.rule("s%d" % i, "status", "/never-%d$" % i, status=503) for i in range(10)])
        host = "127.0.0.1:%d" % self.up.http_port
        conn = http.client.HTTPConnection("127.0.0.1", self.inst.proxy_port)
        for i in range(N):
            conn.request("GET", "http://%s/json/small?n=%d" % (host, i), headers={"Host": host})
            conn.getresponse().read()
        conn.request("GET", "http://%s/echo?needle=1" % host, headers={"Host": host})
        conn.getresponse().read()
        wait_for(lambda: len(self.inst.flows()) > N, 60, 0.5, "%d flows" % N)
        r = {}
        self.page.add_init_script("try { localStorage.setItem('rivis-welcome', 'done') } catch (e) {}")
        self.timed("open page", lambda: self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password)),
                   lambda: self.page.locator("#proxy-panel-host").locator("#fab").count() > 0
                   and self.page.locator(".flow-table tbody tr").count() > 0, r)
        self.timed("open Tools", lambda: self.P("#fab").click(), lambda: self.P("#drawer.open").count() > 0, r)
        row = self.page.locator(".flow-table tbody tr").nth(3)
        self.timed("select a call", lambda: row.click(), lambda: "Map Local this call" in self.panel_text(), r)
        box = self.P("#sq")
        rows_with = lambda text: self.page.locator(".flow-table tbody tr", has_text=text).count()
        try:
            self.timed("filter to one call", lambda: (box.click(), box.fill("needle")),
                       lambda: rows_with("needle") == 1 and rows_with("json/small") == 0, r)
        except AssertionError:
            shot(self.page, "scale-filter-fail")
            print("DEBUG rows=%d needle=%d small=%d filter=%r" % (self.page.locator(".flow-table tbody tr").count(), rows_with("needle"),
                  rows_with("json/small"), box.input_value()))
            raise
        self.timed("Rules tab", lambda: self.P("button[data-t=rules]").click(), lambda: "s9" in self.panel_text(), r)
        shot(self.page, "scale-5000")
        with open(os.path.join(harness.ARTIFACTS, "scale-ui.json"), "w") as fh:
            json.dump(r, fh)
        for label, secs in r.items():
            self.assertLess(secs, BUDGET_S if label != "open page" else 2 * BUDGET_S, "%s took %.2fs with %d calls: %s" % (label, secs, N, r))
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
