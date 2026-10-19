"""Performance budgets from STANDARDS §3, measured (numbers are written to tests/.artifacts/perf.json and printed):
startup < 3 s, proxy adds < 5 ms median with no rules, panel stays responsive with 5,000 flows, bounded memory growth.
Skipped by `run.sh --fast`. This is a short soak (5,000 calls), not the full-workday soak."""
import http.client
import json
import os
import statistics
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import harness
from harness import Instance, Suite, wait_for

RESULTS = {}


def rss_mb(pids):
    total = 0
    for pid in pids:
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
        total += int(out or 0)
    return total / 1024.0


def group(inst):
    out = subprocess.run(["pgrep", "-g", str(inst.proc.pid)], capture_output=True, text=True).stdout.split()
    return [int(x) for x in out]


def through_proxy(conn, url, host, path):
    conn.request("GET", url, headers={"Host": host})
    r = conn.getresponse()
    r.read()
    return r.status


def median_ms(fn, n):
    samples = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t) * 1000)
    return statistics.median(samples), sorted(samples)[int(n * 0.95)]


class Budgets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()
        cls.up = cls.suite.upstream()

    @classmethod
    def tearDownClass(cls):
        os.makedirs(harness.ARTIFACTS, exist_ok=True)
        with open(os.path.join(harness.ARTIFACTS, "perf.json"), "w") as fh:
            json.dump(RESULTS, fh, indent=1)
        print("\nPERF %s" % json.dumps(RESULTS))

    def test_startup_under_3_seconds(self):
        times = []
        for i in range(3):
            inst = Instance(self.suite, "startup%d" % i)
            t = time.perf_counter()
            inst.start()
            times.append(time.perf_counter() - t)
            inst.stop()
        RESULTS["startup_s"] = [round(x, 2) for x in times]
        self.assertLess(min(times), 3.0, "startup times: %s" % times)
        self.assertLess(statistics.median(times), 3.0, "startup times: %s" % times)

    def test_proxy_adds_under_5ms_median_with_no_rules_and_panel_scales_to_5000_flows(self):
        # the retention cap (default 5,000, trims to 90%) would keep this list below 5,000 — measure the panel itself
        inst = Instance(self.suite, "perf", extra_env={"RIVIS_MAX_FLOWS": "20000"}).start()
        try:
            host = "127.0.0.1:%d" % self.up.http_port
            url = "http://%s/json/small" % host
            direct = http.client.HTTPConnection("127.0.0.1", self.up.http_port)
            proxied = http.client.HTTPConnection("127.0.0.1", inst.proxy_port)
            for _ in range(20):                                           # warm up both paths
                through_proxy(direct, "/json/small", host, "/json/small")
                through_proxy(proxied, url, host, "/json/small")
            d_med, d_p95 = median_ms(lambda: through_proxy(direct, "/json/small", host, "/json/small"), 300)
            p_med, p_p95 = median_ms(lambda: through_proxy(proxied, url, host, "/json/small"), 300)
            RESULTS["latency_ms"] = {"direct_median": round(d_med, 2), "proxy_median": round(p_med, 2), "added_median": round(p_med - d_med, 2),
                                     "direct_p95": round(d_p95, 2), "proxy_p95": round(p_p95, 2)}
            self.assertLess(p_med - d_med, 5.0, RESULTS["latency_ms"])

            pids = group(inst)
            base_rss = rss_mb(pids)
            t = time.perf_counter()
            for i in range(5000):
                through_proxy(proxied, url + "?i=%d" % i, host, "/json/small")
            gen_s = time.perf_counter() - t
            wait_for(lambda: len(inst.flows()) >= 5000, 60, 0.5, "5,000 flows listed")
            RESULTS["flows_generated"] = {"count": len(inst.flows()), "seconds": round(gen_s, 1)}
            state_ms = median_ms(lambda: inst.panel.state(), 7)[0]
            flows_t = time.perf_counter()
            inst.flows()
            flows_ms = (time.perf_counter() - flows_t) * 1000
            summ_t = time.perf_counter()
            inst.panel.ok("viewer_summaries", {"limit": 12})
            summ_ms = (time.perf_counter() - summ_t) * 1000
            post_t = time.perf_counter()
            inst.panel.ok("view", {"project_only": False, "show_dns": False})
            post_ms = (time.perf_counter() - post_t) * 1000
            call_t = time.perf_counter()
            through_proxy(proxied, url, host, "/json/small")
            call_ms = (time.perf_counter() - call_t) * 1000
            rss_after = rss_mb(group(inst))
            RESULTS["panel_with_5000_flows_ms"] = {"state_median": round(state_ms, 1), "flows_list": round(flows_ms, 1),
                                                   "viewer_summaries_first_batch": round(summ_ms, 1), "view_op": round(post_ms, 1),
                                                   "proxied_call": round(call_ms, 1)}
            RESULTS["rss_mb"] = {"start": round(base_rss, 1), "after_5000_flows": round(rss_after, 1), "growth": round(rss_after - base_rss, 1)}
            self.assertLess(state_ms, 1000, RESULTS)
            self.assertLess(flows_ms, 5000, RESULTS)
            self.assertLess(summ_ms, 2000, RESULTS)
            self.assertLess(post_ms, 2000, RESULTS)
            self.assertLess(call_ms, 500, RESULTS)
            self.assertLess(rss_after - base_rss, 600, "memory growth for 5,000 small flows: %s" % RESULTS["rss_mb"])
        finally:
            inst.stop()


    def test_twenty_rules_on_add_under_5ms_median(self):
        # Every call runs every ON rule's match and its hit counting: a project with many rules must stay fast.
        inst = Instance(self.suite, "perfrules").start()
        try:
            rules = [{"name": "r%02d" % i, "enabled": True, "match": r"/never-%d(/|$)" % i, "action": "status", "status": 503}
                     for i in range(18)]
            rules += [{"name": "hdr", "enabled": True, "match": "/json/small", "action": "set_header", "side": "response",
                       "header": "X-Perf", "value": "1"},
                      {"name": "patch", "enabled": True, "match": "/json/small", "action": "json_patch", "set": {"perf": True}}]
            inst.write_cfg({"rules": rules})
            host = "127.0.0.1:%d" % self.up.http_port
            url = "http://%s/json/small" % host
            direct = http.client.HTTPConnection("127.0.0.1", self.up.http_port)
            proxied = http.client.HTTPConnection("127.0.0.1", inst.proxy_port)
            for _ in range(20):
                through_proxy(direct, "/json/small", host, "/json/small")
                through_proxy(proxied, url, host, "/json/small")
            d_med, _ = median_ms(lambda: through_proxy(direct, "/json/small", host, "/json/small"), 300)
            p_med, p_p95 = median_ms(lambda: through_proxy(proxied, url, host, "/json/small"), 300)
            RESULTS["latency_20_rules_ms"] = {"direct_median": round(d_med, 2), "proxy_median": round(p_med, 2),
                                              "added_median": round(p_med - d_med, 2), "proxy_p95": round(p_p95, 2)}
            self.assertLess(p_med - d_med, 5.0, RESULTS["latency_20_rules_ms"])
            hits = inst.panel.state()["rule_hits"]["rules"]
            self.assertGreaterEqual(hits["patch"]["count"], 300)
        finally:
            inst.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
