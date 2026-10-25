"""Isolated 6k-flow latency probe. Set RIVIS_PERF_LONG=1 for a 25-minute steady run."""
import http.client
import concurrent.futures
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import ARTIFACTS, Instance, Suite


def percentile(values, fraction):
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction))], 2)


class GcPauses(unittest.TestCase):
    def test_full_list_poll_does_not_stall_proxy_calls(self):
        suite = Suite.get()
        upstream = suite.upstream()
        trace = os.path.join(suite.root, "gc-pauses.jsonl")
        inst = Instance(suite, "gc-pauses", extra_env={"RIVIS_MAX_FLOWS": "7000",
                                                        "RIVIS_PERF_TRACE": trace,
                                                        "RIVIS_PERF_FORCE_GEN2_AT": "6001"}).start()
        target = "http://127.0.0.1:%d/json/small" % upstream.http_port
        conn = http.client.HTTPConnection("127.0.0.1", inst.proxy_port, timeout=30)
        samples = []
        panel_samples = []
        long_mode = os.environ.get("RIVIS_PERF_LONG") == "1"
        try:
            def call(i):
                start = time.perf_counter_ns()
                conn.request("GET", target + "?gcprobe=%d" % i)
                response = conn.getresponse()
                response.read()
                end = time.perf_counter_ns()
                self.assertEqual(response.status, 200)
                return {"start_ns": start, "end_ns": end, "ms": (end - start) / 1e6}

            for i in range(6000):
                call(i)
            retained = len(inst.flows())
            self.assertGreaterEqual(retained, 6000)
            deadline = time.monotonic() + (1500 if long_mode else 20)
            i = 6000
            def poll_panel():
                while time.monotonic() < deadline:
                    start = time.perf_counter_ns()
                    inst.panel.get_json("/proxy/api/flows_since?epoch=&cursor=")
                    end = time.perf_counter_ns()
                    panel_samples.append({"start_ns": start, "end_ns": end, "ms": (end - start) / 1e6})
                    time.sleep(2 if long_mode else .5)

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(poll_panel)
                while time.monotonic() < deadline:
                    samples.append(call(i))
                    i += 1
                    if long_mode:
                        time.sleep(max(0, 0.25 - samples[-1]["ms"] / 1000))
                future.result()
            conn.close()
            with open(trace) as fh:
                events = [json.loads(line) for line in fh if line.strip()]
            gc_events = [e for e in events if e["kind"] == "gc"]
            gen2 = [e for e in gc_events if e["generation"] == 2]
            self.assertTrue(gen2, "the 6k-flow collection probe did not run")
            slow = [s for s in samples if s["ms"] > 150]
            overlap = sum(any(e["start_ns"] < s["end_ns"] and e["end_ns"] > s["start_ns"]
                              for e in gen2) for s in slow)
            gc_ms = [(e["end_ns"] - e["start_ns"]) / 1e6 for e in gc_events]
            gen2_ms = [(e["end_ns"] - e["start_ns"]) / 1e6 for e in gen2]
            result = {"retained": retained, "measured_calls": len(samples),
                      "panel_ms": {"p50": percentile([s["ms"] for s in panel_samples], .5),
                                   "p99": percentile([s["ms"] for s in panel_samples], .99),
                                   "max": percentile([s["ms"] for s in panel_samples], 1)},
                      "call_ms": {"p50": percentile([s["ms"] for s in samples], .5),
                                  "p99": percentile([s["ms"] for s in samples], .99),
                                  "max": percentile([s["ms"] for s in samples], 1)},
                      "gc_ms": {"p50": percentile(gc_ms, .5), "p99": percentile(gc_ms, .99),
                                "max": percentile(gc_ms, 1)},
                      "gen2_ms": {"count": len(gen2), "p50": percentile(gen2_ms, .5),
                                  "p99": percentile(gen2_ms, .99), "max": percentile(gen2_ms, 1)},
                      "calls_over_150_ms": len(slow), "slow_calls_overlapping_gen2": overlap}
            os.makedirs(ARTIFACTS, exist_ok=True)
            with open(os.path.join(ARTIFACTS, "gc-pauses-calls.jsonl"), "w") as fh:
                for item in samples:
                    fh.write(json.dumps({"kind": "call", **item}) + "\n")
                for item in panel_samples:
                    fh.write(json.dumps({"kind": "panel", **item}) + "\n")
                for item in events:
                    fh.write(json.dumps(item) + "\n")
            with open(os.path.join(ARTIFACTS, "gc-pauses.json"), "w") as fh:
                json.dump(result, fh, indent=2)
            print("\nGC PAUSES " + json.dumps(result, sort_keys=True))
            self.assertLessEqual(result["gen2_ms"]["max"], 150, result)
            self.assertLessEqual(result["call_ms"]["max"], 150, result)
        finally:
            conn.close()
            inst.stop()
