"""W5 full soak: at least 50k hermetic calls, bounded flow store, and post-warmup RSS plateau."""
import concurrent.futures
import http.client
import json
import os
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import harness
from harness import Instance, Suite, wait_for

CALLS = 50000
WORKERS = 10
LIMIT = 5000


def rss_mb(inst):
    out = subprocess.run(["pgrep", "-g", str(inst.proc.pid)], capture_output=True, text=True).stdout.split()
    pids = sorted({inst.proc.pid} | {int(x) for x in out})
    total = 0
    for pid in pids:
        raw = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
        total += int(raw or 0)
    return total / 1024.0


class Soak(unittest.TestCase):
    def test_50000_flows_plateau_after_the_cap_is_warm(self):
        suite = Suite.get()
        up = suite.upstream()
        inst = Instance(suite, "soak-50k", extra_env={"RIVIS_MAX_FLOWS": str(LIMIT)}).start()
        host = "127.0.0.1:%d" % up.http_port
        url = "http://%s/json/small" % host
        started = time.perf_counter()

        def batch(bounds):
            worker, begin, end = bounds
            conn = http.client.HTTPConnection("127.0.0.1", inst.proxy_port, timeout=30)
            try:
                for i in range(begin + worker, end, WORKERS):
                    conn.request("GET", url + "?soak=%d" % i, headers={"Host": host})
                    response = conn.getresponse()
                    response.read()
                    if response.status != 200:
                        raise AssertionError("call %d returned %s" % (i, response.status))
            finally:
                conn.close()

        try:
            snapshots = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
                for begin, end in ((0, 10000), (10000, 30000), (30000, CALLS)):
                    list(pool.map(batch, [(worker, begin, end) for worker in range(WORKERS)]))
                    snapshots.append((end, rss_mb(inst)))
            flows = wait_for(lambda: (lambda x: x if len(x) <= LIMIT else None)(inst.flows()),
                             60, 0.5, "retention after 50k calls")
            elapsed = time.perf_counter() - started
            warm = snapshots[0][1]
            final = rss_mb(inst)
            result = {"calls": CALLS, "workers": WORKERS, "limit": LIMIT, "retained": len(flows),
                      "seconds": round(elapsed, 1), "rss_warm_mb": round(warm, 1),
                      "rss_final_mb": round(final, 1), "rss_growth_after_warm_mb": round(final - warm, 1),
                      "rss_snapshots_mb": [[n, round(rss, 1)] for n, rss in snapshots],
                      "trimmed": inst.panel.state()["retention"]["trimmed"]}
            os.makedirs(harness.ARTIFACTS, exist_ok=True)
            with open(os.path.join(harness.ARTIFACTS, "soak.json"), "w") as fh:
                json.dump(result, fh, indent=2)
            print("\nSOAK %s" % json.dumps(result, sort_keys=True))
            self.assertEqual(len(flows), LIMIT, result)
            self.assertGreaterEqual(result["trimmed"], CALLS - LIMIT, result)
            self.assertLess(final - warm, 120.0, result)
        finally:
            inst.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
