"""Tree worker under large / deep / invalid bodies: must finish (ok or error), never hang the panel."""
import json
import os
import subprocess
import tempfile
import textwrap
import unittest

import harness

WORKER = os.path.join(harness.REPO, "addons", "tree-worker.js")
# Mirror the worker in worker_threads: same parse + postMessage contract the browser Dedicated Worker uses.
RUNNER = textwrap.dedent(r"""
const fs = require("fs");
const { Worker, isMainThread, parentPort, workerData } = require("worker_threads");
if (!isMainThread) {
  const src = fs.readFileSync(workerData.workerPath, "utf8")
    .replace(/self\.onmessage\s*=\s*\(([^)]*)\)\s*=>\s*\{/, "const __on = ($1) => {")
    .replace(/self\.postMessage/g, "parentPort.postMessage");
  eval(src + "\n; parentPort.on('message', (data) => __on({ data }));");
  return;
}
const text = fs.readFileSync(process.argv[2], "utf8");
const t0 = Date.now();
const w = new Worker(__filename, { workerData: { workerPath: process.argv[3] } });
let done = false;
const finish = (obj, code) => {
  if (done) return;
  done = true;
  console.log(JSON.stringify(obj));
  try { w.terminate(); } catch (e) {}
  process.exit(code);
};
w.on("message", (msg) => {
  const summary = msg && msg.error
    ? { error: String(msg.error).slice(0, 300) }
    : { ok: true, type: typeof (msg && msg.data) };
  finish({ ms: Date.now() - t0, msg: summary }, 0);
});
w.on("error", (e) => finish({ ms: Date.now() - t0, msg: { error: String(e) } }, 1));
setTimeout(() => finish({ ms: Date.now() - t0, msg: { error: "TIMEOUT" } }, 2), Number(process.argv[4] || 5000));
w.postMessage(text);
""")


@unittest.skipUnless(harness.node_ok(), "node not installed")
class TreeWorkerExtremes(unittest.TestCase):
    def run_worker(self, payload, timeout_ms=5000):
        with tempfile.TemporaryDirectory(prefix=harness.run_prefix()) as tmp:
            payload_path = os.path.join(tmp, "body.json")
            runner_path = os.path.join(tmp, "run.js")
            with open(payload_path, "w", encoding="utf-8") as fh:
                fh.write(payload)
            with open(runner_path, "w") as fh:
                fh.write(RUNNER)
            cp = subprocess.run([harness.NODE, runner_path, payload_path, WORKER, str(timeout_ms)],
                                capture_output=True, text=True, timeout=(timeout_ms / 1000.0) + 5)
            self.assertTrue(cp.stdout.strip(), "worker produced no stdout: rc=%s stderr=%r" % (cp.returncode, cp.stderr))
            return json.loads(cp.stdout.strip().splitlines()[-1])

    def test_deeply_nested_json_errors_instead_of_hanging(self):
        # Without a depth guard, postMessage of a ~5000-deep value never returns (measured on Node 26).
        result = self.run_worker("[" * 5000 + "]" * 5000, timeout_ms=5000)
        self.assertNotEqual(result["msg"].get("error"), "TIMEOUT", result)
        self.assertIn("nested more than", result["msg"].get("error", ""), result)
        self.assertLess(result["ms"], 2000, result)

    def test_moderate_depth_and_large_string_still_parse(self):
        shallow = self.run_worker("[" * 2000 + "]" * 2000, timeout_ms=5000)
        self.assertTrue(shallow["msg"].get("ok"), shallow)
        self.assertNotIn("error", shallow["msg"], shallow)
        huge = self.run_worker('{"data":"' + ("a" * (5 * 1024 * 1024)) + '"}', timeout_ms=15000)
        self.assertTrue(huge["msg"].get("ok"), huge)
        self.assertLess(huge["ms"], 5000, huge)

    def test_invalid_and_empty_json_return_an_error(self):
        for payload in ('{"a":', ""):
            result = self.run_worker(payload, timeout_ms=3000)
            self.assertIn("error", result["msg"], result)
            self.assertNotEqual(result["msg"]["error"], "TIMEOUT", result)

    def test_a_leading_byte_order_mark_is_not_content(self):
        # Servers that prepend a BOM send valid JSON; the tree must draw it, not call it broken.
        result = self.run_worker("\ufeff{\"a\":1}", timeout_ms=3000)
        self.assertTrue(result["msg"].get("ok"), result)
        self.assertNotIn("error", result["msg"], result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
