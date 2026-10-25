"""Capture restore safety under traffic, overlapping operations and commit failures."""
import json
import os
import unittest

import harness


class CaptureRestore(unittest.TestCase):
    def run_probe(self, group):
        suite = harness.Suite.get()
        home = suite.new_home("restore-probe")
        result = os.path.join(home, "result.json")
        env = suite.env(home, {"RESTORE_RESULT": result, "PROBE_GROUP": group})
        cp = suite.run([harness.REAL_MITMDUMP, "-n", "--set", "confdir=" + os.path.join(home, "ca"),
                        "-s", os.path.join(harness.TESTS, "restore_review_probe.py")], home=home, env=env, timeout=30)
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertTrue(os.path.isfile(result), cp.stdout + cp.stderr)
        errors = json.load(open(result))
        self.assertFalse(errors, "\n".join(errors))

    def test_restore_transactions_preserve_live_calls_and_recover(self):
        self.run_probe("restore")

    def test_content_absent_streamed_empty_and_message_lists(self):
        self.run_probe("content")
