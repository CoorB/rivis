"""`rivis rules test` must predict what the proxy really does with a locally answered call: response rules (status,
json_patch, response set_header / replace_body) still change the local answer (QA of 0.9.11 rc4, D4)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: F401  (puts addons/ on the path the way every test does)
sys.path.insert(0, os.path.join(harness.REPO, "addons"))
from proxy_rule_validation import explain_rules  # noqa: E402


class LocalAnswerStillGetsResponseRules(unittest.TestCase):
    def test_a_status_rule_changes_a_local_reply_and_says_so(self):
        rules = [{"name": "qa-reply", "match": "/qa", "action": "respond", "status": 200, "body": "hello"},
                 {"name": "qa-preview", "match": "/qa-preview", "action": "status", "status": 503},
                 {"name": "qa-hdr", "match": "/qa", "action": "set_header", "side": "response", "header": "X-T", "value": "1"},
                 {"name": "qa-req-hdr", "match": "/qa", "action": "set_header", "side": "request", "header": "X-R", "value": "1"}]
        with tempfile.TemporaryDirectory() as d:
            rows = {r["name"]: r for r in explain_rules(rules, d, "https://example.com/qa-preview", "GET")}
        self.assertTrue(rows["qa-reply"]["fires"])
        self.assertTrue(rows["qa-preview"]["fires"], rows["qa-preview"])
        self.assertIn("503", rows["qa-preview"]["effect"])
        self.assertIn("local answer from 'qa-reply'", rows["qa-preview"]["effect"])
        self.assertNotIn("server's", rows["qa-preview"]["effect"])
        self.assertTrue(rows["qa-hdr"]["fires"], rows["qa-hdr"])
        self.assertIn("local answer", rows["qa-hdr"]["effect"])


if __name__ == "__main__":
    unittest.main()
