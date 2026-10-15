"""F-05: user-supplied regexes run on mitmproxy's single event loop, so shapes that backtrack catastrophically are refused."""
import re
import time
import unittest

import _paths  # noqa: F401
from harness import LiveCase
from proxy_common import MAX_PATTERN, user_regex

UNSAFE = ("(a+)+$", "(.*)*x", r"(\w+\s?)*$", "((ab)*)+c", "(?:x+y?)+z", "(a{1,1000})+")
SAFE = (".", "^/api/v1/.*$", r"/accounts/\d+/balance", "(foo|bar)+", "([a-z]+)/", "x{1,5}(ab)+", r"\.neo\.sa(:\d+)?/")


class Patterns(unittest.TestCase):
    def test_unsafe_shapes_are_refused_with_a_hint(self):
        for p in UNSAFE:
            with self.assertRaises(re.error, msg=p) as cm:
                user_regex(p)
            self.assertIn("nested repetition", str(cm.exception))

    def test_everyday_url_patterns_still_compile(self):
        for p in SAFE:
            self.assertTrue(user_regex(p).pattern == p, p)

    def test_length_cap_and_type(self):
        with self.assertRaises(re.error):
            user_regex("a" * (MAX_PATTERN + 1))
        with self.assertRaises(re.error):
            user_regex(5)
        with self.assertRaises(re.error):
            user_regex("(unclosed")


class Live(LiveCase):
    def test_an_unsafe_rule_is_skipped_and_the_proxy_stays_fast(self):
        self.reset_state(rules=[self.rule("evil", "respond", "/(a+)+$", body="x")])
        skipped = {r["name"]: r["error"] for r in self.panel.state()["skipped_rules"]}
        self.assertIn("nested repetition", skipped.get("evil", ""))
        t = time.time()
        self.fetch("/" + "a" * 40 + "!")
        self.assertLess(time.time() - t, 5)

    def test_the_panel_refuses_an_unsafe_match(self):
        code, doc, _ = self.panel.post("add", {"rule": {"name": "evil", "action": "block", "match": "(.*)*x"}})
        self.assertEqual(code, 400)
        self.assertIn("nested repetition", doc["error"])


if __name__ == "__main__":
    unittest.main()
