"""F-05: user-supplied regexes run on mitmproxy's single event loop, so shapes that backtrack catastrophically are refused."""
import re
import time
import unittest

import _paths  # noqa: F401
from harness import LiveCase
from proxy_common import MAX_PATTERN, user_regex

UNSAFE = ("(a+)+$", "(.*)*x", r"(\w+\s?)*$", "((ab)*)+c", "(?:x+y?)+z", "(a{1,1000})+")
SAFE = (".", "^/api/v1/.*$", r"/accounts/\d+/balance", "(foo|bar)+", "([a-z]+)/", "x{1,5}(ab)+", r"\.neo\.sa(:\d+)?/",
        "(a|b)+", "(ab?)+", "(foo|bars)+", r".*foo.*bar.*", r"^https://[^/]+/accounts(\?|$)", r"[^/]+/[^/]+", r"^/x/.*?/y$",
        r"api\.example\.test(:\d+)?/accounts", r"(\d{2})+")
# Review R2: no nested repeat, yet exponential (several ways to split the same text) or polynomial (repeats in a row
# that take the same characters: each one multiplies the work by the URL length)
AMBIGUOUS = ("(a|aa)+$", "(ab|ab)+", "(a?a)+", "(?:x|xy)*z")
ADJACENT = ("a*a*$", ".*.*x", r"\d+\d*z", "(a*)(a*)b", "a*b?a*c", r".*\S*\.json$")


class Patterns(unittest.TestCase):
    def test_unsafe_shapes_are_refused_with_a_hint(self):
        for p in UNSAFE:
            with self.assertRaises(re.error, msg=p) as cm:
                user_regex(p)
            self.assertIn("nested repetition", str(cm.exception))

    def test_ambiguous_and_adjacent_repeats_are_refused_with_a_hint(self):
        for patterns, hint in ((AMBIGUOUS, "alternatives or optional parts"), (ADJACENT, "two repeats in a row")):
            for p in patterns:
                with self.assertRaises(re.error, msg=p) as cm:
                    user_regex(p)
                self.assertIn(hint, str(cm.exception), p)

    def test_the_refused_shapes_really_are_slow(self):
        """Not a style rule: each refused example takes over a second on a short input (in a child, with a deadline)."""
        import subprocess
        import sys
        for p, text in (("(a|aa)+$", "a" * 40 + "!"), ("(a?a)+$", "a" * 40 + "!"), (".*.*.*.*x", "a" * 400)):
            with self.assertRaises(subprocess.TimeoutExpired, msg=p):
                subprocess.run([sys.executable, "-I", "-c", "import re, sys; re.search(sys.argv[1], sys.argv[2])", p, text],
                               timeout=1)

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

    def test_an_ambiguous_rule_is_skipped_and_the_proxy_stays_fast(self):
        self.reset_state(rules=[self.rule("evil2", "respond", "/(a|aa)+$", body="x")])
        skipped = {r["name"]: r["error"] for r in self.panel.state()["skipped_rules"]}
        self.assertIn("alternatives or optional parts", skipped.get("evil2", ""))
        t = time.time()
        self.fetch("/" + "a" * 40 + "!")
        self.assertLess(time.time() - t, 5)

    def test_the_panel_refuses_an_unsafe_match(self):
        code, doc, _ = self.panel.post("add", {"rule": {"name": "evil", "action": "block", "match": "(.*)*x"}})
        self.assertEqual(code, 400)
        self.assertIn("nested repetition", doc["error"])


class ProjectProfiles(unittest.TestCase):
    """R5A-06: a project's hosts regex runs on every call (project filter, private-host allow-list): an unsafe one
    in a hand-made or older project.json is dropped on load, never matched."""

    def test_unsafe_profile_regexes_are_dropped_with_a_reason(self):
        import json, os, tempfile
        from unittest import mock
        import proxy_common
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "profiles", "evil"))
            with open(os.path.join(d, "profiles", "evil", "project.json"), "w") as fh:
                json.dump({"id": "evil", "label": "E", "hosts": "(a+)+$", "record_match": "(.*)*x", "throttle_match": r"api\.test"}, fh)
            with mock.patch.object(proxy_common, "STATE_ROOT", d):
                doc = proxy_common.project_profile("evil")
        self.assertEqual((doc["hosts"], doc["record_match"], doc["throttle_match"]), ("", ".", r"api\.test"))
        self.assertIn("nested repetition", doc["regex_errors"]["hosts"])
        self.assertNotIn("throttle_match", doc["regex_errors"])


if __name__ == "__main__":
    unittest.main()
