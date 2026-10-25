"""Synthetic Proxyman RuleTree import through the public CLI."""
import json
import os
import re
import shutil
import unittest

import harness
from harness import Suite


class ProxymanImport0910(unittest.TestCase):
    def setUp(self):
        self.suite = Suite.get()
        self.home = os.path.join(self.suite.root, self.id().split(".")[-1])
        self.fixture = os.path.join(harness.REPO, "tests", "fixtures", "proxyman")
        self.source = os.path.join(self.home, "source")
        shutil.copytree(self.fixture, self.source)
        cp = self.suite.rivis("rules", "list", home=self.home)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.rules = os.path.join(self.home, ".rivis", "projects", "default", "rules.json")

    def run_import(self, *args):
        return self.suite.rivis("mocks", "import-proxyman", self.source, *args, home=self.home)

    def cfg(self):
        with open(self.rules) as fh:
            return json.load(fh)

    def test_dry_run_import_and_name_clash(self):
        before = self.cfg()
        dry = self.run_import("--dry-run")
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertIn("dry-run: imported 4, skipped 1", dry.stdout)
        self.assertEqual(self.cfg(), before)
        self.assertFalse(os.listdir(os.path.join(os.path.dirname(self.rules), "mocks")))
        first = self.run_import()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("imported 4, skipped 1", first.stdout)
        self.assertIn("file missing", first.stdout)
        second = self.run_import()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("imported 4, skipped 1", second.stdout)
        self.assertIn("wild-2", [r["name"] for r in self.cfg()["rules"]])

    def test_matching_method_disabled_group_and_copies(self):
        cp = self.run_import()
        self.assertEqual(cp.returncode, 0, cp.stderr)
        rules = {r["name"]: r for r in self.cfg()["rules"]}
        self.assertIsNotNone(__import__("re").search(rules["wild"]["match"], "https://api.example.com/v1/cards/abc"))
        self.assertIsNone(__import__("re").search(rules["wild"]["match"], "https://api.example.com/v1/other/abc"))
        self.assertEqual(rules["wild"]["method"], "GET")
        self.assertFalse(rules["regex"]["enabled"])
        self.assertEqual(rules["regex"]["method"], "POST")
        self.assertIsNotNone(__import__("re").search(rules["regex"]["match"], "https://api.example.com/v1/profile/123"))
        self.assertIn("group: Team mocks", rules["folder"]["note"])
        self.assertEqual(rules["folder"]["base"], "https://api.example.com/v1/mocks/")
        self.assertTrue(os.path.isfile(os.path.join(rules["folder"]["file"], "card.json")))
        self.assertTrue(os.path.isfile(rules["wild"]["file"]))
        with open(rules["wild"]["file"], "rb") as fh:
            self.assertIn(b"HTTP/1.1 202", fh.read())
        # most saved Proxyman rules are one exact URL: it also matches that call with a query string, never a longer path
        exact = rules["exact"]["match"]
        self.assertIsNotNone(re.search(exact, "https://api.example.com/api/cards/extended"))
        self.assertIsNotNone(re.search(exact, "https://api.example.com/api/cards/extended?page=2"))
        self.assertIsNone(re.search(exact, "https://api.example.com/api/cards/extended/more"))


if __name__ == "__main__":
    unittest.main()
