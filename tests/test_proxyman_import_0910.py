"""Synthetic Proxyman RuleTree import through the public CLI."""
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

import harness
from harness import Suite

sys.path.insert(0, os.path.join(harness.REPO, "addons"))
from proxyman_import import _method, import_proxyman


class ProxymanMethodEdgeCases(unittest.TestCase):
    def test_method_missing_name_skips_instead_of_traceback(self):
        # Proxyman sometimes writes method.exact as [{}] / [null]. .upper() on None aborted the
        # whole import with an AttributeError instead of skipping that one rule.
        for value in ({"exact": [{}]}, {"exact": [None]}, {"exact": [{"name": None}]}, {"exact": [123]}):
            with self.assertRaises(ValueError):
                _method(value)
        self.assertEqual(_method({"exact": [{"name": "GET"}]}), "GET")
        self.assertEqual(_method({"exact": ["POST"]}), "POST")
        self.assertIsNone(_method({"exact": ["GET", "POST"]}))

    def test_import_continues_after_a_bad_method_entry(self):
        tmp = tempfile.mkdtemp(prefix="rivis-t-proxyman-method-")
        try:
            src = os.path.join(tmp, "source")
            os.makedirs(src)
            with open(os.path.join(src, "ok.json"), "w") as fh:
                fh.write("HTTP/1.1 200 OK\n\n{}\n")
            tree = {"nodes": [
                {"name": "bad-method", "url": "https://api.example.com/bad", "localFile": {"path": "ok.json"},
                 "isEnabled": True, "regex": "useWildcard", "method": {"exact": [{}]}, "id": "1"},
                {"name": "good", "url": "https://api.example.com/good", "localFile": {"path": "ok.json"},
                 "isEnabled": True, "regex": "useWildcard", "id": "2"},
            ]}
            with open(os.path.join(src, "MapLocalFiles-RuleTree"), "w") as fh:
                json.dump(tree, fh)
            rules = os.path.join(tmp, "rules.json")
            with open(rules, "w") as fh:
                json.dump({"rules": []}, fh)
            summary = import_proxyman(rules, src, dry_run=True)
            self.assertIn("skipped bad-method:", summary)
            self.assertIn("would import good", summary)
            self.assertIn("imported 1, skipped 1", summary)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class ProxymanImport0910(unittest.TestCase):
    def setUp(self):
        self.suite = Suite.get()
        self.home = os.path.join(self.suite.root, self.id().split(".")[-1])
        os.makedirs(self.home, exist_ok=True)
        harness.seed_terms_acceptance(self.home)
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
