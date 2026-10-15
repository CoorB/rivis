"""The suite must be able to fail.

2026-10-15: test_cli.CliBase defined a helper named fail() ("this command must be refused"). unittest's assertions
raise through self.fail(msg), so every failed assertEqual/assertIn in 75 CLI tests ran `rivis "<message>"`, which
was refused, and the test passed. Five real bugs hid behind it. This test keeps any test class from shadowing
unittest's own methods again, and proves an assertion inside a real test class still fails.
"""
import glob
import importlib
import inspect
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
RESERVED = {n for n in dir(unittest.TestCase) if not n.startswith("__")} - {
    "setUp", "tearDown", "setUpClass", "tearDownClass", "run", "debug", "id", "shortDescription", "maxDiff", "longMessage"}


def every_test_class():
    for path in sorted(glob.glob(os.path.join(HERE, "test_*.py")) + glob.glob(os.path.join(HERE, "ui", "test_*.py"))):
        name = os.path.splitext(os.path.basename(path))[0]
        if name == "test_suite_integrity":
            continue
        if os.path.dirname(path) not in sys.path:
            sys.path.insert(0, os.path.dirname(path))
        module = importlib.import_module(name)
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if issubclass(cls, unittest.TestCase) and cls.__module__ == name:
                yield name, cls


class SuiteIntegrity(unittest.TestCase):
    def test_no_test_class_shadows_unittest_methods(self):
        bad = []
        for module, cls in every_test_class():
            for klass in cls.__mro__:
                if klass.__module__.startswith("unittest"):
                    break
                bad += ["%s.%s.%s" % (module, klass.__name__, n) for n in RESERVED & set(vars(klass))]
        self.assertEqual(sorted(set(bad)), [], "these override unittest's own methods, so assertions may never fail")

    def test_assertions_fail_inside_every_test_class(self):
        for module, cls in every_test_class():
            case = cls.__new__(cls)
            unittest.TestCase.__init__(case)
            with self.assertRaises(AssertionError, msg="%s.%s swallows failures" % (module, cls.__name__)):
                case.assertEqual("  a  ", "a")


if __name__ == "__main__":
    unittest.main()
