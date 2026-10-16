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



class LeftoverCheckIsPerRun(unittest.TestCase):
    """2026-10-16: two sessions ran tests/run.sh at once and each run's leftover check failed on the other's temp
    dirs and mitmweb processes. Under run.sh every temp root carries the run id; the check looks only at its own."""

    def test_another_runs_temp_dir_is_not_a_leftover_but_this_runs_is(self):
        import subprocess
        import tempfile
        code = ("import os, sys, tempfile; sys.path.insert(0, sys.argv[1]); import harness, hermetic; "
                "mine = tempfile.mkdtemp(prefix=harness.run_prefix()); other = tempfile.mkdtemp(prefix='rivis-t-zz9other-'); "
                "found = hermetic.tmp_leftovers(); os.rmdir(mine); os.rmdir(other); "
                "print(harness.run_prefix(), any(f.endswith(os.path.basename(mine)) for f in found), "
                "any(f.endswith(os.path.basename(other)) for f in found))")
        out = subprocess.run([sys.executable, "-I", "-c", code, HERE], capture_output=True, text=True,
                             env=dict(os.environ, RIVIS_TEST_RUN="zz1mine", TMPDIR=tempfile.gettempdir())).stdout.split()
        self.assertEqual(out, ["rivis-t-zz1mine-", "True", "False"])


class LeftoverCheckIgnoresTheUsersLiveRivis(unittest.TestCase):
    """2026-10-16: an open `rivis browser` window writes its profile under ~/.rivis/browser, and the check reported
    "$HOME/.rivis changed" for a run that never touched it. logs/ and browser/ are the live app's; the rest counts."""

    def test_browser_and_logs_are_ignored_but_project_state_is_not(self):
        import tempfile
        import hermetic
        home = tempfile.mkdtemp(prefix="rivis-hermetic-")
        try:
            root = os.path.join(home, ".rivis")
            for d in ("logs", "browser/chrome", "projects/default"):
                os.makedirs(os.path.join(root, d))
            before = hermetic.tree_digest(root)
            for f in ("logs/mitmweb.log", "browser/chrome/Cookies"):
                open(os.path.join(root, f), "w").write("x")
            self.assertEqual(hermetic.tree_digest(root), before)
            open(os.path.join(root, "projects", "default", "rules.json"), "w").write("{}")
            self.assertNotEqual(hermetic.tree_digest(root), before)
        finally:
            import shutil
            shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
