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
RESERVED = {n for n in dir(unittest.TestCase) if not n.startswith("_")} - {
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
            for d in ("logs", "browser/chrome", "projects/default", "android-ramdisk"):
                os.makedirs(os.path.join(root, d))
            before = hermetic.tree_digest(root)
            # an emulator the user set up appends to android-ramdisk/rooted.log for as long as it runs
            for f in ("logs/mitmweb.log", "browser/chrome/Cookies", "android-ramdisk/rooted.log"):
                open(os.path.join(root, f), "w").write("x")
            self.assertEqual(hermetic.tree_digest(root), before)
            open(os.path.join(root, "projects", "default", "rules.json"), "w").write("{}")
            self.assertNotEqual(hermetic.tree_digest(root), before)
        finally:
            import shutil
            shutil.rmtree(home, ignore_errors=True)


class LivePortAndStateGuards(unittest.TestCase):
    """A test that forced 8080/8083 or the real ~/.rivis once killed the maintainer's proxy mid-session.
    These prove the harness refuses that instead of quietly succeeding."""

    def test_env_refuses_every_forbidden_port(self):
        import harness
        suite = harness.Suite.get()
        home = suite.new_home("guard")
        for port in sorted(harness.FORBIDDEN_PORTS):
            with self.assertRaises(AssertionError) as caught:
                suite.env(home, ports=(port, harness.free_port()))
            self.assertIn("live ports", str(caught.exception))
            with self.assertRaises(AssertionError):
                suite.env(home, ports=(harness.free_port(), port))

    def test_env_refuses_forbidden_port_forced_via_extra(self):
        import harness
        suite = harness.Suite.get()
        home = suite.new_home("guard-extra")
        safe = (harness.free_port(), harness.free_port())
        with self.assertRaises(AssertionError):
            suite.env(home, ports=safe, extra={"RIVIS_PORT": "8080"})
        with self.assertRaises(AssertionError):
            suite.env(home, ports=safe, extra={"RIVIS_WEB_PORT": "8083"})

    def test_free_port_never_returns_a_forbidden_port(self):
        import harness
        for _ in range(200):
            self.assertNotIn(harness.free_port(), harness.FORBIDDEN_PORTS)

    def test_new_home_is_never_the_real_state_directory(self):
        import harness
        suite = harness.Suite.get()
        real_state = os.path.realpath(os.path.join(harness.REAL_HOME, ".rivis"))
        home = os.path.realpath(suite.new_home("not-real"))
        self.assertFalse(home == real_state or home.startswith(real_state + os.sep), home)
        self.assertFalse(os.path.realpath(suite.root).startswith(real_state + os.sep))


class SuiteOnForbiddenPortIsAHermeticFailure(unittest.TestCase):
    """before/after (cmd, name) alone misses a suite process that replaced the user's listener on the same address.
    Holding a protected port with this run's prefix in argv must fail the hermetic check."""

    def test_suite_process_on_a_protected_port_is_reported(self):
        import subprocess
        import tempfile
        import time
        import hermetic

        # child binds an ephemeral port (never 8080/8083); script path carries PREFIX so suite_pids() claims it
        script = tempfile.NamedTemporaryFile("w", delete=False, prefix=hermetic.PREFIX, suffix=".py")
        script.write(
            "import socket, sys, time\n"
            "s = socket.socket()\n"
            "s.bind(('127.0.0.1', 0))\n"
            "s.listen(1)\n"
            "open(sys.argv[1], 'w').write(str(s.getsockname()[1]))\n"
            "time.sleep(60)\n")
        script.close()
        portfile = script.name + ".port"
        child = subprocess.Popen([sys.executable, script.name, portfile],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if os.path.isfile(portfile) and open(portfile).read().strip().isdigit():
                    break
                time.sleep(0.05)
            else:
                self.fail("child did not publish its listen port")
            port = int(open(portfile).read().strip())
            old = hermetic.FORBIDDEN
            hermetic.FORBIDDEN = (port,)
            try:
                held = hermetic.suite_on_forbidden()
                self.assertTrue(held, "suite listener on protected port %d was not detected" % port)
                self.assertTrue(any(n.endswith(":%d" % port) for _, n in held), held)
            finally:
                hermetic.FORBIDDEN = old
        finally:
            child.kill()
            try:
                child.wait(timeout=5)
            except Exception:
                pass
            for p in (script.name, portfile):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def test_report_fails_when_suite_holds_a_protected_port(self):
        """End-to-end: hermetic report exits non-zero for a suite-held protected port even when the
        (cmd, name) listener set is unchanged and leftover_processes is empty (pid-swap case)."""
        import io
        import json
        import subprocess
        import tempfile
        import time
        import unittest.mock as mock
        import hermetic

        script = tempfile.NamedTemporaryFile("w", delete=False, prefix=hermetic.PREFIX, suffix=".py")
        script.write(
            "import socket, sys, time\n"
            "s = socket.socket()\n"
            "s.bind(('127.0.0.1', 0))\n"
            "s.listen(1)\n"
            "open(sys.argv[1], 'w').write(str(s.getsockname()[1]))\n"
            "time.sleep(60)\n")
        script.close()
        portfile = script.name + ".port"
        child = subprocess.Popen([sys.executable, script.name, portfile],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        results = tempfile.mkdtemp(prefix="rivis-hermetic-res-")
        try:
            for _ in range(100):
                if os.path.isfile(portfile) and open(portfile).read().strip().isdigit():
                    break
                time.sleep(0.05)
            port = int(open(portfile).read().strip())
            with open(os.path.join(results, "empty.json"), "w") as fh:
                json.dump({"passed": 0, "failed": 0, "skipped": 0, "xfailed": 0,
                           "unexpected_success": 0, "error": 0, "seconds": 0, "exitstatus": 0,
                           "failures": [], "skips": {}, "xfails": []}, fh)
            old = hermetic.FORBIDDEN
            hermetic.FORBIDDEN = (port,)
            try:
                # snapshot WHILE the suite listener is up so before/after (cmd, name) match
                snap = hermetic.snap()
                snap_path = os.path.join(results, "before.snap")
                json.dump(snap, open(snap_path, "w"))
                buf = io.StringIO()
                with mock.patch.object(hermetic, "leftover_processes", return_value=[]), \
                        mock.patch.object(hermetic, "tmp_leftovers", return_value=snap["tmp"]), \
                        mock.patch.object(sys, "argv", ["hermetic.py", "report", results, snap_path]), \
                        mock.patch("sys.stdout", buf):
                    rc = hermetic.main()
                self.assertEqual(rc, 1, buf.getvalue())
                self.assertIn("protected port", buf.getvalue())
            finally:
                hermetic.FORBIDDEN = old
        finally:
            child.kill()
            try:
                child.wait(timeout=5)
            except Exception:
                pass
            import shutil
            shutil.rmtree(results, ignore_errors=True)
            for p in (script.name, portfile):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def test_report_passes_without_suite_on_forbidden_when_only_pid_swapped(self):
        """Fails without the suite_on_forbidden check: prove the new guard is what makes report fail."""
        import io
        import json
        import subprocess
        import tempfile
        import time
        import unittest.mock as mock
        import hermetic

        script = tempfile.NamedTemporaryFile("w", delete=False, prefix=hermetic.PREFIX, suffix=".py")
        script.write(
            "import socket, sys, time\n"
            "s = socket.socket()\n"
            "s.bind(('127.0.0.1', 0))\n"
            "s.listen(1)\n"
            "open(sys.argv[1], 'w').write(str(s.getsockname()[1]))\n"
            "time.sleep(60)\n")
        script.close()
        portfile = script.name + ".port"
        child = subprocess.Popen([sys.executable, script.name, portfile],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        results = tempfile.mkdtemp(prefix="rivis-hermetic-res-")
        try:
            for _ in range(100):
                if os.path.isfile(portfile) and open(portfile).read().strip().isdigit():
                    break
                time.sleep(0.05)
            port = int(open(portfile).read().strip())
            with open(os.path.join(results, "empty.json"), "w") as fh:
                json.dump({"passed": 0, "failed": 0, "skipped": 0, "xfailed": 0,
                           "unexpected_success": 0, "error": 0, "seconds": 0, "exitstatus": 0,
                           "failures": [], "skips": {}, "xfails": []}, fh)
            old = hermetic.FORBIDDEN
            hermetic.FORBIDDEN = (port,)
            try:
                snap = hermetic.snap()
                snap_path = os.path.join(results, "before.snap")
                json.dump(snap, open(snap_path, "w"))
                buf = io.StringIO()
                with mock.patch.object(hermetic, "leftover_processes", return_value=[]), \
                        mock.patch.object(hermetic, "tmp_leftovers", return_value=snap["tmp"]), \
                        mock.patch.object(hermetic, "suite_on_forbidden", return_value=[]), \
                        mock.patch.object(sys, "argv", ["hermetic.py", "report", results, snap_path]), \
                        mock.patch("sys.stdout", buf):
                    rc = hermetic.main()
                self.assertEqual(rc, 0, buf.getvalue())
            finally:
                hermetic.FORBIDDEN = old
        finally:
            child.kill()
            try:
                child.wait(timeout=5)
            except Exception:
                pass
            import shutil
            shutil.rmtree(results, ignore_errors=True)
            for p in (script.name, portfile):
                try:
                    os.unlink(p)
                except OSError:
                    pass


class HermeticWatchesRealHomeNotTheFakeOne(unittest.TestCase):
    def test_snap_uses_current_HOME(self):
        import json
        import subprocess
        import tempfile
        fake = tempfile.mkdtemp(prefix="rivis-hermetic-home-")
        try:
            os.makedirs(os.path.join(fake, ".rivis", "projects"))
            open(os.path.join(fake, ".rivis", "projects", "x"), "w").write("1")
            snap_path = os.path.join(fake, "snap.json")
            env = dict(os.environ, HOME=fake)
            subprocess.run([sys.executable, "-I", os.path.join(HERE, "hermetic.py"), "snapshot", snap_path],
                           check=True, env=env, capture_output=True)
            data = json.load(open(snap_path))
            self.assertIsNotNone(data["watch"][".rivis"])
            # mutating the fake home Rivis state changes the digest when HOME is that fake
            open(os.path.join(fake, ".rivis", "projects", "x"), "w").write("2")
            snap2 = os.path.join(fake, "snap2.json")
            subprocess.run([sys.executable, "-I", os.path.join(HERE, "hermetic.py"), "snapshot", snap2],
                           check=True, env=env, capture_output=True)
            self.assertNotEqual(json.load(open(snap_path))["watch"][".rivis"],
                                json.load(open(snap2))["watch"][".rivis"])
        finally:
            import shutil
            shutil.rmtree(fake, ignore_errors=True)

    def test_adb_keys_are_on_the_watch_list(self):
        import hermetic
        self.assertIn(".android/adbkey", hermetic.WATCH)
        self.assertIn(".android/adbkey.pub", hermetic.WATCH)


class LastRunArtifactsReplacePriorRun(unittest.TestCase):
    def test_stale_module_logs_are_removed_before_copy(self):
        """CI uploads tests/.artifacts/last-run/; a merge of two runs made a failing module's log look like a pass."""
        import subprocess
        import tempfile
        art = tempfile.mkdtemp(prefix="rivis-art-")
        res = tempfile.mkdtemp(prefix="rivis-res-")
        try:
            open(os.path.join(art, "old_module.log"), "w").write("pass")
            open(os.path.join(art, "old_module.json"), "w").write("{}")
            open(os.path.join(res, "new_module.log"), "w").write("fail")
            open(os.path.join(res, "new_module.json"), "w").write('{"failed":1}')
            # same stanza as tests/run.sh
            subprocess.check_call([
                "bash", "-c",
                'ART="$1"; RES="$2"; mkdir -p "$ART" && rm -f "$ART"/*.log "$ART"/*.json; '
                'cp "$RES"/*.log "$RES"/*.json "$ART/"',
                "_", art, res])
            self.assertEqual(sorted(os.listdir(art)), ["new_module.json", "new_module.log"])
            self.assertEqual(open(os.path.join(art, "new_module.log")).read(), "fail")
        finally:
            import shutil
            shutil.rmtree(art, ignore_errors=True)
            shutil.rmtree(res, ignore_errors=True)

    def test_run_sh_clears_last_run_before_copy(self):
        text = open(os.path.join(HERE, "run.sh")).read()
        self.assertIn('rm -f "$ART"/*.log "$ART"/*.json', text)
        self.assertIn('ART="$HERE/.artifacts/last-run"', text)


class CiWiresUiSuite(unittest.TestCase):
    def test_gitlab_keeps_fast_gate_and_adds_ui_job(self):
        root = os.path.dirname(HERE)
        text = open(os.path.join(root, ".gitlab-ci.yml")).read()
        self.assertIn("bash tests/run.sh --fast", text)
        self.assertIn("bash tests/run.sh --ui", text)
        self.assertIn("rivis-fast-tests:", text)
        self.assertIn("rivis-ui-tests:", text)
        self.assertIn("tests/.artifacts/last-run/", text)
        # fast job body must stay a single --fast invocation (the merge gate)
        fast = text.split("rivis-fast-tests:")[1].split("rivis-ui-tests:")[0]
        self.assertIn("bash tests/run.sh --fast", fast)
        self.assertNotIn("bash tests/run.sh --ui", fast)

    def test_github_ui_workflow_runs_ui_and_uploads_logs_on_failure(self):
        root = os.path.dirname(HERE)
        text = open(os.path.join(root, ".github/workflows/ui.yml")).read()
        self.assertIn("bash tests/run.sh --ui", text)
        self.assertIn("actions/upload-artifact@v4", text)
        self.assertIn("tests/.artifacts/last-run", text)
        self.assertNotIn("secrets.", text.lower())
        self.assertNotIn("token:", text.lower())


class FreePortCloseThenUseIsStealable(unittest.TestCase):
    """free_port() binds port 0 and closes. Between that and a listener binding the number, anything can take it —
    the symptom is 'port already taken' in a module that never chose that port. Instance.start uses free_port()
    then hold_port() through env/CA/pre, and closes the holders only immediately before Popen."""

    def test_a_released_free_port_is_taken_during_a_ten_ms_gap(self):
        import socket
        import threading
        import time
        import harness
        steals = 0
        for _ in range(40):
            port = harness.free_port()
            held = {"s": None}

            def thief(p=port):
                s = socket.socket()
                try:
                    s.bind(("127.0.0.1", p))
                    s.listen(1)
                    held["s"] = s
                except OSError:
                    s.close()

            t = threading.Thread(target=thief)
            t.start()
            time.sleep(0.01)
            s = socket.socket()
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                steals += 1
            finally:
                s.close()
            t.join()
            if held["s"] is not None:
                held["s"].close()
        self.assertGreaterEqual(steals, 30, "free_port close-then-use gap should be stealable (got %d/40)" % steals)

    def test_hold_port_after_free_port_blocks_thieves_until_the_holder_closes(self):
        """Instance.start: free_port() (patchable) then hold_port() through setup — the pattern restart_on_same_port relies on."""
        import socket
        import threading
        import time
        import harness
        steals = 0
        for _ in range(40):
            port = harness.free_port()
            holder = harness.hold_port(port)
            held = {"s": None}

            def thief(p=port):
                s = socket.socket()
                try:
                    s.bind(("127.0.0.1", p))
                    s.listen(1)
                    held["s"] = s
                except OSError:
                    s.close()

            t = threading.Thread(target=thief)
            t.start()
            time.sleep(0.01)
            holder.close()
            s = socket.socket()
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                steals += 1
            finally:
                s.close()
            t.join()
            if held["s"] is not None:
                held["s"].close()
        self.assertEqual(steals, 0, "held port must not be stealable during the setup gap (got %d/40)" % steals)

    def test_instance_start_holds_chosen_ports_through_pre(self):
        """Wiring check: without hold_port in Instance.start, free_port()'s gap leaves the numbers bindable during pre."""
        import socket
        import harness

        suite = harness.Suite.get()
        # True = bind succeeded during pre (port was not held). Must stay False with the hold wiring.
        seen = {"proxy_free": None, "web_free": None}

        def pre(inst):
            for key, port in (("proxy_free", inst.proxy_port), ("web_free", inst.web_port)):
                s = socket.socket()
                try:
                    s.bind(("127.0.0.1", port))
                    seen[key] = True
                except OSError:
                    seen[key] = False
                finally:
                    s.close()
            raise RuntimeError("stop before Popen")

        inst = harness.Instance(suite, "hold-through-pre", pre=pre)
        with self.assertRaises(RuntimeError):
            inst.start()
        self.assertIs(seen["proxy_free"], False, "proxy port must stay held through pre")
        self.assertIs(seen["web_free"], False, "web port must stay held through pre")
        self.assertNotIn(inst, suite.instances)


class UpstreamClientDropStaysQuiet(unittest.TestCase):
    """A client that drops an accepted socket used to dump a socketserver traceback on stderr. Under a herd that
    noise rattled later tests sharing the same Upstream (failures landed in a different class each run)."""

    def test_http_drop_mid_response_prints_no_traceback_and_serves_the_next_call(self):
        import contextlib
        import io
        import socket
        import urllib.request
        import harness
        import upstream as upstream_mod

        suite = harness.Suite.get()
        up = suite.upstream()
        try:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                c = socket.create_connection(("127.0.0.1", up.http_port), timeout=2)
                c.sendall(b"GET /big?mb=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                c.recv(32)
                c.close()
                # give the handler thread a moment to hit the broken write
                import time
                time.sleep(0.2)
                body = urllib.request.urlopen(up.url("/json/small"), timeout=5).read()
            self.assertNotIn("Exception occurred during processing of request", err.getvalue(), err.getvalue())
            self.assertNotIn("Traceback", err.getvalue(), err.getvalue())
            self.assertIn(b"alice", body)
            self.assertTrue(upstream_mod._client_gone(ConnectionResetError(54, "Connection reset by peer")))
            self.assertFalse(upstream_mod._client_gone(ValueError("boom")))
        finally:
            up.close()
            if up in suite.upstreams:
                suite.upstreams.remove(up)

    def test_client_gone_classifier_keeps_real_bugs_loud(self):
        import errno
        import ssl
        import upstream as upstream_mod
        self.assertTrue(upstream_mod._client_gone(BrokenPipeError()))
        self.assertTrue(upstream_mod._client_gone(OSError(errno.EBADF, "Bad file descriptor")))
        self.assertTrue(upstream_mod._client_gone(ssl.SSLError("UNEXPECTED_EOF_WHILE_READING")))
        self.assertFalse(upstream_mod._client_gone(ssl.SSLError("PEM lib")))
        self.assertFalse(upstream_mod._client_gone(RuntimeError("handler bug")))


class SuiteUpstreamReusesCert(unittest.TestCase):
    """Suite.upstream used to spend an openssl invocation per Upstream. LiveCase builds two per class; share one
    cert/key pair per Suite so the second (and later) skip the ~40ms openssl cost."""

    def test_two_upstreams_from_the_same_suite_share_one_cert_file(self):
        import ssl
        import urllib.request
        import harness

        suite = harness.Suite.get()
        suite._upstream_cert_key = None
        up1 = suite.upstream()
        up2 = suite.upstream()
        try:
            self.assertEqual(up1.cert, up2.cert)
            self.assertIs(suite._upstream_cert_key[0], up1.cert)
            body = urllib.request.urlopen(up1.url("/json/small"), timeout=5).read()
            self.assertIn(b"alice", body)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            body2 = urllib.request.urlopen(up2.url("/json/small", tls=True), context=ctx, timeout=5).read()
            self.assertIn(b"alice", body2)
        finally:
            for u in (up1, up2):
                u.close()
                if u in suite.upstreams:
                    suite.upstreams.remove(u)


class LiveCaseTearDownClosesUpstreams(unittest.TestCase):
    """LiveCase used to stop the Rivis instance but leave both Upstream listeners in Suite.upstreams until process
    exit. A later class in the same module could then see leftover hits/connections if it forgot reset_hits."""

    def test_tear_down_class_closes_upstreams_and_removes_them_from_the_suite(self):
        import socket
        import harness

        suite = harness.Suite.get()
        suite_before = list(suite.upstreams)
        kept = {}

        class Probe(harness.LiveCase):
            @classmethod
            def setUpClass(cls):
                cls.suite = suite
                cls.up = suite.upstream()
                cls.up2 = suite.upstream()
                cls.inst = type("Inst", (), {"stop": staticmethod(lambda: None)})()
                kept["up"], kept["up2"] = cls.up, cls.up2

            def setUp(self):
                pass  # no Rivis; only exercising tearDownClass upstream cleanup

            def test_placeholder(self):
                self.assertTrue(self.up.http_port > 0)

        loaded = unittest.defaultTestLoader.loadTestsFromTestCase(Probe)
        result = unittest.TestResult()
        loaded.run(result)
        self.assertTrue(result.wasSuccessful(), result.failures + result.errors)
        up, up2 = kept["up"], kept["up2"]
        self.assertNotIn(up, suite.upstreams)
        self.assertNotIn(up2, suite.upstreams)
        for port in (up.http_port, up.https_port, up2.http_port, up2.https_port):
            s = socket.socket()
            s.settimeout(0.3)
            try:
                self.assertNotEqual(s.connect_ex(("127.0.0.1", port)), 0, "upstream still listening on %d" % port)
            finally:
                s.close()
        for u in (up, up2):
            if u in suite.upstreams:
                u.close()
                suite.upstreams.remove(u)
        self.assertEqual(suite.upstreams, suite_before)


if __name__ == "__main__":
    unittest.main()
