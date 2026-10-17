"""addons/devices.py (Devices tab): simulator trust read from the trust store, emulator status from adb + the CLI's
verified-install record, setup commands built only from validated IDs, and one job at a time."""
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "addons"))
import devices  # noqa: E402

UDID = "11111111-2222-3333-4444-555555555555"
OTHER = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
PEM = ("-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ2VydA==\n-----END CERTIFICATE-----\n")


class Status(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="rivis-dev-")
        self.env = mock.patch.dict(os.environ, {"HOME": self.home})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.ca = os.path.join(self.home, "ca.pem")
        open(self.ca, "w").write(PEM)
        self.want = devices.ca_sha256(self.ca)

    def trust(self, udid, sha_hex):
        d = os.path.join(self.home, "Library/Developer/CoreSimulator/Devices", udid, "data/private/var/protected/trustd")
        os.makedirs(d)
        db = sqlite3.connect(os.path.join(d, "TrustStore.sqlite3"))
        db.execute("create table tsettings (sha256 blob)")
        db.execute("insert into tsettings values (?)", (bytes.fromhex(sha_hex),))
        db.commit()
        db.close()

    def test_ca_sha256_is_the_der_hash(self):
        import base64
        der = base64.b64decode("MIIBszCCAVmgAwIBAgIUQ2VydA==")
        self.assertEqual(self.want, hashlib.sha256(der).hexdigest().upper())

    def test_ios_ready_only_when_this_ca_is_in_the_trust_store(self):
        self.trust(UDID, self.want)
        self.trust(OTHER, "AB" * 32)
        listing = {"devices": {"com.apple.CoreSimulator.SimRuntime.iOS-26-0": [
            {"udid": UDID, "name": "iPhone 17", "state": "Booted"},
            {"udid": OTHER, "name": "iPad", "state": "Booted"},
            {"udid": "../evil", "name": "x", "state": "Booted"}]}}
        with mock.patch.object(devices, "_simctl", return_value=(0, json.dumps(listing), "")):
            got = devices.ios_devices(self.want)
        self.assertEqual([(d["name"], d["ready"], d["os"]) for d in got], [("iPad", False, "iOS 26.0"), ("iPhone 17", True, "iOS 26.0")])
        with mock.patch.object(devices, "_simctl", return_value=("missing", "", "")):
            self.assertIsNone(devices.ios_devices(self.want))          # no Xcode tools

    def test_android_ready_needs_the_recorded_ca_and_the_proxy(self):
        state = os.path.join(self.home, "state")
        os.makedirs(state)
        open(os.path.join(state, "android-ca"), "w").write("Pixel_9\t%s\nOld\tDEAD\n" % self.want)
        answers = {
            ("devices",): "List of devices attached\nemulator-5554\tdevice\nemulator-5556\tdevice\nR58M1\tdevice\n",
            ("-s", "emulator-5554", "emu", "avd", "name"): "Pixel_9\nOK\n",
            ("-s", "emulator-5556", "emu", "avd", "name"): "Old\nOK\n",
        }

        def fake(argv, timeout=None):
            key = tuple(argv[1:])
            if key in answers:
                return 0, answers[key]
            if key[-1] == "http_proxy":
                return 0, "10.0.2.2:8080\n" if key[1] == "emulator-5554" else "null\n"
            if key[-1] == "ro.build.type":
                return 0, "user\n"
            return 0, "16\n"
        with mock.patch.object(devices, "_run", side_effect=fake):
            got = devices.android_devices("/x/adb", self.want, state, 8080)
        self.assertEqual([(d["id"], d["name"], d["ca_ok"], d["proxy_ok"], d["ready"], d["play"]) for d in got],
                         [("emulator-5554", "Pixel_9", True, True, True, True),
                          ("emulator-5556", "Old", False, False, False, True)])      # physical R58M1 is not listed
        self.assertIsNone(devices.android_devices(None, self.want, state, 8080))


class Commands(unittest.TestCase):
    def test_setup_argv_only_from_validated_ids(self):
        self.assertEqual(devices.setup_argv("ios", UDID)[1:], ["ios", "on", "--udid", UDID])
        self.assertEqual(devices.setup_argv("ios", "all")[1:], ["ios", "on", "--all"])
        self.assertEqual(devices.setup_argv("android", "emulator-5554", consent=True)[1:], ["android", "on", "-s", "emulator-5554", "--yes"])
        self.assertEqual(devices.setup_argv("android", "all")[1:], ["android", "on", "--all"])
        for platform, target in (("ios", "../x"), ("ios", UDID + ";rm -rf ~"), ("android", "R58M1"), ("android", "emulator-1 --x"),
                                 ("windows", "all")):
            with self.assertRaises(ValueError):
                devices.setup_argv(platform, target)

    def test_snapshot_never_waits_runs_one_refresh_at_a_time_and_keeps_the_last_good_value(self):
        calls = []
        def check():
            calls.append(1)
            time.sleep(0.3)
            if len(calls) == 2:
                raise OSError("adb went away")
            return len(calls)
        snap = devices.Snapshot(check, 0)
        t = time.time()
        self.assertEqual(snap.get(), (False, None))                       # nothing yet, and no waiting
        self.assertEqual(snap.get(), (False, None))                       # the first refresh is still running
        self.assertLess(time.time() - t, 0.1)
        for _ in range(50):
            if snap.get()[0]:
                break
            time.sleep(0.05)
        self.assertEqual(snap.get()[1], 1)
        for _ in range(50):                                               # the second (failing) refresh ends
            if len(calls) >= 3:
                break
            time.sleep(0.05)
        self.assertIn(snap.get()[1], (1, 3))                              # never None after a failed check
        self.assertLessEqual(len(calls), 4)

    def test_browser_argv_only_from_known_browsers_and_never_an_option(self):
        self.assertEqual(devices.browser_argv("chrome")[1:], ["browser", "--browser", "chrome"])
        self.assertEqual(devices.browser_argv("edge", " https://a.test/x ")[1:], ["browser", "--browser", "edge", "--", "https://a.test/x"])
        for browser, url in (("opera", ""), ("chrome --x", ""), ("chrome", "--user-data-dir=/tmp/x"), ("chrome", "a b"),
                             ("chrome", "https://a.test/\n--x"), ("chrome", "https://a.test/" + "x" * 2000)):
            with self.assertRaises(ValueError):
                devices.browser_argv(browser, url)

    def test_one_job_at_a_time_and_output_is_kept(self):
        jobs = devices.Jobs()
        jobs.start(["/bin/sh", "-c", "echo one; sleep 1; echo two"], "test")
        with self.assertRaises(RuntimeError):
            jobs.start(["/bin/true"], "second")
        for _ in range(50):
            s = jobs.summary()
            if not s["running"]:
                break
            time.sleep(0.1)
        self.assertEqual((s["rc"], s["lines"]), (0, ["one", "two"]))
        jobs.start(["/bin/sh", "-c", "printf '\\033[1mbold\\033[0m\\n'; exit 3"], "again")
        for _ in range(50):
            s = jobs.summary()
            if not s["running"]:
                break
            time.sleep(0.1)
        self.assertEqual((s["rc"], s["lines"]), (3, ["bold"]))                # ANSI colours stripped


if __name__ == "__main__":
    unittest.main(verbosity=2)


class SimctlProblems(unittest.TestCase):
    """Night QA lane A: every `xcrun simctl` failure was shown as 'Xcode command-line tools are not installed', even
    with Xcode installed (license not accepted, Command Line Tools selected, a hung CoreSimulator)."""

    def status(self, rc=0, err="", exc=None):
        import subprocess as sp
        def fake(*a, **k):
            if exc:
                raise exc
            return sp.CompletedProcess(a[0], rc, '{"devices": {}}' if rc == 0 else "", err)
        with mock.patch.object(devices.subprocess, "run", side_effect=fake):
            return devices.ios_status("")

    def test_each_failure_says_what_to_do(self):
        import subprocess as sp
        self.assertIn("license", self.status(69, "You have not agreed to the Xcode license agreements.")[1])
        self.assertIn("xcode-select -s", self.status(72, 'xcrun: error: unable to find utility "simctl", not a developer tool or in PATH')[1])
        self.assertIn("Install Xcode", self.status(exc=FileNotFoundError("xcrun"))[1])
        self.assertIn("did not answer", self.status(exc=sp.TimeoutExpired("xcrun", 8))[1])
        self.assertIn("CoreSimulatorService connection", self.status(1, "An error was encountered processing the command"
                                                                     " (CoreSimulatorService connection interrupted)")[1])
        self.assertEqual(self.status(0), ([], None))


class AdbPathIsAbsolute(unittest.TestCase):
    def test_a_relative_platform_tools_adb_in_the_working_directory_is_never_run(self):
        # Night QA A8: with no SDK variable set, adb_path() returned "platform-tools/adb" relative to the directory
        # Rivis was started in (often ~/Downloads) and the Devices tab executed it.
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "platform-tools"))
            planted = os.path.join(d, "platform-tools", "adb")
            with open(planted, "w") as fh:
                fh.write("#!/bin/sh\nexit 0\n")
            os.chmod(planted, 0o755)
            cwd = os.getcwd()
            os.chdir(d)
            try:
                env = {k: v for k, v in os.environ.items() if k not in ("ADB", "ANDROID_SDK_ROOT", "ANDROID_HOME")}
                with mock.patch.dict(os.environ, env, clear=True):
                    found = devices.adb_path()
            finally:
                os.chdir(cwd)
            self.assertNotEqual(found, "platform-tools/adb")
            self.assertTrue(found is None or os.path.isabs(found), found)
