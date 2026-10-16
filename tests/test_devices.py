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
        real = devices._run
        with mock.patch.object(devices, "_run", side_effect=lambda argv, timeout=None:
                               real(argv) if argv[0] == "/usr/bin/sqlite3" else (0, json.dumps(listing))):
            got = devices.ios_devices(self.want)
        self.assertEqual([(d["name"], d["ready"], d["os"]) for d in got], [("iPad", False, "iOS 26.0"), ("iPhone 17", True, "iOS 26.0")])
        with mock.patch.object(devices, "_run", return_value=(None, "")):
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
