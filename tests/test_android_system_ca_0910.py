"""Android system certificate (pilot 2026-10-21, asked by three testers: "apps that ignore user certificates").

`rivis android on --system` also puts the CA in the emulator's SYSTEM store (addons/android/rivis_system_ca.sh: a
tmpfs over /system/etc/security/cacerts + the Conscrypt APEX bind on Android 14+). tests/fakes/emulator_adb.py plays the
emulator; the on-device script itself is exercised on real emulators (qa-overnight/DEVICE-TEST-0910.md)."""
import os
import shutil
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from test_cli import CliBase

sys.path.insert(0, os.path.join(harness.REPO, "addons"))
import devices                       # noqa: E402

FAKE_ADB = os.path.join(harness.REPO, "tests", "fakes", "emulator_adb.py")


class AndroidSystemCa(CliBase):
    def setUp(self):
        super().setUp()
        self.emu = os.path.join(self.home, "emu")
        os.makedirs(os.path.join(self.emu, "cacerts"))
        with open(os.path.join(self.emu, "avd"), "w") as fh:
            fh.write("Test_API_37")
        self.env = dict(self.env, ADB=FAKE_ADB, FAKE_EMU=self.emu)
        self.ours = os.path.join(self.env["RIVIS_CONFDIR"], "mitmproxy-ca-cert.pem")
        self.hashname = subprocess.run(["openssl", "x509", "-in", self.ours, "-noout", "-subject_hash_old"],
                                       capture_output=True, text=True, check=True).stdout.strip() + ".0"
        self.system = os.path.join(self.emu, "system", self.hashname)

    def root_image(self):
        open(os.path.join(self.emu, "root"), "w").close()

    def log(self):
        return open(os.path.join(self.emu, "log")).read()

    def wanted(self):
        try:
            return open(os.path.join(self.state, "android-system-ca")).read().split()
        except OSError:
            return []

    def test_system_flag_adds_the_ca_to_the_system_store_and_records_the_avd(self):
        self.root_image()
        out = self.ok("android", "on", "--system").stdout
        with open(self.system) as a, open(self.ours) as b:
            self.assertEqual(a.read(), b.read())
        self.assertIn("also in the SYSTEM store", out)
        self.assertEqual(self.wanted(), ["Test_API_37"])
        self.assertTrue(os.path.exists(os.path.join(self.emu, "cacerts", self.hashname)), "the user store as before")
        self.assertEqual(open(os.path.join(self.emu, "proxy")).read(), "10.0.2.2:" + self.env["RIVIS_PORT"])

    def test_without_the_flag_the_system_store_is_not_touched(self):
        self.root_image()
        self.ok("android", "on")
        self.assertNotIn("rivis_system_ca.sh", self.log())
        self.assertFalse(os.path.exists(self.system))
        self.assertEqual(self.wanted(), [])

    def test_a_failed_system_install_says_so_and_keeps_the_user_store_and_proxy(self):
        self.root_image()
        open(os.path.join(self.emu, "system_fail"), "w").close()
        r = self.cli("android", "on", "--system")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("could not add the CA to the system store", r.stdout + r.stderr)
        self.assertIn("zygote-123", r.stdout + r.stderr)
        self.assertIn("NOT in the system store", r.stdout + r.stderr)
        self.assertEqual(open(os.path.join(self.emu, "proxy")).read(), "10.0.2.2:" + self.env["RIVIS_PORT"])
        self.assertEqual(self.wanted(), [])

    def test_off_removes_only_this_workstations_ca_from_the_system_store(self):
        self.root_image()
        self.ok("android", "on", "--system")
        foreign = os.path.join(self.home, "other.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", os.path.join(self.home, "k.pem"),
                        "-out", foreign, "-days", "2", "-subj", "/CN=mitmproxy/O=mitmproxy"], capture_output=True, check=True)
        shutil.copy(foreign, self.system)
        out = self.ok("android", "off")
        self.assertTrue(os.path.exists(self.system), "another workstation's CA in the system store was removed")
        self.assertEqual(self.wanted(), [])
        shutil.copy(self.ours, self.system)
        out = self.ok("android", "off").stdout
        self.assertFalse(os.path.exists(self.system))
        self.assertIn("CA removed from the system store", out)

    def test_system_and_strict_are_refused_together(self):
        r = self.cli("android", "on", "--system", "--strict")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("do not go together", r.stdout + r.stderr)

    def test_play_image_without_magisk_says_why_not(self):
        os.makedirs(os.path.join(self.emu, "user"))
        shutil.copy(self.ours, os.path.join(self.emu, "user", "1.pem"))      # already trusts the CA in the user store
        env = dict(self.env, RIVIS_MAGISK_DIR=os.path.join(self.home, "no-magisk"))
        r = self.suite.rivis("android", "on", "--system", home=self.home, env=env, timeout=120)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("needs one-click setup (Magisk)", r.stdout + r.stderr)
        self.assertIn("NOT in the system store", r.stdout + r.stderr)

    def test_the_running_proxy_puts_it_back_after_a_restart(self):
        self.root_image()
        self.ok("android", "on", "--system")
        name = devices.ca_android_name(self.ours)
        self.assertEqual(name, self.hashname)
        with mock.patch.dict(os.environ, self.env, clear=True):
            self.assertTrue(devices.system_ca_present(FAKE_ADB, "emulator-5554", name))
            rows = devices.android_devices(FAKE_ADB, devices.ca_sha256(self.ours), self.state, self.env["RIVIS_PORT"], name)
            self.assertEqual((rows[0]["system_wanted"], rows[0]["system_ok"]), (True, True))
            self.assertEqual(devices.restore_android_system_ca(FAKE_ADB, self.state, name), [], "present: nothing to do")
            with open(os.path.join(self.emu, "boot_id"), "w") as fh:          # a cold boot: the tmpfs is gone
                fh.write("boot-2")
            os.remove(self.system)
            self.assertFalse(devices.system_ca_present(FAKE_ADB, "emulator-5554", name))
            done = devices.restore_android_system_ca(FAKE_ADB, self.state, name)
            self.assertEqual(done, [("emulator-5554", "Test_API_37", True)])
            self.assertTrue(devices.system_ca_present(FAKE_ADB, "emulator-5554", name))

    def test_a_play_image_is_not_restored_but_reported(self):
        self.root_image()
        self.ok("android", "on", "--system")
        os.remove(os.path.join(self.emu, "root"))                              # now a 'user' build without adb root
        with open(os.path.join(self.emu, "boot_id"), "w") as fh:
            fh.write("boot-2")
        name = self.hashname
        with mock.patch.dict(os.environ, self.env, clear=True):
            self.assertEqual(devices.restore_android_system_ca(FAKE_ADB, self.state, name), [])
            row = devices.android_devices(FAKE_ADB, devices.ca_sha256(self.ours), self.state, self.env["RIVIS_PORT"], name)[0]
            self.assertEqual((row["play"], row["system_wanted"], row["system_ok"]), (True, True, False))

    def test_panel_setup_argv_passes_the_flag(self):
        self.assertEqual(devices.setup_argv("android", "emulator-5554", True, True)[-2:], ["--yes", "--system"])
        self.assertNotIn("--system", devices.setup_argv("android", "emulator-5554"))


class OnDeviceScript(unittest.TestCase):
    """The on-device script is plain sh: parse it, and keep the rules it must follow."""
    PATH = os.path.join(harness.REPO, "addons", "android", "rivis_system_ca.sh")

    def test_parses_and_never_writes_the_image(self):
        self.assertEqual(subprocess.run(["sh", "-n", self.PATH]).returncode, 0)
        src = open(self.PATH).read()
        self.assertIn("mount -t tmpfs tmpfs \"$SYS\"", src)
        self.assertNotIn("remount", src)                  # the system image is never made writable
        self.assertIn("sys_is_ours", src.split("remove)")[1])    # remove only our own tmpfs
        self.assertIn("pidof zygote zygote64", src)

    def test_magisk_overlay_carries_the_script(self):
        inject = open(os.path.join(harness.REPO, "addons", "android", "rivis_inject.sh")).read()
        self.assertIn("overlay.d/sbin/rivis_system_ca.sh", inject)
        ca = open(os.path.join(harness.REPO, "addons", "android", "rivis_ca.sh")).read()
        self.assertIn("rivis-ca.want-system", ca)


if __name__ == "__main__":
    harness.main()
