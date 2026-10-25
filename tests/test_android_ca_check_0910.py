"""Device pass 2026-10-23 (Android 17 Google Play emulator): `rivis android on` timed out ("CA trust check timed out
after 45 s; proxy left off") on an emulator whose user store already held another workstation's mitmproxy CA.
Android 17's Settings shows two "mitmproxy" lines per certificate (organization and name), so the check opened the same
certificate twice, and its OK button sits in the bottom 12% of the screen, so every tap on it first scrolled three
times. tests/fakes/emulator_adb.py plays that layout (flag file api37)."""
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from test_cli import CliBase


class AndroidCaCheckApi37(CliBase):
    def setUp(self):
        super().setUp()
        self.emu = os.path.join(self.home, "emu")
        os.makedirs(os.path.join(self.emu, "user"))
        open(os.path.join(self.emu, "api37"), "w").close()
        self.env = dict(self.env, ADB=os.path.join(harness.REPO, "tests", "fakes", "emulator_adb.py"), FAKE_EMU=self.emu)
        self.ours = os.path.join(self.env["RIVIS_CONFDIR"], "mitmproxy-ca-cert.pem")
        self.foreign = os.path.join(self.home, "other.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", os.path.join(self.home, "k.pem"),
                        "-out", self.foreign, "-days", "2", "-subj", "/CN=mitmproxy/O=mitmproxy"], capture_output=True, check=True)

    def check(self):
        t = time.monotonic()
        r = self.cli("__android_settings", "emulator-5554", "0", timeout=120)
        return r.returncode, time.monotonic() - t

    def opened(self):
        try:
            return open(os.path.join(self.emu, "opened")).read().split()
        except OSError:
            return []

    def swipes(self):
        return open(os.path.join(self.emu, "log")).read().count("input swipe")

    def test_another_workstations_ca_is_opened_once_and_never_scrolled_past(self):
        shutil.copy(self.foreign, os.path.join(self.emu, "user", "1.pem"))
        rc, _ = self.check()
        self.assertNotEqual(rc, 0, "this workstation's CA is not there")
        self.assertEqual(self.opened(), ["0"], "each certificate is opened once")
        self.assertEqual(self.swipes(), 0, "a dialog button is closed without scrolling the screen")

    def test_this_workstations_ca_is_found_behind_another_one(self):
        shutil.copy(self.foreign, os.path.join(self.emu, "user", "1.pem"))
        shutil.copy(self.ours, os.path.join(self.emu, "user", "2.pem"))
        rc, _ = self.check()
        self.assertEqual(rc, 0)
        self.assertEqual(self.opened(), ["0", "1"])
        self.assertEqual(self.swipes(), 0)


if __name__ == "__main__":
    harness.main()
