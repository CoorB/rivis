"""addons/android_magisk.sh: the one-click CA on Google Play emulators stops BEFORE touching the emulator when the Magisk
files fail their pins, when consent is not given, or when the AVD is not a Play image. A fake adb records every call;
nothing here needs a real emulator (the live path was verified on an Android 37 Play AVD, 2026-10-15)."""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness

SCRIPT = os.path.join(harness.REPO, "addons", "android_magisk.sh")
PINS = os.path.join(harness.REPO, "addons", "android", "magisk.pins")
FAKE_ADB = r'''#!/bin/sh
echo "$@" >> "$FAKE_LOG"
case "$*" in
  *"emu avd name"*) printf 'Test_Play\r\nOK\r\n' ;;
  *"getprop ro.build.version.sdk"*) echo 36 ;;
  *"getprop ro.product.cpu.abi"*) echo arm64-v8a ;;
esac
exit 0
'''


def pin(key):
    for line in open(PINS):
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()


class MagiskGuards(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="rivis-magisk-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.log = os.path.join(self.root, "adb.log")
        sdk = os.path.join(self.root, "sdk")
        img = os.path.join(sdk, "system-images", "android-36", "google_apis_playstore", "arm64-v8a")
        os.makedirs(img)
        open(os.path.join(img, "ramdisk.img"), "wb").write(b"stock")
        os.makedirs(os.path.join(sdk, "emulator"))
        emu = os.path.join(sdk, "emulator", "emulator")
        open(emu, "w").write("#!/bin/sh\necho emulator \"$@\" >> \"$FAKE_LOG\"\n")
        os.chmod(emu, 0o755)
        self.adb = os.path.join(sdk, "platform-tools", "adb")
        os.makedirs(os.path.dirname(self.adb))
        open(self.adb, "w").write(FAKE_ADB)
        os.chmod(self.adb, 0o755)
        self.avd_home = os.path.join(self.root, "avd")
        self.avd_dir = os.path.join(self.avd_home, "Test_Play.avd")
        os.makedirs(self.avd_dir)
        self.write_config("PlayStore.enabled = true\nimage.sysdir.1 = system-images/android-36/google_apis_playstore/arm64-v8a/\n")
        self.magisk = os.path.join(self.root, "magisk")
        os.makedirs(self.magisk)
        self.ca = os.path.join(self.root, "ca.pem")
        open(self.ca, "w").write("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")
        self.state = os.path.join(self.root, "state")
        os.makedirs(self.state)

    def write_config(self, text):
        open(os.path.join(self.avd_dir, "config.ini"), "w").write(text)

    def run_it(self, *extra):
        env = dict(os.environ, ADB=self.adb, ANDROID_SDK_ROOT=os.path.join(self.root, "sdk"),
                   ANDROID_AVD_HOME=self.avd_home, FAKE_LOG=self.log, HOME=self.root)
        return subprocess.run(["/bin/bash", SCRIPT, "emulator-5554", self.ca, "c8750f0d.0", self.magisk, self.state, *extra],
                              capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL, timeout=60)

    def touched_emulator(self):
        log = open(self.log).read() if os.path.exists(self.log) else ""
        return any(w in log for w in ("emu kill", "push", "emulator -avd"))

    def test_missing_or_tampered_magisk_is_refused_before_anything_happens(self):
        r = self.run_it("--yes")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not installed", r.stderr)
        open(os.path.join(self.magisk, pin("MAGISK_APK")), "wb").write(b"not magisk")
        open(os.path.join(self.magisk, "host_patch.sh"), "wb").write(b"#")
        r = self.run_it("--yes")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("SHA-256 mismatch", r.stderr)
        self.assertFalse(self.touched_emulator())

    def test_consent_comes_after_verification_and_before_any_change(self):
        # order in the flow: verify the pinned files → ask → only then stop/patch/boot the emulator
        src = open(SCRIPT).read()
        self.assertLess(src.index("SHA-256 mismatch"), src.index("Continue? [y/N]"))
        self.assertLess(src.index("Continue? [y/N]"), src.index("emu kill"))
        self.assertIn("< /dev/tty", src)                     # adb would swallow a piped answer

    def test_a_non_play_avd_is_refused(self):
        self.write_config("PlayStore.enabled = false\ntag.ids = google_apis\nimage.sysdir.1 = system-images/android-36/google_apis_playstore/arm64-v8a/\n")
        r = self.run_it("--yes")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not a Google Play AVD", r.stderr)
        self.assertFalse(self.touched_emulator())

    def test_only_emulator_serials_and_safe_ca_names(self):
        env = dict(os.environ, ADB=self.adb, FAKE_LOG=self.log)
        for serial, name, msg in (("R58M123", "c8750f0d.0", "not an Android Studio emulator"),
                                  ("emulator-5554", "../x.0", "bad CA file name")):
            r = subprocess.run(["/bin/bash", SCRIPT, serial, self.ca, name, self.magisk, self.state, "--yes"],
                               capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL, timeout=30)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn(msg, r.stderr)

    def test_pins_match_the_official_magisk_release(self):
        self.assertEqual(pin("MAGISK_VERSION"), "30.7")
        for k in ("MAGISK_APK_SHA256", "MAGISK_HOST_PATCH_SHA256", "MAGISK_LICENSE_SHA256"):
            self.assertRegex(pin(k), r"^[0-9a-f]{64}$")
        for k in ("MAGISK_APK_URL", "MAGISK_HOST_PATCH_URL", "MAGISK_LICENSE_URL"):
            self.assertTrue(pin(k).startswith("https://"), k)
        self.assertIn(pin("MAGISK_COMMIT"), pin("MAGISK_HOST_PATCH_URL"))

    def test_the_boot_service_is_oneshot_and_grants_nothing_else(self):
        rc = open(os.path.join(harness.REPO, "addons", "android", "rivis_ca.rc")).read()
        self.assertIn("oneshot", rc)
        sh = open(os.path.join(harness.REPO, "addons", "android", "rivis_ca.sh")).read()
        for forbidden in ("magisk --sqlite", "policies", "su ", "setprop"):
            self.assertNotIn(forbidden, sh)
        self.assertIn("/data/misc/user/0/cacerts-added", sh)


if __name__ == "__main__":
    unittest.main(verbosity=2)
