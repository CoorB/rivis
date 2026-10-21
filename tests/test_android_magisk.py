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


class MagiskFixture(unittest.TestCase):
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


class MagiskGuards(MagiskFixture):
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
        # the first restart (not the helper that defines how to restart) comes after consent
        self.assertLess(src.index("Continue? [y/N]"), src.index("info \"restarting '$AVD' with the temporary ramdisk"))
        self.assertIn("< /dev/tty", src)                     # adb would swallow a piped answer

    def test_a_non_play_avd_is_refused(self):
        self.write_config("PlayStore.enabled = false\ntag.ids = google_apis\nimage.sysdir.1 = system-images/android-36/google_apis_playstore/arm64-v8a/\n")
        r = self.run_it("--yes")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not a Google Play AVD", r.stderr)
        self.assertFalse(self.touched_emulator())

    def test_studio_embedded_api_36_1_is_refused_before_restart(self):
        self.write_config('PlayStore.enabled=true\nimage.sysdir.1=system-images/android-36.1/google_apis_playstore/arm64-v8a/\n')
        image = os.path.join(self.root, 'sdk', 'system-images', 'android-36.1', 'google_apis_playstore', 'arm64-v8a')
        os.makedirs(image)
        open(os.path.join(image, 'ramdisk.img'), 'wb').write(b'API 36.1 stock')
        fake_bin = os.path.join(self.root, 'fake-bin')
        os.makedirs(fake_bin)
        ps = os.path.join(fake_bin, 'ps')
        open(ps, 'w').write('#!/bin/sh\necho "qemu-system-aarch64 -avd Test_Play -qt-hide-window -grpc-use-token -port 5554"\n')
        os.chmod(ps, 0o755)
        env = dict(os.environ, ADB=self.adb, ANDROID_SDK_ROOT=os.path.join(self.root, 'sdk'),
                   ANDROID_AVD_HOME=self.avd_home, FAKE_LOG=self.log, HOME=self.root,
                   PATH=fake_bin + os.pathsep + os.environ.get('PATH', ''))
        r = subprocess.run(['/bin/bash', SCRIPT, 'emulator-5554', self.ca, 'c8750f0d.0', self.magisk, self.state, '--yes'],
                           capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL, timeout=30)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('running embedded in Android Studio', r.stderr)
        self.assertIn('cannot safely restart', r.stderr)
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


FLOW_ADB = r"""#!/bin/sh
echo "$@" >> "$FAKE_LOG"
case "$*" in
  *"emu avd name"*) printf 'Test_Play\r\nOK\r\n' ;;
  *"emu kill"*) : > "$FAKE_DIR/killed" ;;
  *"get-state"*) [ -f "$FAKE_DIR/killed" ] && exit 1; echo device ;;
  *"getprop ro.build.version.sdk"*) echo 36 ;;
  *"getprop ro.product.cpu.abi"*) echo arm64-v8a ;;
  *"getprop sys.boot_completed"*) echo 1 ;;
  *"cat /data/local/tmp/rivis-ca.status"*) echo "${FAKE_STATUS-ok c8750f0d.0}" ;;
esac
exit 0
"""
# the real pinned Magisk files (the installer puts them next to the tool; the pilot mirror keeps a copy)
REAL_MAGISK = next((d for d in (os.environ.get("RIVIS_TEST_MAGISK_DIR", ""),
                                os.path.expanduser("~/Work/NEO/proxy-replacement/pilot-mirror/magisk/30.7"))
                    if d and os.path.isfile(os.path.join(d, "host_patch.sh"))), None)


class MagiskRestarts(MagiskFixture):
    """How many times the emulator is restarted (2026-10-16: Proxyman takes ~30 s with ONE restart; Rivis took 2–4 min
    with two). A fake adb/emulator record every restart; the patched ramdisk is pre-cached, so no patching runs."""

    def setUp(self):
        super().setUp()
        if not REAL_MAGISK:
            self.skipTest("the pinned Magisk files are not on this machine (set RIVIS_TEST_MAGISK_DIR)")
        open(self.adb, "w").write(FLOW_ADB)
        emu = os.path.join(self.root, "sdk", "emulator", "emulator")
        open(emu, "w").write('#!/bin/sh\necho emulator "$@" >> "$FAKE_LOG"\nrm -f "$FAKE_DIR/killed"\n')
        for f in os.listdir(REAL_MAGISK):
            shutil.copy(os.path.join(REAL_MAGISK, f), self.magisk)
        sha = lambda b: hashlib.sha256(b).hexdigest()
        here = os.path.join(harness.REPO, "addons", "android")
        files = b"".join(open(os.path.join(here, f), "rb").read() for f in ("rivis_ca.rc", "rivis_ca.sh", "rivis_inject.sh"))
        stock = open(os.path.join(self.root, "sdk", "system-images", "android-36", "google_apis_playstore", "arm64-v8a",
                                  "ramdisk.img"), "rb").read()
        key = sha(("%s %s %s %s" % (sha(stock), pin("MAGISK_APK_SHA256"), sha(files), sha(open(self.ca, "rb").read()))).encode())
        cache = os.path.join(self.state, "android-ramdisk")
        os.makedirs(cache, exist_ok=True)
        patched = os.path.join(cache, key + ".img")
        open(patched, "wb").write(b"patched ramdisk")
        open(patched + ".sha256", "w").write(sha(b"patched ramdisk") + "\n")

    def run_flow(self, *extra, status=None):
        env = dict(os.environ, ADB=self.adb, ANDROID_SDK_ROOT=os.path.join(self.root, "sdk"), ANDROID_AVD_HOME=self.avd_home,
                   FAKE_LOG=self.log, FAKE_DIR=self.root, HOME=self.root)
        if status is not None:
            env["FAKE_STATUS"] = status
        r = subprocess.run(["/bin/bash", SCRIPT, "emulator-5554", self.ca, "c8750f0d.0", self.magisk, self.state, *extra],
                           capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL, timeout=120)
        return r, self.emulator_starts()

    def emulator_starts(self):
        """The emulator is started in the background: wait until its start is logged and no more follow (a fixed
        0.5 s sleep failed when the suite ran four modules at once)."""
        import time
        read = lambda: [l for l in open(self.log).read().splitlines() if l.startswith("emulator ")]
        end, last, steady = time.time() + 10, None, 0
        while time.time() < end:
            now = read()
            steady = steady + 1 if now == last and now else 0
            if steady >= 5:                                           # 0.5 s without a new start
                break
            last = now
            time.sleep(0.1)
        return read()

    def test_review_m5_declined_consent_returns_distinct_code_without_restart(self):
        env = dict(os.environ, ADB=self.adb, ANDROID_SDK_ROOT=os.path.join(self.root, "sdk"),
                   ANDROID_AVD_HOME=self.avd_home, FAKE_LOG=self.log, FAKE_DIR=self.root, HOME=self.root)
        result = subprocess.run(["/bin/bash", SCRIPT, "emulator-5554", self.ca, "c8750f0d.0", self.magisk, self.state],
                                capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL, timeout=30)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("cancelled — nothing changed", result.stderr)
        self.assertNotIn("emu kill", open(self.log).read())

    def test_default_restarts_once_into_the_setup_boot_and_stops_there(self):
        r, starts = self.run_flow("--yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(starts), 1, starts)
        self.assertIn("-ramdisk", starts[0])
        self.assertIn("-no-snapshot-save", starts[0])                 # the rooted boot is never saved as Quick Boot
        self.assertIn("temporary setup boot", r.stdout)

    def test_strict_goes_back_to_the_stock_boot_at_once(self):
        r, starts = self.run_flow("--yes", "--strict")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sorted("-ramdisk" in x for x in starts), [False, True], starts)   # one patched boot, one normal

    def test_a_failed_setup_always_goes_back_to_the_stock_boot(self):
        r, starts = self.run_flow("--yes", status="fail: no cert")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(sorted("-ramdisk" in x for x in starts), [False, True], starts)

    def test_restore_restarts_normally_without_needing_magisk(self):
        shutil.rmtree(self.magisk)
        env = dict(os.environ, ADB=self.adb, ANDROID_SDK_ROOT=os.path.join(self.root, "sdk"), ANDROID_AVD_HOME=self.avd_home,
                   FAKE_LOG=self.log, FAKE_DIR=self.root, HOME=self.root)
        r = subprocess.run(["/bin/bash", SCRIPT, "emulator-5554", self.ca, "c8750f0d.0", "-", self.state, "--restore"],
                           capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL, timeout=120)
        starts = self.emulator_starts()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(starts), 1, starts)
        self.assertNotIn("-ramdisk", starts[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
