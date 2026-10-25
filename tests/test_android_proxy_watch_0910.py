"""Pilot 2026-10-21: "after a cold boot the proxy setting reverted and had to be fixed by hand". `android on` lists the
AVD it pointed at this proxy, `android off` unlists it, and the running proxy puts the setting back on a listed emulator
that comes back with no proxy at all. An emulator pointed at another tool is left alone.
tests/fakes/emulator_adb.py plays the emulator.

  bash tests/run.sh --fast -k test_android_proxy_watch_0910
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness                                          # noqa: E402
from test_cli import CliBase                            # noqa: E402

sys.path.insert(0, os.path.join(harness.REPO, "addons"))
import devices                                          # noqa: E402

FAKE_ADB = os.path.join(harness.REPO, "tests", "fakes", "emulator_adb.py")


class Emulator(CliBase):
    def setUp(self):
        super().setUp()
        self.emu = os.path.join(self.home, "emu")
        os.makedirs(os.path.join(self.emu, "cacerts"))
        open(os.path.join(self.emu, "root"), "w").close()               # a Google APIs image: the CA goes in by adb root
        open(os.path.join(self.emu, "avd"), "w").write("Pixel_Test")
        self.env = dict(self.env, ADB=FAKE_ADB, FAKE_EMU=self.emu)
        self.marks = os.path.join(self.state, "android-proxy")

    def proxy(self, value=None):
        path = os.path.join(self.emu, "proxy")
        if value is not None:
            open(path, "w").write(value)
        return open(path).read().strip() if os.path.exists(path) else ":0"

    def listed(self):
        return open(self.marks).read().split() if os.path.exists(self.marks) else []

    def restore(self, port):
        old = os.environ.get("FAKE_EMU")
        os.environ["FAKE_EMU"] = self.emu
        try:
            return devices.restore_android_proxy(FAKE_ADB, self.state, port)
        finally:
            if old is None:
                os.environ.pop("FAKE_EMU", None)
            else:
                os.environ["FAKE_EMU"] = old


class AndroidProxyStays(Emulator):
    def test_android_on_lists_the_emulator_and_off_unlists_it(self):
        self.ok("android", "on")
        self.assertEqual(self.listed(), ["Pixel_Test"])
        self.ok("android", "on")
        self.assertEqual(self.listed(), ["Pixel_Test"], "listed once")
        self.ok("android", "off")
        self.assertEqual(self.listed(), [])

    def test_a_listed_emulator_that_lost_its_proxy_gets_it_back(self):
        port = self.env["RIVIS_PORT"]
        self.ok("android", "on")
        self.proxy(":0")                                                 # what a cold boot from an older snapshot shows
        self.assertEqual(self.restore(port), [("emulator-5554", "Pixel_Test")])
        self.assertEqual(self.proxy(), "10.0.2.2:" + port)
        self.assertEqual(self.restore(port), [], "nothing to do while it is set")

    def test_another_tools_proxy_and_an_unlisted_emulator_are_left_alone(self):
        port = self.env["RIVIS_PORT"]
        self.ok("android", "on")
        self.proxy("10.0.2.2:9090")                                      # the tester pointed it at another tool
        self.assertEqual(self.restore(port), [])
        self.assertEqual(self.proxy(), "10.0.2.2:9090")
        self.ok("android", "off")                                        # turned off on purpose: never turned back on
        self.proxy(":0")
        self.assertEqual(self.restore(port), [])
        self.assertEqual(self.proxy(), ":0")

    @unittest.skipUnless(os.access(harness.PWSH, os.X_OK), "portable pwsh not found")
    def test_powershell_edition_keeps_the_same_list(self):
        bindir = os.path.join(self.home, "adb-bin")
        os.makedirs(bindir, exist_ok=True)
        os.symlink(FAKE_ADB, os.path.join(bindir, "adb"))
        env = dict(self.env, PATH=bindir + ":" + self.env["PATH"])
        run = lambda *a: self.suite.run([harness.PWSH, "-NoProfile", "-NonInteractive", "-File",
                                         os.path.join(harness.REPO, "rivis.ps1")] + list(a), home=self.home, env=env, timeout=120)
        r = run("android", "on")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.listed(), ["Pixel_Test"])
        r = run("android", "off")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.listed(), [])


class RunningProxyPutsItBack(unittest.TestCase):
    """The same, end to end: a running Rivis notices on its own and the panel state reports it."""

    def test_the_running_proxy_restores_a_listed_emulator(self):
        suite = harness.Suite.get()
        home = suite.new_home("androidwatch")
        emu = os.path.join(home, "emu")
        os.makedirs(os.path.join(emu, "cacerts"))
        open(os.path.join(emu, "avd"), "w").write("Pixel_Test")
        open(os.path.join(emu, "proxy"), "w").write(":0")               # came back from a cold boot without it

        def listed(inst):
            os.makedirs(os.path.join(inst.home, ".rivis"), exist_ok=True)
            open(os.path.join(inst.home, ".rivis", "android-proxy"), "w").write("Pixel_Test\n")

        inst = harness.Instance(suite, "androidwatch", pre=listed,
                                extra_env={"ADB": FAKE_ADB, "FAKE_EMU": emu, "RIVIS_ANDROID_WATCH_SECONDS": "1"}).start()
        self.addCleanup(inst.stop)
        want = "10.0.2.2:%d" % inst.proxy_port
        harness.wait_for(lambda: open(os.path.join(emu, "proxy")).read().strip() == want, 15, 0.3, "the proxy put back")
        restored = harness.wait_for(lambda: inst.panel.state().get("android_restored"), 5, 0.3, "reported to the panel")
        self.assertEqual((restored[-1]["serial"], restored[-1]["avd"]), ("emulator-5554", "Pixel_Test"))


if __name__ == "__main__":
    unittest.main()
