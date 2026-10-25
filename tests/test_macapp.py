"""Native window packaging and one-time UI links."""
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import LiveCase, REPO, RIVIS, Suite
from test_new_ui_routes import get, opener


@unittest.skipUnless(shutil.which("swiftc"), "swiftc is not on PATH")
class MacAppBuild(unittest.TestCase):
    def test_allow_list_menu_sends_the_window_command(self):
        with open(os.path.join(REPO, 'addons', 'macapp', 'RivisApp.swift')) as source:
            swift = source.read()
        self.assertIn('command("Allow List", "allow", to: tools, key: "a", modifiers: [.command, .option])', swift)
        with open(os.path.join(REPO, 'addons', 'ui', 'app.js')) as source:
            script = source.read()
        self.assertIn('else if (detail === "allow") openAllowList();', script)

    def test_local_navigation_and_download_names(self):
        with tempfile.TemporaryDirectory(prefix="rivis-window-policy-") as folder:
            main = os.path.join(folder, "main.swift")
            with open(main, "w") as file:
                with open(os.path.join(REPO, "addons/macapp/RivisApp.swift")) as source:
                    file.write(source.read())
                file.write("""
let window = RivisApp()
window.allowedPort = 12345
let localBlob = URL(string: "blob:http://127.0.0.1:12345/abc")!
let remoteBlob = URL(string: "blob:https://example.test/abc")!
let localLink = URL(string: "http://127.0.0.1:12345/rivis/")!
let remoteLink = URL(string: "https://example.test/")!
let fileLink = URL(fileURLWithPath: "/tmp/untrusted")
let folder = URL(fileURLWithPath: CommandLine.arguments[1])
let existing = folder.appendingPathComponent("capture.har")
try! Data().write(to: existing)
let pending = folder.appendingPathComponent("capture 2.har")
guard window.isAllowedBlob(localBlob), !window.isAllowedBlob(remoteBlob),
      window.canChooseFile(from: localLink), !window.canChooseFile(from: remoteLink),
      !window.canChooseFile(from: nil),
      window.canOpenExternalLink(remoteLink, activated: true),
      !window.canOpenExternalLink(remoteLink, activated: false),
      !window.canOpenExternalLink(fileLink, activated: true),
      window.shouldDownloadResponse(disposition: "  Attachment; filename=capture.har", canShowMIMEType: true),
      window.shouldDownloadResponse(disposition: "inline", canShowMIMEType: false),
      !window.shouldDownloadResponse(disposition: "inline", canShowMIMEType: true),
      window.destination(for: "capture.har", in: folder, reserved: [pending]).lastPathComponent == "capture 3.har",
      window.destination(for: "", in: folder, reserved: []).lastPathComponent == "Download",
      !window.isAllowedBlob(localLink) else { exit(1) }
""")
            binary = os.path.join(folder, "runner")
            build = subprocess.run(["swiftc", "-D", "RIVIS_TEST", main, "-o", binary,
                                    "-framework", "AppKit", "-framework", "WebKit"],
                                   capture_output=True, text=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run([binary, folder], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_cli_runner_drains_stderr_while_waiting_for_stdout(self):
        with tempfile.TemporaryDirectory(prefix="rivis-cli-pipes-") as folder:
            fake = os.path.join(folder, "fake-cli")
            with open(fake, "w") as file:
                file.write("#!/bin/sh\nhead -c 131072 /dev/zero >&2\nprintf 'http://127.0.0.1:12345/ready\\n'\n")
            os.chmod(fake, 0o755)
            main = os.path.join(folder, "main.swift")
            with open(main, "w") as file:
                with open(os.path.join(REPO, "addons/macapp/RivisApp.swift")) as source:
                    file.write(source.read())
                file.write("\n")
                file.write("""import Foundation
let result = RivisApp().runCLI([], using: CommandLine.arguments[1])
guard result.0 == 0, result.1 == "http://127.0.0.1:12345/ready\\n", result.2.count == 131072 else { exit(1) }
""")
            binary = os.path.join(folder, "runner")
            build = subprocess.run(["swiftc", "-D", "RIVIS_TEST", main, "-o", binary,
                                    "-framework", "AppKit", "-framework", "WebKit"],
                                   capture_output=True, text=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run([binary, fake], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_delegate_compiles_in_swift6_mode(self):
        version = subprocess.run(["swiftc", "-version"], capture_output=True, text=True)
        if not re.search(r"Swift version ([6-9]|[1-9][0-9])\.", version.stdout):
            self.skipTest("Swift 6 is unavailable")
        source = os.path.join(REPO, "addons", "macapp", "RivisApp.swift")
        result = subprocess.run(["swiftc", "-swift-version", "6", "-typecheck", source,
                                 "-framework", "AppKit", "-framework", "WebKit"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_builds_signed_bundle(self):
        with tempfile.TemporaryDirectory(prefix="rivis-app-build-") as folder:
            result = subprocess.run(["bash", os.path.join(REPO, "addons/macapp/build.sh"), folder],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            app = os.path.join(folder, "Rivis.app")
            self.assertEqual(result.stdout.strip(), app)
            self.assertTrue(os.path.isfile(os.path.join(app, "Contents/MacOS/Rivis")))
            with open(os.path.join(app, "Contents/Info.plist"), "rb") as file:
                self.assertEqual(plistlib.load(file)["CFBundleIdentifier"], "io.rivis.app")
            signed = subprocess.run(["codesign", "-v", app], capture_output=True, text=True)
            self.assertEqual(signed.returncode, 0, signed.stderr)


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("swiftc"), "native Mac build unavailable")
class MacAppCommand(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()

    def setUp(self):
        self.home = self.suite.new_home("macapp")
        self.env = self.suite.cli_env(self.home)
        self.app = os.path.join(self.home, ".rivis", "app", "Rivis.app")
        self.binary = os.path.join(self.app, "Contents", "MacOS", "Rivis")

    def cli(self, *args):
        result = self.suite.rivis("app", *args, home=self.home, env=self.env, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_build_rebuild_and_open_environment(self):
        self.assertEqual(self.cli("--build").stdout.strip(), self.app)
        self.assertTrue(os.path.isfile(self.binary))
        os.utime(self.binary, (1, 1))
        self.assertEqual(self.cli("--build").stdout.strip(), self.app)
        self.assertGreater(os.stat(self.binary).st_mtime, 1, "--build must rebuild an existing bundle")

        before = os.stat(self.binary).st_mtime_ns
        log_before = self.suite.shim_log("open.log")
        self.cli()
        self.assertEqual(os.stat(self.binary).st_mtime_ns, before, "current binary should be reused")
        opened = self.suite.shim_log("open.log")[len(log_before):]
        self.assertIn("--env RIVIS_CLI=" + os.path.realpath(RIVIS), opened)
        self.assertIn("--env PATH=" + self.env["PATH"], opened)
        self.assertIn(self.app, opened)

        os.utime(self.binary, (1, 1))
        self.cli()
        self.assertGreater(os.stat(self.binary).st_mtime, 1, "stale source must rebuild")
        os.unlink(self.binary)
        self.cli()
        self.assertTrue(os.path.isfile(self.binary), "missing binary must rebuild")


class MacAppLinks(LiveCase):
    def base(self):
        return "http://127.0.0.1:%d" % self.inst.web_port

    def test_new_ui_url_is_one_line_and_signs_in_fresh_browser(self):
        before = self.suite.shim_log("open.log")
        result = self.suite.rivis("ui", "--new", "--url", home=self.inst.home, env=self.inst.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"\Ahttp://127\.0\.0\.1:\d+/proxy/bootstrap/[0-9a-f]{32}\?next=rivis\n\Z")
        self.assertEqual(self.suite.shim_log("open.log"), before)
        status, _, _, final = get(opener(), result.stdout.strip())
        self.assertEqual((status, final), (200, self.base() + "/rivis/"))

    def test_classic_ui_url_is_one_line(self):
        before = self.suite.shim_log("open.log")
        result = self.suite.rivis("ui", "--classic", "--url", home=self.inst.home, env=self.inst.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"\Ahttp://127\.0\.0\.1:\d+/proxy/bootstrap/[0-9a-f]{32}\n\Z")
        self.assertEqual(self.suite.shim_log("open.log"), before)
        status, _, _, final = get(opener(), result.stdout.strip())
        self.assertEqual((status, final), (200, self.base() + "/"))

    def test_plain_ui_url_opens_the_new_window(self):
        result = self.suite.rivis("ui", "--url", home=self.inst.home, env=self.inst.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.strip().endswith("?next=rivis"))
        status, _, _, final = get(opener(), result.stdout.strip())
        self.assertEqual((status, final), (200, self.base() + "/rivis/"))
