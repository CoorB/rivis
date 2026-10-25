"""Installer (install.sh) and release builder (make-release.sh): dry-run changes nothing, real install into a fake HOME is
idempotent and reversible, hash pins are enforced, releases carry no state/secrets."""
import hashlib
import os
import pty
import select
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import Suite

INSTALL = os.path.join(harness.REPO, "install", "install.sh")
MAKE_RELEASE = os.path.join(harness.REPO, "install", "mirror", "make-release.sh")


def snapshot(root):
    """{relative path: (type, mode, size, sha1-of-content or link target)} for every entry under root."""
    out = {}
    for base, dirs, files in os.walk(root):
        for name in dirs + files:
            p = os.path.join(base, name)
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                detail = os.readlink(p)
            elif stat.S_ISREG(st.st_mode):
                detail = hashlib.sha1(open(p, "rb").read()).hexdigest()
            else:
                detail = ""
            out[os.path.relpath(p, root)] = (stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_size, detail)
    return out


class InstallerBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()

    def setUp(self):
        self.home = self.suite.new_home("inst")
        with open(os.path.join(self.home, ".zshrc"), "w") as fh:
            fh.write("# mine\nexport A=1\n")

    def install(self, *args, env=None, timeout=240, bin=None):
        env = env or self.suite.env(self.home)
        shim = os.path.join(self.suite.root, "shim", "mitmdump")
        if "--uninstall" not in args and "--help" not in args and os.path.isfile(shim) \
                and os.path.join(self.suite.root, "shim") in env.get("PATH", "").split(":"):
            args = args + ("--trust-mitmdump", shim)   # the hermetic shim is unsigned (F-10 refuses it otherwise)
        return self.suite.run(["/bin/bash", bin or INSTALL] + list(args), home=self.home, env=env, timeout=timeout)

    def ok(self, *args, **kw):
        cp = self.install(*args, **kw)
        self.assertEqual(cp.returncode, 0, "install %s -> %s\n%s\n%s" % (args, cp.returncode, cp.stdout[-1500:], cp.stderr[-800:]))
        return cp


class DryRun(InstallerBase):
    def test_intel_architecture_uses_the_pinned_x86_64_release(self):
        fakebin = os.path.join(self.home, "fake-intel-bin")
        os.makedirs(fakebin)
        uname = os.path.join(fakebin, "uname")
        with open(uname, "w") as fh:
            fh.write('#!/bin/sh\n[ "$1" = "-m" ] && { echo x86_64; exit 0; }\nexec /usr/bin/uname "$@"\n')
        os.chmod(uname, 0o755)
        env = self.suite.env(self.home, extra={"PATH": fakebin + ":/usr/bin:/bin:/usr/sbin:/sbin"})
        out = self.ok("--dry-run", "--allow-official", env=env).stdout
        self.assertIn("mitmproxy-12.2.3-macos-x86_64.tar.gz", out)
        self.assertIn("x86_64", out)
        pins = open(os.path.join(harness.REPO, "addons", "android", "magisk.pins")).read()
        self.assertNotIn("MACOS_ARM64", pins)

    def test_dry_run_changes_nothing_in_home(self):
        before = snapshot(self.home)
        for args in (["--dry-run"], ["--dry-run", "--yes", "--no-rc"], ["--dry-run", "--skip-local-capture"],
                     ["--uninstall", "--dry-run"]):
            cp = self.ok(*args)
            self.assertIn("dry run finished", cp.stdout) if "--uninstall" not in args else None
            self.assertEqual(snapshot(self.home), before, args)
        self.assertEqual(sorted(os.listdir(self.home)), [".zshrc"])

    def test_dry_run_prints_the_plan_and_the_safety_promises(self):
        out = self.ok("--dry-run").stdout
        for needle in ("plan:", "no sudo, no system proxy changes", "127.0.0.1", "nothing changed"):
            self.assertIn(needle, out)

    def test_dry_run_never_calls_networksetup_or_sudo(self):
        self.ok("--dry-run")
        self.assertNotIn("-set", self.suite.shim_log("networksetup.log"))
        src = open(INSTALL).read()
        self.assertNotRegex(src.replace("sudo", "sudo", 1), r"(^|[;&|]\s*)sudo\s", "install.sh must not call sudo")

    def test_unknown_option_and_missing_values_exit_2(self):
        for args in (["--bogus"], ["--from-mirror"], ["--tool-tarball"], ["--mitmproxy-tarball"]):
            cp = self.install(*args)
            self.assertEqual(cp.returncode, 2, args)
        self.assertEqual(self.install("--help").returncode, 0)

    def test_official_download_requires_explicit_opt_in(self):
        env = self.suite.env(self.home, extra={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"})
        cp = self.install("--dry-run", env=env)
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("--allow-official", cp.stdout + cp.stderr)
        cp = self.install("--dry-run", "--allow-official", env=env)
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("explicitly allowed", cp.stdout)

    def test_a_mitmdump_that_only_claims_the_pinned_version_is_not_reused(self):
        """F-10: a fake `mitmdump` printing the right version must not be trusted; the signed cask still is."""
        fake_bin = os.path.join(self.home, "fakebin")
        os.makedirs(fake_bin)
        fake = os.path.join(fake_bin, "mitmdump")
        with open(fake, "w") as fh:
            fh.write("#!/bin/sh\necho 'Mitmproxy: 12.2.3'\n")
        os.chmod(fake, 0o755)
        env = self.suite.env(self.home, extra={"PATH": fake_bin + ":/usr/bin:/bin:/usr/sbin:/sbin"})
        cp = self.install("--dry-run", "--allow-official", env=env)
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("not reusing " + fake, cp.stdout)
        self.assertNotIn("reuse (no download)", cp.stdout)
        cask = "/opt/homebrew/Caskroom/mitmproxy/12.2.3/mitmproxy.app/Contents/MacOS"
        if os.path.isdir(cask):      # positive control on machines with the signed Homebrew cask
            env = self.suite.env(self.home, extra={"PATH": cask + ":/usr/bin:/bin:/usr/sbin:/sbin"})
            self.assertIn("reuse (no download)", self.ok("--dry-run", env=env).stdout)

    def test_installer_bundle_carries_product_identity(self):
        bundle = os.path.join(self.suite.root, "installer-bundle")
        os.makedirs(bundle)
        for name in ("install.sh", "install.ps1", "VERSION", "mirror.conf", "product.json"):
            shutil.copy2(os.path.join(harness.REPO, "install", name), os.path.join(bundle, name))
        cp = self.install("--dry-run", "--from-mirror", "https://mirror.example", bin=os.path.join(bundle, "install.sh"))
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("Rivis (rivis)", cp.stdout)

    def test_installer_source_has_no_eval_and_copies_local_archives_before_verification(self):
        src = open(INSTALL).read()
        self.assertNotRegex(src, r"(?m)^\s*eval\s")
        self.assertNotRegex(open(harness.RIVIS).read(), r"(?m)^\s*eval\s")
        self.assertIn('cp "$MITM_TARBALL" "$TMP/mitm-local.tar.gz"', src)
        self.assertIn('cp "$TOOL_TARBALL" "$TMP/tool-local.tar.gz"', src)

    def test_unverified_tool_metadata_is_never_extracted_or_evaluated(self):
        """F-02: product.json from a bad archive cannot run before SHA-256 verification."""
        stage = os.path.join(self.suite.root, "standalone-installer")
        os.makedirs(os.path.join(stage, "install"))
        for name in ("install.sh", "VERSION", "mirror.conf"):
            shutil.copy2(os.path.join(harness.REPO, "install", name), os.path.join(stage, "install", name))
        marker = os.path.join(self.suite.root, "F02-PWNED")
        archive = os.path.join(self.suite.root, "evil-product.tar.gz")
        payload = os.path.join(self.suite.root, "evil-product")
        os.makedirs(os.path.join(payload, "rivis-evil"))
        product = {"name": "Rivis", "cli": "rivis",
                   "env_prefix": "X_CONFDIR:-}; touch %s; : ${Y" % marker,
                   "state_dir": "~/.rivis"}
        import json
        with open(os.path.join(payload, "rivis-evil", "product.json"), "w") as fh:
            json.dump(product, fh)
        with tarfile.open(archive, "w:gz") as tf:
            tf.add(os.path.join(payload, "rivis-evil"), arcname="rivis-evil")
        cp = self.install("--dry-run", "--tool-tarball", archive,
                          bin=os.path.join(stage, "install", "install.sh"))
        self.assertNotEqual(cp.returncode, 0)
        self.assertRegex(cp.stdout + cp.stderr, r"no pinned SHA-256|MISMATCH")
        self.assertFalse(os.path.exists(marker), "unverified env_prefix executed")


class RealInstall(InstallerBase):
    def test_uninstall_keeps_an_unowned_launcher(self):
        link = os.path.join(self.home, ".local", "bin", "rivis")
        os.makedirs(os.path.dirname(link), exist_ok=True)
        with open(link, "w") as fh:
            fh.write("#!/bin/sh\necho user-owned\n")
        self.ok("--uninstall", "--yes")
        self.assertEqual(open(link).read(), "#!/bin/sh\necho user-owned\n")

    def test_installed_path_with_spaces_is_detected_on_uninstall(self):
        self.home = self.suite.new_home("installer path with spaces")
        self.ok("--yes", "--skip-local-capture")
        link = os.path.join(self.home, ".local", "bin", "rivis")
        port, web = harness.free_port(), harness.free_port()
        env = self.suite.env(self.home, extra={"RIVIS_PORT": str(port), "RIVIS_WEB_PORT": str(web)})
        try:
            result = self.suite.run([link, "start", "--background", "--no-open", "--no-ios"], home=self.home, env=env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(harness.port_open(web))
            self.ok("--uninstall", "--yes", env=env)
            self.assertFalse(harness.port_open(web))
        finally:
            if harness.port_open(web):
                self.suite.rivis("stop", home=self.home, env=env)
    def test_review_m4_interactive_default_start_removes_temp_dir(self):
        stage = os.path.join(self.home, "release")
        shutil.copytree(harness.REPO, stage, ignore=shutil.ignore_patterns(".git", "tests", "__pycache__", ".artifacts"))
        with open(os.path.join(stage, "rivis"), "w") as fh:
            fh.write("#!/bin/bash\necho \"started $*\" >> \"$HOME/start.log\"\n")
        os.chmod(os.path.join(stage, "rivis"), 0o755)
        mitm = os.path.join(self.home, ".local", "rivis", "mitmproxy-12.2.3",
                            "mitmproxy.app", "Contents", "MacOS", "mitmdump")
        os.makedirs(os.path.dirname(mitm))
        with open(mitm, "w") as fh:
            fh.write("#!/bin/sh\necho 'Mitmproxy: 12.2.3'\n")
        os.chmod(mitm, 0o755)
        shutil.copytree(self.suite.ca_dir, os.path.join(self.home, ".mitmproxy"))
        env = self.suite.env(self.home, extra={"SKIP_CLT_CHECK": "1"})
        master, slave = pty.openpty()
        proc = subprocess.Popen(["/bin/bash", os.path.join(stage, "install", "install.sh")],
                                env=env, cwd=self.suite.root, stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        output = b""
        try:
            deadline = time.monotonic() + 60
            while proc.poll() is None and time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.2)
                if ready:
                    try:
                        output += os.read(master, 8192)
                    except OSError:
                        break
                    if b"Start Rivis now" in output:
                        os.write(master, b"\n")
                        output = output.replace(b"Start Rivis now", b"Start prompt answered")
            self.assertEqual(proc.wait(timeout=3), 0, output.decode(errors="replace")[-2000:])
            self.assertIn("started start --background", open(os.path.join(self.home, "start.log")).read())
            self.assertFalse([n for n in os.listdir(env["TMPDIR"]) if n.startswith("rivis-inst.")])
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            os.close(master)

    def test_interrupt_during_ca_generation_stops_helper(self):
        shim_dir = os.path.join(self.home, "ca-shim")
        os.makedirs(shim_dir)
        helper = os.path.join(shim_dir, "mitmdump")
        pid_file = os.path.join(self.home, "ca-helper.pid")
        with open(helper, "w") as fh:
            fh.write('#!/bin/sh\n'
                     'if [ "$1" = --version ]; then echo "Mitmproxy: 12.2.3"; exit 0; fi\n'
                     'echo $$ > "$CA_HELPER_PID"\n'
                     'exec /bin/sleep 60\n')
        os.chmod(helper, 0o755)
        env = self.suite.env(self.home, extra={"CA_HELPER_PID": pid_file})
        env["PATH"] = shim_dir + ":" + env["PATH"]
        process = subprocess.Popen(["/bin/bash", INSTALL, "--yes", "--no-rc", "--skip-local-capture",
                                    "--trust-mitmdump", helper], env=env, cwd=self.suite.root,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        helper_pid = None
        try:
            harness.wait_for(lambda: os.path.isfile(pid_file), timeout=15, desc="CA helper to start")
            helper_pid = int(open(pid_file).read())
            os.kill(process.pid, signal.SIGTERM)
            process.communicate(timeout=10)
            self.assertEqual(process.returncode, 130)
            def helper_stopped():
                try:
                    os.kill(helper_pid, 0)
                except ProcessLookupError:
                    return True
                return False
            harness.wait_for(helper_stopped, timeout=3, desc="CA helper to stop after interrupt")
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)
            if helper_pid is not None:
                try:
                    os.kill(helper_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_install_is_idempotent_private_and_reversible(self):
        self.ok("--yes", "--skip-local-capture")
        launcher = os.path.join(self.home, ".local", "bin", "rivis")
        self.assertTrue(os.access(launcher, os.X_OK))
        rc = open(os.path.join(self.home, ".zshrc")).read()
        self.assertTrue(rc.startswith("# mine\nexport A=1\n"))                # user content preserved, block appended
        self.assertEqual(rc.count(">>> proxy-tool installer (managed) >>>"), 1)
        self.assertEqual(rc.count("<<< proxy-tool installer (managed) <<<"), 1)
        for p in (".mitmproxy/mitmproxy-ca.pem", ".local/rivis/install-receipt"):
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.home, p)).st_mode), 0o600, p)
        first = snapshot(self.home)
        self.ok("--yes", "--skip-local-capture")                               # second run
        rc2 = open(os.path.join(self.home, ".zshrc")).read()
        self.assertEqual(rc2.count(">>> proxy-tool installer (managed) >>>"), 1)
        ca = os.path.join(self.home, ".mitmproxy", "mitmproxy-ca.pem")
        self.assertEqual(first[os.path.relpath(ca, self.home)], snapshot(self.home)[os.path.relpath(ca, self.home)])   # CA kept
        cp = subprocess.run([launcher, "--help"], env=self.suite.env(self.home), capture_output=True, text=True)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("127.0.0.1", cp.stdout)
        # uninstall: removes binaries, link and rc block; keeps state and the CA
        os.makedirs(os.path.join(self.home, ".rivis", "projects", "default"))
        with open(os.path.join(self.home, ".rivis", "projects", "default", "rules.json"), "w") as fh:
            fh.write('{"rules": []}')
        self.ok("--uninstall", "--yes")
        self.assertFalse(os.path.lexists(launcher))
        self.assertFalse(os.path.lexists(os.path.join(self.home, ".local", "rivis", "current")))
        self.assertEqual(open(os.path.join(self.home, ".zshrc")).read().rstrip("\n"), "# mine\nexport A=1")
        self.assertTrue(os.path.exists(ca))
        self.assertTrue(os.path.exists(os.path.join(self.home, ".rivis", "projects", "default", "rules.json")))
        self.ok("--uninstall", "--yes")                                          # harmless twice

    def test_no_rc_leaves_shell_files_alone(self):
        self.ok("--yes", "--skip-local-capture", "--no-rc")
        self.assertEqual(open(os.path.join(self.home, ".zshrc")).read(), "# mine\nexport A=1\n")

    def test_uninstall_stops_a_running_background_proxy_before_removing_it(self):
        self.ok("--yes", "--skip-local-capture")
        launcher = os.path.join(self.home, ".local", "bin", "rivis")
        port, web = harness.free_port(), harness.free_port()
        env = self.suite.env(self.home, extra={"RIVIS_PORT": str(port), "RIVIS_WEB_PORT": str(web)})
        try:
            started = self.suite.run([launcher, "start", "--background", "--no-open", "--no-ios"],
                                     home=self.home, env=env, timeout=60)
            self.assertEqual(started.returncode, 0, started.stdout + started.stderr)
            self.assertTrue(harness.port_open(port))
            self.ok("--uninstall", "--yes", env=env)
            self.assertFalse(harness.port_open(port), "uninstall left the proxy port listening")
            self.assertFalse(harness.port_open(web), "uninstall left the UI port listening")
        finally:
            if harness.port_open(port) or harness.port_open(web):
                self.suite.rivis("stop", home=self.home, env=env)

    def test_uninstall_stops_every_project_using_this_install(self):
        # R4A-04: deleting tool-* while project B still runs strips its live rules and panel.
        self.ok("--yes", "--skip-local-capture")
        launcher = os.path.join(self.home, ".local", "bin", "rivis")
        pairs = [(harness.free_port(), harness.free_port()) for _ in range(2)]
        envs = [self.suite.env(self.home, extra={"RIVIS_PORT": str(p), "RIVIS_WEB_PORT": str(w)}) for p, w in pairs]
        try:
            for env in envs:
                started = self.suite.run([launcher, "start", "--background", "--no-open", "--no-ios"], home=self.home, env=env, timeout=60)
                self.assertEqual(started.returncode, 0, started.stdout + started.stderr)
            self.assertTrue(all(harness.port_open(p) and harness.port_open(w) for p, w in pairs))
            out = self.ok("--uninstall", "--yes", env=envs[0]).stdout
            self.assertEqual(out.count("stopped pid"), 2, out)
            self.assertTrue(all(not harness.port_open(p) and not harness.port_open(w) for p, w in pairs))
        finally:
            for env in envs:
                self.suite.rivis("stop", home=self.home, env=env)

    def test_uninstall_prints_separate_ca_cleanup_command(self):
        # R4A-06: saved state and the CA live in different directories.
        out = self.ok("--uninstall", "--dry-run").stdout
        self.assertIn('rm -rf "%s"' % os.path.join(self.home, ".rivis"), out)
        self.assertIn('To remove the CA and private key too:  rm -rf "%s"' % os.path.join(self.home, ".mitmproxy"), out)

    def test_upgrade_restarts_the_old_tool_directory_on_saved_ports(self):
        # R4A-01: a new launcher version must not leave an old tool's add-ons serving traffic.
        self.ok("--yes", "--skip-local-capture")
        root = os.path.join(self.home, ".local", "rivis")
        current = os.path.join(root, "current")
        new_tool = os.path.realpath(current)
        old_tool = os.path.join(root, "tool-0.9.4")
        shutil.copytree(new_tool, old_tool)
        with open(os.path.join(old_tool, "VERSION"), "w") as fh: fh.write("0.9.4\n")
        os.unlink(current); os.symlink(old_tool, current)
        launcher = os.path.join(self.home, ".local", "bin", "rivis")
        port, web = harness.free_port(), harness.free_port()
        env = self.suite.env(self.home, extra={"RIVIS_PORT": str(port), "RIVIS_WEB_PORT": str(web)})
        try:
            started = self.suite.run([launcher, "start", "--background", "--no-open", "--no-ios"], home=self.home, env=env, timeout=60)
            self.assertEqual(started.returncode, 0, started.stdout + started.stderr)
            self.assertIn("0.9.4", self.suite.run([os.path.join(new_tool, "rivis"), "status"], home=self.home, env=env).stderr)
            self.assertIn("0.9.4", self.suite.run([os.path.join(new_tool, "rivis"), "start", "--no-open", "--no-ios"], home=self.home, env=env).stderr)
            out = self.ok("--yes", "--skip-local-capture", env=env).stdout
            self.assertIn("restarted :%d/:%d" % (port, web), out)
            self.assertTrue(harness.port_open(port) and harness.port_open(web))
            status = self.suite.run([launcher, "status"], home=self.home, env=env)
            self.assertEqual(status.returncode, 0, status.stdout + status.stderr)
            self.assertNotIn("running pid", status.stderr)
        finally:
            self.suite.rivis("stop", home=self.home, env=env, bin=launcher)

    def test_upgrade_restart_is_health_checked(self):
        # an upgrade must not report success on "it started": the proxy and panel must answer, on the new version
        self.ok("--yes", "--skip-local-capture")
        launcher = os.path.join(self.home, ".local", "bin", "rivis")
        port, web = harness.free_port(), harness.free_port()
        env = self.suite.env(self.home, extra={"RIVIS_PORT": str(port), "RIVIS_WEB_PORT": str(web)})
        try:
            self.assertEqual(self.suite.run([launcher, "health"], home=self.home, env=env).returncode, 3)
            started = self.suite.run([launcher, "start", "--background", "--no-open", "--no-ios"], home=self.home, env=env, timeout=60)
            self.assertEqual(started.returncode, 0, started.stdout + started.stderr)
            out = self.ok("--yes", "--skip-local-capture", env=env).stdout
            self.assertIn("health check :%d/:%d ok" % (port, web), out)
            health = self.suite.run([launcher, "health"], home=self.home, env=env)
            self.assertEqual(health.returncode, 0, health.stdout + health.stderr)
            self.assertIn("healthy", health.stdout)
        finally:
            self.suite.rivis("stop", home=self.home, env=env, bin=launcher)

    def test_rollback_goes_back_one_version_restarts_with_the_same_options_and_can_be_undone(self):
        self.ok("--yes", "--skip-local-capture")
        root = os.path.join(self.home, ".local", "rivis")
        current = os.path.join(root, "current")
        new_tool = os.path.realpath(current)
        new_version = open(os.path.join(new_tool, "VERSION")).read().strip()
        old_tool = os.path.join(root, "tool-0.9.4")
        shutil.copytree(new_tool, old_tool)
        with open(os.path.join(old_tool, "VERSION"), "w") as fh: fh.write("0.9.4\n")
        launcher = os.path.join(self.home, ".local", "bin", "rivis")
        port, web = harness.free_port(), harness.free_port()
        env = self.suite.env(self.home, extra={"RIVIS_PORT": str(port), "RIVIS_WEB_PORT": str(web)})
        try:
            listed = self.suite.run([launcher, "rollback", "--list"], home=self.home, env=env)
            self.assertEqual(listed.stdout.split(), ["0.9.4", new_version, "←", "current"])
            started = self.suite.run([launcher, "start", "--background", "--no-open", "--no-ios", "--project", "default"],
                                     home=self.home, env=env, timeout=60)
            self.assertEqual(started.returncode, 0, started.stdout + started.stderr)
            back = self.suite.run([launcher, "rollback"], home=self.home, env=env, timeout=90)
            self.assertEqual(back.returncode, 0, back.stdout + back.stderr)
            self.assertEqual(os.path.realpath(current), os.path.realpath(old_tool))
            self.assertIn("0.9.4 is running and healthy", back.stdout + back.stderr)
            self.assertTrue(harness.port_open(port) and harness.port_open(web))
            again = self.suite.run([launcher, "rollback", new_version], home=self.home, env=env, timeout=90)
            self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
            self.assertEqual(os.path.realpath(current), os.path.realpath(new_tool))
            self.assertEqual(self.suite.run([launcher, "health"], home=self.home, env=env).returncode, 0)
        finally:
            self.suite.rivis("stop", home=self.home, env=env, bin=launcher)

    def test_rollback_to_a_version_without_rollback_shows_and_allows_the_way_forward(self):
        # R8 (cover lane): 0.9.6 has no rollback command, so after going back to it "rivis rollback 0.9.7" did not exist
        self.ok("--yes", "--skip-local-capture")
        root = os.path.join(self.home, ".local", "rivis")
        new_tool = os.path.realpath(os.path.join(root, "current"))
        new_version = open(os.path.join(new_tool, "VERSION")).read().strip()
        old_tool = os.path.join(root, "tool-0.9.4")
        shutil.copytree(new_tool, old_tool)
        with open(os.path.join(old_tool, "VERSION"), "w") as fh: fh.write("0.9.4\n")
        cli = os.path.join(old_tool, "rivis")
        with open(cli) as fh: text = fh.read()
        with open(cli, "w") as fh: fh.write(text.replace("cmd_rollback()", "cmd_rollback_absent()"))   # like 0.9.6
        launcher = os.path.join(self.home, ".local", "bin", "rivis")
        env = self.suite.env(self.home)
        back = self.suite.run([launcher, "rollback"], home=self.home, env=env, timeout=90)
        self.assertEqual(back.returncode, 0, back.stdout + back.stderr)
        hint = "%s/rivis rollback %s" % (new_tool, new_version)
        self.assertIn(hint, back.stdout + back.stderr)
        fwd = self.suite.run([os.path.join(new_tool, "rivis"), "rollback", new_version], home=self.home, env=env, timeout=90)
        self.assertEqual(fwd.returncode, 0, fwd.stdout + fwd.stderr)
        self.assertEqual(os.path.realpath(os.path.join(root, "current")), new_tool)

    def test_rollback_with_nothing_older_installed_explains(self):
        self.ok("--yes", "--skip-local-capture")
        launcher = os.path.join(self.home, ".local", "bin", "rivis")
        r = self.suite.run([launcher, "rollback"], home=self.home, env=self.suite.env(self.home))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no earlier version is installed", r.stdout + r.stderr)
        r = self.suite.run([launcher, "rollback", "0.0.1"], home=self.home, env=self.suite.env(self.home))
        self.assertIn("is not installed", r.stdout + r.stderr)

    def test_reinstall_same_version_while_running_restarts_it(self):
        # R4A-01: replacing the live tool dir would unload its add-ons; stop it, swap, start it again on its ports.
        self.ok("--yes", "--skip-local-capture")
        launcher = os.path.join(self.home, ".local", "bin", "rivis")
        port, web = harness.free_port(), harness.free_port()
        env = self.suite.env(self.home, extra={"RIVIS_PORT": str(port), "RIVIS_WEB_PORT": str(web)})
        try:
            started = self.suite.run([launcher, "start", "--background", "--no-open", "--no-ios"], home=self.home, env=env, timeout=60)
            self.assertEqual(started.returncode, 0, started.stdout + started.stderr)
            out = self.ok("--yes", "--skip-local-capture", env=env).stdout
            self.assertIn("restarted :%d/:%d" % (port, web), out)
            status = self.suite.run([launcher, "status"], home=self.home, env=env)
            self.assertEqual(status.returncode, 0, status.stdout + status.stderr)
        finally:
            self.suite.rivis("stop", home=self.home, env=env, bin=launcher)

    def test_reinstall_restarts_an_instance_whose_start_is_only_in_the_shared_file(self):
        # R7A upgrade: published 0.9.6 saved every port's start in last-start; the per-port lookup refused the upgrade
        self.ok("--yes", "--skip-local-capture")
        launcher = os.path.join(self.home, ".local", "bin", "rivis")
        port, web = harness.free_port(), harness.free_port()
        env = self.suite.env(self.home, extra={"RIVIS_PORT": str(port), "RIVIS_WEB_PORT": str(web)})
        state = os.path.join(self.home, ".rivis")
        try:
            started = self.suite.run([launcher, "start", "--background", "--no-open", "--no-ios"], home=self.home, env=env, timeout=60)
            self.assertEqual(started.returncode, 0, started.stdout + started.stderr)
            os.replace(os.path.join(state, "last-start-%d" % web), os.path.join(state, "last-start"))   # the 0.9.6 layout
            out = self.ok("--yes", "--skip-local-capture", env=env).stdout
            self.assertIn("restarted :%d/:%d" % (port, web), out)
        finally:
            self.suite.rivis("stop", home=self.home, env=env, bin=launcher)

    def test_uninstall_clears_only_this_ports_emulator_proxy(self):
        # B-01: removing the launcher must not strand a running emulator behind this now-dead proxy.
        emu = os.path.join(self.home, "emu")
        os.makedirs(emu)
        adb = os.path.join(harness.REPO, "tests", "fakes", "emulator_adb.py")
        port, web = harness.free_port(), harness.free_port()
        env = self.suite.env(self.home, extra={"ADB": adb, "FAKE_EMU": emu, "RIVIS_PORT": str(port),
                                               "RIVIS_WEB_PORT": str(web)})
        proxy = os.path.join(emu, "proxy")
        with open(proxy, "w") as fh: fh.write("10.0.2.2:%s" % port)
        dry = self.ok("--uninstall", "--dry-run", env=env).stdout
        self.assertIn("would clear", dry)
        self.assertNotIn("cleared, so", dry)
        self.assertEqual(open(proxy).read(), "10.0.2.2:%s" % port)
        self.ok("--uninstall", "--yes", env=env)
        self.assertEqual(open(proxy).read(), ":0")
        with open(proxy, "w") as fh: fh.write("10.0.2.2:%s" % (port + 1))
        self.ok("--uninstall", "--yes", env=env)
        self.assertEqual(open(proxy).read(), "10.0.2.2:%s" % (port + 1))

    def test_an_existing_ca_is_never_replaced(self):
        conf = os.path.join(self.home, ".mitmproxy")
        shutil.copytree(self.suite.ca_dir, conf)
        before = snapshot(conf)
        self.ok("--yes", "--skip-local-capture")
        after = snapshot(conf)
        for name in ("mitmproxy-ca.pem", "mitmproxy-ca-cert.pem"):
            self.assertEqual(before[name], after[name], name)

    def test_never_changes_the_system_proxy_and_never_listens_beyond_loopback(self):
        self.ok("--yes", "--skip-local-capture")
        log = self.suite.shim_log("networksetup.log")
        self.assertNotRegex(log, r"-set|REFUSED")
        self.assertNotIn("0.0.0.0", open(INSTALL).read().replace("beyond 0.0.0.0", ""))

    def test_fish_path_block_is_written_to_fish_config_and_removed(self):
        env = self.suite.env(self.home, extra={"SHELL": "/opt/homebrew/bin/fish"})
        self.ok("--yes", "--skip-local-capture", env=env)
        fish = os.path.join(self.home, ".config", "fish", "config.fish")
        self.assertIn("set -gx PATH", open(fish).read())
        self.ok("--uninstall", "--yes", env=env)
        self.assertNotIn("proxy-tool installer", open(fish).read())


class Pins(InstallerBase):
    def test_unpinned_or_wrong_tool_tarball_is_refused(self):
        bogus = os.path.join(self.suite.root, "bogus.tar.gz")
        with tarfile.open(bogus, "w:gz") as tf:
            info = tarfile.TarInfo("rivis-0.9.0/evil")
            info.size = 0
            tf.addfile(info)
        cp = self.install("--yes", "--tool-tarball", bogus, "--skip-local-capture")
        self.assertNotEqual(cp.returncode, 0)
        self.assertRegex(cp.stdout + cp.stderr, r"no pinned SHA-256|MISMATCH")
        self.assertFalse(os.path.exists(os.path.join(self.home, ".local", "rivis", "current")))

    def test_pinned_hash_mismatch_is_refused_for_both_artifacts(self):
        stage = os.path.join(self.suite.root, "pin-stage")
        shutil.copytree(harness.REPO, stage, ignore=shutil.ignore_patterns("tests", ".git", "__pycache__"))
        conf = os.path.join(stage, "install", "mirror.conf")
        text = open(conf).read().replace("TOOL_SHA256=", "TOOL_SHA256=" + "0" * 64, 1)
        open(conf, "w").write(text)
        bogus = os.path.join(self.suite.root, "bogus2.tar.gz")
        with open(bogus, "wb") as fh:
            fh.write(b"not a tarball")
        cp = self.install("--yes", "--tool-tarball", bogus, "--skip-local-capture", bin=os.path.join(stage, "install", "install.sh"))
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("MISMATCH", cp.stdout + cp.stderr)
        # no mitmproxy on PATH → needs the tarball → pinned hash must refuse a wrong file
        env = self.suite.env(self.home, extra={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"})
        cp = self.install("--yes", "--mitmproxy-tarball", bogus, "--skip-local-capture", env=env)
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("MISMATCH", cp.stdout + cp.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.home, ".local", "rivis", "current")))

    def test_mirror_conf_pins_every_macos_artifact_with_a_sha256(self):
        conf = dict(line.split("=", 1) for line in open(os.path.join(harness.REPO, "install", "mirror.conf")).read().splitlines()
                    if "=" in line and not line.startswith("#"))
        self.assertEqual(conf["MITMPROXY_VERSION"], "12.2.3")
        for key in ("MITMPROXY_SHA256_MACOS_ARM64", "MITMPROXY_SHA256_MACOS_X86_64"):
            self.assertRegex(conf[key], r"^[0-9a-f]{64}$", key)
        self.assertNotIn("http://", open(os.path.join(harness.REPO, "install", "mirror.conf")).read())


class Release(unittest.TestCase):
    EXCLUDED_NAMES = ["rules.json", "web-token", "current-project", "a.har", "x.diff", "y.snapshot", "zz-snapshot-1", ".DS_Store",
                      "a.pyc", "m.json", "n.flows", "f.orig", "f.rej", "f.bak", "old.pre-fix"]

    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()
        cls.stage = os.path.join(cls.suite.root, "release-stage", "next")
        shutil.copytree(harness.REPO, cls.stage, ignore=shutil.ignore_patterns("tests", ".git", "__pycache__"))
        for d in ("sessions", "collections", "mocks", "__pycache__"):
            os.makedirs(os.path.join(cls.stage, d), exist_ok=True)
        plant = {"rules.json": "{}", "web-token": "SECRET-TOKEN", "current-project": "neo", "a.har": "{}", "x.diff": "d", "y.snapshot": "s",
                 "zz-snapshot-1": "s", ".DS_Store": "b", "__pycache__/a.pyc": "c", "mocks/m.json": "m", "sessions/n.flows": "n",
                 "collections/c.json": "c", "addons/f.orig": "o", "addons/f.rej": "r", "addons/f.bak": "b", "old.pre-fix": "p"}
        for rel, text in plant.items():
            with open(os.path.join(cls.stage, rel), "w") as fh:
                fh.write(text)
        cls.out = os.path.join(cls.suite.root, "release-out")
        cls.cp = subprocess.run(["/bin/bash", os.path.join(cls.stage, "install", "mirror", "make-release.sh"), cls.out],
                                capture_output=True, text=True, env=cls.suite.env(cls.suite.new_home("rel")))
        cls.tarball = next((os.path.join(cls.out, f) for f in os.listdir(cls.out)), None) if os.path.isdir(cls.out) else None
        cls.names = []
        if cls.tarball:
            with tarfile.open(cls.tarball) as tf:
                cls.names = tf.getnames()

    def test_builds_a_versioned_tarball_and_prints_its_sha256(self):
        self.assertEqual(self.cp.returncode, 0, self.cp.stderr)
        version = open(os.path.join(harness.REPO, "install", "VERSION")).read().strip()
        self.assertEqual(os.path.basename(self.tarball), "rivis-%s.tar.gz" % version)
        sha = hashlib.sha256(open(self.tarball, "rb").read()).hexdigest()
        self.assertIn("sha256  " + sha, self.cp.stdout)

    def test_contains_the_tool_with_the_right_layout_and_modes(self):
        top = os.path.basename(self.tarball)[:-7]
        for rel in ("rivis", "rivis.ps1", "neo-mitm", "product.json", "VERSION", "addons/proxy_rules.py", "addons/panel.js", "addons/js_host.mjs",
                    "projects/default/project.json"):
            self.assertIn(top + "/" + rel, self.names)
        with tarfile.open(self.tarball) as tf:
            self.assertTrue(tf.getmember(top + "/rivis").mode & 0o100)
            for m in tf.getmembers():
                self.assertEqual((m.uid, m.gid), (0, 0), m.name)                   # no build-machine owner leaks

    def test_state_snapshots_and_junk_are_excluded(self):
        leaked = [n for n in self.names if os.path.basename(n) in self.EXCLUDED_NAMES or "/sessions" in n or "/collections" in n or "/mocks" in n
                  or n.endswith((".har", ".diff", ".orig", ".rej", ".bak", ".pyc", ".flows", ".snapshot"))]
        self.assertEqual(leaked, [])
        self.assertFalse([n for n in self.names if "/install" in n])               # the installer is distributed separately
        with tarfile.open(self.tarball) as tf:
            for m in tf.getmembers():
                if m.isfile():
                    self.assertNotIn(b"SECRET-TOKEN", tf.extractfile(m).read(), m.name)

    def test_no_secrets_or_developer_paths_in_the_shipped_files(self):
        import re
        with tarfile.open(self.tarball) as tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                data = tf.extractfile(m).read()
                self.assertNotRegex(data, rb"BEGIN [A-Z ]*PRIVATE KEY", m.name)
                self.assertNotRegex(data, rb"/Users/[a-z0-9._-]+/", m.name)
                self.assertFalse(re.search(rb"(?i)(password|secret|token)\s*[:=]\s*['\"][A-Za-z0-9+/_-]{16,}['\"]", data), m.name)

    def test_release_has_no_vcs_history_env_files_keys_or_test_artifacts(self):
        """FOUND-BUGS B9: make-release.sh is a deny-list; .git/, .env, key files and tests/.artifacts ride along."""
        stage = os.path.join(self.suite.root, "release-stage2", "next")
        shutil.copytree(harness.REPO, stage, ignore=shutil.ignore_patterns("tests", ".git", "__pycache__"))
        os.makedirs(os.path.join(stage, ".git"))
        os.makedirs(os.path.join(stage, "tests", ".artifacts"))
        for rel in (".git/config", ".env", "id_rsa", "server.pem", "tests/.artifacts/run.log"):
            with open(os.path.join(stage, rel), "w") as fh:
                fh.write("x")
        out = os.path.join(self.suite.root, "release-out2")
        subprocess.run(["/bin/bash", os.path.join(stage, "install", "mirror", "make-release.sh"), out], capture_output=True, check=True,
                       env=self.suite.env(self.suite.new_home("rel2")))
        with tarfile.open(os.path.join(out, os.listdir(out)[0])) as tf:
            names = tf.getnames()
        bad = [n for n in names if "/.git" in n or n.endswith((".env", "id_rsa", ".pem")) or ".artifacts" in n]
        self.assertEqual(bad, [])


class Cosmetics(InstallerBase):
    def test_install_then_uninstall_restores_the_rc_file_byte_for_byte(self):
        """FOUND-BUGS B10: install appends a blank line before the managed block; uninstall leaves it behind."""
        self.ok("--yes", "--skip-local-capture")
        self.ok("--uninstall", "--yes")
        self.assertEqual(open(os.path.join(self.home, ".zshrc")).read(), "# mine\nexport A=1\n")

    @unittest.skipUnless(subprocess.run("systemextensionsctl list 2>/dev/null | grep -q org.mitmproxy.macos-redirector", shell=True).returncode == 0,
                         "the Mitmproxy Redirector system extension is not installed on this Mac, so its state line cannot be checked")
    def test_self_check_redirector_state_has_no_stray_bracket(self):
        """FOUND-BUGS B10: `awk '{print $NF}'` of '[activated enabled]' prints 'enabled]'."""
        out = self.ok("--yes", "--skip-local-capture").stdout
        self.assertNotRegex(out, r"redirector\s+\S*\]")

    def _with_fake_redirector(self, listing):
        """A stand-in `systemextensionsctl` first on PATH that lists the Redirector as given ('' = not installed)."""
        fake = os.path.join(self.home, "fake-sysext")
        os.makedirs(fake, exist_ok=True)
        with open(os.path.join(fake, "systemextensionsctl"), "w") as fh:
            fh.write("#!/bin/sh\nprintf '%s\\n' " + shlex.quote(listing) + "\n")
        os.chmod(os.path.join(fake, "systemextensionsctl"), 0o755)
        env = self.suite.env(self.home)
        env["PATH"] = fake + ":" + env["PATH"]
        return env

    def test_self_check_agrees_with_itself_when_local_capture_is_skipped(self):
        """R8D-10: an approved Redirector was reported as 'approved' and then as 'needs the Redirector approved
        (see above)'; and the next steps must say `start --background` like the README and QUICKSTART."""
        env = self._with_fake_redirector("*\t*\tTEAM\torg.mitmproxy.macos-redirector (1.0/1)\tRedirector\t[activated enabled]")
        out = self.ok("--yes", "--skip-local-capture", env=env).stdout
        self.assertRegex(out, r"redirector\s+approved")
        self.assertNotIn("needs the Mitmproxy Redirector approved", out)
        self.assertNotIn("see above", out)
        self.assertIn("rivis start --background", out)
        env = self._with_fake_redirector("")
        out = self.ok("--yes", "--skip-local-capture", env=env).stdout
        self.assertRegex(out, r"redirector\s+not installed")
        self.assertIn("needs the Mitmproxy Redirector approved", out)
        self.assertNotIn("see above", out)


class OfflineBundle(InstallerBase):
    """make-bundle.sh: one zip with the installer and every archive; install.sh prefers files next to it over any mirror
    and verifies them like a download. Uses a stand-in mitmproxy archive whose hash is pinned in a staged checkout."""
    NO_MITM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"

    def setUp(self):
        super().setUp()
        root = os.path.join(self.suite.root, "bundle-%s" % self._testMethodName)
        stage = os.path.join(root, "next")
        shutil.copytree(harness.REPO, stage, ignore=shutil.ignore_patterns("tests", ".git", "__pycache__"))
        self.stage, self.out = stage, os.path.join(root, "dist")
        key = "MACOS_ARM64" if os.uname().machine == "arm64" else "MACOS_X86_64"
        conf_path = os.path.join(stage, "install", "mirror.conf")
        conf = open(conf_path).read()
        self.mfile = next(l.split("=", 1)[1] for l in conf.splitlines() if l.startswith("MITMPROXY_FILE_%s=" % key))
        self.mitm = os.path.join(root, self.mfile)
        with tarfile.open(self.mitm, "w:gz") as tf:
            data = b"#!/bin/sh\necho 'Mitmproxy: 12.2.3'\n"
            info = tarfile.TarInfo("mitmproxy.app/Contents/MacOS/mitmdump")
            info.size, info.mode = len(data), 0o755
            import io
            tf.addfile(info, io.BytesIO(data))
        sha = hashlib.sha256(open(self.mitm, "rb").read()).hexdigest()
        lines = [("MITMPROXY_SHA256_%s=%s" % (key, sha)) if l.startswith("MITMPROXY_SHA256_%s=" % key) else l
                 for l in conf.splitlines()]
        open(conf_path, "w").write("\n".join(lines) + "\n")

    def bundle(self, *archives):
        return subprocess.run(["/bin/bash", os.path.join(self.stage, "install", "mirror", "make-bundle.sh"), *archives,
                               "--out", self.out], capture_output=True, text=True, env=self.suite.env(self.home))

    def unzip(self):
        cp = self.bundle(self.mitm)
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        zips = [f for f in os.listdir(self.out) if f.endswith(".zip")]
        self.assertEqual(len(zips), 1, zips)
        dest = os.path.join(self.out, "unzipped")
        subprocess.run(["unzip", "-q", os.path.join(self.out, zips[0]), "-d", dest], check=True)
        (top,) = os.listdir(dest)
        return os.path.join(dest, top)

    def test_bundle_holds_everything_and_pins_the_tool_with_no_mirror(self):
        b = self.unzip()
        version = open(os.path.join(harness.REPO, "install", "VERSION")).read().strip()
        for name in ("install.sh", "install.ps1", "VERSION", "product.json", "mirror.conf", self.mfile, "rivis-%s.tar.gz" % version):
            self.assertTrue(os.path.isfile(os.path.join(b, name)), name)
        conf = open(os.path.join(b, "mirror.conf")).read()
        self.assertRegex(conf, r"(?m)^MIRROR_BASE_URL=$")
        tool_sha = hashlib.sha256(open(os.path.join(b, "rivis-%s.tar.gz" % version), "rb").read()).hexdigest()
        self.assertIn("TOOL_SHA256=" + tool_sha, conf)

    def test_install_from_the_bundle_uses_the_files_next_to_it(self):
        b = self.unzip()
        env = self.suite.env(self.home, extra={"PATH": self.NO_MITM_PATH})
        out = self.ok("--dry-run", env=env, bin=os.path.join(b, "install.sh")).stdout
        self.assertIn("from local tarball %s" % os.path.join(b, self.mfile), out)
        self.assertIn("install tool from tarball %s" % os.path.join(b, "rivis-"), out)
        self.assertNotIn("mirror", out.split("plan:", 1)[1].split("no sudo")[0])
        cp = self.ok("--yes", "--skip-local-capture", "--no-rc", bin=os.path.join(b, "install.sh"))   # mitmproxy: hermetic shim
        self.assertIn("tool tarball (TOOL_SHA256): sha256 OK", cp.stdout)
        self.assertTrue(os.path.isfile(os.path.join(self.home, ".local", "rivis", "current", "rivis")))

    def stage_magisk(self):
        """Fake Magisk files with their hashes pinned in the staged tool's magisk.pins (the real APK is 11 MB)."""
        src = os.path.join(self.suite.root, "magisk-src-%s" % self._testMethodName)
        os.makedirs(src)
        pins_path = os.path.join(self.stage, "addons", "android", "magisk.pins")
        pins = open(pins_path).read()
        apk = next(l.split("=", 1)[1] for l in pins.splitlines() if l.startswith("MAGISK_APK="))
        for name, key in ((apk, "MAGISK_APK_SHA256"), ("host_patch.sh", "MAGISK_HOST_PATCH_SHA256"), ("LICENSE", "MAGISK_LICENSE_SHA256")):
            data = ("fake %s\n" % name).encode()
            open(os.path.join(src, name), "wb").write(data)
            pins = "\n".join(("%s=%s" % (key, hashlib.sha256(data).hexdigest())) if l.startswith(key + "=") else l
                              for l in pins.splitlines()) + "\n"
        open(pins_path, "w").write(pins)
        return src

    def test_bundled_magisk_is_installed_verified_and_removed_on_uninstall(self):
        src = self.stage_magisk()
        cp = subprocess.run(["/bin/bash", os.path.join(self.stage, "install", "mirror", "make-bundle.sh"), self.mitm,
                             "--magisk", src, "--out", self.out], capture_output=True, text=True, env=self.suite.env(self.home))
        self.assertEqual(cp.returncode, 0, cp.stderr)
        dest = os.path.join(self.out, "unzipped")
        subprocess.run(["unzip", "-q", os.path.join(self.out, [f for f in os.listdir(self.out) if f.endswith(".zip")][0]),
                        "-d", dest], check=True)
        (top,) = os.listdir(dest)
        b = os.path.join(dest, top)
        out = self.ok("--yes", "--skip-local-capture", "--no-rc", bin=os.path.join(b, "install.sh")).stdout
        self.assertIn("installed Magisk 30.7", out)
        mdir = os.path.join(self.home, ".local", "rivis", "magisk-30.7")
        self.assertEqual(sorted(os.listdir(mdir)), sorted(os.listdir(src)))
        self.ok("--uninstall", bin=os.path.join(b, "install.sh"))
        self.assertFalse(os.path.exists(mdir))
        # a bundled Magisk file that does not match its pin stops the install
        with open(os.path.join(b, "magisk-30.7", "host_patch.sh"), "ab") as fh:
            fh.write(b"x")
        cp = self.install("--yes", "--skip-local-capture", "--no-rc", bin=os.path.join(b, "install.sh"))
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("MISMATCH", cp.stdout + cp.stderr)

    def test_make_bundle_refuses_magisk_files_that_do_not_match_their_pins(self):
        src = self.stage_magisk()
        with open(os.path.join(src, "LICENSE"), "ab") as fh:
            fh.write(b"x")
        cp = subprocess.run(["/bin/bash", os.path.join(self.stage, "install", "mirror", "make-bundle.sh"), self.mitm,
                             "--magisk", src, "--out", self.out], capture_output=True, text=True, env=self.suite.env(self.home))
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("does not match its pin", cp.stderr)

    def test_a_tampered_bundle_archive_is_refused(self):
        b = self.unzip()
        with open(os.path.join(b, self.mfile), "ab") as fh:
            fh.write(b"x")
        env = self.suite.env(self.home, extra={"PATH": self.NO_MITM_PATH})
        cp = self.install("--yes", "--skip-local-capture", "--no-rc", env=env, bin=os.path.join(b, "install.sh"))
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("MISMATCH", cp.stdout + cp.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.home, ".local", "rivis", "mitmproxy-12.2.3")))

    def test_make_bundle_refuses_an_archive_that_does_not_match_its_pin(self):
        with open(self.mitm, "ab") as fh:
            fh.write(b"x")
        cp = self.bundle(self.mitm)
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("does not match its pin", cp.stderr)
        stray = os.path.join(self.suite.root, "mitmproxy-9.9.9-whatever.tar.gz")
        open(stray, "wb").close()
        self.assertIn("not a pinned", self.bundle(stray).stderr)

    def test_an_http_mirror_is_refused_up_front_with_a_clear_reason(self):
        conf_path = os.path.join(self.stage, "install", "mirror.conf")
        conf = open(conf_path).read().replace("MIRROR_BASE_URL=\n", "MIRROR_BASE_URL=http://192.0.2.1:8780\n", 1)
        open(conf_path, "w").write(conf)
        env = self.suite.env(self.home, extra={"PATH": self.NO_MITM_PATH})
        cp = self.install("--dry-run", env=env, bin=os.path.join(self.stage, "install", "install.sh"))
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("must be an https:// URL", cp.stderr)
        self.assertNotIn("web filter", cp.stdout + cp.stderr)


class RedirectorApproval(InstallerBase):
    """macOS can list the Redirector twice: an old copy "terminated waiting to uninstall on reboot" FIRST, the approved
    one second (seen on a second Mac, 2026-10-16). The installer read only the first line, so it sat out the full
    3-minute wait after the user had approved. Fakes: systemextensionsctl prints a fixed state, mitmdump is a stand-in."""
    STALE = "\t\tS8XHQB96PW\torg.mitmproxy.macos-redirector.network-extension (2.0/1)\tnetwork-extension\t[terminated waiting to uninstall on reboot]"
    APPROVED = "*\t*\tS8XHQB96PW\torg.mitmproxy.macos-redirector.network-extension (2.0/1)\tnetwork-extension\t[activated enabled]"
    WAITING = "*\t\tS8XHQB96PW\torg.mitmproxy.macos-redirector.network-extension (2.0/1)\tnetwork-extension\t[activated waiting for user]"

    def fakes(self, ext_lines):
        d = os.path.join(self.home, "fakebin")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "systemextensionsctl"), "w") as fh:
            fh.write("#!/bin/sh\ncat <<'X'\n%s\nX\n" % "\n".join(ext_lines))
        pidfile = os.path.join(self.home, "helper.pid")
        with open(os.path.join(d, "mitmdump"), "w") as fh:          # version check passes; anything else = the helper
            fh.write('#!/bin/sh\n[ "$1" = --version ] && { echo "Mitmproxy: 12.2.3"; exit 0; }\n'
                     'echo $$ > "%s"\nexec sleep 600\n' % pidfile)
        for f in ("systemextensionsctl", "mitmdump"):
            os.chmod(os.path.join(d, f), 0o755)
        shutil.copytree(self.suite.ca_dir, os.path.join(self.home, ".mitmproxy"), dirs_exist_ok=True)   # no CA step
        env = self.suite.env(self.home)
        env["PATH"] = d + ":" + env["PATH"]
        self.addCleanup(lambda: os.path.exists(pidfile) and subprocess.run(["kill", "-9", open(pidfile).read().strip()],
                                                                          capture_output=True))
        return env, os.path.join(d, "mitmdump"), pidfile

    def test_an_approved_redirector_listed_after_a_stale_one_counts_as_approved(self):
        env, fake, pidfile = self.fakes([self.STALE, self.APPROVED])
        started = time.time()
        cp = self.suite.run(["/bin/bash", INSTALL, "--yes", "--no-rc", "--trust-mitmdump", fake], home=self.home, env=env, timeout=120)
        out = cp.stdout + cp.stderr
        self.assertEqual(cp.returncode, 0, out[-1500:])
        self.assertIn("already approved", out)
        self.assertNotIn("waiting for the approval", out)
        self.assertFalse(os.path.exists(pidfile), "the approval helper was started although the Redirector is approved")
        self.assertLess(time.time() - started, 60)

    def test_ctrl_c_during_the_approval_wait_leaves_no_helper_running(self):
        env, fake, pidfile = self.fakes([self.WAITING])
        p = subprocess.Popen(["/bin/bash", INSTALL, "--yes", "--no-rc", "--trust-mitmdump", fake], env=env, cwd=self.home,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True,
                             # tests/run.sh runs modules as background jobs, which inherit SIGINT *ignored*; bash cannot
                             # trap a signal ignored at entry. A user's Terminal has the default, so restore it here.
                             preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL))
        try:
            out = ""
            deadline = time.time() + 90
            while time.time() < deadline and "waiting for the approval" not in out:
                line = p.stdout.readline()
                if not line:
                    break
                out += line
            self.assertIn("waiting for the approval", out, out[-2500:])
            harness.wait_for(lambda: os.path.isfile(pidfile) and os.path.getsize(pidfile),
                             timeout=5, desc="approval helper PID")
            helper = int(open(pidfile).read().strip())
            os.kill(p.pid, signal.SIGINT)                               # Ctrl-C reaches the installer
            p.wait(timeout=30)
            time.sleep(0.5)
            alive = subprocess.run(["kill", "-0", str(helper)], capture_output=True).returncode == 0
            self.assertFalse(alive, "the local-capture helper kept running after Ctrl-C")
        finally:
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGKILL)
            if os.path.exists(pidfile):
                subprocess.run(["kill", "-9", open(pidfile).read().strip()], capture_output=True)


class WindowsInstallerSource(unittest.TestCase):
    def test_bundle_first_and_https_only_mirror_like_the_mac_installer(self):
        src = open(os.path.join(harness.REPO, "install", "install.ps1")).read()
        self.assertIn("function Assert-HttpsMirror", src)
        self.assertRegex(src, r'if \(\$MitmproxyZip\)\s+\{ \$From = "local zip')          # local/bundle before mirror
        self.assertRegex(src, r"elseif \(\$Mirror\)\s+\{ Assert-HttpsMirror")
        self.assertIn('Join-Path $Here "$Cli-$ToolVersion.tar.gz"', src)
        self.assertNotIn("web filter", src)

    def test_junctions_are_removed_without_recursive_delete_and_official_is_opt_in(self):
        src = open(os.path.join(harness.REPO, "install", "install.ps1")).read()
        self.assertIn("function Remove-Junction", src)
        self.assertNotRegex(src, r"Remove-Item -Recurse -Force \$Current")
        self.assertNotIn('cmd.exe /c rmdir', src)
        self.assertIn('[IO.FileAttributes]::ReparsePoint', src)
        self.assertIn("[switch]$AllowOfficial", src)
        self.assertIn("official site (explicitly allowed)", src)

    def test_own_reuse_restores_installed_by_us_and_external_reuse_needs_a_signature(self):
        for rel in ("install/install.sh", "install/install.ps1"):
            src = open(os.path.join(harness.REPO, rel)).read()
            self.assertRegex(src, r"MITM_BY_US=1|MitmByUs = .*StartsWith")
            self.assertRegex(src, r"signed_by_mitmproxy|Test-MitmSigned")      # F-10: never trust a version string alone


if __name__ == "__main__":
    unittest.main(verbosity=2)


class SourceInstallLeavesOutTestArtifacts(InstallerBase):
    def test_checkout_install_does_not_copy_test_artifacts(self):
        """A checkout install copied tests/.artifacts (soak traces, ~1 GB) into every install: the suite filled the disk."""
        stage = os.path.join(self.suite.root, "artifacts-stage", "next")
        shutil.copytree(harness.REPO, stage, ignore=shutil.ignore_patterns(".git", "__pycache__", ".artifacts"))
        os.makedirs(os.path.join(stage, "tests", ".artifacts", "soak", "run"))
        with open(os.path.join(stage, "tests", ".artifacts", "soak", "run", "trace.zip"), "wb") as fh:
            fh.write(b"x" * 1024)
        self.ok("--yes", "--skip-local-capture", "--no-rc", bin=os.path.join(stage, "install", "install.sh"))
        tools = [d for d in os.listdir(os.path.join(self.home, ".local", "rivis")) if d.startswith("tool-")]
        self.assertTrue(tools)
        for d in tools:
            root = os.path.join(self.home, ".local", "rivis", d)
            self.assertTrue(os.path.isfile(os.path.join(root, "rivis")), d)
            self.assertFalse(os.path.exists(os.path.join(root, "tests", ".artifacts")), d)
