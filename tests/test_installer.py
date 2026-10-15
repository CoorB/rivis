"""Installer (install.sh) and release builder (make-release.sh): dry-run changes nothing, real install into a fake HOME is
idempotent and reversible, hash pins are enforced, releases carry no state/secrets."""
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tarfile
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
        return self.suite.run(["/bin/bash", bin or INSTALL] + list(args), home=self.home,
                              env=env or self.suite.env(self.home), timeout=timeout)

    def ok(self, *args, **kw):
        cp = self.install(*args, **kw)
        self.assertEqual(cp.returncode, 0, "install %s -> %s\n%s\n%s" % (args, cp.returncode, cp.stdout[-1500:], cp.stderr[-800:]))
        return cp


class DryRun(InstallerBase):
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


class WindowsInstallerSource(unittest.TestCase):
    def test_junctions_are_removed_without_recursive_delete_and_official_is_opt_in(self):
        src = open(os.path.join(harness.REPO, "install", "install.ps1")).read()
        self.assertIn("function Remove-Junction", src)
        self.assertNotRegex(src, r"Remove-Item -Recurse -Force \$Current")
        self.assertIn("[switch]$AllowOfficial", src)
        self.assertIn("official site (explicitly allowed)", src)

    def test_own_reuse_restores_installed_by_us_and_external_reuse_needs_a_signature(self):
        for rel in ("install/install.sh", "install/install.ps1"):
            src = open(os.path.join(harness.REPO, rel)).read()
            self.assertRegex(src, r"MITM_BY_US=1|MitmByUs = .*StartsWith")
            self.assertRegex(src, r"signed_by_mitmproxy|Test-MitmSigned")      # F-10: never trust a version string alone


if __name__ == "__main__":
    unittest.main(verbosity=2)
