"""Upgrade durability: state written by older releases must still work after installing the current tree.

Fixtures under tests/fixtures/upgrade/<version>/ are real ~/.rivis trees produced by that version's CLI
(absolute paths rewritten to the token __HOME__). Dist zips under ../dist-0.9.*/ are read-only sources for
installer-over-old-install probes.
"""
import hashlib
import json
import os
import shutil
import stat
import sys
import time
import unittest
import urllib.request
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import Suite, wait_for

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "upgrade")
INSTALL = os.path.join(harness.REPO, "install", "install.sh")
DIST_ROOT = os.path.abspath(os.path.join(harness.REPO, ".."))


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def plant_fixture(home, version):
    """Copy tests/fixtures/upgrade/<version> into home, rewriting __HOME__ to this home."""
    src = os.path.join(FIX, version)
    if not os.path.isdir(src):
        raise unittest.SkipTest("missing fixture %s" % src)
    state_src = os.path.join(src, "rivis-state")
    state_dst = os.path.join(home, ".rivis")
    if os.path.isdir(state_dst):
        shutil.rmtree(state_dst)
    shutil.copytree(state_src, state_dst)
    outside_src = os.path.join(src, "outside.json")
    if os.path.isfile(outside_src):
        shutil.copy2(outside_src, os.path.join(home, "outside.json"))
    for base, _dirs, files in os.walk(home):
        for name in files:
            if not name.endswith(".json"):
                continue
            path = os.path.join(base, name)
            text = open(path, encoding="utf-8").read()
            if "__HOME__" in text:
                open(path, "w", encoding="utf-8").write(text.replace("__HOME__", home))
    # Refresh LAN last_seen so a health check during upgrade does not TTL-expire the fixture device.
    lan = os.path.join(home, ".rivis", "lan-devices.json")
    if os.path.isfile(lan):
        doc = json.load(open(lan))
        now = time.time()
        for row in doc.get("devices") or []:
            if isinstance(row, dict):
                row["last_seen"] = now
                row.setdefault("added", now)
        json.dump(doc, open(lan, "w"), indent=2)
        open(lan, "a").write("\n")
    return os.path.join(home, ".rivis")


def state_snapshot(home):
    """Content hashes of durable state (not tokens, start files or logs)."""
    out = {}
    root = os.path.join(home, ".rivis")
    for base, _dirs, files in os.walk(root):
        for name in files:
            path = os.path.join(base, name)
            rel = os.path.relpath(path, root)
            if rel.startswith("logs/") or rel.startswith("web-") or rel.startswith("last-start"):
                continue
            out[rel] = hashlib.sha256(open(path, "rb").read()).hexdigest()
    ca = os.path.join(home, ".mitmproxy", "mitmproxy-ca-cert.pem")
    if os.path.isfile(ca):
        out["__ca__"] = hashlib.sha256(open(ca, "rb").read()).hexdigest()
    return out


def extract_installer(suite, version):
    zpath = os.path.join(DIST_ROOT, "dist-%s" % version, "rivis-installer-%s.zip" % version)
    if not os.path.isfile(zpath):
        raise unittest.SkipTest("missing %s" % zpath)
    dest = os.path.join(suite.root, "dist-%s" % version)
    root = os.path.join(dest, "rivis-installer-%s" % version)
    if not os.path.isdir(root):
        os.makedirs(dest, exist_ok=True)
        with zipfile.ZipFile(zpath) as bundle:
            bundle.extractall(dest)
    return root


class FixtureReads(unittest.TestCase):
    """Current CLI and a live panel read every older fixture without losing rules, scripts or filters."""

    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()

    def setUp(self):
        self.home = self.suite.new_home("up-fix")
        shutil.copytree(self.suite.ca_dir, os.path.join(self.home, ".mitmproxy"))
        self.port, self.web = harness.free_port(), harness.free_port()
        self.env = self.suite.env(self.home, ports=(self.port, self.web),
                                  confdir=os.path.join(self.home, ".mitmproxy"))

    def tearDown(self):
        self.suite.rivis("stop", home=self.home, env=self.env)

    def _assert_fixture_readable(self, version):
        plant_fixture(self.home, version)
        # Drop stale last-start ports from the fixture; this run uses fresh ports.
        for name in os.listdir(os.path.join(self.home, ".rivis")):
            if name.startswith("last-start"):
                os.unlink(os.path.join(self.home, ".rivis", name))

        listed = self.suite.rivis("--project", "default", "rules", "list", home=self.home, env=self.env)
        self.assertEqual(listed.returncode, 0, listed.stdout + listed.stderr)
        self.assertIn("keepme", listed.stdout)
        self.assertIn("card", listed.stdout)
        self.assertIn("3g-urban", listed.stdout)

        bp = self.suite.rivis("--project", "default", "breakpoint", home=self.home, env=self.env)
        self.assertEqual(bp.returncode, 0, bp.stdout + bp.stderr)
        self.assertIn("login", bp.stdout)

        scripts = self.suite.rivis("--project", "default", "scripts", "list", home=self.home, env=self.env)
        self.assertEqual(scripts.returncode, 0, scripts.stdout + scripts.stderr)
        self.assertIn("hdr", scripts.stdout)
        self.assertNotIn("(none)", scripts.stdout)

        trust = self.suite.rivis("--project", "default", "rules", "trusted-files", home=self.home, env=self.env)
        self.assertIn(os.path.join(self.home, "outside.json"), trust.stdout)

        projects = self.suite.rivis("projects", "list", home=self.home, env=self.env)
        self.assertIn("sit", projects.stdout)
        sit = self.suite.rivis("--project", "sit", "rules", "list", home=self.home, env=self.env)
        self.assertIn("sit503", sit.stdout)

        started = self.suite.rivis("start", "--background", "--no-open", "--no-ios", "--project", "default",
                                   home=self.home, env=self.env, timeout=90)
        self.assertEqual(started.returncode, 0, started.stdout + started.stderr)
        token_file = os.path.join(self.home, ".rivis",
                                  "web-token" if self.web == 8083 else "web-token-%d" % self.web)
        wait_for(lambda: os.path.isfile(token_file), 10, 0.1, "web token")
        token = open(token_file).read().strip()
        req = urllib.request.Request("http://127.0.0.1:%d/proxy/api/state" % self.web,
                                     headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(req, timeout=15) as resp:
            state = json.loads(resp.read().decode())
        self.assertEqual(state.get("version"), open(os.path.join(harness.REPO, "install", "VERSION")).read().strip())
        names = [r.get("name") for r in state.get("rules") or []]
        self.assertEqual(set(names) & {"keepme", "card"}, {"keepme", "card"})
        filters = state.get("saved_filters") or []
        self.assertTrue(any(f.get("name") == "errors" for f in filters), filters)
        self.assertEqual(state.get("throttle"), "3g-urban")

    def test_current_reads_state_written_by_0_9_1(self):
        self._assert_fixture_readable("0.9.1")

    def test_current_reads_state_written_by_0_9_6(self):
        self._assert_fixture_readable("0.9.6")


class InstallerUpgrade(unittest.TestCase):
    """Installer over an older install, twice, over a running instance, uninstall/reinstall, and downgrade."""

    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()

    def setUp(self):
        self.home = self.suite.new_home("up-inst")
        with open(os.path.join(self.home, ".zshrc"), "w") as fh:
            fh.write("# mine\n")
        self.env = self.suite.env(self.home)

    def install_from_checkout(self, env=None, timeout=300):
        env = env or self.env
        shim = os.path.join(self.suite.root, "shim", "mitmdump")
        return self.suite.run(["/bin/bash", INSTALL, "--yes", "--skip-local-capture",
                               "--trust-mitmdump", shim], home=self.home, env=env, timeout=timeout)

    def install_from_zip(self, version, env=None, timeout=300):
        root = extract_installer(self.suite, version)
        env = env or self.env
        return self.suite.run(["/bin/bash", os.path.join(root, "install.sh"), "--yes", "--skip-local-capture"],
                              home=self.home, env=env, timeout=timeout)

    def launcher(self):
        return os.path.join(self.home, ".local", "bin", "rivis")

    def test_upgrade_from_0_9_6_keeps_rules_scripts_filters_and_restarts_healthily(self):
        r = self.install_from_zip("0.9.6")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        plant_fixture(self.home, "0.9.6")
        before = state_snapshot(self.home)
        port, web = harness.free_port(), harness.free_port()
        env = self.suite.env(self.home, ports=(port, web), confdir=os.path.join(self.home, ".mitmproxy"))
        # Rewrite the fixture last-start to these ports so the upgrade can restart it.
        open(os.path.join(self.home, ".rivis", "last-start"), "w").write(
            "START_PORT=%d\nSTART_WEB_PORT=%d\nSTART_ARGS=(--project default start --background --no-open)\n"
            % (port, web))
        started = self.suite.run([self.launcher(), "start", "--background", "--no-open", "--no-ios",
                                  "--project", "default"], home=self.home, env=env, timeout=90)
        self.assertEqual(started.returncode, 0, started.stdout + started.stderr)
        try:
            up = self.install_from_checkout(env=env)
            self.assertEqual(up.returncode, 0, up.stdout + up.stderr)
            self.assertIn("0.9.10", self.suite.run([self.launcher(), "--version"], home=self.home, env=env).stdout)
            self.assertIn("health check :%d/:%d ok" % (port, web), up.stdout)
            after = state_snapshot(self.home)
            lost = sorted(set(before) - set(after))
            self.assertEqual(lost, [], "upgrade must not delete durable state: %s" % lost)
            listed = self.suite.run([self.launcher(), "--project", "default", "rules", "list"],
                                    home=self.home, env=env)
            self.assertIn("keepme", listed.stdout)
            self.assertIn("hdr", self.suite.run([self.launcher(), "--project", "default", "scripts", "list"],
                                                home=self.home, env=env).stdout)
            lan = json.load(open(os.path.join(self.home, ".rivis", "lan-devices.json")))
            self.assertEqual(lan["devices"][0]["name"], "Pixel")
            self.assertTrue(os.path.isdir(os.path.join(self.home, ".local", "rivis", "tool-0.9.6")),
                            "previous tool directory stays for rollback")
        finally:
            self.suite.run([self.launcher(), "stop"], home=self.home, env=env)

    def test_installer_run_twice_leaves_state_byte_identical(self):
        self.assertEqual(self.install_from_checkout().returncode, 0)
        plant_fixture(self.home, "0.9.6")
        for name in os.listdir(os.path.join(self.home, ".rivis")):
            if name.startswith("last-start"):
                os.unlink(os.path.join(self.home, ".rivis", name))
        before = state_snapshot(self.home)
        self.assertEqual(self.install_from_checkout().returncode, 0)
        after = state_snapshot(self.home)
        self.assertEqual(before, after)

    def test_uninstall_keeps_state_and_ca_and_reinstall_reads_them(self):
        self.assertEqual(self.install_from_checkout().returncode, 0)
        plant_fixture(self.home, "0.9.1")
        for name in os.listdir(os.path.join(self.home, ".rivis")):
            if name.startswith("last-start"):
                os.unlink(os.path.join(self.home, ".rivis", name))
        before = state_snapshot(self.home)
        ca = os.path.join(self.home, ".mitmproxy", "mitmproxy-ca-cert.pem")
        self.assertTrue(os.path.isfile(ca))
        un = self.suite.run(["/bin/bash", INSTALL, "--uninstall", "--yes"], home=self.home, env=self.env)
        self.assertEqual(un.returncode, 0, un.stdout + un.stderr)
        self.assertFalse(os.path.lexists(self.launcher()))
        self.assertTrue(os.path.isfile(ca), "uninstall must keep the CA")
        self.assertTrue(os.path.isdir(os.path.join(self.home, ".rivis")))
        self.assertEqual(state_snapshot(self.home), before)
        self.assertEqual(self.install_from_checkout().returncode, 0)
        env = self.suite.cli_env(self.home)
        listed = self.suite.run([self.launcher(), "--project", "default", "rules", "list"],
                                home=self.home, env=env)
        self.assertIn("keepme", listed.stdout)
        self.assertIn("hdr", self.suite.run([self.launcher(), "--project", "default", "scripts", "list"],
                                            home=self.home, env=env).stdout)

    def test_downgrade_by_one_version_does_not_corrupt_state(self):
        # Installing the previous release zip over the current one must leave rules, scripts and the CA intact
        # (a refusal with a plain sentence would also be fine; today the older tool directory is staged beside it).
        self.assertEqual(self.install_from_checkout().returncode, 0)
        plant_fixture(self.home, "0.9.6")
        for name in os.listdir(os.path.join(self.home, ".rivis")):
            if name.startswith("last-start"):
                os.unlink(os.path.join(self.home, ".rivis", name))
        # Add a field only the current release writes; an older rewrite must not strip it.
        rules_path = os.path.join(self.home, ".rivis", "projects", "default", "rules.json")
        doc = json.load(open(rules_path))
        doc["no_cache"] = True
        json.dump(doc, open(rules_path, "w"), indent=2)
        open(rules_path, "a").write("\n")
        before = state_snapshot(self.home)
        down = self.install_from_zip("0.9.9")
        self.assertEqual(down.returncode, 0, down.stdout + down.stderr)
        version = self.suite.run([self.launcher(), "--version"], home=self.home, env=self.env).stdout
        self.assertIn("0.9.9", version)
        after = state_snapshot(self.home)
        self.assertEqual(sorted(set(before) - set(after)), [])
        self.assertEqual(before, after)
        self.assertTrue(json.load(open(rules_path)).get("no_cache") is True)
        self.assertTrue(os.path.isdir(os.path.join(self.home, ".local", "rivis", "tool-0.9.10")))


class LegacyMigrationParity(unittest.TestCase):
    """PowerShell must copy the same legacy project files the bash CLI does."""

    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()

    def test_powershell_migrate_copies_scripts_filters_and_trusted_files(self):
        if not (os.path.isfile(harness.PWSH) and os.access(harness.PWSH, os.X_OK)):
            self.skipTest("portable pwsh not found at %s" % harness.PWSH)
        home = self.suite.new_home("ps-mig")
        env = self.suite.cli_env(home)
        old = os.path.join(home, ".neo-mitm")
        os.makedirs(os.path.join(old, "mocks"))
        os.makedirs(os.path.join(old, "scripts"))
        open(os.path.join(old, "mocks", "m.json"), "w").write("{}")
        open(os.path.join(old, "scripts", "hdr.py"), "w").write("def on_request(context, url, request):\n    return request\n")
        json.dump({"throttle": "off", "rules": [], "scripts": [
            {"name": "hdr", "file": "hdr.py", "lang": "py", "enabled": True, "match": ".", "method": None}]},
                  open(os.path.join(old, "rules.json"), "w"))
        json.dump([{"name": "errors", "filter": "~c 5xx"}], open(os.path.join(old, "filters.json"), "w"))
        outside = os.path.join(home, "out.json")
        open(outside, "w").write("{}")
        json.dump({"files": [outside]}, open(os.path.join(old, "trusted-files.json"), "w"))
        r = self.suite.run([harness.PWSH, "-NoProfile", "-File",
                            os.path.join(harness.REPO, "rivis.ps1"), "projects", "list"],
                           home=home, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("copied legacy", r.stdout + r.stderr)
        target = os.path.join(home, ".rivis", "projects", "neo")
        self.assertTrue(os.path.isfile(os.path.join(target, "scripts", "hdr.py")))
        self.assertEqual(json.load(open(os.path.join(target, "filters.json")))[0]["name"], "errors")
        self.assertEqual(json.load(open(os.path.join(target, "trusted-files.json")))["files"], [outside])


if __name__ == "__main__":
    unittest.main(verbosity=2)
