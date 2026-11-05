"""Concurrent writers of the same state file must not lose each other's changes.

The panel, bash CLI and PowerShell CLI all read-change-write rules.json (and a few sibling
JSON files). Without one shared advisory lock, two adds that interleave each say "ok" and
only the last write survives. These tests force the interleaving; they do not rely on luck.
"""
import fcntl
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "addons"))
import harness
from harness import Suite
import proxy_common
import proxy_lan

HAVE_PWSH = bool(harness.PWSH) and os.path.isfile(harness.PWSH or "")


class CliBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()

    def setUp(self):
        self.home = self.suite.new_home("lock")
        self.state = os.path.join(self.home, ".rivis")
        self.env = self.suite.cli_env(self.home)

    def cli(self, *args, **kw):
        kw.setdefault("env", self.env)
        return self.suite.rivis(*args, home=self.home, **kw)

    def ok(self, *args, **kw):
        r = self.cli(*args, **kw)
        self.assertEqual(r.returncode, 0, "rivis %s -> rc=%s\nout=%s\nerr=%s" %
                         (" ".join(args), r.returncode, r.stdout, r.stderr))
        return r

    def rules_file(self, project="default"):
        return os.path.join(self.state, "projects", project, "rules.json")

    def cfg(self, project="default"):
        with open(self.rules_file(project)) as fh:
            return json.load(fh)


class StateLockHelper(unittest.TestCase):
    def test_state_lock_path_keeps_the_existing_rules_sidecar_name(self):
        self.assertEqual(os.path.basename(proxy_common.state_lock_path("/tmp/proj/rules.json")), ".rules.lock")
        self.assertEqual(os.path.basename(proxy_common.state_lock_path("/tmp/proj/trusted-files.json")),
                         ".trusted-files.lock")
        self.assertEqual(os.path.basename(proxy_common.state_lock_path("/tmp/lan-devices.json")),
                         ".lan-devices.lock")


class ScriptsAndRules(CliBase):
    def test_scripts_new_waits_for_shared_rules_lock(self):
        # Without the scripts_cli lock, this finishes while .rules.lock is held and rewrites rules.json.
        self.ok("rules", "list")
        lock_path = os.path.join(os.path.dirname(self.rules_file()), ".rules.lock")
        with open(lock_path, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            proc = subprocess.Popen(
                ["/bin/bash", harness.RIVIS, "scripts", "new", "under-lock", "--lang", "py"],
                env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline:
                    self.assertIsNone(proc.poll(), "scripts new finished while the rules lock was held")
                    cfg = self.cfg()
                    self.assertNotIn("under-lock", [s.get("name") for s in cfg.get("scripts") or []],
                                     "scripts wrote rules.json without waiting for the shared lock")
                    time.sleep(0.1)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
            out, err = proc.communicate(timeout=15)
            self.assertEqual(proc.returncode, 0, out + err)
        self.assertIn("under-lock", [s["name"] for s in self.cfg()["scripts"]])

    def test_without_state_lock_scripts_clobber_a_rules_add(self):
        # Fail-before: load, wait until a rules add has written, then save the stale cfg → rules add gone.
        self.ok("rules", "list")
        import scripts_cli
        ready = threading.Barrier(2)
        rules_written = threading.Event()
        original_save = scripts_cli.save

        def clobber_save(path, cfg):
            ready.wait(timeout=5)
            self.assertTrue(rules_written.wait(10), "rules add did not finish")
            original_save(path, cfg)

        def run_scripts():
            with mock.patch.object(scripts_cli, "save", clobber_save), \
                    mock.patch.object(scripts_cli, "acquire_state_lock", return_value=None):
                scripts_cli.main([self.rules_file(), "--script-dir",
                                  os.path.join(os.path.dirname(self.rules_file()), "scripts"),
                                  "new", "from-scripts-nolock", "--lang", "py"])

        t = threading.Thread(target=run_scripts)
        t.start()
        ready.wait(timeout=5)
        self.ok("rules", "add", "from-rules-nolock", "match=/from-rules-nolock", "action=block")
        rules_written.set()
        t.join(15)
        names = {r["name"] for r in self.cfg()["rules"]}
        scripts = {s["name"] for s in self.cfg().get("scripts") or []}
        self.assertIn("from-scripts-nolock", scripts)
        self.assertNotIn("from-rules-nolock", names,
                         "unlocked scripts save must clobber the concurrent rules add; got rules=%r" % names)

    def test_scripts_new_and_rules_add_both_persist(self):
        # With the shared lock, scripts holds .rules.lock across load+save; the rules add waits, then both remain.
        # Without the lock, a short pause before save lets rules add finish and the stale save drops it — that is
        # the fail-before this test must catch (a bare barrier is not enough: rules add is a slower subprocess).
        self.ok("rules", "list")
        import scripts_cli
        ready = threading.Barrier(2)
        original_save = scripts_cli.save
        saved = threading.Event()

        def gated_save(path, cfg):
            ready.wait(timeout=5)
            time.sleep(0.8)
            original_save(path, cfg)
            saved.set()

        def run_scripts():
            with mock.patch.object(scripts_cli, "save", gated_save):
                scripts_cli.main([self.rules_file(), "--script-dir",
                                  os.path.join(os.path.dirname(self.rules_file()), "scripts"),
                                  "new", "from-scripts-lock", "--lang", "py"])

        t = threading.Thread(target=run_scripts)
        t.start()
        ready.wait(timeout=5)
        self.ok("rules", "add", "from-rules-lock", "match=/from-rules-lock", "action=block")
        t.join(15)
        self.assertTrue(saved.wait(5))
        names = {r["name"] for r in self.cfg()["rules"]}
        scripts = {s["name"] for s in self.cfg().get("scripts") or []}
        self.assertIn("from-rules-lock", names)
        self.assertIn("from-scripts-lock", scripts)


class TrustedFilesLock(CliBase):
    def test_unlocked_trusted_rmw_loses_the_other_path(self):
        # The defect the lock closes: two readers each add one path and rewrite; only the last write remains.
        project = self.suite.new_home("trust-lose")
        outside = self.suite.new_home("trust-lose-src")
        a = os.path.join(outside, "a.txt")
        b = os.path.join(outside, "b.txt")
        for path in (a, b):
            with open(path, "w") as fh:
                fh.write("x\n")
        target = os.path.join(project, "trusted-files.json")
        proxy_common.atomic_json(target, {"files": []})
        barrier = threading.Barrier(2)

        def unlocked_add(path):
            files = proxy_common.trusted_files(project)
            barrier.wait(timeout=5)
            time.sleep(0.05)
            files = files | {os.path.realpath(path)}
            proxy_common.atomic_json(target, {"files": sorted(files)})

        t1 = threading.Thread(target=unlocked_add, args=(a,))
        t2 = threading.Thread(target=unlocked_add, args=(b,))
        t1.start(); t2.start()
        t1.join(15); t2.join(15)
        trusted = proxy_common.trusted_files(project)
        self.assertEqual(len(trusted), 1, "unlocked RMW must lose one path (got %r)" % trusted)

    def test_concurrent_allow_file_keeps_both_paths(self):
        self.ok("rules", "list")
        project = os.path.dirname(self.rules_file())
        outside = self.suite.new_home("trust-src")
        paths = [os.path.join(outside, "f%d.txt" % i) for i in range(6)]
        for path in paths:
            with open(path, "w") as fh:
                fh.write("x\n")
        errors = []

        def one(path):
            try:
                proxy_common.set_trusted_file(project, path)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=one, args=(p,)) for p in paths]
        [t.start() for t in threads]; [t.join(30) for t in threads]
        self.assertEqual(errors, [])
        trusted = proxy_common.trusted_files(project)
        self.assertEqual(trusted, {os.path.realpath(p) for p in paths}, trusted)


class LanDevicesLock(unittest.TestCase):
    def test_unlocked_lan_rmw_loses_the_other_device(self):
        path = os.path.join(Suite.get().new_home("lan-lose"), "lan-devices.json")
        barrier = threading.Barrier(2)

        def unlocked_allow(ip, name):
            d = proxy_lan.Devices(path)
            # Bypass Devices.allow's lock: the pre-fix read-change-write shape.
            rows = list(d._read())
            barrier.wait(timeout=5)
            time.sleep(0.05)
            now = int(time.time())
            rows = [r for r in rows if r["ip"] != ip] + [
                {"ip": ip, "name": name, "added": now, "last_seen": now, "mac": None}]
            d._write(rows)

        t1 = threading.Thread(target=unlocked_allow, args=("192.168.1.10", "A"))
        t2 = threading.Thread(target=unlocked_allow, args=("192.168.1.11", "B"))
        t1.start(); t2.start()
        t1.join(15); t2.join(15)
        ips = [r["ip"] for r in proxy_lan.Devices(path).rows()]
        self.assertEqual(len(ips), 1, "unlocked RMW must lose one device (got %r)" % ips)

    def test_concurrent_allow_keeps_both_devices(self):
        path = os.path.join(Suite.get().new_home("lan-race"), "lan-devices.json")
        errors = []

        def allow(ip, name):
            try:
                with mock.patch.object(proxy_lan, "lookup_mac", return_value=None):
                    proxy_lan.Devices(path).allow(ip, name)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=allow, args=("192.168.1.%d" % (10 + i), "D%d" % i))
                   for i in range(6)]
        [t.start() for t in threads]; [t.join(30) for t in threads]
        self.assertEqual(errors, [])
        ips = sorted(r["ip"] for r in proxy_lan.Devices(path).rows())
        self.assertEqual(ips, ["192.168.1.%d" % (10 + i) for i in range(6)], ips)

    def test_lan_allow_waits_for_sidecar_lock(self):
        path = os.path.join(Suite.get().new_home("lan-wait"), "lan-devices.json")
        # Hardcoded sidecar name so this fails for the right reason against a tree that lacks state_lock_path.
        lock_path = os.path.join(os.path.dirname(path) or ".", ".lan-devices.lock")
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        with open(lock_path, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            started = time.monotonic()
            done = []

            def allow():
                with mock.patch.object(proxy_lan, "lookup_mac", return_value=None):
                    proxy_lan.Devices(path).allow("192.168.1.20", "Phone")
                done.append(time.monotonic())

            t = threading.Thread(target=allow)
            t.start()
            time.sleep(0.4)
            self.assertEqual(done, [], "lan allow wrote without waiting for .lan-devices.lock")
            fcntl.flock(lock, fcntl.LOCK_UN)
            t.join(15)
        self.assertEqual(len(done), 1)
        self.assertGreater(done[0] - started, 0.35)
        self.assertEqual([r["ip"] for r in proxy_lan.Devices(path).rows()], ["192.168.1.20"])


@unittest.skipUnless(HAVE_PWSH, "portable pwsh not available")
class PowershellRulesLock(CliBase):
    def test_powershell_rules_on_waits_for_shared_rules_lock(self):
        self.ok("rules", "add", "shared", "match=/shared", "action=block")
        self.ok("rules", "off", "shared")
        lock_path = os.path.join(os.path.dirname(self.rules_file()), ".rules.lock")
        with open(lock_path, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            proc = subprocess.Popen(
                [harness.PWSH, "-NoProfile", "-NonInteractive", "-File",
                 os.path.join(harness.REPO, "rivis.ps1"), "rules", "on", "shared"],
                env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline:
                    self.assertIsNone(proc.poll(), "PowerShell rules on finished while the rules lock was held")
                    self.assertFalse(self.cfg()["rules"][0].get("enabled", True),
                                     "PowerShell wrote rules.json without waiting for the shared lock")
                    time.sleep(0.1)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
            out, err = proc.communicate(timeout=15)
            self.assertEqual(proc.returncode, 0, out + err)
        self.assertTrue(self.cfg()["rules"][0].get("enabled", True))

    def test_powershell_scripts_new_waits_for_shared_rules_lock(self):
        # Native scripts new also rewrote rules.json; same sidecar as rules on / bash scripts_cli.
        self.ok("rules", "list")
        lock_path = os.path.join(os.path.dirname(self.rules_file()), ".rules.lock")
        with open(lock_path, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            proc = subprocess.Popen(
                [harness.PWSH, "-NoProfile", "-NonInteractive", "-File",
                 os.path.join(harness.REPO, "rivis.ps1"),
                 "scripts", "new", "ps-under-lock", "-Lang", "py"],
                env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline:
                    self.assertIsNone(proc.poll(), "PowerShell scripts new finished while the rules lock was held")
                    cfg = self.cfg()
                    self.assertNotIn("ps-under-lock", [s.get("name") for s in cfg.get("scripts") or []],
                                     "PowerShell scripts wrote rules.json without waiting for the shared lock")
                    time.sleep(0.1)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
            out, err = proc.communicate(timeout=15)
            self.assertEqual(proc.returncode, 0, out + err)
        self.assertIn("ps-under-lock", [s["name"] for s in self.cfg()["scripts"]])


if __name__ == "__main__":
    unittest.main()
