"""Regressions for the overnight review, using only the isolated test harness."""
import json
import os
import re
import socket
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import harness
from test_cli import CliBase


class StartSafety(CliBase):
    def test_rules_help_names_action_specific_keys(self):
        help_text = self.ok("rules", "--help").stdout
        for key in ("header=", "set=", "replace=", "with="):
            self.assertIn(key, help_text)

    def test_invalid_private_hosts_regex_is_refused(self):
        result = self.refused("start", "--no-ios", "--allow-private-hosts", "(")
        self.assertIn("regex", result.stderr)

    def test_saved_start_has_each_flag_once_and_keeps_foreground(self):
        env = dict(self.env, SHIM_DRYRUN="1")
        self.ok("start", "--no-ios", "--no-open", env=env)
        path = os.path.join(self.state, "last-start-" + self.env["RIVIS_WEB_PORT"])
        saved = open(path).read()
        self.assertEqual(saved.count("--no-open"), 1, saved)
        self.assertNotIn("--background", saved)

    def test_live_unlisted_loopback_listener_is_never_cleared(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        self.addCleanup(sock.close)
        from test_cli import LeftoverSystemProxy
        env, log = LeftoverSystemProxy.fake(self, "127.0.0.1", sock.getsockname()[1])
        result = self.ok("net-reset", "--auto", env=env)
        self.assertEqual(LeftoverSystemProxy.changes(self, log), [])
        self.assertIn("in use (TCP connection succeeded)", result.stderr)

    def test_unproven_dead_proxy_is_never_cleared(self):
        from test_cli import LeftoverSystemProxy
        port, holder = harness.reserve_dead_port()
        self.addCleanup(holder.close)
        env, log = LeftoverSystemProxy.fake(self, "127.0.0.1", port)
        result = self.ok("net-reset", "--auto", env=env)
        self.assertEqual(LeftoverSystemProxy.changes(self, log), [])
        self.assertIn("cannot prove", result.stderr)

    def test_recorded_proxy_process_still_alive_is_not_cleared(self):
        from test_cli import LeftoverSystemProxy
        port, holder = harness.reserve_dead_port()
        self.addCleanup(holder.close)
        env, log = LeftoverSystemProxy.fake(self, "127.0.0.1", port)
        os.makedirs(self.state, exist_ok=True)
        with open(os.path.join(self.state, "proxy-owner-history"), "w") as fh:
            fh.write("127.0.0.1:%d %d\n" % (port, os.getpid()))
        self.ok("net-reset", "--auto", env=env)
        self.assertEqual(LeftoverSystemProxy.changes(self, log), [])

    def test_observed_proxyman_then_dead_endpoint_can_be_cleared(self):
        from test_cli import LeftoverSystemProxy
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        env, log = LeftoverSystemProxy.fake(self, "127.0.0.1", port)
        fake_dir = os.path.dirname(log)
        live = os.path.join(fake_dir, "live")
        open(live, "w").close()
        lsof = os.path.join(fake_dir, "lsof")
        with open(lsof, "w") as fh:
            fh.write('#!/bin/sh\nif [ -f "%s" ]; then printf "COMMAND PID USER FD TYPE DEVICE SIZE NODE NAME\\nProxyman 987654321 me 1u IPv4 0x0 0t0 TCP 127.0.0.1:%d (LISTEN)\\n"; fi\n' % (live, port))
        os.chmod(lsof, 0o755)
        try:
            self.ok("net-reset", "--auto", env=env)
            self.assertEqual(LeftoverSystemProxy.changes(self, log), [])
            self.assertTrue(os.path.isfile(os.path.join(self.state, "proxy-owner-history")))
        finally:
            listener.close()
        os.unlink(live)
        holder = socket.socket()
        holder.bind(("127.0.0.1", port))
        self.addCleanup(holder.close)
        result = self.ok("net-reset", "--auto", env=env)
        self.assertIn("fixed:", result.stdout)
        self.assertEqual(len(LeftoverSystemProxy.changes(self, log)), 2)

    def test_ios_all_reports_each_simulator_after_one_failure(self):
        fake = os.path.join(self.home, "fake-xcrun")
        os.makedirs(fake)
        log = os.path.join(fake, "calls")
        first = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"
        second = "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB"
        script = os.path.join(fake, "xcrun")
        with open(script, "w") as fh:
            fh.write('#!/bin/sh\n'
                     'if [ "$1 $2 $3" = "simctl list devices" ]; then\n'
                     '  echo "A (%s) (Booted)"; echo "B (%s) (Booted)"; exit 0; fi\n'
                     'echo "$*" >> "%s"\n'
                     'case "$*" in *%s*) exit 1;; esac\nexit 0\n' % (first, second, log, first))
        os.chmod(script, 0o755)
        env = dict(self.env, PATH=fake + ":" + self.env["PATH"])
        result = self.refused("ios", "on", "--all", env=env)
        self.assertIn(first, result.stderr)
        self.assertIn(second, open(log).read())

    def test_second_start_does_not_replace_first_web_token(self):
        fake = os.path.join(self.home, "fake-mitm")
        os.makedirs(fake)
        path = os.path.join(fake, "mitmweb")
        with open(path, "w") as fh:
            fh.write("#!/bin/sh\nsleep 2\n")
        os.chmod(path, 0o755)
        env = dict(self.env, PATH=fake + ":" + self.env["PATH"])
        proc = subprocess.Popen(["/bin/bash", harness.RIVIS, "start", "--no-ios", "--no-open"],
                                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        token = os.path.join(self.state, "web-token-" + self.env["RIVIS_WEB_PORT"])
        try:
            harness.wait_for(lambda: os.path.isfile(token), 10)
            first = open(token).read()
            second = self.cli("start", "--no-ios", "--no-open", env=env)
            self.assertNotEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertIn("start already in progress", second.stderr)
            self.assertEqual(open(token).read(), first)
        finally:
            proc.communicate(timeout=10)


class SourceContracts(unittest.TestCase):
    def test_example_has_rule_keys(self):
        path = os.path.join(harness.REPO, "projects", "_template", "rules.example.json")
        rules = json.load(open(path))["rule_examples"]
        self.assertTrue(any("header" in r for r in rules))
        self.assertTrue(any("replace" in r for r in rules))

    def test_timing_text_is_conservative(self):
        for path in ("addons/tls_cli.py", "addons/proxy_panel.py", "rivis.ps1"):
            self.assertNotIn("within a second", open(os.path.join(harness.REPO, path)).read())

    def test_installer_keeps_unowned_launcher(self):
        src = open(os.path.join(harness.REPO, "install", "install.sh")).read()
        self.assertIn("link_owned_by_us", src)

    def test_running_tool_dir_accepts_spaces_in_home_path(self):
        source = open(harness.RIVIS).read()
        start = source.index("running_tool_dir() {")
        body = source[start:source.index("\n}", start) + 2]
        home = "/tmp/rivis review space"
        shell = ("HOME='" + home + "'; CLI=rivis\n"
                 "ps() { echo 'mitmweb -s " + home + "/.local/rivis/tool-0.9.4/addons/proxy_auth.py'; }\n"
                 + body + "\nrunning_tool_dir 123\n")
        result = subprocess.run(["/bin/bash", "-c", shell], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), home + "/.local/rivis/tool-0.9.4/addons")

    def test_bug_report_masks_private_lan_addresses(self):
        sys.path.insert(0, os.path.join(harness.REPO, "addons"))
        from bug_report import redact
        result = redact("proxy 192.168.17.81:9090 and 10.4.2.7 plus fd00::1; local 127.0.0.1", "/tmp/other")
        self.assertNotIn("192.168.17.81", result)
        self.assertNotIn("10.4.2.7", result)
        self.assertNotIn("fd00::1", result)
        self.assertIn("127.0.0.1", result)


class TlsLock(CliBase):
    def test_tls_cli_waits_for_shared_rules_lock(self):
        import fcntl
        self.ok("tls", "list")
        lock_path = os.path.join(os.path.dirname(self.rules_file()), ".rules.lock")
        with open(lock_path, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            proc = subprocess.Popen(["/bin/bash", harness.RIVIS, "tls", "ignore", "add", "api.example.test"],
                                    env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline:
                    with open(self.rules_file()) as fh:
                        self.assertNotIn("api.example.test", fh.read(), "tls wrote without waiting for the CLI rules lock")
                    time.sleep(0.1)
                self.assertIsNone(proc.poll(), "tls finished while the CLI rules lock was held")
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
            out, err = proc.communicate(timeout=15)
            self.assertEqual(proc.returncode, 0, out + err)


if __name__ == "__main__":
    unittest.main()
