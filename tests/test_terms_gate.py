"""Terms of Use gate: nothing that captures, decrypts or changes traffic runs until the user agreed to the CURRENT
terms text; stop / status / off commands always work; the proxy itself passes nothing while they are not accepted."""
import hashlib
import json
import os
import pty
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import Instance, LiveCase, wait_for

TERMS_PY = os.path.join(harness.REPO, "addons", "terms.py")


def tree_copy(terms_text):
    """A minimal installed-copy layout (product.json + addons/terms.py [+ terms/TERMS.md]) to vary the shipped text."""
    root = tempfile.mkdtemp(prefix="rivis-t-terms-")
    os.makedirs(os.path.join(root, "addons"))
    shutil.copy(TERMS_PY, os.path.join(root, "addons", "terms.py"))
    shutil.copy(os.path.join(harness.REPO, "product.json"), os.path.join(root, "product.json"))
    if terms_text is not None:
        os.makedirs(os.path.join(root, "terms"))
        with open(os.path.join(root, "terms", "TERMS.md"), "w") as fh:
            fh.write(terms_text)
    return root


class TermsModule(unittest.TestCase):
    def setUp(self):
        self.suite = harness.Suite.get()
        self.home = self.suite.new_home("terms", terms=False)
        self.roots = []

    def tearDown(self):
        for r in self.roots:
            shutil.rmtree(r, ignore_errors=True)

    def py(self, *args, root=None):
        script = os.path.join(root, "addons", "terms.py") if root else TERMS_PY
        env = dict(os.environ, HOME=self.home)
        return subprocess.run(["/usr/bin/python3", "-I", script] + list(args), env=env, capture_output=True, text=True, timeout=30)

    def copy(self, text):
        root = tree_copy(text)
        self.roots.append(root)
        return root

    def test_a_first_run_is_not_accepted_and_agreeing_records_who_when_and_which_text(self):
        r = self.py("status")
        self.assertEqual((r.returncode, r.stdout.strip()), (3, "required"))
        r = self.py("accept", "cli")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.py("status").returncode, 0)
        path = os.path.join(self.home, ".rivis-terms-acceptance.json")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        cur = json.load(open(path))["current"]
        with open(os.path.join(harness.REPO, "terms", "TERMS.md"), "rb") as fh:
            self.assertEqual(cur["terms_sha256"], hashlib.sha256(fh.read()).hexdigest())
        self.assertEqual((cur["answer"], cur["via"]), ("accepted", "cli"))
        self.assertNotIn("name", cur)                       # no typed name: the accounts say who agreed
        self.assertNotIn("account", cur)                    # not signed in for IT approval (yet)
        for key in ("at", "mac_user", "host", "version"):
            self.assertTrue(cur[key], key)

    def test_the_organisation_account_from_it_approval_is_recorded_with_the_agreement(self):
        with open(os.path.join(self.home, ".rivis-access.json"), "w") as fh:
            json.dump({"result": "approved", "account": "ada@example.test"}, fh)
        self.assertEqual(self.py("accept", "window").returncode, 0)
        cur = json.load(open(os.path.join(self.home, ".rivis-terms-acceptance.json")))["current"]
        self.assertEqual((cur["account"], cur["via"]), ("ada@example.test", "window"))

    def test_a_changed_text_asks_again_and_history_is_kept(self):
        root = self.copy("# Terms v1\n\nOne.\n")
        self.assertEqual(self.py("accept", "window", root=root).returncode, 0)
        self.assertEqual(self.py("status", root=root).returncode, 0)
        with open(os.path.join(root, "terms", "TERMS.md"), "w") as fh:
            fh.write("# Terms v2\n\nTwo.\n")
        r = self.py("status", "--json", root=root)
        self.assertEqual(r.returncode, 3)
        self.assertEqual(json.loads(r.stdout)["state"], "changed")
        self.assertEqual(self.py("accept", "cli", root=root).returncode, 0)
        doc = json.load(open(os.path.join(self.home, ".rivis-terms-acceptance.json")))
        self.assertEqual(len(doc["history"]), 1)
        self.assertEqual(doc["history"][0]["terms_title"], "Terms v1")

    def test_a_copy_without_terms_text_fails_closed(self):
        root = self.copy(None)
        self.assertEqual(self.py("status", root=root).returncode, 4)
        r = self.py("accept", "cli", root=root)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.py("status", root=self.copy("   \n")).returncode, 4)      # blank counts as none

    def test_a_hostile_or_unwritable_record_is_not_an_agreement(self):
        # JSON nested 100,000 deep raised RecursionError inside the proxy, and an add-on error lets the call through
        path = os.path.join(self.home, ".rivis-terms-acceptance.json")
        self.assertEqual(self.py("accept", "cli").returncode, 0)
        with open(path, "w") as fh:
            fh.write("[" * 100000 + "]" * 100000)
        r = self.py("status")
        self.assertEqual((r.returncode, r.stdout.strip()), (3, "required"), r.stdout + r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        # and when the answer cannot be saved, one plain sentence, not a traceback
        os.unlink(path)
        os.mkdir(path)                                     # a directory where the record should be
        r = self.py("accept", "cli")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("could not save your answer", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_declining_keeps_it_locked_and_only_known_channels_count(self):
        self.assertEqual(self.py("decline", "cli").returncode, 0)
        self.assertEqual(self.py("status").stdout.strip(), "declined")
        self.assertEqual(self.py("status").returncode, 3)
        self.assertEqual(self.py("accept", "email").returncode, 2)                       # unknown channel
        self.assertEqual(self.py("accept", "Ada Lovelace", "cli").returncode, 2)         # the old form: refused
        self.assertEqual(self.py("accept").returncode, 2)
        self.assertNotEqual(self.py("status").returncode, 0)


class TermsCli(unittest.TestCase):
    def setUp(self):
        self.suite = harness.Suite.get()
        self.home = self.suite.new_home("terms-cli", terms=False)
        self.env = self.suite.cli_env(self.home)

    def cli(self, *args):
        return self.suite.rivis(*args, home=self.home, env=self.env)

    def test_without_agreement_capture_commands_refuse_and_undo_commands_work(self):
        for args in (("rules", "list"), ("scripts", "list"), ("setup",), ("throttle", "3g"), ("android", "on")):
            r = self.cli(*args)
            self.assertEqual(r.returncode, 10, "%s -> %s %s" % (args, r.returncode, r.stdout + r.stderr))
            self.assertIn("Terms of Use", r.stderr)
            self.assertIn("rivis terms", r.stderr)
        for args in (("status",), ("stop",), ("version",), ("--help",), ("terms", "status"), ("terms", "show"),
                     ("android", "off"), ("ios", "off")):
            r = self.cli(*args)
            self.assertNotEqual(r.returncode, 10, "%s was gated: %s" % (args, r.stdout + r.stderr))
        self.assertIn("not accepted yet", self.cli("terms", "status").stdout)
        self.assertIn("Rivis Terms of Use", self.cli("terms", "show").stdout)

    def tty_run(self, args, typed):
        """Run the CLI on a pseudo-terminal (the gate asks only a person at a terminal) and type `typed`."""
        master, slave = pty.openpty()
        env = dict(self.env, PAGER="cat", TERM="dumb")
        p = subprocess.Popen(["/bin/bash", harness.RIVIS] + list(args), stdin=slave, stdout=slave, stderr=slave,
                             env=env, cwd=self.suite.root, close_fds=True)
        os.close(slave)
        out, sent, deadline = b"", False, time.time() + 30
        while time.time() < deadline:
            r, _, _ = select.select([master], [], [], 0.2)
            if r:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
                if not sent and b"Type yes to agree" in out:
                    os.write(master, typed.encode() + b"\n")
                    sent = True
            if p.poll() is not None and not r:
                break
        p.wait(10)
        os.close(master)
        return p.returncode, out.decode("utf-8", "replace")

    def test_a_person_at_a_terminal_is_asked_and_their_answer_counts(self):
        rc, out = self.tty_run(["rules", "list"], "")                       # Enter = decline
        self.assertEqual(rc, 10, out)
        self.assertIn("will not run", out)
        self.assertIn("declined", self.cli("terms", "status").stdout)
        rc, out = self.tty_run(["terms"], "YES ")
        self.assertEqual(rc, 0, out)
        self.assertIn("accepted", out)
        self.assertEqual(self.cli("rules", "list").returncode, 0)


class TermsLocked(LiveCase):
    """Started with nobody at a terminal and no agreement: the proxy runs LOCKED and the window asks."""
    INSTANCE_KW = {"terms": False}

    def setUp(self):
        pass        # reset_state() proves reloads with a call through the proxy, which is locked here

    def test_locked_until_agreed_in_the_window_then_traffic_flows(self):
        st = self.panel.state()["terms"]
        self.assertEqual(st["state"], "required")
        self.assertEqual(self.panel.ok("terms_status", {})["terms"]["state"], "required")      # what the window's cover asks
        r = self.fetch("/json/small")
        self.assertEqual(r.status, 403)
        self.assertIn(b"Terms of Use", r.body)
        self.assertEqual(len(self.up.hits_for("/json/small")), 0)                 # never reached the server
        doc = self.panel.ok("terms_text", {})
        self.assertIn("Terms of Use", doc["text"])
        code, _d, raw = self.panel.post("terms_accept", {"sha256": "0" * 64})
        self.assertEqual(code, 400)
        self.assertIn("changed", raw.decode())
        code, _d, raw = self.panel.post("terms_accept", {})                # never fetched: never agreed
        self.assertEqual(code, 400)
        self.assertEqual(self.fetch("/json/small").status, 403)
        self.panel.ok("terms_accept", {"sha256": doc["sha256"]})
        self.assertEqual(self.panel.state()["terms"]["state"], "accepted")
        self.assertEqual(self.fetch("/json/small").status, 200)
        rec = json.load(open(os.path.join(self.inst.home, ".rivis-terms-acceptance.json")))["current"]
        self.assertEqual((rec["answer"], rec["via"]), ("accepted", "window"))

    def test_z_declining_in_the_window_stops_rivis(self):
        self.panel.ok("terms_decline", {})
        wait_for(lambda: self.inst.proc.poll() is not None, 20, 0.2, "proxy stopped after decline")
        self.assertEqual(json.load(open(os.path.join(self.inst.home, ".rivis-terms-acceptance.json")))["current"]["answer"],
                         "declined")


if __name__ == "__main__":
    unittest.main()
