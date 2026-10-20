"""Bash CLI (`rivis`, run with /bin/bash 3.2): projects, rules, throttle, breakpoint, scripts, tls, compose,
net-reset, the neo-mitm shim, `start` argv, migration. Offline: no proxy is started."""
import hashlib
import json
import subprocess
import os
import shutil
import socket
import re
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import NEO_MITM, Suite, wait_for


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class CliBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()

    def setUp(self):
        self.home = self.suite.new_home("cli")
        self.state = os.path.join(self.home, ".rivis")
        self.env = self.suite.cli_env(self.home)

    def cli(self, *args, **kw):
        kw.setdefault("env", self.env)
        return self.suite.rivis(*args, home=self.home, **kw)

    def ok(self, *args, **kw):
        r = self.cli(*args, **kw)
        self.assertEqual(r.returncode, 0, "rivis %s -> rc=%s\nout=%s\nerr=%s" % (" ".join(args), r.returncode, r.stdout, r.stderr))
        return r

    def stopped_status(self, *args, **kw):
        """`status` while nothing runs: prints everything, exit code 3 (QA-11)."""
        r = self.cli("status", *args, **kw)
        self.assertEqual(r.returncode, 3, "rivis status (nothing running) -> rc=%s\nout=%s\nerr=%s" % (r.returncode, r.stdout, r.stderr))
        return r

    def refused(self, *args, msg=None, **kw):
        r = self.cli(*args, **kw)
        self.assertNotEqual(r.returncode, 0, "rivis %s unexpectedly succeeded: %s" % (" ".join(args), r.stdout))
        if msg:
            self.assertIn(msg, r.stdout + r.stderr)
        return r

    def rules_file(self, project="default"):
        return os.path.join(self.state, "projects", project, "rules.json")

    def cfg(self, project="default"):
        with open(self.rules_file(project)) as fh:
            return json.load(fh)


class Help(CliBase):
    def test_version_prints_the_release(self):
        # pilot support: "which version are you on?" (the repo copy reads install/VERSION)
        want = open(os.path.join(harness.REPO, "install", "VERSION")).read().strip()
        for flag in ("--version", "-V", "version"):
            self.assertEqual(self.ok(flag).stdout.strip(), "rivis " + want, flag)

    def test_help_lists_commands(self):
        out = self.ok("--help").stdout
        for word in ("start", "projects", "rules", "scripts", "throttle", "tls", "compose", "breakpoint", "net-reset", "bug-report", "android", "ios"):
            self.assertIn(word, out)
        self.assertIn("rivis", out)

    def test_unknown_command(self):
        self.refused("frobnicate", msg="unknown command")

    def test_works_under_bash_3_2(self):
        r = self.suite.run(["/bin/bash", "--version"], env=self.env)
        self.assertIn("version 3.2", r.stdout)       # the macOS system bash the installer's users have


class BugReport(CliBase):
    def test_runs_without_options_under_bash_3_2(self):
        # bash 3.2 + set -u: an empty "${out[@]}" was 'unbound variable' — the pilot kit tells testers to run this bare
        r = self.ok("bug-report")
        self.assertNotIn("unbound variable", r.stderr)
        made = os.listdir(os.path.join(self.state, "bug-reports"))
        self.assertEqual(len(made), 1, made)
        self.assertTrue(made[0].startswith("rivis-bug-report-") and made[0].endswith(".zip"), made)


class Projects(CliBase):
    def test_list_shows_shipped_profiles_and_marks_default(self):
        out = self.ok("projects", "list").stdout
        self.assertRegex(out, r"(?m)^\* default\b")
        self.assertRegex(out, r"(?m)^  neo\b")
        self.assertNotIn("_template", out)

    def test_use_show_and_current_project_file(self):
        self.ok("projects", "use", "neo")
        cp = os.path.join(self.state, "current-project")
        self.assertEqual(open(cp).read().strip(), "neo")
        self.assertEqual(mode(cp), 0o600)
        self.assertRegex(self.ok("projects", "list").stdout, r"(?m)^\* neo\b")
        shown = json.loads(self.ok("projects", "show", "neo").stdout)
        self.assertEqual(shown["id"], "neo")
        self.assertIn("neo", self.ok("projects", "show").stdout)        # default argument = current project

    def test_resolution_order_flag_env_current_default(self):
        # R2A-09: a port in --hosts can never match (the filter compares host names), so it is refused up front
        for bad in (r"127\.0\.0\.1:18081", r"api\.test:\d+"):
            self.assertIn("host names only", self.refused("projects", "new", "p-port", "--label", "P", "--hosts", bad).stderr)
        # R5A-06: --hosts runs on every call through the proxy, so it gets the same safety check as rules and throttle
        self.assertIn("nested repetition", self.refused("projects", "new", "p-rx", "--label", "R", "--hosts", "(a+)+$").stderr)
        self.ok("projects", "new", "p-flag", "--label", "F", "--hosts", "f")
        self.ok("projects", "new", "p-env", "--label", "E", "--hosts", "e")
        self.ok("projects", "new", "p-cur", "--label", "C", "--hosts", "c")
        self.assertIn("project: default", self.stopped_status().stdout)
        self.ok("projects", "use", "p-cur")
        self.assertIn("project: p-cur", self.stopped_status().stdout)
        env = dict(self.env, RIVIS_PROJECT="p-env")
        self.assertIn("project: p-env", self.stopped_status(env=env).stdout)
        r = self.cli("--project", "p-flag", "status", env=env)
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn("project: p-flag", r.stdout)
        self.assertIn("project: p-flag", self.stopped_status("--project=p-flag", env=env).stdout)
        self.assertIn("project: p-flag", self.ok("rules", "list", "--project", "p-flag", env=env).stdout.replace("rules (", "project: p-flag ("))
        # state is isolated per project
        self.assertTrue(os.path.isfile(self.rules_file("p-flag")))
        self.assertTrue(os.path.isfile(self.rules_file("p-env")))

    def test_legacy_env_alias_is_a_fallback(self):
        self.ok("projects", "new", "p-leg", "--label", "L", "--hosts", "l")
        env = dict(self.env, NEO_MITM_PROJECT="p-leg")
        self.assertIn("project: p-leg", self.stopped_status(env=env).stdout)
        env["RIVIS_PROJECT"] = "default"        # the product-prefixed name wins over the legacy one
        self.assertIn("project: default", self.stopped_status(env=env).stdout)

    def test_invalid_ids_are_refused(self):
        for bad in ("../x", "A", "Up", ".hidden", "-lead", "a/b", "a b", "x" * 65, "semi;colon", "$(id)"):
            r = self.cli("--project", bad, "status")
            self.assertNotEqual(r.returncode, 0, bad)
            self.assertIn("invalid project ID", r.stderr, bad)
            r = self.cli("projects", "use", bad)
            self.assertNotEqual(r.returncode, 0, bad)
            r = self.cli("projects", "new", bad, "--label", "x", "--hosts", "y")
            self.assertNotEqual(r.returncode, 0, bad)
            r = self.cli("projects", "show", bad)
            self.assertNotEqual(r.returncode, 0, bad)
        self.assertFalse(os.path.exists(os.path.join(self.state, "profiles")) and os.listdir(os.path.join(self.state, "profiles")))
        self.assertFalse(os.path.exists(os.path.join(self.home, "x")))

    def test_unknown_project(self):
        self.refused("--project", "nope", "status", msg="unknown project")
        self.refused("projects", "use", "nope", msg="unknown project")
        self.refused("projects", "show", "nope", msg="unknown project")

    def test_flag_without_value(self):
        self.refused("status", "--project", msg="needs an ID")
        self.refused("status", "--project=", msg="needs an ID")

    def test_bad_or_stale_current_project_falls_back_with_a_warning(self):
        os.makedirs(self.state)
        with open(os.path.join(self.state, "current-project"), "w") as fh:
            fh.write("../../etc\n")
        r = self.stopped_status()
        self.assertIn("project: default", r.stdout)
        self.assertIn("ignoring invalid current-project", r.stderr)
        with open(os.path.join(self.state, "current-project"), "w") as fh:
            fh.write("deleted-project\n")
        r = self.stopped_status()
        self.assertIn("project: default", r.stdout)
        self.assertIn("no longer exists", r.stderr)

    def test_new_creates_private_profile_and_validates_input(self):
        r = self.ok("projects", "new", "bank-a", "--label", "Bank A", "--hosts", r"api\.bank-a\.test")
        pdir = os.path.join(self.state, "profiles", "bank-a")
        doc = json.load(open(os.path.join(pdir, "project.json")))
        self.assertEqual((doc["id"], doc["label"], doc["hosts"]), ("bank-a", "Bank A", r"api\.bank-a\.test"))
        self.assertEqual(doc["record_match"], doc["hosts"])
        ex = json.load(open(os.path.join(pdir, "rules.example.json")))
        self.assertEqual(ex["throttle_match"], r"api\.bank-a\.test")
        self.assertEqual(ex["collections"]["record_match"], r"api\.bank-a\.test")
        self.assertEqual(mode(os.path.join(pdir, "project.json")), 0o600)
        self.assertEqual(mode(pdir), 0o700)
        self.assertIn("created user profile", r.stdout)
        self.assertRegex(self.ok("projects", "list").stdout, r"(?m)^  bank-a\s+Bank A")
        self.refused("projects", "new", "bank-a", "--label", "x", "--hosts", "y", msg="already exists")
        self.refused("projects", "new", "p2", "--hosts", "y", msg="--label is required")
        self.refused("projects", "new", "p2", "--label", "x", msg="--hosts is required")
        self.refused("projects", "new", "p2", "--label", "x", "--hosts", "(unclosed", msg="invalid hosts regex")
        self.refused("projects", "new", "p2", "--label", "x", "--hosts", "y", "--bogus", msg="unknown option")
        self.assertFalse(os.path.exists(os.path.join(self.state, "profiles", "p2")))
        self.assertEqual([x for x in os.listdir(os.path.join(self.state, "profiles")) if x.startswith(".")], [])   # no temp dirs left

    def test_user_profile_overrides_shipped_one(self):
        os.makedirs(os.path.join(self.state, "profiles", "neo"))
        with open(os.path.join(self.state, "profiles", "neo", "project.json"), "w") as fh:
            json.dump({"id": "neo", "label": "Mine", "hosts": "x"}, fh)
        self.assertRegex(self.ok("projects", "list").stdout, r"neo\s+Mine")

    def test_first_use_copies_example_rules_with_private_modes(self):
        self.ok("rules", "list")
        rf = self.rules_file()
        self.assertEqual(mode(rf), 0o600)
        for d in ("", "projects/default", "projects/default/mocks", "projects/default/scripts",
                  "projects/default/collections", "projects/default/sessions"):
            p = os.path.join(self.state, d)
            self.assertEqual(mode(p), 0o700, p)
        self.assertEqual(self.cfg()["rules"], [])
        self.ok("--project", "neo", "rules", "list")
        self.assertGreaterEqual(len(self.cfg("neo")["rules"]), 1)
        self.assertTrue(all(r["enabled"] is False for r in self.cfg("neo")["rules"]))    # "all rules off"


class Rules(CliBase):
    def test_rules_rm_keeps_user_and_legacy_mocks_and_cross_project_reader(self):
        self.ok("projects", "use", "neo")
        self.ok("rules", "list")
        self.ok("projects", "use", "default")
        self.ok("rules", "list")
        self.ok("projects", "use", "neo")
        mocks = os.path.join(self.state, "projects", "neo", "mocks")
        paths = {"mine": os.path.join(mocks, "my-response.json"),
                 "legacy": os.path.join(mocks, "legacy.json")}
        for path in paths.values():
            with open(path, "w") as fh: fh.write("{}")
        self.ok("rules", "add", "mine", "match=/x", "action=map_local", "file=" + paths["mine"])
        neo = self.cfg("neo")
        neo["rules"].append({"name": "legacy", "enabled": True, "match": "/legacy",
                             "action": "map_local", "file": paths["legacy"]})
        with open(self.rules_file("neo"), "w") as fh: json.dump(neo, fh)
        self.ok("rules", "add", "shared", "match=/shared", "action=map_local", "body={}")
        paths["shared"] = next(r["file"] for r in self.cfg("neo")["rules"] if r["name"] == "shared")
        default = self.cfg("default")
        default["rules"].append({"name": "reader", "action": "respond", "match": "/read",
                                 "body_file": paths["shared"]})
        with open(self.rules_file("default"), "w") as fh: json.dump(default, fh)
        for name in ("mine", "legacy", "shared"):
            output = self.ok("rules", "rm", name).stdout
            self.assertIn("mock file kept: " + paths[name], output)
            self.assertTrue(os.path.isfile(paths[name]))

    def test_mock_set_preserves_other_methods_on_same_match(self):
        mock_file = os.path.join(self.home, "mock.json")
        with open(mock_file, "w") as fh:
            fh.write('{}')

        def set_mock(name, method):
            return self.ok("rules", "mock-set", name, "match=/shared", "action=map_local",
                           "file=" + mock_file, "method=" + method)

        set_mock("get-mock", "GET")
        post = set_mock("post-mock", "POST")
        self.assertNotIn("replaced Map Local", post.stdout)
        self.assertEqual({r["name"] for r in self.cfg()["rules"]}, {"get-mock", "post-mock"})

        replaced = set_mock("post-new", "post")
        self.assertIn("replaced Map Local rule: post-mock", replaced.stdout)
        self.assertEqual({r["name"] for r in self.cfg()["rules"]}, {"get-mock", "post-new"})

    def test_r10_10_unwritable_project_reports_a_single_actionable_error(self):
        self.ok("rules", "add", "r10-10", "match=/x", "action=status", "status=503")
        project = os.path.dirname(self.rules_file())
        os.chflags(project, stat.UF_IMMUTABLE)
        try:
            for args in (("rules", "off", "r10-10"),
                         ("rules", "add", "r10-10-new", "match=/y", "action=status", "status=504")):
                with self.subTest(args=args):
                    r = self.refused(*args)
                    self.assertIn("could not save rules", r.stderr)
                    self.assertNotIn("Traceback", r.stderr)
                    self.assertEqual(len(r.stderr.strip().splitlines()), 1, r.stderr)
        finally:
            os.chflags(project, 0)

    def test_missing_map_local_file_messages_are_actionable(self):
        missing = os.path.join(self.home, "missing-mock.json")
        add = self.refused("rules", "add", "missing", "match=/x", "action=map_local", "file=" + missing)
        self.assertIn("file not found: " + missing, add.stdout + add.stderr)
        self.assertNotIn("use an absolute path", add.stdout + add.stderr)

        with open(missing, "w") as fh:
            fh.write("{}")
        self.ok("rules", "add", "gone", "match=/x", "action=map_local", "file=" + missing)
        os.unlink(missing)
        listed = self.ok("rules", "list").stdout
        self.assertIn("is missing or unreadable — this rule answers 502", listed)
        self.assertNotIn("R2A-02", listed)

    def test_r5a02_add_and_list_use_proxy_rule_validation(self):
        # R5A-02: a rule advertised ON must survive the proxy's load check.
        for name, fields, reason in (("bad-headers", ("action=respond", "headers=nope"), "headers must be"),
                                     ("bad-patch", ("action=json_patch", "set=nope"), "json_patch set"),
                                     ("bad-side", ("action=set_header", "header=X-QA", "side=whatever"), "set_header side")):
            self.refused("rules", "add", name, "match=/x", *fields, msg=reason)
        self.assertEqual(self.cfg()["rules"], [])
        c = self.cfg()
        c["rules"] = [{"name": "imported", "enabled": True, "match": "/x", "action": "respond", "headers": "nope"},
                      {"name": "bad-method", "enabled": True, "match": "/x", "action": "block", "method": 7},
                      {"name": "bad-file", "enabled": True, "match": "/x", "action": "map_local", "file": 7}]
        with open(self.rules_file(), "w") as fh:
            json.dump(c, fh)
        out = self.ok("rules", "list").stdout
        self.assertRegex(out, r"SKIPPED\s+imported")
        self.assertIn("headers must be", out)
        self.assertRegex(out, r"SKIPPED\s+bad-method")
        self.assertRegex(out, r"SKIPPED\s+bad-file")

    def test_concurrent_adds_all_persist(self):
        # R7B-03: simultaneous adds each read, changed and rewrote the file; all said "added", only the last survived
        import threading
        out = []
        ts = [threading.Thread(target=lambda n=n: out.append(self.ok("rules", "add", "par-%d" % n, "match=/par%d" % n,
                                                                      "action=block").returncode)) for n in range(6)]
        [t.start() for t in ts]; [t.join(60) for t in ts]
        self.assertEqual(out, [0] * 6)
        listed = self.ok("rules", "list").stdout
        self.assertEqual([n for n in range(6) if "par-%d" % n in listed], list(range(6)), listed)

    def test_r7a02_reversed_map_remote_is_reported(self):
        # R7A-02: the reversed keys left an ON rule that matched calls but never rewrote their URLs.
        self.ok("rules", "add", "backwards", "match=/remote", "action=map_remote",
                "replace=https://destination.test/echo", "with=/remote")
        listed = self.ok("rules", "list").stdout
        self.assertIn("backwards", listed)
        self.assertIn("replace", listed)
        self.assertIn("never", listed.lower())

    def test_r5a02_edit_refuses_rule_proxy_would_skip(self):
        # R5A-02: a rejected edit leaves the rules file that the proxy reloads intact.
        self.ok("rules", "list")
        before = open(self.rules_file()).read()
        editor = os.path.join(self.home, "invalid-editor")
        with open(editor, "w") as fh:
            fh.write('#!/bin/sh\nprintf \'%s\\n\' \'{"rules":[{"name":"bad","action":"respond","headers":"nope"}]}\' > "$1"\n')
        os.chmod(editor, 0o700)
        r = self.refused("rules", "edit", env=dict(self.env, EDITOR=editor), msg="headers must be")
        self.assertNotIn("Traceback", r.stderr)
        self.assertEqual(open(self.rules_file()).read(), before)
        staged = [os.path.join(os.path.dirname(self.rules_file()), name)
                  for name in os.listdir(os.path.dirname(self.rules_file())) if name.startswith(".rules-edit-")]
        self.assertEqual(len(staged), 1, staged)
        self.assertIn(staged[0], r.stderr)
        self.assertIn("kept", r.stderr)
        self.assertEqual(json.load(open(staged[0]))["rules"][0]["name"], "bad")

    def test_non_object_rule_entries_do_not_crash_cli(self):
        # R3A-07: hand-edited junk must not hide valid rules or raise a traceback.
        self.ok("rules", "list")
        with open(self.rules_file(), "w") as fh:
            json.dump({"rules": [1, "x", None, {"name": "ok", "match": "/x", "action": "block", "enabled": True}]}, fh)
        self.assertIn("entry 1 is not an object", self.ok("rules", "list").stdout)
        self.ok("rules", "off", "ok")
        self.ok("rules", "rm", "ok")

    def test_add_list_show_on_off_rm(self):
        r = self.ok("rules", "add", "hello", "match=/hello", "action=respond", "status=201", "body=hi")
        self.assertIn("added and ON", r.stdout)
        out = self.ok("rules", "list").stdout
        self.assertIn("hello", out)
        self.assertRegex(out, r"ON\s+hello\s+respond")
        shown = json.loads(self.ok("rules", "show", "hello").stdout)
        self.assertEqual((shown["status"], shown["body"], shown["match"]), (201, "hi", "/hello"))
        self.assertIn("OFF", self.ok("rules", "off", "hello").stdout)
        self.assertFalse(self.cfg()["rules"][0]["enabled"])
        self.assertRegex(self.ok("rules", "list").stdout, r"off\s+hello")
        self.ok("rules", "on", "hello")
        self.assertTrue(self.cfg()["rules"][0]["enabled"])
        self.assertIn("removed hello", self.ok("rules", "rm", "hello").stdout)
        self.assertEqual(self.cfg()["rules"], [])
        self.assertIn("(none)", self.ok("rules", "list").stdout)

    def test_pilot_rm_deletes_the_rules_own_mock_file_only(self):
        # pilot feedback #5: `rules rm` of a mock left mocks/NAME.json behind; a file the user pointed at stays
        self.ok("rules", "list")
        mocks = os.path.join(self.state, "projects", "default", "mocks")
        os.makedirs(mocks, exist_ok=True)
        own, shared, user = (os.path.join(mocks, "own.json"), os.path.join(mocks, "shared.json"),
                             os.path.join(self.home, "mine.json"))
        for f in (shared, user):
            open(f, "w").write("{}")
        self.ok("rules", "add", "own", "match=/own", "action=map_local", "body={}")
        own = next(r["file"] for r in self.cfg()["rules"] if r["name"] == "own")
        self.ok("rules", "add", "sh1", "match=/sh1", "action=map_local", "file=" + shared)
        self.ok("rules", "add", "sh2", "match=/sh2", "action=map_local", "file=" + shared)
        self.ok("rules", "add", "user", "match=/user", "action=map_local", "file=" + user)
        self.assertIn("its mock file", self.ok("rules", "rm", "own").stdout)
        self.assertFalse(os.path.exists(own))
        self.ok("rules", "rm", "sh1")
        self.assertTrue(os.path.exists(shared))              # sh2 still serves it
        self.ok("rules", "rm", "sh2")
        self.assertTrue(os.path.exists(shared))
        self.assertIn("mock file kept:", self.ok("rules", "rm", "user").stdout)
        self.assertTrue(os.path.exists(user))

    def test_mock_file_shared_by_body_file_survives_cli_delete(self):
        self.ok("rules", "list")
        mocks = os.path.join(self.state, "projects", "default", "mocks")
        os.makedirs(mocks, exist_ok=True)
        path = os.path.join(mocks, "shared.json")
        open(path, "w").write("{}")
        self.ok("rules", "add", "owner", "match=/a", "action=map_local", "file=" + path)
        cfg = self.cfg()
        cfg["rules"].append({"name": "reader", "action": "respond", "match": "/b", "body_file": path})
        with open(self.rules_file(), "w") as fh:
            json.dump(cfg, fh)
        self.ok("rules", "rm", "owner")
        self.assertTrue(os.path.isfile(path))

    def test_rules_override_keeps_project_scope_and_mock_folder(self):
        self.env["RIVIS_RULES"] = os.path.join(self.home, "override", "rules.json")
        os.makedirs(os.path.dirname(self.env["RIVIS_RULES"]))
        self.ok("rules", "list", "--project", "neo")
        self.ok("throttle", "lte", "match=/old", "--project", "neo")
        self.ok("throttle", "off", "--project", "neo")
        cfg = json.load(open(self.env["RIVIS_RULES"]))
        self.assertEqual(cfg["throttle_match"], json.load(open(os.path.join(harness.REPO, "projects", "neo", "project.json")))["throttle_match"])
        mocks = os.path.join(self.state, "projects", "neo", "mocks")
        os.makedirs(mocks, exist_ok=True)
        path = os.path.join(mocks, "owned.json")
        self.ok("rules", "add", "owned", "match=/a", "action=map_local", "body={}", "--project", "neo")
        with open(self.env["RIVIS_RULES"]) as fh:
            path = next(r["file"] for r in json.load(fh)["rules"] if r["name"] == "owned")
        self.ok("rules", "rm", "owned", "--project", "neo")
        self.assertFalse(os.path.exists(path))

    def test_every_action_can_be_added(self):
        mock_file = os.path.join(self.home, "m.json")
        open(mock_file, "w").write("{}")
        cases = {
            "r-respond": ["action=respond", "status=404", 'headers={"X-A":"1"}'],
            "r-map-local": ["action=map_local", "file=" + mock_file],
            "r-status": ["action=status", "status=503"],
            "r-patch": ["action=json_patch", 'set={"a.b[0]":1}'],
            "r-delay": ["action=delay", "ms=250"],
            "r-header": ["action=set_header", "header=X-QA", "value=on", "side=response"],
            "r-remote": ["action=map_remote", r"replace=https://a\.test", "with=https://b.test"],
            "r-block": ["action=block", "method=POST"],
        }
        for name, extra in cases.items():
            self.ok("rules", "add", name, "match=/x", *extra)
        rules = {r["name"]: r for r in self.cfg()["rules"]}
        self.assertEqual(len(rules), 8)
        self.assertEqual(rules["r-respond"]["headers"], {"X-A": "1"})       # JSON values are parsed
        self.assertEqual(rules["r-delay"]["ms"], 250)
        self.assertEqual(rules["r-patch"]["set"], {"a.b[0]": 1})
        self.assertEqual(rules["r-block"]["method"], "POST")

    def test_required_fields_and_bad_input_are_refused(self):
        self.refused("rules", "add", "a", "action=map_local", msg="needs: file")
        self.refused("rules", "add", "a", "action=status", msg="needs: status")
        self.refused("rules", "add", "a", "action=json_patch", msg="needs: set")
        self.refused("rules", "add", "a", "action=delay", msg="needs: ms")
        self.refused("rules", "add", "a", "action=set_header", msg="needs: header")
        self.refused("rules", "add", "a", "action=map_remote", "replace=x", msg="needs: with")
        # R2A-11: a map_remote whose result is not http(s)+host is refused when added, not at the first call
        self.refused("rules", "add", "a", "action=map_remote", "replace=^.*$", "with=not-a-url", msg="unusable")
        self.refused("rules", "add", "a", "action=map_remote", "replace=^.*$", "with=ftp://x.example/y", msg="unusable")
        self.refused("rules", "add", "a", "action=explode", msg="action must be one of")
        self.refused("rules", "add", "a", msg="action must be one of")
        self.refused("rules", "add", "a", "action=block", "match=(unclosed", msg="bad regex")
        for status in ("0", "99", "600", "99999", "true", "200.5"):
            r = self.refused("rules", "add", "s" + status.replace(".", "-"), "action=status", "status=" + status,
                          msg="status must be an integer from 100 to 599")
            self.assertNotIn("Traceback", r.stderr)
        self.refused("rules", "add", "a", "action=map_local", "file=/no/such/file", msg="file not found")
        self.refused("rules", "add", "a", "action=block", "noequals", msg="expected key=value")
        self.assertEqual(self.cfg()["rules"], [])
        self.ok("rules", "add", "a", "action=block")
        self.refused("rules", "add", "a", "action=block", msg="exists")
        self.refused("rules", "on", "missing", msg="no rule named")
        self.refused("rules", "rm", "missing", msg="no rule named")
        self.refused("rules", "show", "missing", msg="no rule named")
        self.refused("rules", "frob", "a", msg="unknown rules command")
        self.refused("rules", "on", msg="usage")

    def test_rules_edit_uses_editor_and_detects_broken_json(self):
        self.ok("rules", "list")
        self.ok("rules", "edit")                    # EDITOR=/usr/bin/true: file unchanged, still valid
        with open(self.rules_file(), "w") as fh:
            fh.write("{ not json")
        r = self.refused("rules", "list")              # reading a corrupt file must fail loudly, not silently reset it
        self.assertIn("not valid JSON", r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        self.assertEqual(open(self.rules_file()).read(), "{ not json")

    def test_rules_edit_does_not_lock_out_other_commands_or_overwrite_their_changes(self):
        self.ok("rules", "list")
        editor = os.path.join(self.home, "waiting-editor")
        ready = os.path.join(self.home, "editor-ready")
        release = os.path.join(self.home, "editor-release")
        with open(editor, "w") as fh:
            fh.write('#!/bin/sh\ntouch "$RIVIS_TEST_EDITOR_READY"\n'
                     'while [ ! -e "$RIVIS_TEST_EDITOR_RELEASE" ]; do sleep 0.1; done\n')
        os.chmod(editor, 0o700)
        env = dict(self.env, EDITOR=editor, RIVIS_TEST_EDITOR_READY=ready, RIVIS_TEST_EDITOR_RELEASE=release)
        editing = subprocess.Popen(["/bin/bash", harness.RIVIS, "rules", "edit"], env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            wait_for(lambda: os.path.exists(ready), 5, 0.05, "editor did not open")
            added = self.cli("rules", "add", "concurrent", "action=block", timeout=3)
            self.assertEqual(added.returncode, 0, added.stderr)
        finally:
            open(release, "w").close()
            out, err = editing.communicate(timeout=5)
        self.assertNotEqual(editing.returncode, 0, out + err)
        self.assertIn("changed while the editor was open", err)
        self.assertIn("concurrent", [r["name"] for r in self.cfg()["rules"]])
        self.assertIn("edited rules kept at", err)

    def test_rules_file_written_atomically_and_private(self):
        self.ok("rules", "add", "a", "action=block")
        self.assertEqual(mode(self.rules_file()), 0o600)
        left = [x for x in os.listdir(os.path.dirname(self.rules_file())) if x.startswith(".rules-")]
        self.assertEqual(left, [])


class NoCache(CliBase):
    def test_on_off_status(self):
        self.assertEqual(self.ok("nocache").stdout.strip().splitlines()[-1], "No caching: off")   # first run also creates rules.json
        self.assertNotIn("No caching", self.stopped_status().stdout)
        self.assertEqual(self.ok("nocache", "on").stdout.strip(), "No caching: on")
        self.assertIs(self.cfg()["no_cache"], True)
        self.assertEqual(self.ok("nocache", "status").stdout.strip(), "No caching: on")
        self.assertIn("No caching: on", self.stopped_status().stdout)
        self.assertEqual(self.ok("nocache", "off").stdout.strip(), "No caching: off")
        self.assertIs(self.cfg()["no_cache"], False)
        self.assertNotIn("No caching", self.stopped_status().stdout)
        self.refused("nocache", "maybe", msg="on | off | status")
        self.refused("nocache", "on", "extra", msg="on | off | status")

    def test_help_lists_nocache(self):
        self.assertIn("nocache on|off|status", self.ok("--help").stdout)
        self.assertIn("nocache", self.ok("nocache", "--help").stdout)


class Throttle(CliBase):
    def test_r5a04_manual_values_are_reported(self):
        # R5A-04: both the setter and readback must show the active manual settings.
        out = self.ok("throttle", "manual", "latency_ms=120", "jitter_ms=4", "down_kbps=500",
                      "up_kbps=250", "loss_pct=3", "response_delay_ms=20", "match=/x").stdout
        for text in ("latency_ms=120", "jitter_ms=4", "down_kbps=500", "up_kbps=250", "loss_pct=3", "response_delay_ms=20"):
            self.assertIn(text, out)
            self.assertIn(text, self.ok("throttle").stdout)
        self.assertIn("loss: 3.0%", self.ok("throttle").stdout)
        self.assertIn("latency_ms=120", self.ok("rules", "list").stdout)

    PROFILES = ["3g-urban", "lte-congested", "high-latency-vpn", "packet-loss-8", "lte", "3g", "edge", "slow", "manual"]

    def test_loss_override_expires_when_profile_changes(self):
        # R3A-03: one loss=100 experiment must not poison subsequent profiles.
        self.ok("throttle", "packet-loss-8", "loss=100")
        self.ok("throttle", "3g-urban")
        self.assertEqual(self.cfg()["loss"], 0)
        self.ok("throttle", "packet-loss-8")
        self.assertEqual(self.cfg()["loss"], 0)

    def test_r906_match_scope_expires_when_profile_changes(self):
        self.ok("throttle", "300ms", "match=only-this")
        self.assertEqual(self.cfg()["throttle_match"], "only-this")
        out = self.ok("throttle", "packet-loss-8").stdout
        self.assertIn("match: (all)", out)
        self.assertEqual(self.cfg()["throttle_match"], "")
        self.ok("throttle", "lte", "match=next-only")
        self.assertIn("match: (all)", self.ok("throttle", "off").stdout)
        self.assertEqual(self.cfg()["throttle_match"], "")

    def test_pilot_off_returns_to_the_project_default_scope(self):
        # pilot feedback #2: after `throttle off` a bare profile must throttle the project's hosts again, not the
        # last match= (0.9.6) and not every call (0.9.7)
        self.ok("--project", "neo", "throttle", "manual", "match=qa-th-slow", "latency_ms=300")
        self.assertEqual(self.cfg("neo")["throttle_match"], "qa-th-slow")
        self.assertIn(r"match: neo\.sa", self.ok("--project", "neo", "throttle", "off").stdout)
        self.ok("--project", "neo", "throttle", "3g-urban")
        self.assertEqual(self.cfg("neo")["throttle_match"], r"neo\.sa")

    def test_every_profile(self):
        for p in self.PROFILES:
            self.ok("throttle", p)
            self.assertEqual(self.cfg()["throttle"], p)
        self.ok("throttle", "off")
        self.assertEqual(self.cfg()["throttle"], "off")

    def test_latency_spec_and_case_insensitive(self):
        self.ok("throttle", "400ms")
        self.assertEqual(self.cfg()["throttle"], "400ms")
        self.ok("throttle", "250ms/512kbps")
        self.assertEqual(self.cfg()["throttle"], "250ms/512kbps")
        self.ok("throttle", "LTE")
        self.assertEqual(self.cfg()["throttle"], "lte")

    def test_shorthand_latency_and_bandwidth_have_manual_caps(self):
        # R1A-01: a typo in shorthand once stored eleven days of latency as a valid profile.
        self.ok("throttle", "120000ms/1000000kbps")
        before = self.cfg()["throttle"]
        for spec, label in (("120001ms", "latency_ms"), ("999999999ms", "latency_ms"),
                            ("1ms/1000001kbps", "down_kbps")):
            self.refused("throttle", spec, msg=label)
            self.assertEqual(self.cfg()["throttle"], before)

    def test_options(self):
        self.ok("throttle", "3g-urban", r"match=api\.x\.test", "loss=5")
        c = self.cfg()
        self.assertEqual((c["throttle_match"], c["loss"]), (r"api\.x\.test", 5.0))
        self.ok("throttle", "manual", "latency_ms=100", "jitter_ms=10", "down_kbps=500", "up_kbps=250",
                "loss_pct=3", "response_delay_ms=40")
        self.assertEqual(self.cfg()["manual"], {"latency_ms": 100.0, "jitter_ms": 10.0, "down_kbps": 500.0,
                                                "up_kbps": 250.0, "loss_pct": 3.0, "response_delay_ms": 40.0})
        self.ok("throttle", "off")
        self.assertEqual(self.cfg()["loss"], 0)               # "off" = clean network

    def test_show_without_args(self):
        self.ok("throttle", "lte")
        self.assertIn("throttle: lte", self.ok("throttle").stdout)

    def test_invalid(self):
        self.refused("throttle", "warp9", msg="throttle:")
        self.refused("throttle", "100ms/", msg="throttle:")
        self.refused("throttle", "lte", "bogus=1", msg="throttle options")
        r = self.cli("throttle", "lte", "match=(unclosed")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("bad regex", r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        r = self.cli("throttle", "lte", "loss=abc")
        self.assertNotEqual(r.returncode, 0)

    def test_match_whitespace_is_trimmed(self):
        self.ok("throttle", "lte", "match=  /json/small  ")
        self.assertEqual(self.cfg()["throttle_match"], "/json/small")


    def test_out_of_range_and_non_finite_numbers_are_refused(self):
        """FOUND-BUGS B14: loss=150 / -1 / nan and manual latency=-5 / 1e99 / inf are written to rules.json."""
        for args in (("lte", "loss=150"), ("lte", "loss=-1"), ("lte", "loss=nan"), ("manual", "latency_ms=-5"),
                     ("manual", "loss_pct=500"), ("manual", "down_kbps=inf"), ("manual", "latency_ms=1e99")):
            r = self.cli("throttle", *args)
            self.assertNotEqual(r.returncode, 0, "throttle %s was accepted: %s" % (" ".join(args), r.stdout[-80:]))

    def test_nan_in_rules_json_would_break_the_panel_state_json(self):
        """Why B14 matters: Python writes NaN/Infinity, which is not JSON and breaks JSON.parse in the browser."""
        import json as _json
        self.assertIn("NaN", _json.dumps({"loss": float("nan")}))
        with self.assertRaises(ValueError):
            _json.loads('{"loss": NaN}', parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))


class Breakpoints(CliBase):
    def test_r5a05_unknown_name_is_refused_with_choices(self):
        # R5A-05: a typo must not claim that an armed breakpoint was removed.
        self.ok("breakpoint", "/real")
        before = self.cfg()["breakpoints"]
        r = self.refused("breakpoint", "off", "mistyped", msg="no breakpoint named")
        self.assertIn(before[0]["name"], r.stderr)
        self.assertEqual(self.cfg()["breakpoints"], before)

    def test_add_list_off(self):
        self.ok("breakpoint", r"/api/login")
        self.ok("breakpoint", r"/api/pay", "--request", "--method", "post")
        self.ok("breakpoint", r"/api/res", "--response")
        bps = self.cfg()["breakpoints"]
        self.assertEqual(len(bps), 3)
        self.assertTrue(bps[0]["request"] and bps[0]["response"])
        self.assertTrue(bps[1]["request"] and not bps[1]["response"] and bps[1]["method"] == "POST")
        self.assertTrue(not bps[2]["request"] and bps[2]["response"])
        out = self.ok("breakpoint").stdout
        self.assertIn("/api/pay", out)
        self.assertIn("POST", out)
        self.ok("breakpoint", "off", bps[0]["name"])
        self.assertEqual(len(self.cfg()["breakpoints"]), 2)
        self.ok("breakpoint", "off")
        self.assertEqual(self.cfg()["breakpoints"], [])
        self.assertIn("none", self.ok("breakpoint").stdout)

    def test_pilot_both_phase_flags_pause_both_phases(self):
        # pilot feedback #1: `--request --response` printed ON but stored request:false, response:false
        self.ok("breakpoint", "/both", "--request", "--response")
        self.ok("breakpoint", "/both-rev", "--response", "--request")
        for b in self.cfg()["breakpoints"]:
            self.assertTrue(b["request"] and b["response"], b)
        self.assertIn("(request+response)", self.ok("breakpoint").stdout)

    def test_same_regex_gets_distinct_names(self):
        self.ok("breakpoint", "/dup")
        self.ok("breakpoint", "/dup")
        names = [b["name"] for b in self.cfg()["breakpoints"]]
        self.assertEqual(len(set(names)), 2)

    def test_invalid(self):
        self.refused("breakpoint", "(unclosed", msg="bad regex")
        self.refused("breakpoint", "/x", "--frob", msg="breakpoint options")
        self.assertEqual(self.cfg()["breakpoints"], [])

    def test_legacy_singleton_is_migrated(self):
        self.ok("rules", "list")
        c = self.cfg()
        c["breakpoint"] = {"match": "/old", "phase": "request"}
        json.dump(c, open(self.rules_file(), "w"))
        self.assertIn("legacy", self.ok("breakpoint").stdout)
        self.ok("breakpoint", "/new")
        c = self.cfg()
        self.assertNotIn("breakpoint", c)
        self.assertEqual({b["name"] for b in c["breakpoints"]} & {"legacy"}, {"legacy"})


class Scripts(CliBase):
    def test_lifecycle_for_both_languages_and_every_template(self):
        for tpl in ("header", "json", "mock", "latency", "token"):
            for lang in ("py", "js"):
                self.ok("scripts", "new", "s-%s-%s" % (tpl, lang), "--lang", lang, "--template", tpl)
        sdir = os.path.join(self.state, "projects", "default", "scripts")
        self.assertEqual(len(os.listdir(sdir)), 10)
        for name in os.listdir(sdir):
            self.assertEqual(mode(os.path.join(sdir, name)), 0o600)
        self.assertEqual(mode(sdir), 0o700)
        out = self.ok("scripts", "list").stdout
        self.assertIn("s-header-py", out)
        self.ok("scripts", "off", "s-header-py")
        self.assertIn("off s-header-py", self.ok("scripts", "list").stdout)
        self.ok("scripts", "on", "s-header-py.py")                  # by file name too
        self.ok("scripts", "rm", "s-header-py")
        self.assertFalse(os.path.exists(os.path.join(sdir, "s-header-py.py")))
        self.assertNotIn("s-header-py", self.ok("scripts", "list").stdout)

    def test_match_and_method_options(self):
        self.ok("scripts", "new", "m", "--lang", "py", "--match", "/api/", "--method", "post")
        item = self.cfg()["scripts"][0]
        self.assertEqual((item["match"], item["method"], item["lang"], item["file"]), ("/api/", "POST", "py", "m.py"))

    def test_invalid(self):
        self.refused("scripts", "new", "../evil", "--lang", "py", msg="bad script name")
        self.refused("scripts", "new", "ok", "--lang", "rb")
        bad_rx = self.refused("scripts", "new", "ok", "--lang", "py", "--match", "(x", msg="bad regex")
        self.assertNotIn("Traceback", bad_rx.stderr)
        self.ok("scripts", "new", "dup", "--lang", "py")
        self.refused("scripts", "new", "dup", "--lang", "py", msg="already exists")
        self.refused("scripts", "on", "ghost", msg="no script named")
        self.refused("scripts", "frob", "dup", msg="unknown scripts command")
        self.assertFalse(os.path.exists(os.path.join(self.home, "evil.py")))

    def test_edit_runs_the_editor(self):
        self.ok("scripts", "new", "ed", "--lang", "js")
        self.ok("scripts", "edit", "ed")          # EDITOR=/usr/bin/true
        env = dict(self.env, EDITOR="/usr/bin/false")
        self.refused("scripts", "edit", "ed", env=env)


class Tls(CliBase):
    def test_default_and_modes(self):
        out = self.ok("tls", "list").stdout
        self.assertIn("tls mode: all", out)
        self.ok("tls", "mode", "allow")
        self.assertEqual(self.cfg()["tls"]["mode"], "allow")
        self.assertIn("nothing would be decrypted", self.ok("tls", "mode", "allow").stdout)
        self.assertIn("tls mode: allow", self.ok("tls", "mode").stdout)
        self.ok("tls", "mode", "ignore")
        self.ok("tls", "mode", "all")
        self.assertIn("TLS decryption: all", self.stopped_status().stdout)

    def test_allow_ignore_add_rm(self):
        self.ok("tls", "allow", "add", "*.Example.test")
        self.ok("tls", "allow", "add", "*.example.test")           # duplicate (case-insensitive) is a no-op
        self.ok("tls", "ignore", "add", "pay.example.test:8443")
        t = self.cfg()["tls"]
        self.assertEqual(t["allow"], ["*.example.test"])
        self.assertEqual(t["ignore"], ["pay.example.test:8443"])
        out = self.ok("tls", "list").stdout
        self.assertIn(r"^.*\.example\.test(?::\d+)?$", out)
        self.ok("tls", "allow", "rm", "*.example.test")
        self.assertEqual(self.cfg()["tls"]["allow"], [])
        self.ok("tls", "mode", "ignore")
        self.assertIn("TLS decryption: ignore (1 host pattern)", self.stopped_status().stdout)

    def test_invalid_patterns(self):
        for bad in ("http://x.test", "a b", "a/b", ".x.test", "x.test:99999", "x.test:0", ""):
            r = self.cli("tls", "allow", "add", bad)
            self.assertNotEqual(r.returncode, 0, repr(bad))
        self.refused("tls", "mode", "sideways", msg="tls mode")
        self.refused("tls", "bogus")
        self.assertEqual(self.cfg()["tls"]["allow"], [])


class Compose(CliBase):
    def test_list_empty_and_send_errors_offline(self):
        self.assertIn("no saved requests", self.ok("compose", "list").stdout)
        self.assertIn("no saved requests", self.ok("compose").stdout)
        self.refused("compose", "send", "ghost", msg="no saved request")
        d = os.path.join(self.state, "projects", "default", "composer")
        os.makedirs(d)
        json.dump({"method": "POST", "url": "http://x.test/a"}, open(os.path.join(d, "ping.json"), "w"))
        json.dump({"edge": "http://x.test"}, open(os.path.join(d, "vars.json"), "w"))
        out = self.ok("compose", "list").stdout
        self.assertRegex(out, r"ping\s+POST\s+http://x\.test/a")
        self.assertIn("variables: edge", out)
        r = self.refused("compose", "send", "ping")            # exists, but no token file / nothing listening
        self.assertRegex(r.stderr, r"no token file|cannot reach")
        self.refused("compose", "send", "../ping")
        self.refused("compose", "frob")
        self.refused("compose", "send")


class NetReset(CliBase):
    def test_dry_run_prints_only_and_never_changes_anything(self):
        self.assertEqual(os.path.dirname(harness.shutil.which("networksetup", path=self.env["PATH"])), self.suite.shim)
        r = self.ok("net-reset", "--dry-run")
        self.assertRegex(r.stdout, r"network is clean|left alone|dry run|no stale local proxy")
        log = self.suite.shim_log("networksetup.log")
        self.assertNotRegex(log, r"(?m)^-set", "net-reset --dry-run must not call a networksetup setter")
        self.assertNotIn("REFUSED", log)
        self.assertIn("-listallnetworkservices", log)


class NeoMitmShim(CliBase):
    def test_defaults_to_project_neo(self):
        out = self.ok("projects", "list", bin=NEO_MITM).stdout
        self.assertRegex(out, r"(?m)^\* neo\b")

    def test_project_flag_forms_win(self):
        self.assertRegex(self.ok("projects", "list", "--project=default", bin=NEO_MITM).stdout, r"(?m)^\* default\b")
        self.assertRegex(self.ok("--project", "default", "projects", "list", bin=NEO_MITM).stdout, r"(?m)^\* default\b")

    def test_flag_after_double_dash_is_not_a_project_flag(self):
        # `--` ends option scanning in the shim, so neo is still selected
        r = self.ok("projects", "list", "--", "--project=default", bin=NEO_MITM)
        self.assertRegex(r.stdout, r"(?m)^\* neo\b")

    def test_passes_through_rules(self):
        self.ok("rules", "add", "viashim", "action=block", bin=NEO_MITM)
        self.assertTrue(os.path.isfile(self.rules_file("neo")))
        self.assertIn("viashim", self.cfg("neo")["rules"][-1]["name"])


class LeftoverSystemProxy(CliBase):
    """A proxy app that quit (Proxyman, Charles…) left the Mac's proxy on its dead loopback port: the Simulator and every
    Mac app lost the network until `rivis net-reset` (a tester's Mac, 2026-10-16). Fake networksetup: Wi-Fi web+https
    proxy on PORT; every change is logged, nothing real is touched."""

    def fake(self, host, port, deny=False):
        d = os.path.join(self.home, "fakenet")
        os.makedirs(d, exist_ok=True)
        log = os.path.join(d, "set.log")
        with open(os.path.join(d, "networksetup"), "w") as fh:
            fh.write("""#!/bin/sh
case "$1" in
  -listallnetworkservices) printf 'An asterisk (*) denotes that a network service is disabled.\\nWi-Fi\\n' ;;
  -getwebproxy|-getsecurewebproxy) printf 'Enabled: Yes\\nServer: %s\\nPort: %s\\nAuthenticated Proxy Enabled: 0\\n' ;;
  -getsocksfirewallproxy) printf 'Enabled: No\\nServer: \\nPort: 0\\n' ;;
  -set*) echo "$*" >> "%s"; %s ;;
esac
exit 0
""" % (host, port, log, 'echo "You must be administrator to make this change." >&2; exit 1' if deny else ":"))
        os.chmod(os.path.join(d, "networksetup"), 0o755)
        return dict(self.env, PATH=d + ":" + self.env["PATH"]), log

    def changes(self, log):
        return open(log).read().split("\n")[:-1] if os.path.exists(log) else []

    def test_auto_clears_a_dead_loopback_proxy_and_says_so(self):
        env, log = self.fake("127.0.0.1", harness.free_port())
        r = self.ok("net-reset", "--auto", env=env)
        self.assertEqual(sorted(self.changes(log)), ["-setsecurewebproxystate Wi-Fi off", "-setwebproxystate Wi-Fi off"])
        self.assertIn("fixed:", r.stdout)

    def test_never_touches_a_live_or_a_remote_proxy(self):
        busy = socket.socket(); busy.bind(("127.0.0.1", 0)); busy.listen(1)     # another proxy app still running
        self.addCleanup(busy.close)
        for host, port in (("127.0.0.1", busy.getsockname()[1]), ("10.1.2.3", 3128)):
            env, log = self.fake(host, port)
            if os.path.exists(log):
                os.remove(log)
            r = self.ok("net-reset", "--auto", env=env)
            self.assertEqual(self.changes(log), [], (host, port))
            self.assertEqual(r.stdout.strip(), "", "--auto must stay silent when it changes nothing")

    def test_start_clears_the_leftover_before_capturing(self):
        env, log = self.fake("127.0.0.1", harness.free_port())
        env["SHIM_DRYRUN"] = "1"
        r = self.suite.rivis("start", "--no-open", "--no-ios", home=self.home, env=env)
        self.assertIn("-setsecurewebproxystate Wi-Fi off", self.changes(log), r.stdout + r.stderr)


    def test_start_still_starts_when_this_account_may_not_change_network_settings(self):
        # Night QA A4: a standard (non-admin) account behind a Proxyman leftover — `start` died on the
        # refused networksetup call, so Rivis never started at all. Now it says how to clear it and starts.
        env, log = self.fake("127.0.0.1", harness.free_port(), deny=True)
        env["SHIM_DRYRUN"] = "1"
        open(os.path.join(self.suite.shimlog, "mitm-argv.log"), "w").close()
        r = self.suite.rivis("start", "--no-open", "--no-ios", home=self.home, env=env)
        out = r.stdout + r.stderr
        self.assertIn("System Settings", out)
        with open(os.path.join(self.suite.shimlog, "mitm-argv.log")) as fh:
            self.assertIn("mitmweb", fh.read(), out)
        self.assertNotEqual(self.suite.rivis("net-reset", home=self.home, env=env).returncode, 0,
                            "a manual net-reset still reports the failure")


class DamagedCa(CliBase):
    """Night QA A13: a malformed ~/.mitmproxy/mitmproxy-ca-cert.pem passed silently and mitmproxy replaced the CA at
    start, so every device set up with the old one stopped trusting Rivis without a word."""

    def test_start_stops_and_keeps_the_damaged_files(self):
        pem = os.path.join(self.env["RIVIS_CONFDIR"], "mitmproxy-ca-cert.pem")
        with open(pem, "w") as fh:
            fh.write("not a certificate\n")
        r = self.cli("start", "--no-open", "--no-ios", env=dict(self.env, SHIM_DRYRUN="1"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("damaged", r.stderr)
        self.assertIn("mv ", r.stderr)
        with open(pem) as fh:
            self.assertEqual(fh.read(), "not a certificate\n")


class AdbDiscovery(CliBase):
    """Night QA A7: Devices found adb under ANDROID_SDK_ROOT, but its Set up ran `rivis android on`, whose CLI only
    looked on PATH and in ~/Library/Android/sdk — 'adb not found'. The CLI now looks where the panel looks."""

    def test_cli_uses_adb_from_android_sdk_root(self):
        sdk = os.path.join(self.home, "custom-sdk")
        os.makedirs(os.path.join(sdk, "platform-tools"))
        log = os.path.join(self.home, "adb.log")
        adb = os.path.join(sdk, "platform-tools", "adb")
        with open(adb, "w") as fh:
            fh.write('#!/bin/sh\necho "$@" >> "%s"\necho "List of devices attached"\n' % log)
        os.chmod(adb, 0o755)
        env = dict(self.env, ANDROID_SDK_ROOT=sdk, PATH="/usr/bin:/bin:/usr/sbin:/sbin:" + self.suite.root + "/shim")
        env.pop("ADB", None)
        r = self.cli("android", "on", "--all", env=env)
        self.assertNotIn("adb not found", r.stdout + r.stderr)
        self.assertTrue(os.path.exists(log), r.stdout + r.stderr)


class NoCommandLineTools(CliBase):
    """Night review A2: on a Mac without Apple's Command Line Tools, /usr/bin/python3 only pops an install dialog, and
    every rivis command failed with shell errors. Both the CLI and the installer now say what to do, up front."""

    def no_clt_env(self):
        d = os.path.join(self.home, "noclt")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "xcode-select"), "w") as fh:
            fh.write('#!/bin/sh\necho "xcode-select: error: unable to get active developer directory" >&2\nexit 2\n')
        os.chmod(os.path.join(d, "xcode-select"), 0o755)
        return dict(self.env, PATH=d + ":" + self.env["PATH"])

    def test_cli_says_how_to_install_them(self):
        r = self.cli("--version", env=self.no_clt_env())
        self.assertEqual(r.returncode, 1)
        self.assertIn("xcode-select --install", r.stderr)
        self.assertNotIn("command not found", r.stderr)

    def test_installer_says_how_to_install_them_before_touching_anything(self):
        env = self.no_clt_env()
        before = sorted(os.listdir(self.home))
        cp = self.suite.run(["/bin/bash", os.path.join(harness.REPO, "install", "install.sh"), "--yes"],
                            home=self.home, env=env, timeout=60)
        self.assertEqual(cp.returncode, 1, cp.stdout + cp.stderr)
        self.assertIn("xcode-select --install", cp.stderr)
        self.assertEqual(sorted(os.listdir(self.home)), before)

    def test_uninstall_is_never_blocked_and_developer_dir_is_honoured(self):
        # night QA lane C3: uninstall must work after the tools are gone; DEVELOPER_DIR is what xcrun uses first
        env = self.no_clt_env()
        cp = self.suite.run(["/bin/bash", os.path.join(harness.REPO, "install", "install.sh"), "--uninstall", "--dry-run"],
                            home=self.home, env=env, timeout=60)
        self.assertNotIn("xcode-select --install", cp.stderr)
        dev = os.path.join(self.home, "dev")
        os.makedirs(os.path.join(dev, "usr", "bin"))
        os.symlink("/usr/bin/python3", os.path.join(dev, "usr", "bin", "python3"))
        self.ok("--version", env=dict(env, DEVELOPER_DIR=dev))

    def test_with_the_tools_present_nothing_changes(self):
        self.ok("--version")


class StartArgv(CliBase):
    """`start` with the mitmweb shim in dry-run mode: proves which security-relevant flags are passed."""

    def start_argv(self, *args, **envx):
        env = dict(self.env, SHIM_DRYRUN="1", **envx)
        open(os.path.join(self.suite.shimlog, "mitm-argv.log"), "w").close()
        r = self.suite.rivis("start", "--no-open", *args, home=self.home, env=env)
        lines = [l for l in self.suite.shim_log("mitm-argv.log").splitlines() if l.startswith("mitmweb ")]
        self.assertEqual(len(lines), 1, "rivis start did not run mitmweb once: %s %s" % (r.stdout, r.stderr))
        return lines[0], r

    def test_without_an_approved_redirector_start_leaves_ios_capture_off_and_says_how(self):
        # Night QA A15: an Android-only tester skips the Redirector in the installer, then `rivis start` asked for
        # local capture anyway (macOS prompts / errors). Unknown states (no listing) keep the old behaviour.
        sysext = os.path.join(self.suite.shimlog, "sysext")
        try:
            for listing, local in (("0 extension(s)\n", False),
                                   ("*\t\tS8XHQB96PW\torg.mitmproxy.macos-redirector (12.2.3/12.2.3)\t"
                                    "org.mitmproxy.macos-redirector\t[activated waiting for user]\n", False),
                                   ("", True)):
                with open(sysext, "w") as fh:
                    fh.write(listing)
                line, r = self.start_argv()
                self.assertEqual("local:" in line, local, (listing, line))
                if not local:
                    self.assertIn("iOS Simulator capture is off", r.stdout)
        finally:
            os.remove(sysext)
        line, r = self.start_argv()                           # approved (the shim's default): capture as before
        self.assertIn("--mode local:CoreSimulator", line)
        self.assertNotIn("capture is off", r.stdout)

    def test_binds_loopback_only_and_uses_private_ca_dir(self):
        line, r = self.start_argv("--no-ios")
        self.assertIn("--listen-host 127.0.0.1", line)
        self.assertIn("web_host=127.0.0.1", line)
        self.assertIn("regular@%s" % self.env["RIVIS_PORT"], line)
        self.assertIn("web_port=%s" % self.env["RIVIS_WEB_PORT"], line)
        self.assertIn("confdir=" + self.env["RIVIS_CONFDIR"], line)
        self.assertIn("http2=false", line)
        self.assertNotIn("0.0.0.0", line)
        self.assertNotIn("local:", line)                       # --no-ios: no local capture
        self.assertNotIn("ssl_insecure", line)
        self.assertIn("web_open_browser=false", line)
        self.assertNotIn("web_password=", line)
        self.assertIn("proxy_auth_token_file=" + os.path.join(self.state, "web-token"), line)
        self.assertNotIn(" x", line)
        self.assertEqual(self.suite.shim_log("open.log"), "")  # --no-open really does not open anything

        line, _ = self.start_argv("--no-ios", RIVIS_HTTP2="1")
        self.assertIn("http2=true", line)

    def test_ios_local_capture_is_scoped_to_simulator_processes(self):
        line, _ = self.start_argv()
        self.assertIn("local:CoreSimulator", line)
        line, _ = self.start_argv("--ios-filter", "MyApp")
        self.assertIn("local:MyApp", line)

    def test_capture_filter_can_never_mean_the_whole_mac(self):
        """F-13: an empty spec captures every process; '!x' captures everything except x."""
        for bad in ("", "!CoreSimulator", "Core*", "a,CoreSimulator", "x;y", "CoreSimulator,", ",,"):
            r = self.refused("start", "--no-open", "--ios-filter", bad)
            self.assertRegex(r.stderr, r"--ios-filter (is empty|'.*')", bad)   # refused by the filter check itself
        line, _ = self.start_argv("--ios-filter", "CoreSimulator,MyApp")
        self.assertIn("local:CoreSimulator,MyApp", line)

    def test_insecure_and_dev_alias(self):
        for flag in ("--insecure", "--dev"):
            line, _ = self.start_argv("--no-ios", flag)
            self.assertIn("ssl_insecure=true", line)

    def test_views(self):
        line, _ = self.start_argv("--no-ios")
        self.assertIn("view_filter=~http", line)
        line, _ = self.start_argv("--no-ios", "--all")
        self.assertNotIn("view_filter", line)
        env_home = self.home
        self.suite.rivis("projects", "new", "bank", "--label", "B", "--hosts", r"a\.test|b'q", home=env_home, env=self.env)
        env = dict(self.env, SHIM_DRYRUN="1")
        self.suite.rivis("--project", "bank", "start", "--no-open", "--no-ios", "--project-only", home=env_home, env=env)
        last = [l for l in self.suite.shim_log("mitm-argv.log").splitlines() if l.startswith("mitmweb ")][-1]
        self.assertIn(r"~d 'a\\.test|b\'q'", last)           # backslashes doubled, quote escaped for mitmproxy's filter parser

    def test_refuses_a_taken_port_and_never_kills_it(self):
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        taken = s.getsockname()[1]
        try:
            env = dict(self.env, SHIM_DRYRUN="1", RIVIS_PORT=str(taken))
            r = self.suite.rivis("start", "--no-open", "--no-ios", home=self.home, env=env)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("already taken", r.stderr)
            # night QA: the hint was "a previous rivis? run: rivis stop", which cannot stop another program
            self.assertNotIn("%s stop" % "rivis", r.stderr)
            self.assertIn("RIVIS_PORT=", r.stderr)
        finally:
            s.close()

    def test_unknown_option(self):
        self.refused("start", "--bogus", msg="unknown option")

    def test_never_touches_the_system_proxy(self):
        self.start_argv("--no-ios")
        self.assertNotRegex(self.suite.shim_log("networksetup.log"), r"(?m)^-set")

    def test_writes_token_file_private(self):
        self.start_argv("--no-ios")
        tf = os.path.join(self.state, "web-token-" + self.env["RIVIS_WEB_PORT"])
        self.assertEqual(open(tf).read().strip(), "x")
        self.assertEqual(mode(tf), 0o600)

    def test_nondefault_web_port_gets_its_own_private_token_and_bootstrap(self):
        # R4A-05: a second project cannot replace the first project's login files.
        first = dict(self.env, SHIM_DRYRUN="1", RIVIS_WEB_PORT="18083")
        second = dict(self.env, SHIM_DRYRUN="1", RIVIS_WEB_PORT="18084")
        self.ok("start", "--no-open", "--no-ios", env=first)
        path = os.path.join(self.state, "web-token-18083")
        original = open(path).read()
        self.ok("start", "--no-open", "--no-ios", env=second)
        self.assertEqual(open(path).read(), original)
        self.assertTrue(os.path.isfile(os.path.join(self.state, "web-token-18084")))
        self.assertTrue(os.path.isfile(os.path.join(self.state, "web-bootstrap-18083")))
        self.assertTrue(os.path.isfile(os.path.join(self.state, "web-bootstrap-18084")))
        self.assertEqual(mode(path), 0o600)


class StatusUiStop(CliBase):
    def test_restart_follows_selected_project_after_096_upgrade(self):
        self.ok("projects", "new", "qa_alpha", "--label", "Alpha", "--hosts", "alpha.test")
        try:
            self.ok("start", "--background", "--no-open", "--no-ios", timeout=60)
            start_file = os.path.join(self.state, "last-start-" + self.env["RIVIS_WEB_PORT"])
            # 0.9.6 had no source marker. Its installer replayed the saved
            # --project, so the new launcher mistook that replay for a user choice.
            with open(start_file) as fh:
                saved = fh.read()
            with open(start_file, "w") as fh:
                fh.write(saved.replace("START_PROJECT_SOURCE=current-project\n", "START_PROJECT_SOURCE=argument\n")
                              .replace("START_PROJECT_SOURCE=default\n", "START_PROJECT_SOURCE=argument\n"))
            self.ok("projects", "use", "qa_alpha")
            self.ok("restart", timeout=60)
            out = self.ok("status").stdout
            self.assertIn("project: qa_alpha (Alpha)", out)
            self.assertNotIn("selected project:", out)
        finally:
            self.cli("stop")

    def test_r904_restart_loads_project_selected_with_projects_use(self):
        self.ok("projects", "new", "qa_alpha", "--label", "Alpha", "--hosts", "alpha.test")
        try:
            self.ok("start", "--background", "--no-open", "--no-ios", timeout=60)
            self.ok("projects", "use", "qa_alpha")
            self.ok("restart", timeout=60)
            out = self.ok("status").stdout
            self.assertIn("project: qa_alpha (Alpha)", out)
            self.assertNotIn("selected project:", out)
            self.ok("projects", "use", "neo")
            self.ok("restart", timeout=60)
            self.assertIn("project: neo (NEO)", self.ok("status").stdout)
        finally:
            self.cli("stop")

    def test_restart_preserves_explicit_start_project(self):
        self.ok("projects", "new", "qa_alpha", "--label", "Alpha", "--hosts", "alpha.test")
        try:
            self.ok("--project", "qa_alpha", "start", "--background", "--no-open", "--no-ios", timeout=60)
            self.ok("projects", "use", "neo")
            self.ok("restart", timeout=60)
            out = self.ok("status").stdout
            self.assertIn("project: qa_alpha (running", out)
            self.assertIn("selected project: neo", out)
        finally:
            self.cli("stop")

    def test_r5a03_status_identifies_running_project_on_port(self):
        # R5A-03: the selected default can differ from the instance on these ports.
        self.ok("projects", "new", "qa_alpha", "--label", "Alpha", "--hosts", "alpha.test")
        try:
            self.ok("--project", "qa_alpha", "start", "--background", "--no-open", "--no-ios", timeout=60)
            out = self.ok("status").stdout
            self.assertIn("project: qa_alpha", out)
            self.assertIn("selected project: default", out)
        finally:
            self.cli("stop")

    def test_r5a01_mock_bad_regex_has_one_error_line(self):
        # R5A-01: invalid user input must not reveal a Python traceback.
        try:
            self.ok("start", "--background", "--no-open", "--no-ios", timeout=60)
            r = self.refused("mock", "bad", "[", msg="bad regex")
            self.assertNotIn("Traceback", r.stderr)
            self.assertEqual(len(r.stderr.strip().splitlines()), 1)
        finally:
            self.cli("stop")

    def test_two_running_web_ports_reopen_independently(self):
        # R4A-05: reopening A after starting or stopping B must authenticate against A's saved token.
        import http.cookiejar
        import urllib.request
        first = dict(self.env)
        second = dict(self.env, RIVIS_PORT=str(harness.free_port()), RIVIS_WEB_PORT=str(harness.free_port()))
        try:
            self.ok("start", "--background", "--no-open", "--no-ios", env=first)
            first_token = open(os.path.join(self.state, "web-token-" + first["RIVIS_WEB_PORT"])).read()
            self.ok("start", "--background", "--no-open", "--no-ios", env=second)
            self.assertEqual(open(os.path.join(self.state, "web-token-" + first["RIVIS_WEB_PORT"])).read(), first_token)
            before = self.suite.shim_log("open.log")
            self.ok("ui", env=first)
            opened = self.suite.shim_log("open.log")[len(before):].strip().splitlines()[-1]
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                                 urllib.request.ProxyHandler({}))
            self.assertEqual(opener.open(opened, timeout=10).status, 200)
            self.ok("stop", env=second)
            self.assertFalse(os.path.exists(os.path.join(self.state, "web-token-" + second["RIVIS_WEB_PORT"])))
            self.assertTrue(os.path.exists(os.path.join(self.state, "web-token-" + first["RIVIS_WEB_PORT"])))
            before = self.suite.shim_log("open.log")
            self.ok("ui", env=first)
            opened = self.suite.shim_log("open.log")[len(before):].strip().splitlines()[-1]
            self.assertEqual(opener.open(opened, timeout=10).status, 200)
        finally:
            self.cli("stop", env=first)
            self.cli("stop", env=second)

    def test_status_when_nothing_runs(self):
        out = self.stopped_status().stdout
        self.assertRegex(out, r"proxy :\d+\s+not listening")
        self.assertRegex(out, r"web UI :\d+\s+not listening")
        self.assertIn("project: default (All)", out)
        self.assertIn("TLS decryption: all (every host)", out)

    def test_tests_never_see_a_real_browser(self):
        # the UI sweep once clicked "Open Microsoft Edge" and real windows opened on the tester's desktop
        self.assertEqual(self.ok("browser", "--list").stdout, "")
        self.refused("browser", msg="no Chrome, Edge")

    def test_ui_needs_a_running_proxy(self):
        before = self.suite.shim_log("open.log")      # other tests in this class may have opened a browser already
        self.refused("ui", msg="not running")
        self.assertEqual(self.suite.shim_log("open.log"), before)

    def test_stop_with_nothing_running_is_harmless(self):
        self.assertIn("nothing to stop", self.ok("stop").stdout)

    def test_mock_needs_a_running_proxy(self):
        self.refused("mock", "x", "/y", msg="not running")
        self.refused("mock", "only-one-arg", msg="usage")

    def test_help_on_any_command_prints_help_and_changes_nothing(self):
        """QA TXT-03/04: `stop --help` stopped the proxy, `breakpoint --help` added a breakpoint named 'help'."""
        rules = os.path.join(self.state, "projects", "default", "rules.json")
        before = open(rules).read() if os.path.exists(rules) else None
        for args in (("stop", "--help"), ("setup", "--help"), ("cert", "-h"), ("status", "--help"), ("breakpoint", "--help"),
                     ("rules", "add", "x", "match=/y", "action=block", "--help"), ("tls", "--help"), ("bug-report", "--help"),
                     ("android", "on", "--help"), ("ios", "--help"), ("mock", "m", "/x", "--help")):
            r = self.ok(*args)
            self.assertIn(args[0], r.stdout, args)
        after = open(rules).read() if os.path.exists(rules) else None
        self.assertEqual(before, after, "--help must not write the rules file")
        self.assertFalse(os.path.exists(os.path.join(self.env["RIVIS_CONFDIR"], "mitmproxy-ca-cert.pem.new")))

    def test_start_background_returns_and_keeps_running_until_stop(self):
        port, web = harness.free_port(), harness.free_port()
        env = dict(self.env, RIVIS_PORT=str(port), RIVIS_WEB_PORT=str(web))
        try:
            out = self.ok("start", "--background", "--no-open", "--no-ios", env=env, timeout=60).stdout
            self.assertIn("running in the background", out)
            self.assertIn("Tools → Devices", out)
            self.assertTrue(harness.port_open(web), "UI port should still listen after start returned")
            log = os.path.join(self.state, "logs", "mitmweb.log")
            self.assertEqual(os.stat(log).st_mode & 0o777, 0o600)
        finally:
            self.cli("stop", env=env)
        self.assertFalse(harness.port_open(port), "stop returned while the proxy port was still listening")

    def test_start_background_without_other_options_on_macos_bash(self):
        # issue #2: `start --background` (the installer's "Start now?" answer) left no options to save, and bash 3.2
        # under set -u died on the empty array: "fwd[@]: unbound variable". No --no-open / --no-ios here on purpose.
        port, web = harness.free_port(), harness.free_port()
        shimlog = tempfile.mkdtemp(dir=self.home)
        with open(os.path.join(shimlog, "sysext"), "w") as fh:
            fh.write("0 extension(s)\n")   # Redirector not approved: Simulator capture stays off, no real capture
        env = dict(self.env, RIVIS_PORT=str(port), RIVIS_WEB_PORT=str(web), SHIM_LOG=shimlog)
        try:
            r = self.ok("start", "--background", env=env, timeout=60)
            self.assertNotIn("unbound variable", r.stdout + r.stderr)
            self.assertIn("running in the background", r.stdout)
            self.assertTrue(harness.port_open(web), "UI port should listen after start returned")
            with open(os.path.join(self.state, "last-start-%d" % web)) as fh:
                saved = fh.read()
            self.assertRegex(saved, r"START_ARGS=\(--project \S+ start --background --no-open \)")
        finally:
            self.cli("stop", env=env)
        self.assertFalse(harness.port_open(web), "stop returned while the UI port was still listening")

    def test_stop_never_stops_another_homes_rivis(self):
        # 2026-10-16: a test's `rivis stop` from a scratch HOME killed the user's live Rivis on the same ports
        port, web = harness.free_port(), harness.free_port()
        env = dict(self.env, RIVIS_PORT=str(port), RIVIS_WEB_PORT=str(web))
        other = self.suite.new_home("cli-other")
        other_env = dict(self.suite.cli_env(other), RIVIS_PORT=str(port), RIVIS_WEB_PORT=str(web))
        try:
            self.ok("start", "--background", "--no-open", "--no-ios", env=env, timeout=60)
            r = self.suite.rivis("stop", home=other, env=other_env)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("not ours", r.stdout + r.stderr)
            self.assertTrue(harness.port_open(port), "a stop from another HOME stopped this HOME's proxy")
            self.assertTrue(harness.port_open(web))
        finally:
            self.cli("stop", env=env)
        self.assertFalse(harness.port_open(port), "its own stop must still work")

    def test_android_and_ios_without_devices(self):
        r = self.refused("android", "on")
        self.assertIn("adb not found", r.stderr)
        r = self.refused("ios", "frob")
        self.assertIn("usage", r.stderr + r.stdout)
        r = self.refused("android", "frob")


class CertAndCa(CliBase):
    def test_cert_prints_fingerprint(self):
        out = self.ok("cert").stdout
        self.assertIn("sha256:", out)
        self.assertRegex(out, r"android:\s+[0-9a-f]{8}\.0")
        self.assertIn(self.env["RIVIS_CONFDIR"], out)

    def test_ensure_ca_generation_binds_loopback_only(self):
        """No CA yet -> the CLI generates one by running mitmdump. It must not listen beyond 127.0.0.1."""
        env = dict(self.env, RIVIS_CONFDIR=os.path.join(self.home, "fresh-ca"), SHIM_DRYRUN="")
        open(os.path.join(self.suite.shimlog, "mitm-argv.log"), "w").close()
        r = self.suite.rivis("cert", home=self.home, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = [l for l in self.suite.shim_log("mitm-argv.log").splitlines() if l.startswith("mitmdump ")]
        self.assertEqual(len(lines), 1)
        self.assertIn("--listen-host 127.0.0.1", lines[0],
                      "ensure_ca() starts mitmdump without --listen-host, so it briefly binds all interfaces")


class Migration(CliBase):
    """First use copies a legacy ~/.neo-mitm into project 'neo' (copy only, idempotent, rewrites mock paths)."""

    def make_legacy(self):
        old = os.path.join(self.home, ".neo-mitm")
        os.makedirs(os.path.join(old, "mocks"))
        os.makedirs(os.path.join(old, "collections"))
        os.makedirs(os.path.join(old, "sessions"))
        open(os.path.join(old, "mocks", "m.json"), "w").write('{"legacy": true}')
        open(os.path.join(old, "collections", "c.json"), "w").write('{"name":"c","entries":[]}')
        open(os.path.join(old, "sessions", "s.flows"), "w").write("x")
        doc = {"throttle": "off", "rules": [
            {"name": "ml", "enabled": True, "match": "/m", "action": "map_local", "file": os.path.join(old, "mocks", "m.json")},
            {"name": "rs", "enabled": True, "match": "/r", "action": "respond", "body_file": os.path.join(old, "mocks", "m.json")},
            {"name": "outside", "enabled": True, "match": "/o", "action": "map_local", "file": "/etc/hosts"}]}
        json.dump(doc, open(os.path.join(old, "rules.json"), "w"))
        os.chmod(os.path.join(old, "rules.json"), 0o644)
        return old

    @staticmethod
    def snapshot(root):
        out = {}
        for d, _, files in os.walk(root):
            for f in files:
                p = os.path.join(d, f)
                out[os.path.relpath(p, root)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
        return out

    def test_copy_only_and_idempotent(self):
        old = self.make_legacy()
        before = self.snapshot(old)
        r = self.ok("projects", "list")
        self.assertIn("copied legacy", r.stdout)
        target = os.path.join(self.state, "projects", "neo")
        for rel in ("rules.json", "mocks/m.json", "collections/c.json", "sessions/s.flows"):
            self.assertTrue(os.path.isfile(os.path.join(target, rel)), rel)
        self.assertEqual(self.snapshot(old), before, "the legacy directory must be left exactly as it was")
        self.assertEqual(mode(os.path.join(target, "rules.json")), 0o600)
        self.assertEqual(mode(target), 0o700)
        # idempotent: change the copy, run again, the copy is not overwritten and no second copy message appears
        with open(os.path.join(target, "mocks", "m.json"), "w") as fh:
            fh.write("edited")
        self.assertNotIn("copied legacy", self.ok("projects", "list").stdout)
        self.assertEqual(open(os.path.join(target, "mocks", "m.json")).read(), "edited")
        self.assertEqual(self.snapshot(old), before)
        self.assertEqual([x for x in os.listdir(os.path.join(self.state, "projects")) if x.startswith(".")], [])

    def test_map_local_and_body_file_paths_point_at_files_that_exist(self):
        self.make_legacy()
        self.ok("projects", "list")
        rules = {r["name"]: r for r in self.cfg("neo")["rules"]}
        mocks = os.path.join(self.state, "projects", "neo", "mocks")
        for name, key in (("ml", "file"), ("rs", "body_file")):
            path = rules[name][key]
            self.assertTrue(path.startswith(mocks + os.sep), "%s.%s = %s should live under %s" % (name, key, path, mocks))
            self.assertTrue(os.path.isfile(path), "%s.%s = %s does not exist after migration (FOUND-BUGS B12)" % (name, key, path))
        self.assertEqual(rules["outside"]["file"], "/etc/hosts")           # paths outside the legacy dir are untouched

    def test_neo_mitm_users_land_in_project_neo_without_flags(self):
        self.make_legacy()
        r = self.ok("rules", "list")                                    # the very first plain command already shows their rules
        self.assertIn("projects/neo/rules.json", r.stdout)
        self.assertIn("ml", r.stdout)
        self.assertEqual(open(os.path.join(self.state, "current-project")).read().strip(), "neo")
        self.assertIn("projects/neo/rules.json", self.ok("rules", "list").stdout)   # and every later one

    def test_fresh_install_without_legacy_stays_on_default(self):
        self.assertIn("projects/default/rules.json", self.ok("rules", "list").stdout)
        self.assertFalse(os.path.exists(os.path.join(self.state, "current-project")))

    def test_does_not_run_when_target_exists_or_no_legacy(self):
        self.ok("--project", "neo", "rules", "list")          # creates projects/neo first
        self.make_legacy()
        self.assertNotIn("copied legacy", self.ok("projects", "list").stdout)
        self.assertEqual(open(self.rules_file("neo")).read().count("legacy"), 0)

    def test_corrupt_legacy_rules_do_not_crash_or_block(self):
        old = os.path.join(self.home, ".neo-mitm")
        os.makedirs(old)
        open(os.path.join(old, "rules.json"), "w").write("{ broken")
        r = self.ok("projects", "list")
        self.assertTrue(os.path.isdir(os.path.join(self.state, "projects", "neo")))



class TrustedFiles(CliBase):
    """Item 0 of SEC2: a Map Local rule typed on this machine may read the user's own file outside the project."""

    def trust_list(self):
        p = os.path.join(self.state, "projects", "default", "trusted-files.json")
        if not os.path.exists(p):
            return []
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
        with open(p) as fh:
            return json.load(fh)["files"]

    def test_relative_map_local_path_is_stored_absolute(self):
        # R3A-08: CLI cwd and proxy cwd differ; an ON rule must target the same file in both.
        path = os.path.join(self.home, "relative.json")
        open(path, "w").write("{}")
        env = dict(self.env, PWD=self.home)
        r = self.suite.run(["/bin/bash", harness.RIVIS, "rules", "add", "relative", "match=/x",
                            "action=map_local", "file=relative.json"], env=env, cwd=self.home)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.cfg()["rules"][0]["file"], path)

    def test_rules_add_with_an_outside_file_trusts_it_and_says_so(self):
        mine = os.path.join(self.home, "Desktop", "mock.json")
        os.makedirs(os.path.dirname(mine))
        with open(mine, "w") as fh:
            fh.write("{}")
        out = self.ok("rules", "add", "m", "match=/x", "action=map_local", "file=" + mine).stdout
        self.assertIn("outside the project", out)
        self.assertEqual(self.trust_list(), [os.path.realpath(mine)])
        self.ok("rules", "disallow-file", mine)
        self.assertEqual(self.trust_list(), [])
        self.ok("rules", "allow-file", mine)
        self.assertIn(os.path.realpath(mine), self.ok("rules", "trusted-files").stdout)

    def test_keys_and_credential_stores_are_refused(self):
        for rel in (".ssh/id_rsa", ".mitmproxy/mitmproxy-ca.pem", ".aws/credentials", "certs/client.p12"):
            p = os.path.join(self.home, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write("secret")
            self.refused("rules", "allow-file", p, msg="refusing")
            self.refused("rules", "add", "k" + str(abs(hash(rel)) % 1000), "match=/x", "action=map_local", "file=" + p,
                      msg="refusing")
        self.assertEqual(self.trust_list(), [])



class CaRemoval(CliBase):
    """F-07: `ios off` removes every CA Rivis ever trusted on the Simulator, also after the CA was regenerated."""
    UDID = "11111111-2222-3333-4444-555555555555"

    def sha(self, pem):
        out = subprocess.run(["openssl", "x509", "-in", pem, "-noout", "-fingerprint", "-sha256"],
                             capture_output=True, text=True, check=True).stdout
        return out.split("=", 1)[1].strip().replace(":", "")

    def test_ios_on_all_trusts_every_booted_simulator(self):
        udids = [self.UDID, "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"]
        booted = os.path.join(self.suite.shimlog, "booted")
        with open(booted, "w") as fh:
            fh.write("".join("    iPhone %d (%s) (Booted)\n" % (i, u) for i, u in enumerate(udids)))
        try:
            r = self.refused("ios", "on", msg="several simulators booted")
            self.assertIn("ios on --all", r.stderr)
            out = self.ok("ios", "on", "--all").stdout
            for u in udids:
                self.assertIn("%s: mitmproxy CA trusted" % u, out)
            log = self.suite.shim_log("xcrun.log")
            for u in udids:
                self.assertIn("simctl keychain %s add-root-cert" % u, log)
            self.refused("ios", "on", "--all", "--udid", self.UDID, msg="not both")
        finally:
            os.remove(booted)

    def test_ios_off_removes_current_and_earlier_cas_but_nothing_else(self):
        import sqlite3
        pem = os.path.join(self.env["RIVIS_CONFDIR"], "mitmproxy-ca-cert.pem")
        self.ok("ios", "on", "--udid", self.UDID)
        old = self.sha(pem)
        # regenerate: a different CA in the same place (what "delete ~/.mitmproxy and start" does)
        key = os.path.join(self.home, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", pem,
                        "-days", "2", "-subj", "/CN=mitmproxy"], capture_output=True, check=True)
        self.ok("ios", "on", "--udid", self.UDID)
        new = self.sha(pem)
        self.assertNotEqual(old, new)
        trustd = os.path.join(self.home, "Library/Developer/CoreSimulator/Devices", self.UDID,
                              "data/private/var/protected/trustd")
        os.makedirs(trustd)
        db = sqlite3.connect(os.path.join(trustd, "TrustStore.sqlite3"))
        db.execute("create table tsettings (sha256 blob, subj blob, tset blob, data blob)")
        other = "AB" * 32
        for h in (old, new, other):
            db.execute("insert into tsettings (sha256) values (?)", (bytes.fromhex(h),))
        db.commit()
        db.close()
        out = self.ok("ios", "off", "--udid", self.UDID).stdout
        self.assertIn("removed 2 trust entries", out)
        db = sqlite3.connect(os.path.join(trustd, "TrustStore.sqlite3"))
        left = [r[0].hex().upper() for r in db.execute("select sha256 from tsettings")]
        db.close()
        self.assertEqual(left, [other])
        hist = os.path.join(self.state, "ca-history")
        self.assertEqual(os.stat(hist).st_mode & 0o777, 0o600)



class CliNames(CliBase):
    """F-17: names and UDIDs are validated before any file is touched."""

    def test_bad_names_and_udids_are_refused_up_front(self):
        for bad in ("../x", "a/b", ".hidden", "x" * 65, "a b"):
            self.refused("rules", "add", bad, "match=/x", "action=block", msg="letters, digits")
            self.refused("mock", bad, "/x", msg="letters, digits")
        for bad in ("../../etc", "11111111-2222-3333-4444-55555555555/../x", "abc"):
            self.refused("ios", "off", "--udid", bad, msg="simulator UDID")
        self.assertFalse(os.path.exists(os.path.join(self.state, "projects", "x.json")))

    def test_rule_names_are_unique_ignoring_case(self):
        self.ok("rules", "add", "Login", "match=/a", "action=block")
        self.refused("rules", "add", "login", "match=/b", "action=block", msg="exists")


class AndroidCaRemoval(CliBase):
    """Review R3: `android off` removed every certificate called "mitmproxy". Every mitmproxy CA has that name and the
    same subject (so also the same <hash>.0 file name), so another workstation's or another tool's CA on a shared
    emulator was removed too. Now only a CA whose SHA-256 this workstation recorded is removed.
    tests/fakes/emulator_adb.py plays the emulator: its CA store, and the Settings → Trusted credentials screens."""

    def setUp(self):
        super().setUp()
        self.emu = os.path.join(self.home, "emu")
        os.makedirs(os.path.join(self.emu, "cacerts"))
        self.env = dict(self.env, ADB=os.path.join(harness.REPO, "tests", "fakes", "emulator_adb.py"), FAKE_EMU=self.emu)
        self.ours = os.path.join(self.env["RIVIS_CONFDIR"], "mitmproxy-ca-cert.pem")
        self.foreign = os.path.join(self.home, "other-mitmproxy-ca.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", os.path.join(self.home, "k.pem"),
                        "-out", self.foreign, "-days", "2", "-subj", "/CN=mitmproxy/O=mitmproxy"], capture_output=True, check=True)
        self.hashname = subprocess.run(["openssl", "x509", "-in", self.ours, "-noout", "-subject_hash_old"],
                                       capture_output=True, text=True, check=True).stdout.strip() + ".0"

    def test_root_image_keeps_another_workstations_ca_under_the_same_file_name(self):
        open(os.path.join(self.emu, "root"), "w").close()
        store = os.path.join(self.emu, "cacerts", self.hashname)
        shutil.copy(self.foreign, store)
        out = self.ok("android", "off").stdout
        self.assertTrue(os.path.exists(store), "another workstation's CA was removed")
        self.assertIn("removed 0 CA file(s)", out)
        self.assertIn("not this workstation's CA", out)
        shutil.copy(self.ours, store)
        out = self.ok("android", "off").stdout
        self.assertFalse(os.path.exists(store), "this workstation's CA was not removed")
        self.assertIn("removed 1 CA file(s)", out)
        self.assertNotIn("not this workstation's CA", out)

    def proxy(self):
        try:
            return open(os.path.join(self.emu, "proxy")).read().strip()
        except FileNotFoundError:
            return ":0"

    def test_root_image_installs_the_ca_then_turns_the_proxy_on(self):
        open(os.path.join(self.emu, "root"), "w").close()
        out = self.ok("android", "on").stdout
        self.assertTrue(os.path.exists(os.path.join(self.emu, "cacerts", self.hashname)))
        self.assertEqual(self.proxy(), "10.0.2.2:" + self.env["RIVIS_PORT"])
        self.assertNotIn("NOT DONE", out)

    def test_without_a_verified_ca_the_proxy_stays_off_and_the_command_is_not_done(self):
        """Review R7: the proxy was turned on and the command (and the Devices tab) said done while no CA was trusted,
        so every HTTPS call from the emulator failed."""
        r = self.cli("android", "on", "--manual")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("NOT DONE", r.stdout)
        self.assertIn("--proxy-only", r.stdout)
        self.assertEqual(self.proxy(), ":0", "the proxy was turned on without a trusted CA")
        r = self.cli("android", "on", "--all", "--manual")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not done on emulator-5554", r.stderr)
        self.assertEqual(self.proxy(), ":0")
        out = self.ok("android", "on", "--manual", "--proxy-only").stdout      # deliberate: installed by hand
        self.assertIn("--proxy-only", out)
        self.assertEqual(self.proxy(), "10.0.2.2:" + self.env["RIVIS_PORT"])

    def ps(self, *args):
        bindir = os.path.join(self.home, "adb-bin")
        os.makedirs(bindir, exist_ok=True)
        if not os.path.exists(os.path.join(bindir, "adb")):
            os.symlink(self.env["ADB"], os.path.join(bindir, "adb"))
        env = dict(self.env, PATH=bindir + ":" + self.env["PATH"])
        return self.suite.run([harness.PWSH, "-NoProfile", "-NonInteractive", "-File", os.path.join(harness.REPO, "rivis.ps1")]
                              + list(args), home=self.home, env=env, timeout=120)

    @unittest.skipUnless(os.access(harness.PWSH, os.X_OK), "portable pwsh not found")
    def test_powershell_edition_keeps_foreign_cas_and_waits_for_the_ca(self):
        open(os.path.join(self.emu, "root"), "w").close()
        r = self.ps("android", "on")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        store = os.path.join(self.emu, "cacerts", self.hashname)
        self.assertTrue(os.path.exists(store))
        shutil.copy(self.foreign, store)                                    # another workstation's CA, same name
        r = self.ps("android", "off")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(os.path.exists(store), "another workstation's CA was removed")
        self.assertIn("not this workstation's CA", r.stdout)
        shutil.copy(self.ours, store)
        self.assertIn("removed 1 CA file", self.ps("android", "off").stdout)
        self.assertFalse(os.path.exists(store))
        os.remove(os.path.join(self.emu, "root"))                            # a Google Play image: no verification possible
        r = self.ps("android", "on")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("NOT DONE", r.stdout)
        self.assertEqual(self.proxy(), ":0")
        r = self.ps("android", "on", "-ProxyOnly")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.proxy(), "10.0.2.2:" + self.env["RIVIS_PORT"])

    def test_play_image_without_magisk_says_why_the_slow_route_is_used(self):
        # 2026-10-19: a source-checkout Rivis had no Magisk next to it and silently took the ~4-minute Settings route
        env = dict(self.env, RIVIS_MAGISK_DIR=os.path.join(self.home, "no-such-magisk"))
        r = self.cli("android", "on", env=env)
        self.assertIn("one-click setup unavailable", r.stdout + r.stderr)
        self.assertIn("RIVIS_MAGISK_DIR", r.stdout + r.stderr)

    def test_play_image_uninstalls_only_this_workstations_entry_in_settings(self):
        user = os.path.join(self.emu, "user")
        os.makedirs(user)
        for name, pem in (("0.pem", self.foreign), ("1.pem", self.ours), ("2.pem", self.foreign)):
            shutil.copy(pem, os.path.join(user, name))
        out = self.ok("android", "off", timeout=180).stdout
        self.assertEqual(sorted(os.listdir(user)), ["0.pem", "2.pem"], out)
        self.assertIn("removed 1 CA entry of this workstation", out)
        self.assertIn("left 2 other", out)

    def test_android_off_does_not_request_manual_removal_when_user_store_is_empty(self):
        # B-04: Settings removal can return failure after the entry has gone; verify the final list.
        os.makedirs(os.path.join(self.emu, "user"))
        os.remove(self.ours)                         # no CA fingerprint on record makes ui_remove_ca fail
        out = self.ok("android", "off", timeout=120).stdout
        self.assertNotIn("remove the CA by hand", out)
        self.assertIn("no longer in Settings", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
