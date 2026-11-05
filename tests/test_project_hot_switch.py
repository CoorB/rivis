"""Hot-switch the live rules project without restarting the proxy.

The panel Rules menu / `project_use` API reloads that project's rules, mocks, scripts and composer vars within
about one second. `rivis projects use` only saves the selection (CLI mutations and the next start). A start with
`--project` pins the Rules/API switch until unpin; while pinned, `projects use` still saves for the next start.
"""
import json
import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import Background, LiveCase, wait_for

needs_node = unittest.skipUnless(harness.NODE, "node is not installed")


def write_project(home, project_id, label, mock_name, mock_body, match_path):
    """A user profile + Map Local so each project answers the same URL differently."""
    profile = os.path.join(home, ".rivis", "profiles", project_id)
    state = os.path.join(home, ".rivis", "projects", project_id)
    os.makedirs(os.path.join(profile), mode=0o700, exist_ok=True)
    os.makedirs(os.path.join(state, "mocks"), mode=0o700, exist_ok=True)
    os.makedirs(os.path.join(state, "scripts"), mode=0o700, exist_ok=True)
    os.makedirs(os.path.join(state, "composer"), mode=0o700, exist_ok=True)
    with open(os.path.join(profile, "project.json"), "w") as fh:
        json.dump({"id": project_id, "label": label, "description": label, "hosts": r"127\.0\.0\.1",
                   "record_match": ".", "throttle_match": "."}, fh, indent=2)
        fh.write("\n")
    shutil.copy(os.path.join(harness.REPO, "projects", "_template", "rules.example.json"),
                os.path.join(profile, "rules.example.json"))
    mock_path = os.path.join(state, "mocks", mock_name)
    with open(mock_path, "w") as fh:
        fh.write(mock_body)
    rules = {
        "throttle": "off", "throttle_match": ".", "loss": 0, "no_cache": False,
        "rules": [{"name": "hs-" + project_id, "enabled": True, "match": match_path,
                   "action": "map_local", "file": mock_path, "status": 200}],
    }
    with open(os.path.join(state, "rules.json"), "w") as fh:
        json.dump(rules, fh, indent=2)
        fh.write("\n")
    with open(os.path.join(state, "composer", "vars.json"), "w") as fh:
        json.dump({"who": project_id}, fh)
        fh.write("\n")
    return state


def seed_project(home, project_id, rules=None, scripts=None, hosts=r"127\.0\.0\.1"):
    """A project with its own rules.json (written as given) and script files; returns its state dir."""
    state = write_project(home, project_id, project_id, "m.json", "{}", r"/never-matches-%s" % project_id)
    profile = os.path.join(home, ".rivis", "profiles", project_id, "project.json")
    with open(profile) as fh:
        doc = json.load(fh)
    doc["hosts"] = hosts
    with open(profile, "w") as fh:
        json.dump(doc, fh)
    entries = []
    for filename, (code, match) in (scripts or {}).items():
        with open(os.path.join(state, "scripts", filename), "w") as fh:
            fh.write(code)
        entries.append({"name": os.path.splitext(filename)[0], "file": filename,
                        "lang": os.path.splitext(filename)[1][1:], "enabled": True, "match": match})
    with open(os.path.join(state, "rules.json"), "w") as fh:
        json.dump(dict({"rules": []}, **(rules or {}), scripts=entries), fh)
    return state


def hdr(resp, name):
    return {k.lower(): v for k, v in resp.json()["headers"]}.get(name.lower())


class HotSwitch(LiveCase):
    """Started without --project (default), so rules are not pinned."""

    def setUp(self):
        # do not wipe the projects we seed; only clear default's rules via a fresh write below
        self.up.reset_hits()
        self.up2.reset_hits()
        # a prior test may have hot-switched away from default — write_cfg syncs via that project's rules file
        if self.panel.state().get("active_project") != "default":
            self.panel.ok("project_use", {"project": "default"})
            wait_for(lambda: self.panel.state()["active_project"] == "default", 5, 0.1, "back to default")
        write_project(self.inst.home, "app-a", "App A", "a.json", '{"from":"a"}', r"/hot-switch")
        write_project(self.inst.home, "app-b", "App B", "b.json", '{"from":"b"}', r"/hot-switch")
        # default has no Map Local for this path
        self.inst.write_cfg({"rules": []})

    def test_api_switch_serves_the_next_call_from_the_other_projects_map_local(self):
        path = "/hot-switch?hs=1"
        doc = self.panel.ok("project_use", {"project": "app-a"})
        self.assertEqual(doc["active_project"], "app-a")
        wait_for(lambda: self.panel.state()["active_project"] == "app-a", 5, 0.1, "state says app-a")
        self.assertEqual(self.panel.state()["active_project_label"], "App A")
        self.assertFalse(self.panel.state()["project_pinned"])
        r = self.fetch(path)                    # the very next call, no polling: the switch is in place on return
        self.assertEqual((r.status, r.json()), (200, {"from": "a"}))

        self.panel.ok("project_use", {"project": "app-b"})
        r = self.fetch(path)
        self.assertEqual((r.status, r.json()), (200, {"from": "b"}))
        self.assertEqual(self.panel.state()["active_project"], "app-b")
        # composer vars follow the active project; XSRF still works (this call itself proves the session)
        self.assertEqual(self.panel.state()["composer"]["vars"].get("who"), "app-b")
        self.assertEqual(open(os.path.join(self.inst.home, ".rivis", "current-project")).read().strip(), "app-b")

    def test_a_damaged_target_is_refused_and_nothing_changes(self):
        self.panel.ok("project_use", {"project": "app-a"})
        state = seed_project(self.inst.home, "broken")
        with open(os.path.join(state, "rules.json"), "w") as fh:
            fh.write('{"rules": [ {"name": "cut off')
        code, _doc, raw = self.panel.post("project_use", {"project": "broken"})
        self.assertEqual(code, 400)
        self.assertIn("cannot be read", raw.decode())
        self.assertEqual(self.panel.state()["active_project"], "app-a")
        self.assertEqual(open(os.path.join(self.inst.home, ".rivis", "current-project")).read().strip(), "app-a")
        self.assertEqual(self.fetch("/hot-switch?after-refuse=1").json(), {"from": "a"})

    def test_every_nth_counters_start_fresh_in_the_new_project(self):
        rule = {"name": "nth", "enabled": True, "match": "/hot-nth", "action": "block", "every": 2}
        seed_project(self.inst.home, "nth-a", rules={"rules": [rule]})
        seed_project(self.inst.home, "nth-b", rules={"rules": [rule]})
        self.panel.ok("project_use", {"project": "nth-a"})
        self.assertNotEqual(self.fetch("/hot-nth?a=1").status, 0)          # A's 1st match: not blocked
        self.panel.ok("project_use", {"project": "nth-b"})
        self.assertNotEqual(self.fetch("/hot-nth?b=1").status, 0, "B's FIRST match was counted as A's second")
        self.assertEqual(self.fetch("/hot-nth?b=2").status, 0)              # B's 2nd: blocked (connection killed)

    def test_project_only_view_follows_the_switch(self):
        seed_project(self.inst.home, "view-a", hosts=r"alpha\.example")
        seed_project(self.inst.home, "view-b", hosts=r"bravo\.example")
        self.panel.ok("project_use", {"project": "view-a"})
        self.panel.ok("view", {"project": "view-a", "project_only": True})
        self.assertIn("alpha", self.panel.option("view_filter"))
        self.panel.ok("project_use", {"project": "view-b"})
        vf = self.panel.option("view_filter")
        self.assertIn("bravo", vf)
        self.assertNotIn("alpha", vf)
        self.panel.ok("view", {"project_only": False})

    def test_a_pending_recording_is_written_to_the_old_project_only(self):
        a = seed_project(self.inst.home, "rec-a", rules={"collections": {"recording": "capture", "record_match": "/json/small"}})
        b = seed_project(self.inst.home, "rec-b")
        self.panel.ok("project_use", {"project": "rec-a"})
        self.fetch("/json/small?rec=1")
        self.panel.ok("project_use", {"project": "rec-b"})                 # inside the 0.5 s debounce
        wait_for(lambda: os.path.exists(os.path.join(a, "collections", "capture.json")), 5, 0.1, "A's capture written")
        harness.time.sleep(1.0)                                           # past any late debounce
        self.assertFalse(os.path.exists(os.path.join(b, "collections", "capture.json")),
                         "A's recording was saved into project B")
        with open(os.path.join(a, "collections", "capture.json")) as fh:
            self.assertTrue(json.load(fh)["entries"])

    def test_first_use_waits_for_the_target_projects_lock(self):
        import fcntl
        state = seed_project(self.inst.home, "lock-b")
        os.remove(os.path.join(state, "rules.json"))                       # first use: created from the example
        lock = open(os.path.join(state, ".rules.lock"), "a")
        fcntl.flock(lock, fcntl.LOCK_EX)                                   # a CLI mid-edit of lock-b's rules
        try:
            call = Background(self.panel.ok, "project_use", {"project": "lock-b"})
            harness.time.sleep(0.6)
            self.assertTrue(call._t.is_alive(), "project_use did not wait for lock-b's rules lock")
            with open(os.path.join(state, "rules.json"), "w") as fh:     # what that CLI writes
                json.dump({"rules": [{"name": "cli-made", "enabled": True, "match": "/x", "action": "delay", "ms": 1}]}, fh)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()
        call.result(15)
        with open(os.path.join(state, "rules.json")) as fh:
            self.assertEqual([r["name"] for r in json.load(fh)["rules"]], ["cli-made"])

    @needs_node
    def test_same_named_js_script_starts_clean_in_the_new_project(self):
        code = ('function onRequest(context, url, request) {\n'
                '  if (url.includes("set")) { context.token = "A"; globalThis.g = "A"; }\n'
                '  request.headers["X-Tok"] = String(context.token || "") + "/" + String(globalThis.g || "");\n'
                '  return request;\n}\n')
        seed_project(self.inst.home, "js-a", scripts={"auth.js": (code, "/echo")})
        seed_project(self.inst.home, "js-b", scripts={"auth.js": (code, "/echo")})   # same name, same code
        self.panel.ok("project_use", {"project": "js-a"})
        self.assertEqual(hdr(self.fetch("/echo?set=1"), "x-tok"), "A/A")
        self.panel.ok("project_use", {"project": "js-b"})
        self.assertEqual(hdr(self.fetch("/echo"), "x-tok"), "/", "B's auth.js saw A's context or globals")

    def test_same_named_python_script_starts_clean_in_the_new_project(self):
        code = ("G = {}\n"
                "def on_request(context, url, request):\n"
                "    if 'set' in url:\n"
                "        context['token'] = 'A'; G['g'] = 'A'\n"
                "    request['headers']['X-Tok'] = str(context.get('token') or '') + '/' + str(G.get('g') or '')\n"
                "    return request\n")
        seed_project(self.inst.home, "py-a", scripts={"auth.py": (code, "/echo")})
        seed_project(self.inst.home, "py-b", scripts={"auth.py": (code, "/echo")})
        self.panel.ok("project_use", {"project": "py-a"})
        self.assertEqual(hdr(self.fetch("/echo?set=1"), "x-tok"), "A/A")
        self.panel.ok("project_use", {"project": "py-b"})
        self.assertEqual(hdr(self.fetch("/echo"), "x-tok"), "/", "B's auth.py saw A's context or globals")

    @needs_node
    def test_an_old_script_chain_cannot_write_into_the_new_projects_shared_state(self):
        seed_project(self.inst.home, "chain-a", scripts={
            "01-wait.js": ('async function onRequest(c, u, r) { await sleep(1200); return r; }\n', "/hot-chain"),
            "02-token.js": ('function onRequest(c, u, r) { sharedState.tok = "A"; return r; }\n', "/hot-chain")})
        seed_project(self.inst.home, "chain-b", scripts={
            "read.js": ('function onRequest(c, u, r) { r.headers["X-Tok"] = String(sharedState.tok || ""); return r; }\n', "/echo")})
        self.panel.ok("project_use", {"project": "chain-a"})
        call = Background(self.fetch, "/hot-chain?slow=1")
        harness.time.sleep(0.4)                                            # 01-wait.js is sleeping
        self.panel.ok("project_use", {"project": "chain-b"})
        call.result(15)
        self.assertEqual(hdr(self.fetch("/echo"), "x-tok"), "", "A's second script ran after the switch")

    def test_cli_projects_use_saves_without_hot_switching(self):
        """CLI projects use selects for mutations/next start; live rules stay put (panel Rules / API switches)."""
        write_project(self.inst.home, "cli-a", "CLI A", "ca.json", '{"from":"cli-a"}', r"/hot-cli")
        before = self.panel.state()["active_project"]
        r = harness.subprocess.run(
            ["/bin/bash", harness.RIVIS, "projects", "use", "cli-a"],
            env=self.inst.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = r.stdout + r.stderr
        self.assertIn("current project: cli-a", out)
        self.assertIn("Rules menu", out)
        self.assertEqual(open(os.path.join(self.inst.home, ".rivis", "current-project")).read().strip(), "cli-a")
        self.assertEqual(self.panel.state()["active_project"], before)


class HotSwitchPinned(LiveCase):
    """Started with --project neo: rules stay pinned until unpin."""
    PROJECT = "neo"

    def test_project_use_refuses_until_unpin(self):
        write_project(self.inst.home, "other", "Other", "o.json", '{"from":"other"}', r"/hot-pin")
        st = self.panel.state()
        self.assertEqual(st["active_project"], "neo")
        self.assertTrue(st["project_pinned"])
        code, doc, raw = self.panel.post("project_use", {"project": "other"})
        self.assertEqual(code, 400)
        self.assertIn("unpin first", raw.decode())
        self.assertEqual(self.panel.state()["active_project"], "neo")

        r = harness.subprocess.run(["/bin/bash", harness.RIVIS, "projects", "unpin"],
                                   env=self.inst.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        # it must name what actually switches: the Rules menu (projects use only saves the next start)
        self.assertIn("Rules menu", r.stdout + r.stderr)
        self.assertNotIn("switches rules on the running proxy", r.stdout + r.stderr)
        self.assertFalse(self.panel.state()["project_pinned"])
        again = self.panel.ok("project_unpin", {})                                 # idempotent
        self.assertEqual((again["project_pinned"], again["active_project"]), (False, "neo"))
        self.panel.ok("project_use", {"project": "other"})
        wait_for(lambda: self.panel.state()["active_project"] == "other", 5, 0.1, "switched after unpin")
        got = wait_for(lambda: (lambda x: x if x.json().get("from") == "other" else None)(self.fetch("/hot-pin")),
                       5, 0.15, "other mock")
        self.assertEqual(got.json(), {"from": "other"})

    def test_cli_projects_use_while_pinned_saves_for_next_start(self):
        """While pinned, projects use saves current-project for the next start but leaves live rules alone."""
        write_project(self.inst.home, "other", "Other", "o.json", '{"from":"other"}', r"/hot-pin-cli")
        cur = os.path.join(self.inst.home, ".rivis", "current-project")
        r = harness.subprocess.run(
            ["/bin/bash", harness.RIVIS, "projects", "use", "other"],
            env=self.inst.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = (r.stdout + r.stderr).lower()
        self.assertIn("live rules stay", out)
        self.assertIn("unpin", out)
        self.assertIn("rules menu", out)
        self.assertNotIn("until restart", out)          # a restart keeps the --project start: that advice was wrong
        self.assertEqual(open(cur).read().strip(), "other")
        self.assertEqual(self.panel.state()["active_project"], "neo")
        self.assertTrue(self.panel.state()["project_pinned"])


if __name__ == "__main__":
    unittest.main()
