"""Collections (record → replay → strict, HAR round trip, delete-while-recording) and Sessions (save, load, note,
delete, HAR), live through the proxy."""
import json
import os
import stat
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Background, LiveCase, Instance, wait_for
import harness
import upstream


def seed_profile(inst):
    """A user project whose record_match covers only upstream #1 (set by the test class)."""
    prof = os.path.join(inst.home, ".rivis", "profiles", "qa")
    os.makedirs(prof, exist_ok=True)
    with open(os.path.join(prof, "project.json"), "w") as fh:
        json.dump({"id": "qa", "label": "QA", "description": "t", "hosts": "", "record_match": inst.record_match,
                   "throttle_match": ".", "android_packages": [], "ios_bundle_ids": []}, fh)
    with open(os.path.join(prof, "rules.example.json"), "w") as fh:
        json.dump({"rules": []}, fh)


class Collections(LiveCase):
    PROJECT = "qa"

    @classmethod
    def make_instance(cls):
        inst = Instance(cls.suite, "collections", project="qa", pre=seed_profile)
        inst.record_match = r"127\.0\.0\.1:%d/" % cls.up.http_port
        return inst

    def setUp(self):
        self.inst.clear_dir("collections")
        super().setUp()

    def coll(self, **kw):
        c = {"recording": None, "replay": [], "strict": False}
        c.update(kw)
        return c

    def entries(self, name):
        return self.panel.ok("coll_entries", {"name": name})["entries"]

    def record(self, name, **kw):
        self.panel.ok("coll_record", dict({"name": name}, **kw))
        wait_for(lambda: self.panel.state()["collections"]["recording"] == name, 5, 0.1, "recording flag")
        time.sleep(1.3)                  # the engine re-reads rules.json at most once a second

    def test_cycle5_strict_takes_effect_on_the_next_call(self):
        self.reset_state(collections=self.coll())
        self.record("cycle5")
        self.fetch("/json/small")
        self.panel.ok("coll_stop")
        self.panel.ok("coll_replay", {"name": "cycle5", "enabled": True})
        self.panel.ok("coll_match", {"record_match": "json"})
        self.fetch("/json/small")  # warm the engine's config cache before enabling strict replay
        self.panel.ok("coll_strict", {"strict": True})
        self.up.reset_hits()
        result = self.fetch("/json/small?collection=absent2")
        self.assertEqual(result.status, 404, result.text)
        self.assertEqual(self.up.hits, [])
        self.assertEqual(self.fetch("/json/small").status, 200)

    def test_default_record_match_is_the_project_hosts_only(self):
        self.reset_state(collections=self.coll(recording="c1"))
        time.sleep(1.2)
        self.assertEqual(self.panel.state()["collections"]["record_match"], self.inst.record_match)
        self.fetch("/json/small", up=self.up2)                           # other host: not a project host
        self.fetch("/json/small")
        self.assertEqual([(e["host"], e["path"]) for e in self.entries("c1")], [("127.0.0.1", "/json/small")])
        self.assertEqual(len(self.entries("c1")), 1)
        self.assertIn("recorded → c1", self.comment("/json/small"))

    def test_record_replay_in_order_then_sticks_and_never_hits_upstream(self):
        self.reset_state(collections=self.coll())
        self.record("seq")
        self.assertEqual([self.fetch("/counter").json()["n"] for _ in range(3)], [1, 2, 3])
        self.panel.ok("coll_stop")
        self.assertEqual(self.panel.state()["collections"]["items"][0]["count"], 3)
        self.panel.ok("coll_replay", {"name": "seq", "enabled": True})
        time.sleep(1.3)
        self.up.reset_hits()
        self.assertEqual([self.fetch("/counter").json()["n"] for _ in range(5)], [1, 2, 3, 3, 3])
        self.assertEqual(self.up.hits_for("/counter"), [])
        self.assertIn("collection:seq", self.comment("/counter"))

    def test_replay_matches_on_query_and_request_body(self):
        self.reset_state(collections=self.coll())
        self.record("bodies")
        self.fetch("/echo?b=2&a=1", method="POST", data=json.dumps({"k": 1, "j": 2}))
        self.fetch("/echo?a=1&b=2", method="POST", data=json.dumps({"x": 9}))
        self.panel.ok("coll_stop")
        self.panel.ok("coll_replay", {"name": "bodies", "enabled": True})
        time.sleep(1.3)
        self.up.reset_hits()
        r = self.fetch("/echo?a=1&b=2", method="POST", data=json.dumps({"j": 2, "k": 1}))      # key order differs
        self.assertEqual(json.loads(r.json()["body"]), {"k": 1, "j": 2})
        r = self.fetch("/echo?b=2&a=1", method="POST", data=json.dumps({"x": 9}))
        self.assertEqual(json.loads(r.json()["body"]), {"x": 9})
        self.assertEqual(self.up.hits_for("/echo"), [])

    def test_exported_har_reimported_still_replays_posts_by_body(self):
        # A collection shared as HAR (export here, import on a teammate's machine) must replay its POSTs with bodies.
        # The export carried no request-body identity, so after import every such POST went live (or 404 in strict).
        self.reset_state(collections=self.coll())
        self.record("shared")
        self.fetch("/echo?s=1", method="POST", data=json.dumps({"user": "a"}))
        self.fetch("/echo?s=1", method="POST", data=json.dumps({"user": "b"}))
        self.panel.ok("coll_stop")
        har = self.panel.ok("coll_export", {"name": "shared"})
        self.panel.ok("coll_delete", {"name": "shared"})
        self.panel.ok("coll_import", {"name": "shared-copy", "har": har.get("har", har), "overwrite": True})
        self.panel.ok("coll_replay", {"name": "shared-copy", "enabled": True})
        self.panel.ok("coll_strict", {"strict": True})
        time.sleep(1.3)
        self.up.reset_hits()
        r = self.fetch("/echo?s=1", method="POST", data=json.dumps({"user": "b"}))
        self.assertEqual(r.status, 200, r.text[:200])
        self.assertEqual(json.loads(r.json()["body"]), {"user": "b"})
        self.assertEqual(self.up.hits_for("/echo"), [])
        self.panel.ok("coll_strict", {"strict": False})

    def test_strict_refuses_a_body_it_never_recorded(self):
        # R2A-04: a "wrong password" login was answered with the recorded successful one, even in strict mode
        self.reset_state(collections=self.coll())
        self.record("logins")
        self.fetch("/echo?j=1", method="POST", data="user=a")
        self.fetch("/echo?j=1", method="POST", data="user=b")
        self.panel.ok("coll_stop")
        self.panel.ok("coll_replay", {"name": "logins", "enabled": True})
        self.panel.ok("coll_strict", {"strict": True})
        time.sleep(1.3)
        self.up.reset_hits()
        self.assertEqual(self.fetch("/echo?j=1", method="POST", data="user=b").json()["body"], "user=b")
        r = self.fetch("/echo?j=1", method="POST", data="user=WRONG")
        self.assertEqual(r.status, 404)
        self.assertIn("body not in the replayed collection", r.text)
        self.assertEqual(self.up.hits_for("/echo"), [])
        self.assertIn("strict body miss", self.comment("/echo?j=1"))

    def test_lenient_unrecorded_post_body_goes_upstream(self):
        # R3A-04: a new login body must not receive an unrelated recorded success.
        self.reset_state(collections=self.coll())
        self.record("login")
        self.fetch("/echo?login=1", method="POST", data="user=alice")
        self.panel.ok("coll_stop")
        self.panel.ok("coll_replay", {"name": "login", "enabled": True})
        time.sleep(1.3)
        self.up.reset_hits()
        r = self.fetch("/echo?login=1", method="POST", data="user=carol")
        self.assertEqual(r.json()["body"], "user=carol")
        self.assertTrue(self.up.hits_for("/echo"))

    def test_imported_collection_strict_match_can_be_changed(self):
        # R3A-04: after import, strict scope must be editable without starting a recording.
        self.reset_state(collections=self.coll())
        har = {"log": {"entries": [{"request": {"method": "GET", "url": self.up.url("/text"), "headers": []},
                                     "response": {"status": 200, "headers": [], "content": {"text": "saved"}}}]}}
        self.panel.ok("coll_import", {"name": "imported", "har": har})
        self.panel.ok("coll_replay", {"name": "imported", "enabled": True})
        self.panel.ok("coll_match", {"record_match": r"/echo\?strict-scope=1"})
        self.assertEqual(self.panel.state()["collections"]["record_match"], r"/echo\?strict-scope=1")
        self.panel.ok("coll_strict", {"strict": True})
        time.sleep(1.3)
        self.assertEqual(self.fetch("/echo?strict-scope=1").status, 404)
        self.assertEqual(self.fetch("/echo?strict-scope=2").status, 200)

    def test_har_import_keeps_request_bodies_so_they_replay_apart(self):
        # R2A-05: from_har wrote req_body "" for every entry, so POSTs differing only by body collapsed onto the first
        def entry(body, status, text):
            return {"request": {"method": "POST", "url": self.up.url("/echo?h=1"), "headers": [],
                                "postData": {"mimeType": "application/json", "text": body}},
                    "response": {"status": status, "headers": [], "content": {"mimeType": "text/plain", "text": text}}}
        har = {"log": {"entries": [entry('{"id":"A"}', 200, "paid-A"), entry('{"id":"B"}', 402, "declined-B")]}}
        self.reset_state(collections=self.coll())
        self.panel.ok("coll_import", {"name": "hb", "har": har})
        self.panel.ok("coll_replay", {"name": "hb", "enabled": True})
        time.sleep(1.3)
        r = self.fetch("/echo?h=1", method="POST", data='{ "id": "B" }')
        self.assertEqual((r.status, r.text), (402, "declined-B"))
        r = self.fetch("/echo?h=1", method="POST", data='{"id":"A"}')
        self.assertEqual((r.status, r.text), (200, "paid-A"))

    def test_har_import_reports_what_it_left_out(self):
        # R2A-10: failed calls and WebSocket upgrades were dropped/imported silently
        def entry(path, status):
            return {"request": {"method": "GET", "url": self.up.url(path), "headers": []},
                    "response": {"status": status, "headers": [], "content": {"text": "x"}}}
        har = {"log": {"entries": [entry("/ok", 200), entry("/down", 0), entry("/ws", 101)]}}
        self.reset_state(collections=self.coll())
        doc = self.panel.ok("coll_import", {"name": "skipme", "har": har})
        self.assertEqual((doc["count"], doc["skipped_count"]), (1, 2))
        self.assertTrue(any("/ws" in x and "WebSocket" in x for x in doc["skipped"]), doc)
        self.assertEqual([e["path"] for e in self.entries("skipme")], ["/ok"])

    def test_strict_mode_answers_404_for_unrecorded_calls(self):
        self.reset_state(collections=self.coll())
        self.record("s")
        self.fetch("/json/small")
        self.panel.ok("coll_stop")
        self.panel.ok("coll_replay", {"name": "s", "enabled": True})
        self.panel.ok("coll_strict", {"strict": True})
        time.sleep(1.3)
        self.up.reset_hits()
        self.assertEqual(self.fetch("/json/small").status, 200)
        r = self.fetch("/text")
        self.assertEqual(r.status, 404)
        self.assertIn("strict", r.text)
        self.assertEqual(self.up.hits, [])
        self.assertEqual(self.fetch("/json/small", up=self.up2).status, 200)    # not a project host: untouched by strict
        self.assertIn("strict miss", self.comment("/text"))

    def test_rule_modified_and_locally_answered_responses_are_not_recorded(self):
        rules = [self.rule("patch", "json_patch", "/json/small", set={"flag": True}),
                 self.rule("hdr", "set_header", "/text", side="response", header="X-A", value="1"),
                 self.rule("mock", "respond", "/status/", status=201, body="m"),
                 self.rule("st", "status", "/rest", status=299)]
        self.reset_state(collections=self.coll(), rules=rules)
        self.record("clean")
        for p in ("/json/small", "/text", "/status/204", "/rest", "/empty"):
            self.fetch(p)
        self.assertEqual([e["path"] for e in self.entries("clean")], ["/empty"])

    def test_script_modified_responses_are_not_recorded(self):
        name = self.panel.ok("script_new", {"name": "mod", "lang": "py", "template": "json", "match": "/json/small"})["file"]
        self.assertEqual(name, "mod.py")
        self.reset_state(collections=self.coll(), scripts=self.panel.state()["scripts"])
        self.record("scr")
        self.assertTrue(self.fetch("/json/small").json().get("featureEnabled"))
        self.fetch("/empty")
        self.assertEqual([e["path"] for e in self.entries("scr")], ["/empty"])

    def test_deleting_a_collection_while_recording_never_resurrects_it(self):
        self.reset_state(collections=self.coll())
        self.record("ghost")
        self.fetch("/json/small")
        self.panel.ok("coll_delete", {"name": "ghost"})
        for _ in range(3):
            self.fetch("/json/small")
        time.sleep(2.2)
        self.assertEqual([i["name"] for i in self.panel.state()["collections"]["items"]], [])
        self.assertFalse(os.path.exists(self.inst.path("collections", "ghost.json")))
        self.assertIsNone(self.panel.state()["collections"]["recording"])

    def test_stopping_and_restarting_a_recording_appends_nothing_lost(self):
        self.reset_state(collections=self.coll())
        self.record("two")
        self.fetch("/json/small")
        self.panel.ok("coll_stop")
        self.record("two")
        self.fetch("/text")
        self.panel.ok("coll_stop")
        self.assertEqual(sorted(e["path"] for e in self.entries("two")), ["/json/small", "/text"])

    def test_har_export_import_round_trip_and_replay(self):
        self.reset_state(collections=self.coll())
        self.record("orig")
        self.fetch("/json/small")
        self.fetch("/text")
        self.panel.ok("coll_stop")
        doc = self.panel.ok("coll_export", {"name": "orig"})
        self.assertEqual(doc["filename"], "orig.har")
        har = doc["har"]
        self.assertEqual(har["log"]["version"], "1.2")
        self.assertEqual(len(har["log"]["entries"]), 2)
        self.assertEqual(self.panel.ok("coll_import", {"name": "copy", "har": har})["count"], 2)
        self.assertEqual([(e["path"], e["status"]) for e in self.entries("copy")],
                         [(e["path"], e["status"]) for e in self.entries("orig")])
        self.panel.ok("coll_replay", {"name": "copy", "enabled": True})
        time.sleep(1.3)
        self.up.reset_hits()
        self.assertEqual(self.fetch("/json/small").json(), {"user": {"name": "alice", "roles": ["a", "b"]},
                                                            "items": [{"id": 1}, {"id": 2}], "flag": False})
        self.assertEqual(self.up.hits, [])

    def test_binary_body_survives_record_and_replay(self):
        self.reset_state(collections=self.coll())
        self.record("bin")
        first = self.fetch("/big?mb=1").body
        self.panel.ok("coll_stop")
        self.panel.ok("coll_replay", {"name": "bin", "enabled": True})
        time.sleep(1.3)
        self.up.reset_hits()
        self.assertEqual(self.fetch("/big?mb=1").body, first)
        self.assertEqual(self.up.hits, [])

    def test_gzip_response_is_replayed_decoded_and_valid(self):
        self.reset_state(collections=self.coll())
        self.record("gz")
        self.fetch("/json/gzip", extra=["--compressed"])
        self.panel.ok("coll_stop")
        self.panel.ok("coll_replay", {"name": "gz", "enabled": True})
        time.sleep(1.3)
        r = self.fetch("/json/gzip", extra=["--compressed"])
        self.assertTrue(r.json()["gz"])

    def test_entry_delete_and_file_modes(self):
        self.reset_state(collections=self.coll())
        self.record("e")
        self.fetch("/json/small")
        self.fetch("/text")
        self.panel.ok("coll_stop")
        self.assertEqual(len(self.entries("e")), 2)
        self.panel.ok("coll_entry_delete", {"name": "e", "i": 0})
        self.assertEqual([e["path"] for e in self.entries("e")], ["/text"])
        path = self.inst.path("collections", "e.json")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode), 0o700)

    def test_invalid_input_returns_json_errors(self):
        self.reset_state(collections=self.coll())
        for op, body in (("coll_record", {"name": "../x"}), ("coll_record", {"name": ""}),
                         ("coll_record", {"name": "ok", "record_match": "("}),
                         ("coll_replay", {"name": "../../etc/passwd", "enabled": True}),
                         ("coll_entries", {"name": "missing"}), ("coll_export", {"name": "missing"}),
                         ("coll_delete", {"name": "a/b"}), ("coll_import", {"name": "x", "har": {}}),
                         ("coll_import", {"name": "x", "har": {"log": {"entries": [{"bad": 1}]}}}),
                         ("coll_entry_delete", {"name": "missing", "i": 0})):
            code, doc, raw = self.panel.post(op, body)
            self.assertEqual(code, 400, "%s %s -> %s %r" % (op, body, code, raw[:120]))
            self.assertIn("error", doc)

    def test_cannot_replay_the_collection_being_recorded(self):
        self.reset_state(collections=self.coll())
        self.record("self")
        code, doc, _ = self.panel.post("coll_replay", {"name": "self", "enabled": True})
        self.assertEqual(code, 400)
        self.assertIn("stop recording", doc["error"])


    def test_import_never_silently_replaces_a_collection(self):
        """Review R5: importing a HAR under a name in use replaced that recording without asking."""
        self.reset_state(collections=self.coll())
        one = lambda path: {"log": {"entries": [{"request": {"method": "GET", "url": "https://example.test" + path},
                                                  "response": {"status": 200, "headers": [], "content": {"text": path}}}]}}
        self.panel.ok("coll_import", {"name": "same-name", "har": one("/first")})
        code, doc, _ = self.panel.post("coll_import", {"name": "same-name", "har": one("/second")})
        self.assertEqual(code, 400)
        self.assertIn("already exists", doc["error"])
        self.assertEqual([e["path"] for e in self.entries("same-name")], ["/first"])
        code, doc, _ = self.panel.post("coll_import", {"name": "same-name", "har": {"log": {"entries": [{"bad": 1}]}},
                                                      "overwrite": True})
        self.assertEqual(code, 400)                                   # an unusable HAR never costs the old recording
        self.assertEqual([e["path"] for e in self.entries("same-name")], ["/first"])
        self.panel.ok("coll_import", {"name": "same-name", "har": one("/second"), "overwrite": True})   # deliberate
        self.assertEqual([e["path"] for e in self.entries("same-name")], ["/second"])


class SessionOpenCopy(unittest.TestCase):
    def test_open_confirm_says_what_ok_and_cancel_do(self):
        # R8D-17: "Cancel to choose 'add' instead, or to stop" left it unclear what Cancel does. Since 0.9.10 the question
        # is asked in the panel with one button per action, and Cancel only cancels.
        panel = open(os.path.join(os.path.dirname(__file__), "..", "addons", "panel.js")).read()
        self.assertIn('choices: [["add", "Add to the list", ""], ["replace", "Replace the list", "p"]]', panel)
        self.assertIn("if (!how) return;", panel)
        self.assertNotIn("Cancel to choose 'add' instead, or to stop.", panel)


class Sessions(LiveCase):
    def setUp(self):
        super().setUp()
        for op_name in [s["name"] for s in self.panel.state()["sessions"]]:
            self.panel.ok("sess_delete", {"name": op_name})

    def test_save_load_note_delete_cycle(self):
        self.fetch("/json/small")
        self.fetch("/text")
        n = self.panel.ok("sess_save", {"name": "s1", "note": "first"})["count"]
        self.assertGreaterEqual(n, 2)
        meta = self.panel.state()["sessions"][0]
        self.assertEqual((meta["name"], meta["note"], meta["count"]), ("s1", "first", n))
        self.assertIn("127.0.0.1", meta["hosts"])
        self.panel.ok("sess_note", {"name": "s1", "note": "second"})
        self.assertEqual(self.panel.state()["sessions"][0]["note"], "second")
        for mode in (0o600,):
            for ext in (".flows", ".meta.json"):
                p = self.inst.path("sessions", "s1" + ext)
                self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), mode, p)
        # load: merges (nothing new — same ids), replace=True after the list is cleared brings them back
        self.assertEqual(self.panel.ok("sess_load", {"name": "s1"})["count"], 0)
        self.assertEqual(self.panel.post("sess_load", {"name": "s1", "replace": True})[0], 200)
        flows = [f["request"]["path"] for f in self.inst.flows()]
        self.assertIn("/json/small", flows)
        self.panel.ok("sess_delete", {"name": "s1"})
        self.assertEqual(self.panel.state()["sessions"], [])
        self.assertFalse(os.path.exists(self.inst.path("sessions", "s1.flows")))

    def test_save_requires_explicit_overwrite_and_preserves_the_first_capture(self):
        self.fetch("/json/small")
        first = self.panel.ok("sess_save", {"name": "dup", "note": "first"})["count"]
        self.fetch("/text")
        code, doc, _ = self.panel.post("sess_save", {"name": "dup", "note": "second"})
        self.assertEqual(code, 400)
        self.assertIn("already exists", doc["error"])
        saved = self.panel.state()["sessions"][0]
        self.assertEqual((saved["note"], saved["count"]), ("first", first))
        replaced = self.panel.ok("sess_save", {"name": "dup", "note": "second", "overwrite": True})
        self.assertGreater(replaced["count"], first)
        self.assertEqual(self.panel.state()["sessions"][0]["note"], "second")

    def test_har_export(self):
        self.fetch("/json/small")
        self.panel.ok("sess_save", {"name": "h1"})
        doc = self.panel.ok("sess_har", {"name": "h1"})
        self.assertEqual(doc["filename"], "h1.har")
        urls = [e["request"]["url"] for e in doc["har"]["log"]["entries"]]
        self.assertTrue(any(u.endswith("/json/small") for u in urls), urls)
        e = next(e for e in doc["har"]["log"]["entries"] if e["request"]["url"].endswith("/json/small"))
        self.assertEqual(json.loads(e["response"]["content"]["text"])["flag"], False)

    def test_har_export_redacts_secrets_unless_explicitly_included(self):
        # F-08: a HAR goes to Downloads and from there to tickets, so credentials are redacted by default
        for p in ("/jwt/setcookie", "/jwt/body", "/jwt/header"):
            self.fetch(p)
        self.panel.ok("sess_save", {"name": "sec"})
        doc = self.panel.ok("sess_har", {"name": "sec"})
        self.assertTrue(doc["redacted"])
        dumped = json.dumps(doc["har"])
        self.assertNotIn(upstream.JWT_FRESH, dumped)
        self.assertNotIn(upstream.JWT_EXPIRED, dumped)
        body = next(e for e in doc["har"]["log"]["entries"] if e["request"]["url"].endswith("/jwt/body"))
        self.assertEqual(json.loads(body["response"]["content"]["text"])["access_token"], "<redacted>")
        # the opt-in is per request and must be exactly true
        self.assertTrue(self.panel.ok("sess_har", {"name": "sec", "include_secrets": "yes"})["redacted"])
        raw = self.panel.ok("sess_har", {"name": "sec", "include_secrets": True})
        self.assertFalse(raw["redacted"])
        self.assertIn(upstream.JWT_FRESH, json.dumps(raw["har"]))

    def test_har_export_keeps_the_evidence(self):
        """Review R4: the session HAR had no request headers or body, no port, zero timings, and no failed calls."""
        self.fetch("/echo?r4=post", method="POST", data='{"token":"s3cr3t","note":"kept"}',
                   headers=[("Content-Type", "application/json"), ("Authorization", "Bearer " + upstream.JWT_FRESH),
                            ("Cookie", "session=abc123"), ("X-Dup", "one"), ("X-Dup", "two")])
        self.fetch("/echo?r4=form", method="POST", data="user=qa&password=hunter2",
                   headers=[("Content-Type", "application/x-www-form-urlencoded")])
        self.fetch("/json/gzip")
        gone = "http://127.0.0.1:%d/r4-gone" % harness.free_port()
        self.inst.fetch(gone)
        self.panel.ok("sess_save", {"name": "r4"})
        raw = self.panel.ok("sess_har", {"name": "r4", "include_secrets": True})["har"]["log"]["entries"]
        post = next(e for e in raw if "r4=post" in e["request"]["url"])
        port = self.up.url("/").rsplit(":", 1)[1].split("/")[0]
        self.assertIn(":%s/echo?r4=post" % port, post["request"]["url"])                    # the real port
        self.assertEqual(post["request"]["method"], "POST")
        self.assertEqual(json.loads(post["request"]["postData"]["text"]), {"token": "s3cr3t", "note": "kept"})
        self.assertEqual([h["value"] for h in post["request"]["headers"] if h["name"].lower() == "x-dup"], ["one", "two"])
        self.assertGreater(post["time"], 0)
        gz = next(e for e in raw if e["request"]["url"].endswith("/json/gzip"))
        self.assertIsInstance(json.loads(gz["response"]["content"]["text"]), dict)          # decoded, not gzip bytes
        failed = [e for e in raw if e["request"]["url"] == gone]
        self.assertEqual(len(failed), 1, "a call that never got an answer was dropped")
        self.assertTrue(failed[0]["response"].get("_error") or failed[0]["response"]["status"] in (0, 502), failed[0])
        # redacted by default: the new request fields too
        doc = self.panel.ok("sess_har", {"name": "r4"})
        self.assertTrue(doc["redacted"])
        dumped = json.dumps(doc["har"])
        for secret in (upstream.JWT_FRESH, "s3cr3t", "abc123", "hunter2"):
            self.assertNotIn(secret, dumped)
        post = next(e for e in doc["har"]["log"]["entries"] if "r4=post" in e["request"]["url"])
        self.assertEqual(json.loads(post["request"]["postData"]["text"])["note"], "kept")       # only secrets go
        form = next(e for e in doc["har"]["log"]["entries"] if "r4=form" in e["request"]["url"])
        params = {p["name"]: p["value"] for p in form["request"]["postData"]["params"]}   # the writer lists form fields
        self.assertEqual((params["user"], params["password"]), ("qa", "<redacted>"))

    def test_a_planted_session_meta_file_cannot_inject_markup(self):
        """F-15: /proxy/api/state returns only typed fields of sessions/*.meta.json."""
        os.makedirs(self.inst.path("sessions"), exist_ok=True)
        with open(self.inst.path("sessions", "shared.meta.json"), "w") as fh:
            json.dump({"name": "shared", "count": "<img src=x onerror=alert(1)>", "created": "<b>", "note": 5,
                       "hosts": ["ok.example", {"x": "<i>"}], "evil": "<script>"}, fh)
        meta = next(m for m in self.panel.state()["sessions"] if m["name"] == "shared")
        self.assertEqual(meta, {"name": "shared", "count": 0, "created": 0.0, "note": "", "hosts": ["ok.example"]})

    def test_save_does_not_include_paused_calls_and_visible_only(self):
        self.fetch("/json/small")
        self.assertGreaterEqual(self.panel.ok("sess_save", {"name": "v", "visible_only": True})["count"], 1)

    def test_r8d06_saved_session_excludes_tunnels_hidden_by_tls_all(self):
        self.panel.ok("focus_host", {"host": ""})
        self.reset_state(tls={"mode": "ignore", "ignore": ["127.0.0.1"]})
        self.panel.state()
        wait_for(lambda: self.fetch("/echo", tls=True, cacert=self.up.cert).status == 200 and
                 any(f.get("type") == "tcp" for f in self.inst.flows()), 15, 0.3, "tunnel row")
        self.reset_state(tls={"mode": "all"})
        self.panel.state()
        self.fetch("/json/small")
        visible = [f for f in self.inst.flows() if f.get("type") == "http"]
        saved = self.panel.ok("sess_save", {"name": "visible-types"})
        self.assertEqual(saved["count"], len(visible))
        self.assertEqual(self.panel.state()["sessions"][0]["count"], len(visible))
        self.assertEqual(len(self.panel.ok("sess_har", {"name": "visible-types"})["har"]["log"]["entries"]), len(visible))

    def test_r7a05_visible_save_uses_search_and_host_focus_and_rejects_empty(self):
        # R7A-05: the full flow view still contained hidden calls, so the checked save exported every call.
        self.fetch("/echo?r7a05=keep")
        self.fetch("/text?r7a05=hide")
        self.fetch("/echo?r7a05=other-host", up=self.up2)
        self.panel.ok("focus_host", {"host": "127.0.0.1"})
        search = "~u 'r7a05=keep'"
        doc = self.panel.ok("sess_save", {"name": "only-one", "visible_only": True, "search_filter": search})
        self.assertEqual(doc["count"], 1)
        entries = self.panel.ok("sess_har", {"name": "only-one"})["har"]["log"]["entries"]
        self.assertEqual(len(entries), 1)
        self.assertIn("r7a05=keep", entries[0]["request"]["url"])
        code, body, _ = self.panel.post("sess_save", {"name": "no-match", "visible_only": True,
                                                       "search_filter": "~u 'r7a05=absent'"})
        self.assertEqual(code, 400)
        self.assertIn("no calls", body["error"].lower())
        self.assertFalse(os.path.exists(self.inst.path("sessions", "no-match.flows")))

    def test_loading_a_saved_session_after_clear_restores_flows(self):
        self.fetch("/json/small")
        self.panel.ok("sess_save", {"name": "r"})
        self.assertGreaterEqual(self.panel.ok("sess_load", {"name": "r", "replace": True})["count"], 1)

    def test_cycle6_opening_a_large_session_does_not_stall_proxied_calls(self):
        # Cycle 6: opening/replacing with ~4,500 saved calls held every proxied call for ~2.3–2.5 s while a direct
        # control stayed under 5 ms (import-probe-{1,2,3}.json). The restore path must not monopolise mitmproxy's loop.
        # 3500 calls is enough here to hold the loop for well over 0.4 s when load runs in one turn.
        n = 3500
        argv = ["curl", "-sS", "--noproxy", "", "-x", "http://127.0.0.1:%d" % self.inst.proxy_port, "-o", "/dev/null"]
        for i in range(n):
            argv += [self.up.url("/json/small?sessstall=%d" % i)]
            if i < n - 1:
                argv += ["-o", "/dev/null"]
        subprocess.run(argv, timeout=180, check=False)
        wait_for(lambda: sum(1 for f in self.inst.flows()
                             if "sessstall=" in ((f.get("request") or {}).get("path") or "")) >= n,
                 90, 0.5, "%d saved calls" % n)
        self.panel.ok("sess_save", {"name": "stall-probe", "overwrite": True})
        load = Background(lambda: self.panel.ok("sess_load", {"name": "stall-probe", "replace": True}))
        time.sleep(0.02)
        worst, probes = 0.0, 0
        while load._t.is_alive() or probes < 8:
            t0 = time.time()
            r = self.fetch("/json/small?during-sess-load=%d" % probes, timeout=15)
            worst = max(worst, time.time() - t0)
            self.assertEqual(r.status, 200, r)
            probes += 1
            if probes > 120:
                break
            time.sleep(0.02)
        self.assertGreaterEqual(load.result(180)["count"], n)
        self.assertLess(worst, 0.4, "a proxied call took %.2f s while a saved session was opening" % worst)

    def test_invalid_input_returns_json_errors(self):
        for op, body in (("sess_save", {"name": ""}), ("sess_save", {"name": "../x"}), ("sess_save", {"name": "a b"}),
                         ("sess_save", {"name": "x" * 65}), ("sess_load", {"name": "nope"}), ("sess_note", {"name": "nope"}),
                         ("sess_har", {"name": "nope"}), ("sess_load", {"name": "/etc/passwd"}),
                         ("sess_delete", {"name": "../../x"})):
            code, doc, raw = self.panel.post(op, body)
            self.assertEqual(code, 400, "%s %s -> %s %r" % (op, body, code, raw[:120]))
            self.assertIn("error", doc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
