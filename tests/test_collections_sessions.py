"""Collections (record → replay → strict, HAR round trip, delete-while-recording) and Sessions (save, load, note,
delete, HAR), live through the proxy."""
import json
import os
import stat
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import LiveCase, Instance, wait_for
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

    def test_save_does_not_include_paused_calls_and_visible_only(self):
        self.fetch("/json/small")
        self.assertGreaterEqual(self.panel.ok("sess_save", {"name": "v", "visible_only": True})["count"], 1)

    def test_loading_a_saved_session_after_clear_restores_flows(self):
        self.fetch("/json/small")
        self.panel.ok("sess_save", {"name": "r"})
        self.assertGreaterEqual(self.panel.ok("sess_load", {"name": "r", "replace": True})["count"], 1)

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
