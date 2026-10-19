"""Arabic / RTL / emoji corpus through every place a tester types or exports text: proxied calls, Copy as …,
Map Local, Edit & Repeat, Compose, sessions, HAR, collections, Compare, rules. NEO is bilingual: every Unicode bug a
tester hit (R6B-03 Arabic shown as hex, R7A-01 Edit & Repeat on an Arabic URL) was one case of this class; this module
checks the class. Each string must arrive unchanged, and nothing may answer 500 or leak a Python codec error."""
import json
import os
import sys
import unittest
from urllib.parse import parse_qs, quote, urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import LiveCase, wait_for

CORPUS = {
    "arabic": "مرحبا بالعالم",
    "digits": "طلب رقم ١٢٣ — Order 123",           # Arabic-Indic digits + em dash, mixed direction
    "marks": "‏مرحبا‎ abc",                # RLM / LRM direction marks
    "emoji": "👍🏽 تم 👨‍👩‍👧",                         # skin tone + ZWJ family
    "combining": "é ö 東京",
}
CODEC_LEAK = ("codec can't", "ordinal not in range", "UnicodeEncodeError", "UnicodeDecodeError", "Traceback")


class UnicodeCorpus(LiveCase):
    def no_leak(self, text, where):
        for bad in CODEC_LEAK:
            self.assertNotIn(bad, text, "%s leaked a codec error" % where)

    def upstream_query(self, key="q"):
        hit = wait_for(lambda: self.up.hits[-1] if self.up.hits else None, 5, 0.1, "upstream hit")
        return parse_qs(urlsplit(hit["path"]).query).get(key, [None])[0], hit

    def call(self, label, text):
        url = "/echo?q=" + quote(text) + "&case=" + label
        r = self.fetch(url, method="POST", headers={"Content-Type": "application/json; charset=utf-8"},
                       data=json.dumps({"name": text}, ensure_ascii=False).encode())
        self.assertEqual(r.status, 200, (label, r.text[:200]))
        return self.inst.flow_for("case=" + label)

    def test_proxied_call_and_copy_as_every_language(self):
        targets = [t["id"] for t in self.panel.state()["codegen_targets"]]
        for label, text in CORPUS.items():
            with self.subTest(label):
                f = self.call(label, text)
                self.assertEqual(self.up.hits[-1]["body"].decode(), json.dumps({"name": text}, ensure_ascii=False))
                for t in targets:
                    code, doc, raw = self.panel.post("codegen", {"flow_id": f["id"], "target": t})
                    self.assertEqual(code, 200, (label, t, raw[:300]))
                    self.no_leak(doc["text"], "codegen " + t)
                url = self.panel.ok("export", {"flow_id": f["id"], "fmt": "url"})["text"]
                self.assertIn("q=", url)

    def test_map_local_keeps_arabic_body_through_edit_and_save(self):
        for label, text in CORPUS.items():
            with self.subTest(label):
                f = self.call("ml-" + label, text)
                name = self.panel.ok("mock", {"flow_id": f["id"]})["name"]
                got = self.panel.ok("mockfile_get", {"name": name})
                body = json.dumps({"reply": text}, ensure_ascii=False)
                self.panel.ok("mockfile_put", {"name": name, "content": body, "status": 200, "headers": got["headers"]})
                self.panel.ok("toggle", {"name": name, "enabled": True})
                r = wait_for(lambda: (lambda x: x if x.text == body else None)(
                    self.fetch("/echo?q=" + quote(text) + "&case=ml-" + label, method="POST", data=b"{}")), 5, 0.3, "mock served")
                self.assertEqual(r.text, body)
                self.assertEqual(self.panel.ok("mockfile_get", {"name": name})["content"], body)
                self.panel.ok("delete", {"name": name})

    def test_edit_and_repeat_with_raw_unicode_url_header_and_body(self):
        for label, text in CORPUS.items():
            with self.subTest(label):
                f = self.call("er-" + label, text)
                got = self.panel.ok("retry_get", {"flow_id": f["id"]})
                self.no_leak(json.dumps(got, ensure_ascii=False), "retry_get")
                url = self.up.url("/echo?q=" + text + "&case=er2-" + label)      # typed, not encoded (R7A-01 shape)
                code, doc, raw = self.panel.post("retry", {"flow_id": f["id"], "edits": {
                    "url": url, "method": "POST", "headers": got["req_headers"], "body": json.dumps({"n": text}, ensure_ascii=False)}})
                self.assertEqual(code, 200, (label, raw[:300]))
                hit = wait_for(lambda: next((h for h in reversed(self.up.hits) if "case=er2-" + label in h["path"]), None), 8, 0.2, "repeat hit")
                self.assertEqual(parse_qs(urlsplit(hit["path"]).query)["q"][0], text)
                self.assertEqual(json.loads(hit["body"].decode())["n"], text)

    def test_edit_and_repeat_on_a_call_whose_header_is_not_utf8(self):
        # A real server or app can send Latin-1 bytes in a header; Edit & Repeat must not fail with a codec error.
        r = self.fetch("/echo?case=latin1", headers={"X-Name": "José"})
        self.assertEqual(r.status, 200)
        f = self.inst.flow_for("case=latin1")
        got = self.panel.ok("retry_get", {"flow_id": f["id"]})
        code, doc, raw = self.panel.post("retry", {"flow_id": f["id"], "edits": {"headers": got["req_headers"]}})
        self.assertEqual(code, 200, raw[:300])
        self.no_leak(raw.decode("utf-8", "replace"), "retry")

    def test_compose_with_unicode_url_header_value_and_body(self):
        for label, text in CORPUS.items():
            with self.subTest(label):
                spec = {"method": "POST", "url": self.up.url("/echo?q=" + text + "&case=cp-" + label),
                        "headers": [["Content-Type", "text/plain; charset=utf-8"], ["X-Note", text]],
                        "body": text}
                code, doc, raw = self.panel.post("compose_send", {"spec": spec})
                self.assertIn(code, (200, 400), (label, raw[:300]))
                self.no_leak(raw.decode("utf-8", "replace"), "compose_send")
                if code == 400:
                    # refusing a non-ASCII header value is acceptable only with a plain message naming the header
                    self.assertIn("X-Note", raw.decode())
                    spec["headers"] = spec["headers"][:1]
                    self.panel.ok("compose_send", {"spec": spec})
                hit = wait_for(lambda: next((h for h in reversed(self.up.hits) if "case=cp-" + label in h["path"]), None), 8, 0.2, "compose hit")
                self.assertEqual(parse_qs(urlsplit(hit["path"]).query)["q"][0], text)
                self.assertEqual(hit["body"].decode(), text)

    def test_session_note_save_reopen_and_har_keep_unicode(self):
        f = self.call("sess", CORPUS["emoji"])
        self.panel.ok("sess_save", {"name": "unicode-qa", "overwrite": True})
        self.panel.ok("sess_note", {"name": "unicode-qa", "note": CORPUS["digits"]})
        listed = [s for s in self.panel.state()["sessions"] if s.get("name") == "unicode-qa"]
        self.assertEqual(listed[0].get("note"), CORPUS["digits"])
        har = self.panel.ok("sess_har", {"name": "unicode-qa"})
        text = json.dumps(har, ensure_ascii=False)
        self.no_leak(text, "sess_har")
        self.assertIn(CORPUS["emoji"], text if CORPUS["emoji"] in text else json.loads(json.dumps(har)).__str__())
        self.panel.ok("sess_load", {"name": "unicode-qa", "replace": True})
        wait_for(lambda: any("case=sess" in (x.get("request") or {}).get("path", "") for x in self.inst.flows()), 8, 0.2, "session reopened")
        self.panel.ok("sess_delete", {"name": "unicode-qa"})

    def test_har_import_and_export_round_trip(self):
        f = self.call("har", CORPUS["arabic"])
        self.panel.ok("coll_record", {"name": "uni-orig"})
        self.call("har2", CORPUS["marks"])
        self.panel.ok("coll_stop", {})
        har = self.panel.ok("coll_export", {"name": "uni-orig"})
        blob = json.dumps(har, ensure_ascii=False)
        self.no_leak(blob, "coll_export")
        doc = har.get("har", har)
        code, d, raw = self.panel.post("coll_import", {"name": "uni-copy", "har": doc, "overwrite": True})
        self.assertEqual(code, 200, raw[:300])
        # collections keep the response (and only a fingerprint of the request body): the echoed text must survive
        again = self.panel.ok("coll_export", {"name": "uni-copy"})
        entry = again.get("har", again)["log"]["entries"][0]
        self.assertEqual(json.loads(entry["response"]["content"]["text"])["query"]["q"], [CORPUS["marks"]])
        for n in ("uni-orig", "uni-copy"):
            self.panel.ok("coll_delete", {"name": n})

    def test_compare_and_viewer_show_text_not_bytes(self):
        a = self.call("cmpa", CORPUS["arabic"])
        b = self.call("cmpb", CORPUS["emoji"])
        doc = self.panel.ok("diff", {"a": a["id"], "b": b["id"]})
        blob = json.dumps(doc, ensure_ascii=False)
        self.no_leak(blob, "diff")
        self.assertIn(CORPUS["arabic"], blob)
        v = self.panel.ok("viewer", {"flow_id": a["id"]})
        self.no_leak(json.dumps(v, ensure_ascii=False), "viewer")

    def test_rules_with_unicode_values(self):
        self.reset_state(rules=[self.rule("ar-patch", "json_patch", "/json/small", set={"greeting": CORPUS["arabic"]}),
                                self.rule("ar-reply", "respond", "/reply", body=CORPUS["emoji"])])
        r = self.fetch("/json/small")
        self.assertEqual(json.loads(r.text)["greeting"], CORPUS["arabic"])
        self.assertEqual(self.fetch("/reply").text, CORPUS["emoji"])

    def test_set_header_with_unicode_value_is_sent_or_refused_clearly(self):
        self.reset_state(rules=[self.rule("ar-hdr", "set_header", "/echo", side="request", header="X-Note", value=CORPUS["arabic"])])
        r = self.fetch("/echo?case=hdr")
        self.no_leak(r.text, "set_header call")
        state = self.panel.state()
        skipped = {s["name"]: s["error"] for s in state["skipped_rules"]}
        if "ar-hdr" in skipped:
            self.no_leak(skipped["ar-hdr"], "skip reason")
        else:
            self.assertEqual(r.status, 200, r.text[:300])
            sent = dict((k.lower(), v) for k, v in self.up.hits[-1]["headers"])
            self.assertIn("x-note", sent)

    def test_filter_with_arabic_text(self):
        self.call("flt", CORPUS["arabic"])
        code, doc, raw = self.panel.post("filter_check", {"filter": CORPUS["arabic"]})
        self.assertIn(code, (200, 400), raw[:300])
        self.no_leak(raw.decode("utf-8", "replace"), "filter_check")


if __name__ == "__main__":
    unittest.main(verbosity=2)
