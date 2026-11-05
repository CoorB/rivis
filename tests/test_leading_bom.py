"""Leading whitespace and UTF-8 BOM(s) are not content — one rule, every owned parser.

A UTF-8 mark has caused five separate defects (HAR redaction, cURL paste, panel Form, then
incomplete peelers for each). This module is the table that stops the sixth: every shape that
beat an earlier fix is one row. A mark inside a payload stays; a UTF-16 mark is not UTF-8 and
must not be silently accepted as JSON.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import _paths  # noqa: F401
from proxy_common import without_leading_bom
import proxy_redact as R
from curl_import import parse_curl
from panel_har import from_har

_mitm = mock.MagicMock()
sys.modules.setdefault("mitmproxy", _mitm)
sys.modules.setdefault("mitmproxy.ctx", _mitm.ctx)
sys.modules.setdefault("mitmproxy.http", _mitm.http)
import proxy_collections as coll  # noqa: E402
from proxyman_import import import_proxyman  # noqa: E402


# Leading prefixes that are not content. The sixth shape is one more tuple.
LEADING = (
    ("mark", "\ufeff"),
    ("mark-mark", "\ufeff\ufeff"),
    ("space-mark", "  \ufeff"),
    ("mark-space-mark", "\ufeff \ufeff"),
    ("tab-mark", "\t\ufeff"),
    ("crlf-mark", "\r\n\ufeff"),
    ("mixed", " \ufeff\n\ufeff"),
)

SECRET = json.dumps({"password": 123456, "otp": 987654, "pin": 42, "user": "qa"})
PLAIN_JSON = '{"a": 1}'
CURL = "curl https://example.test/x"


class WithoutLeadingBom(unittest.TestCase):
    def test_table_of_leading_shapes_is_stripped(self):
        for name, prefix in LEADING:
            self.assertEqual(without_leading_bom(prefix + PLAIN_JSON), PLAIN_JSON, name)
            self.assertEqual(without_leading_bom(prefix + CURL), CURL, name)

    def test_mark_inside_payload_is_kept(self):
        # A BOM that is content (not leading) must survive — stripping it would change the body.
        inner = 'hello\ufeffworld'
        self.assertEqual(without_leading_bom(inner), inner)
        self.assertEqual(without_leading_bom('  keep\ufeff'), 'keep\ufeff')

    def test_empty_and_non_str(self):
        self.assertEqual(without_leading_bom(""), "")
        self.assertEqual(without_leading_bom("\ufeff\ufeff  "), "")
        self.assertEqual(without_leading_bom(None), None)
        self.assertEqual(without_leading_bom(b"\xef\xbb\xbf"), b"\xef\xbb\xbf")


class RedactLeadingBom(unittest.TestCase):
    def test_table_redacts_numeric_secrets_behind_every_leading_shape(self):
        for name, prefix in LEADING:
            out = R.text(prefix + SECRET, "application/json")
            for leak in ("123456", "987654", "42"):
                self.assertNotIn(leak, out, name)
            self.assertIn("qa", out, name)

    def test_nested_json_string_with_leading_mark_is_redacted(self):
        nested = json.dumps({"payload": "\ufeff \ufeff" + SECRET})
        out = R.text(nested, "application/json")
        for leak in ("123456", "987654", "42"):
            self.assertNotIn(leak, out)
        self.assertIn("qa", out)

    def test_mark_inside_a_string_value_is_not_content_for_redaction_keys(self):
        # The mark sits inside a non-secret string; structure redaction still runs; the mark stays.
        body = json.dumps({"user": "qa\ufeff", "password": 99})
        out = R.text(body, "application/json")
        self.assertNotIn("99", out)
        self.assertIn("qa\ufeff", out)


class CurlLeadingBom(unittest.TestCase):
    def test_table_of_pastes_still_starts_with_curl(self):
        # The first curl BOM fix only did lstrip("\ufeff").strip(); space-mark and mark-space-mark
        # still produced "\ufeffcurl" and were refused.
        for name, prefix in LEADING:
            r = parse_curl(prefix + CURL)
            self.assertEqual(r["spec"]["url"], "https://example.test/x", name)


class BodyHashLeadingBom(unittest.TestCase):
    def test_utf8_leading_shapes_hash_like_plain_json(self):
        want = coll.body_hash(PLAIN_JSON.encode())
        for name, prefix in LEADING:
            raw = (prefix + PLAIN_JSON).encode("utf-8")
            self.assertEqual(coll.body_hash(raw), want, name)

    def test_utf16_bom_is_not_treated_as_json(self):
        # json.loads(bytes) auto-detects UTF-16 and would hash the re-encoded object as if it were
        # the UTF-8 body — two different on-the-wire payloads looked identical on replay.
        plain = coll.body_hash(b'{"a":1}')
        utf16le = b'\xff\xfe{\x00"\x00a\x00"\x00:\x001\x00}\x00'
        utf16be = b'\xfe\xff\x00{\x00"\x00a\x00"\x00:\x001\x00}'
        self.assertNotEqual(coll.body_hash(utf16le), plain)
        self.assertNotEqual(coll.body_hash(utf16be), plain)
        self.assertEqual(coll.body_hash(utf16le), coll.body_hash(utf16le))  # opaque, stable


class CollectionFileLeadingBom(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        coll.COLL_DIR = os.path.join(self.tmp.name, "collections")
        os.makedirs(coll.COLL_DIR, mode=0o700)

    def test_collection_file_with_leading_bom_still_loads(self):
        path = os.path.join(coll.COLL_DIR, "journey.json")
        doc = {"name": "journey", "created": 1.0, "entries": [], "schema_version": 1}
        for name, prefix in LEADING[:3]:   # mark / mark-mark / space-mark cover the file case
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(prefix + json.dumps(doc))
            got = coll.load_coll("journey")
            self.assertEqual(got["name"], "journey", name)


class ProxymanFileLeadingBom(unittest.TestCase):
    def test_ruletree_with_leading_bom_still_imports(self):
        tmp = tempfile.mkdtemp(prefix="rivis-t-bom-proxyman-")
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        src = os.path.join(tmp, "source")
        os.makedirs(src)
        with open(os.path.join(src, "ok.json"), "w") as fh:
            fh.write("HTTP/1.1 200 OK\n\n{}\n")
        tree = {"nodes": [
            {"name": "good", "url": "https://api.example.com/good", "localFile": {"path": "ok.json"},
             "isEnabled": True, "regex": "useWildcard", "id": "1"},
        ]}
        with open(os.path.join(src, "MapLocalFiles-RuleTree"), "w", encoding="utf-8") as fh:
            fh.write("\ufeff" + json.dumps(tree))
        rules = os.path.join(tmp, "rules.json")
        with open(rules, "w", encoding="utf-8") as fh:
            fh.write("  \ufeff" + json.dumps({"rules": []}))
        summary = import_proxyman(rules, src, dry_run=True)
        self.assertIn("would import good", summary)
        self.assertIn("imported 1, skipped 0", summary)


class HarStoreKeepsBom(unittest.TestCase):
    def test_from_har_keeps_a_bom_in_the_response_body(self):
        # Store/replay must stay byte-for-character. Stripping a mark here would change what a
        # collection serves back to the app — a different defect from the parse/redact path.
        text = "\ufeff" + '{"kept": true}'
        har = {"log": {"entries": [{
            "request": {"method": "GET", "url": "https://api.example.test/x", "headers": [],
                        "queryString": [], "cookies": []},
            "response": {"status": 200, "headers": [{"name": "Content-Type", "value": "application/json"}],
                         "cookies": [], "content": {"mimeType": "application/json", "text": text}},
        }]}}
        entries = from_har(har)
        self.assertEqual(entries[0]["text"], text)


if __name__ == "__main__":
    unittest.main()
