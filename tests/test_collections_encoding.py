"""Encoding edge cases for addons/proxy_collections.py (stdlib only — mitmproxy is stubbed for import)."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

# proxy_collections imports mitmproxy at module level; unit tests here never talk to a live proxy.
_mitm = mock.MagicMock()
sys.modules.setdefault("mitmproxy", _mitm)
sys.modules.setdefault("mitmproxy.ctx", _mitm.ctx)
sys.modules.setdefault("mitmproxy.http", _mitm.http)

import _paths  # noqa: F401
import proxy_collections as coll  # noqa: E402


class CollectionFileEncoding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        coll.COLL_DIR = os.path.join(self.tmp.name, "collections")
        os.makedirs(coll.COLL_DIR, mode=0o700)

    def test_arabic_response_text_loads_when_locale_encoding_is_ascii(self):
        # atomic_json writes UTF-8 with Arabic intact; open() without encoding=utf-8 uses the locale and
        # raises on Windows (cp1252) or any ASCII locale when the collection is replayed.
        doc = {"name": "journey", "created": 1.0, "entries": [{
            "method": "GET", "scheme": "http", "host": "h.test", "path": "/echo", "query": "",
            "req_body": "", "status": 200, "headers": [["X-Note", "مرحبا"]], "text": '{"n":"مرحبا 👍🏽"}',
            "recorded_at": 1.0,
        }]}
        coll.save_coll(doc)
        real_open = open

        def ascii_open(path, mode="r", *args, **kwargs):
            if "b" not in mode and kwargs.get("encoding") is None:
                kwargs = dict(kwargs, encoding="ascii")
            return real_open(path, mode, *args, **kwargs)

        with mock.patch("builtins.open", ascii_open):
            got = coll.load_coll("journey")
        self.assertEqual(got["entries"][0]["text"], '{"n":"مرحبا 👍🏽"}')
        self.assertEqual(got["entries"][0]["headers"][0][1], "مرحبا")


class CanonAndBodyHash(unittest.TestCase):
    def test_arabic_query_and_json_body_hash_are_stable(self):
        encoded = coll.canon_query("b=%D8%A3%D9%87%D9%84%D8%A7&a=1")
        raw = coll.canon_query("a=1&b=أهلا")
        self.assertEqual(encoded, "a=1&b=%D8%A3%D9%87%D9%84%D8%A7")
        self.assertEqual(raw, encoded)
        a = json.dumps({"n": "مرحبا", "z": 1}, ensure_ascii=False).encode()
        b = json.dumps({"z": 1, "n": "مرحبا"}, ensure_ascii=False, indent=2).encode()
        self.assertEqual(coll.body_hash(a), coll.body_hash(b))


if __name__ == "__main__":
    unittest.main()
