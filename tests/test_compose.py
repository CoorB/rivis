"""Tests for addons/proxy_compose.py: normalisation, variables, saved-request storage."""
import json
import os
import stat
import tempfile
import unittest

import _paths  # noqa: F401
from proxy_compose import ComposerStore, normalize_request


class Normalize(unittest.TestCase):
    def test_r7a01_unicode_path_query_and_idna_host(self):
        # R7A-01: browser-style URLs need UTF-8 escapes and an ASCII host before mitmproxy sees them.
        out = normalize_request({"url": "https://مثال.إختبار/مرحبا?text=أهلا"})
        self.assertEqual(out["url"], "https://xn--mgbh0fb.xn--kgbechtv/%D9%85%D8%B1%D8%AD%D8%A8%D8%A7?text=%D8%A3%D9%87%D9%84%D8%A7")

    def test_query_table_replaces_url_query_and_toggle(self):
        spec = {"method": "get", "url": "https://h.test/p?old=1",
                "query": [["a", "1 2"], ["b", "x&y"], ["off", "z", False], ["", "ignored"]]}
        out = normalize_request(spec)
        self.assertEqual(out["method"], "GET")
        self.assertEqual(out["url"], "https://h.test/p?a=1+2&b=x%26y&=ignored")

    def test_query_from_url_when_no_table(self):
        out = normalize_request({"url": "https://h.test/p?x=1&y=%C3%A9"})
        self.assertEqual(out["url"], "https://h.test/p?x=1&y=%C3%A9")

    def test_variables_everywhere(self):
        spec = {"method": "POST", "url": "{{edge}}/v1/x", "query": [["id", "{{id}}"]],
                "headers": [["Authorization", "Bearer {{token}}"]], "body_mode": "json", "body": '{"n": "{{id}}"}'}
        out = normalize_request(spec, {"edge": "https://e.test", "id": "7", "token": "T"})
        self.assertEqual(out["url"], "https://e.test/v1/x?id=7")
        self.assertIn(("Authorization", "Bearer T"), out["headers"])
        self.assertIn(("Content-Type", "application/json"), out["headers"])
        self.assertEqual(json.loads(out["body"]), {"n": "7"})

    def test_undefined_variable(self):
        with self.assertRaises(ValueError):
            normalize_request({"url": "https://h.test/{{nope}}"})

    def test_bodies(self):
        form = normalize_request({"method": "POST", "url": "https://h.test/", "body_mode": "form",
                                  "form": [["a", "é"], ["b", "1"], ["c", "2", False]]})
        self.assertEqual(form["body"], b"a=%C3%A9&b=1")
        self.assertIn(("Content-Type", "application/x-www-form-urlencoded"), form["headers"])
        raw = normalize_request({"method": "POST", "url": "https://h.test/", "body_mode": "raw", "body": "héllo"})
        self.assertEqual(raw["body"], "héllo".encode())
        keep = normalize_request({"url": "https://h.test/", "body_mode": "json", "body": "{}",
                                  "headers": [["content-type", "application/vnd.x+json"]]})
        self.assertEqual([h for h in keep["headers"] if h[0].lower() == "content-type"],
                         [("content-type", "application/vnd.x+json")])
        with self.assertRaises(ValueError):
            normalize_request({"url": "https://h.test/", "body_mode": "json", "body": "{nope"})

    def test_json_body_is_kept_byte_for_byte(self):
        # R2A-06: json.loads/dumps turned 10.00 into 10.0, 1E3 into 1000.0 and dropped duplicate keys
        typed = '{"amount":10.00,"big":12345678901234567890123,"e":1E3,"dup":1,"dup":2,"s":"\u0639"}'
        for spec in ({"body_mode": "json"}, {"headers": [["Content-Type", "application/json"]]}, {}):
            out = normalize_request(dict(spec, method="POST", url="https://h.test/", body=typed))
            self.assertEqual(out["body"], typed.encode(), spec)
        with self.assertRaisesRegex(ValueError, "JSON body is invalid"):
            normalize_request({"url": "https://h.test/", "body_mode": "json", "body": "{nope"})

    def test_nonempty_body_without_mode_is_never_dropped(self):
        raw = normalize_request({"method": "POST", "url": "https://h.test/", "body": "plain"})
        self.assertEqual((raw["body_mode"], raw["body"]), ("raw", b"plain"))
        js = normalize_request({"method": "POST", "url": "https://h.test/", "body": '{"x": 1}'})
        self.assertEqual((js["body_mode"], json.loads(js["body"])), ("json", {"x": 1}))
        form = normalize_request({"method": "POST", "url": "https://h.test/", "body": "a=1&b=x%20y",
                                  "headers": [["Content-Type", "application/x-www-form-urlencoded"]]})
        self.assertEqual((form["body_mode"], form["body"]), ("form", b"a=1&b=x+y"))
        with self.assertRaisesRegex(ValueError, "JSON body is invalid"):
            normalize_request({"url": "https://h.test/", "body": "not-json",
                               "headers": [["Content-Type", "application/json"]]})

    def test_header_names_and_values_are_safe_and_unicode_is_preserved(self):
        out = normalize_request({"url": "https://h.test/", "headers": [["X-Name", "Jalapeño 😃"]]})
        self.assertIn(("X-Name", "Jalapeño 😃"), out["headers"])
        for headers in ([["Bad Name", "x"]], [["X-Test", "ok\r\nInjected: yes"]], [["X-Test", "bad\x00"]]):
            with self.assertRaises(ValueError):
                normalize_request({"url": "https://h.test/", "headers": headers})

    def test_rejects(self):
        for bad in ({"url": "ftp://h.test/"}, {"url": "/relative"}, {"url": "https://h.test/", "method": "BAD METHOD"},
                    {"url": "https://h.test/", "body_mode": "xml"}, {"url": "https://h.test/", "headers": [["only-name"]]},
                    "nope"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                normalize_request(bad)


class Store(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = ComposerStore(os.path.join(self.tmp.name, "composer"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_save_load_list_rename_delete_and_modes(self):
        self.assertEqual(self.store.list(), [])
        self.store.save("login", {"method": "POST", "url": "https://h.test/"})
        path = os.path.join(self.store.directory, "login.json")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.store.directory).st_mode), 0o700)
        self.assertEqual(self.store.load("login")["method"], "POST")
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.store.save("login", {"method": "DELETE"})
        self.assertEqual(self.store.load("login")["method"], "POST")
        self.store.save("login", {"method": "PUT"}, overwrite=True)
        self.assertEqual(self.store.load("login")["method"], "PUT")
        self.store.rename("login", "login2")
        self.assertEqual(self.store.list(), ["login2"])
        self.store.save("other", {})
        with self.assertRaises(ValueError):
            self.store.rename("login2", "other")           # never overwrite another saved request
        self.store.delete("login2")
        self.assertEqual(self.store.list(), ["other"])
        self.assertEqual([x for x in os.listdir(self.store.directory) if x.startswith(".composer-")], [])

    def test_name_confinement(self):
        for bad in ("../evil", "a/b", "", "x" * 65, "vars", "..\\x", "a b", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.store.save(bad, {})
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.store.load(bad)
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "evil.json")))

    def test_variables(self):
        self.assertEqual(self.store.variables(), {})
        self.store.save_variables({"edge": "https://e.test", "token": "T"})
        self.assertEqual(self.store.variables(), {"edge": "https://e.test", "token": "T"})
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.store.directory, "vars.json")).st_mode), 0o600)
        self.assertEqual(self.store.list(), [])                  # vars.json is not a saved request
        for bad in ({"bad name": "x"}, {"a": 1}, [], {"1x": "y"}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.store.save_variables(bad)


if __name__ == "__main__":
    unittest.main()
