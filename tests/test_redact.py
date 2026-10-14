"""Unit tests for addons/proxy_redact.py: HAR exports are redacted by default (security finding F-08)."""
import json
import unittest

import _paths  # noqa: F401
import proxy_redact as R

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"


def har(entries):
    return {"log": {"version": "1.2", "entries": entries}}


def entry(url="https://api.example.test/v1/x", req_headers=(), resp_headers=(), text=None, mime="application/json",
          post=None):
    e = {"request": {"method": "GET", "url": url, "headers": [{"name": k, "value": v} for k, v in req_headers],
                     "cookies": [], "queryString": []},
         "response": {"status": 200, "headers": [{"name": k, "value": v} for k, v in resp_headers], "cookies": [],
                      "content": {"mimeType": mime, "text": text, "size": len(text or "")}}}
    if post is not None:
        e["request"]["postData"] = {"mimeType": post[0], "text": post[1]}
    return e


class Headers(unittest.TestCase):
    def test_credential_headers_are_redacted_and_others_kept(self):
        doc = R.har(har([entry(req_headers=[("Authorization", "Bearer " + JWT), ("Cookie", "s=1"), ("Accept", "*/*")],
                               resp_headers=[("Set-Cookie", "s=2; HttpOnly"), ("X-Api-Key", "k"), ("X-CSRF-Token", "c"),
                                             ("Content-Type", "application/json")])]))
        e = doc["log"]["entries"][0]
        req = {h["name"]: h["value"] for h in e["request"]["headers"]}
        resp = {h["name"]: h["value"] for h in e["response"]["headers"]}
        self.assertEqual(req, {"Authorization": R.REDACTED, "Cookie": R.REDACTED, "Accept": "*/*"})
        self.assertEqual(resp, {"Set-Cookie": R.REDACTED, "X-Api-Key": R.REDACTED, "X-CSRF-Token": R.REDACTED,
                                "Content-Type": "application/json"})

    def test_jwt_in_an_innocent_header_is_redacted(self):
        doc = R.har(har([entry(resp_headers=[("X-Debug", "user=" + JWT)])]))
        self.assertNotIn(JWT, json.dumps(doc))


class Bodies(unittest.TestCase):
    def test_secret_json_fields_nested_and_in_lists(self):
        body = json.dumps({"user": {"name": "alice", "password": "p@ss", "newPin": "1234", "otp": "9876"},
                           "access_token": JWT, "items": [{"id": 1, "refreshToken": "r"}], "pinned": True,
                           "opinion": "fine", "tokenType": "Bearer", "count": 3})
        out = json.loads(R.har(har([entry(text=body)]))["log"]["entries"][0]["response"]["content"]["text"])
        self.assertEqual(out["user"], {"name": "alice", "password": R.REDACTED, "newPin": R.REDACTED, "otp": R.REDACTED})
        self.assertEqual(out["access_token"], R.REDACTED)
        self.assertEqual(out["items"], [{"id": 1, "refreshToken": R.REDACTED}])
        # look-alike names are not secrets: the structure a tester needs survives
        self.assertEqual((out["pinned"], out["opinion"], out["count"]), (True, "fine", 3))

    def test_jwt_anywhere_in_a_non_json_body(self):
        out = R.text("<html>token " + JWT + " end</html>", "text/html")
        self.assertNotIn(JWT, out)
        self.assertIn(R.REDACTED, out)

    def test_form_body_by_field_name(self):
        doc = R.har(har([entry(post=("application/x-www-form-urlencoded", "username=a&password=b&otp=1"),
                               text="token=%s&x=1" % JWT, mime="application/x-www-form-urlencoded")]))
        e = doc["log"]["entries"][0]
        self.assertNotIn("password=b", e["request"]["postData"]["text"])
        self.assertIn("username=a", e["request"]["postData"]["text"])
        self.assertNotIn(JWT, e["response"]["content"]["text"])
        self.assertIn("x=1", e["response"]["content"]["text"])

    def test_base64_bodies_are_left_alone(self):
        e = entry(text="AAEC", mime="application/octet-stream")
        e["response"]["content"]["encoding"] = "base64"
        self.assertEqual(R.har(har([e]))["log"]["entries"][0]["response"]["content"]["text"], "AAEC")


class Urls(unittest.TestCase):
    def test_secret_query_params_and_userinfo(self):
        u = R.url("https://bob:hunter2@api.example.test/v1/x?access_token=abc&page=2&code=" + JWT)
        self.assertNotIn("hunter2", u)
        self.assertNotIn("abc", u)
        self.assertNotIn(JWT, u)
        self.assertIn("page=2", u)


class Contract(unittest.TestCase):
    def test_input_is_not_modified_and_doc_is_marked(self):
        src = har([entry(req_headers=[("Authorization", "x")])])
        before = json.dumps(src, sort_keys=True)
        out = R.har(src)
        self.assertEqual(json.dumps(src, sort_keys=True), before)
        self.assertIn("redacted", out["log"]["comment"])


if __name__ == "__main__":
    unittest.main()
