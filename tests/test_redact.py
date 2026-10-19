"""Unit tests for addons/proxy_redact.py: HAR exports are redacted by default (security finding F-08)."""
import base64
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
    def test_fido_login_proofs_are_masked_in_har(self):
        proofs = ("uafResponse", "assertion", "signature", "clientDataJSON", "authenticatorData")
        body = json.dumps({"login": {key: "PROOF-" + key for key in proofs}, "challengeId": "kept"})
        e = R.har(har([entry(post=("application/json", body), text=body)]))["log"]["entries"][0]
        for part in (e["request"]["postData"]["text"], e["response"]["content"]["text"]):
            login = json.loads(part)["login"]
            for key in proofs:
                self.assertEqual(login[key], R.REDACTED, key)
            self.assertEqual(json.loads(part)["challengeId"], "kept")

    def test_short_secret_keys_in_har_request_and_echoed_response(self):
        # R1A-02: pw leaked twice when an endpoint echoed the request body into its response.
        keys = ("pw", "pwd", "pass", "password", "passcode", "pin", "otp", "secret", "token",
                "user_pw", "newPin", "otpCode", "accessToken")
        safe = {"pwned": "safe-pwned", "upward": "safe-upward", "pinned": "safe-pinned",
                "opinion": "safe-opinion", "tokenism": "safe-tokenism"}
        body = json.dumps({**{k: "LEAK-" + k for k in keys}, **safe})
        doc = R.har(har([entry(post=("application/json", body), text=body)]))["log"]["entries"][0]
        for out in (doc["request"]["postData"]["text"], doc["response"]["content"]["text"]):
            obj = json.loads(out)
            for key in keys: self.assertEqual(obj[key], R.REDACTED, key)
            for key, value in safe.items(): self.assertEqual(obj[key], value, key)
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


class JsonInsideStrings(unittest.TestCase):
    def test_json_echoed_as_a_string_inside_json_is_redacted_by_field_name(self):
        """Manual QA RIV-MAN-003: an API echoing the request body as a JSON string leaked password/otp/token."""
        inner = json.dumps({"password": "PW-LEAK", "otp": "654321", "token": "TOK-LEAK", "user": "qa"})
        out = R.text(json.dumps({"method": "POST", "body": inner}), "application/json")
        for leak in ("PW-LEAK", "654321", "TOK-LEAK"):
            self.assertNotIn(leak, out)
        self.assertIn("qa", out)                       # non-secret fields survive

    def test_plain_strings_that_only_look_like_json_are_left_alone(self):
        out = R.text(json.dumps({"note": "[draft] {not json"}), "application/json")
        self.assertIn("[draft] {not json", out)


class DeepJson(unittest.TestCase):
    def test_json_nested_past_the_recursion_limit_is_redacted_as_text(self):
        body = "[" * 5000 + '"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"' + "]" * 5000
        out = R.text(body, "application/json")
        self.assertNotIn("eyJzdWIiOiJ4In0", out)
        self.assertIn("<redacted>", out)


class PilotReview(unittest.TestCase):
    """Review of the overnight redaction change (2026-10-15): no quadratic patterns, and JSON error codes stay readable."""

    def test_large_bodies_redact_in_linear_time(self):
        import time
        html = ("<div><p>hello</p><input name='q' value='x'>" * 20000) + "<span>unterminated " * 5000
        for body, mime in ((html, "text/html"), ("<a>" * 30000 + "text", "text/xml"),
                           ('--B\r\nContent-Disposition: form-data; name="f"\r\n\r\n' + "x\n" * 300000, "multipart/form-data")):
            t = time.monotonic()
            R.text(body, mime)
            self.assertLess(time.monotonic() - t, 3.0, mime)          # was 278 s for the 1 MB page

    def test_json_code_field_kept_but_oauth_code_masked(self):
        self.assertIn('"code": "ACC-710"', R.text(json.dumps({"code": "ACC-710", "authCode": "9"}), "application/json"))
        self.assertNotIn("SECRET", R.url("https://a.test/cb?code=SECRET&state=ok"))
        self.assertNotIn("SECRET", R.text("GET /cb?code=SECRET HTTP/1.1", "text/plain"))
        self.assertIn("<password><redacted></password>", R.text("<r><password>x</password></r>", "text/xml"))


class RoundThreeAuditShapes(unittest.TestCase):
    def test_secret_containers_variants_redirects_and_encoded_bodies(self):
        markers = {
            "object": "LEAK-object", "list": "LEAK-list", "pair": "LEAK-pair", "named": "LEAK-named",
            "pin": "LEAK-pin", "otp": "LEAK-otp", "password": "LEAK-password", "cvv": "LEAK-cvv",
            "auth": "LEAK-auth", "verifier": "LEAK-verifier", "header": "LEAK-header",
            "location": "LEAK-location", "form": "LEAK-form", "xml": "LEAK-xml", "bearer": "LEAK-bearer",
            "encoded_token": "LEAK-encoded-token", "encoded_password": "LEAK-encoded-password",
            "multipart": "LEAK-multipart", "html": "LEAK-html", "jsonp": "LEAK-jsonp", "plain": "LEAK-plain",
        }
        body = json.dumps({
            "token": {"value": markers["object"]}, "otpList": [markers["list"]],
            "headers": [["Authorization", markers["pair"]], {"name": "password", "value": markers["named"]}],
            "pinCode": markers["pin"], "otpCode": markers["otp"], "passwordConfirm": markers["password"],
            "cvv2": markers["cvv"], "authCode": markers["auth"], "code_verifier": markers["verifier"],
            "echoed_form": "grant_type=password&password=%s&safe=kept" % markers["form"],
        })
        latin1 = ('{"token":"%s","password":"%s","name":"René"}' %
                  (markers["encoded_token"], markers["encoded_password"])).encode("latin-1")
        encoded = base64.b64encode(latin1).decode()
        entries = [
            entry(text=body, resp_headers=[("X-OTP", markers["header"]),
                                           ("Location", "https://app.test/cb?code=" + markers["location"])]),
            entry(text="<password>%s</password> Bearer %s" % (markers["xml"], markers["bearer"]), mime="text/xml"),
            entry(text='--x\r\nContent-Disposition: form-data; name="password"\r\n\r\n%s\r\n--x--\r\n' %
                       markers["multipart"], mime="multipart/form-data; boundary=x"),
            entry(text='<input type="hidden" name="csrf_token" value="%s">' % markers["html"], mime="text/html"),
            entry(text='cb({"access_token":"%s","safe":"kept"})' % markers["jsonp"], mime="application/javascript"),
            entry(text="password=%s safe=kept" % markers["plain"], mime="text/plain"),
            entry(text=encoded, mime="application/json; charset=ISO-8859-1"),
        ]
        entries[-1]["response"]["content"]["encoding"] = "base64"
        dumped = json.dumps(R.har(har(entries)))
        for name, marker in markers.items():
            self.assertNotIn(marker, dumped, name)
        self.assertIn("safe=kept", dumped)

        raw = ("POST /login?code=LEAK-raw-code HTTP/1.1\r\nX-Pin: LEAK-raw-header\r\n"
               "Content-Type: application/x-www-form-urlencoded\r\n\r\npassword=LEAK-raw-body&safe=kept")
        masked_raw = R.raw_text(raw)
        for marker in ("LEAK-raw-code", "LEAK-raw-header", "LEAK-raw-body"):
            self.assertNotIn(marker, masked_raw)


if __name__ == "__main__":
    unittest.main()
