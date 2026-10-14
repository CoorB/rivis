"""Unit tests for addons/proxy_codegen.py (stdlib only). Run: /usr/bin/python3 -m unittest discover -s tests"""
import ast
import base64
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest

import _paths  # noqa: F401
from proxy_codegen import TARGETS, generate

IDS = [t[0] for t in TARGETS]
BEARER = "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1In0.sig"
PSEUDO = [(":authority", "api.example.test"), (":method", "GET"), ("Connection", "keep-alive"), ("Content-Length", "99")]


def req(method="GET", url="https://api.example.test/v1/items?x=1&y=a%20b", headers=None, body=b""):
    return {"method": method, "url": url, "headers": list(headers or []), "body": body}


class Tools(unittest.TestCase):
    def run_tool(self, args, text, suffix):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "snippet" + suffix)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            return subprocess.run(args + [path], capture_output=True, text=True, timeout=60)


class TargetsList(unittest.TestCase):
    def test_all_brief_targets_exist(self):
        self.assertEqual(set(IDS), {"curl", "httpie", "wget", "python", "fetch", "axios", "swift", "kotlin",
                                    "java", "go", "powershell", "postman"})

    def test_unknown_target(self):
        with self.assertRaises(ValueError):
            generate(req(), "cobol")


class GetWithQuery(unittest.TestCase):
    headers = [("Accept", "application/json"), ("Authorization", BEARER)] + PSEUDO

    def test_every_target(self):
        for target in IDS:
            out = generate(req(headers=self.headers), target)
            self.assertIn("api.example.test/v1/items?x=1&y=a%20b", out, target)
            self.assertNotIn(":authority", out, target)
            self.assertNotIn(":method", out, target)
            self.assertNotIn("keep-alive", out, target)
            self.assertNotIn("99", out.replace("api.example", ""), target)   # content-length value dropped
            self.assertNotIn("eyJhbGci", out, target)                        # masked by default
            self.assertIn("<redacted>", out, target)
            self.assertIn("application/json", out, target)

    def test_curl_shape(self):
        out = generate(req(headers=self.headers), "curl")
        argv = shlex.split(out.replace("\\\n", " "))
        self.assertEqual(argv[:3], ["curl", "-X", "GET"])
        self.assertIn("Accept: application/json", argv)
        self.assertEqual(argv[-1], "https://api.example.test/v1/items?x=1&y=a%20b")

    def test_mask_off_keeps_token(self):
        for target in IDS:
            out = generate(req(headers=self.headers), target, mask_secrets=False)
            self.assertIn("eyJhbGciOiJub25lIn0", out, target)
            self.assertNotIn("<redacted>", out, target)


class PostJson(Tools):
    body = json.dumps({"a": [1, 2.5], "s": 'quote " and \'single\' $x `tick`\nnew\\line é ☃', "n": None, "t": True},
                      ensure_ascii=False).encode()
    headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]

    def test_python_native_literal(self):
        out = generate(req("POST", headers=self.headers, body=self.body), "python")
        tree = ast.parse(out)
        json_kw = next(k for n in ast.walk(tree) if isinstance(n, ast.Call) for k in n.keywords if k.arg == "json")
        self.assertEqual(ast.literal_eval(json_kw.value), json.loads(self.body))
        self.assertNotIn("content-length", out.lower())

    def test_js_native_literals(self):
        fetch = generate(req("POST", headers=self.headers, body=self.body), "fetch")
        axios = generate(req("POST", headers=self.headers, body=self.body), "axios")
        self.assertIn("JSON.stringify({", fetch)
        self.assertIn("data: {", axios)
        if shutil.which("node"):
            for name, text in (("fetch", fetch), ("axios", axios)):
                result = self.run_tool(["node", "--check"], text, ".mjs")
                self.assertEqual(result.returncode, 0, name + result.stderr)

    def test_strings_escape(self):
        for target in ("swift", "kotlin", "java", "go"):
            out = generate(req("POST", headers=self.headers, body=self.body), target)
            self.assertIn('\\"', out, target)
            self.assertIn("\\n", out, target)
            self.assertNotIn("quote \" and", out, target)
        kotlin = generate(req("POST", headers=self.headers, body=self.body), "kotlin")
        self.assertIn("\\$x", kotlin)            # Kotlin would otherwise interpolate $x

    def test_postman_collection(self):
        doc = json.loads(generate(req("POST", headers=self.headers, body=self.body), "postman"))
        self.assertIn("v2.1.0", doc["info"]["schema"])
        item = doc["item"][0]["request"]
        self.assertEqual(item["method"], "POST")
        self.assertEqual(json.loads(item["body"]["raw"]), json.loads(self.body))
        self.assertTrue(all(h["key"].lower() != "content-length" for h in item["header"]))

    def test_curl_roundtrip(self):
        out = generate(req("POST", headers=self.headers, body=self.body), "curl")
        argv = shlex.split(out.replace("\\\n", " "))
        self.assertEqual(argv[argv.index("--data-binary") + 1].encode(), self.body)

    def test_powershell_and_swift_quotes(self):
        out = generate(req("POST", headers=[("X-Q", "it's ‘curly’ ’")], body=b"x"), "powershell")
        self.assertIn("'it''s ‘‘curly’’ ’’'", out)
        swift = generate(req("POST", headers=[("X-U", "a\u0001b")], body=b"x"), "swift")
        self.assertIn("\\u{0001}", swift)
        self.assertNotIn("\\u0001", swift)

    def test_swift_go_syntax_when_toolchain_present(self):
        text = generate(req("POST", headers=self.headers, body=self.body), "go")
        if shutil.which("gofmt"):
            self.assertEqual(self.run_tool(["gofmt", "-e"], text, ".go").returncode, 0)
        if shutil.which("swiftc"):
            swift = generate(req("POST", headers=self.headers, body=self.body), "swift")
            self.assertEqual(self.run_tool(["swiftc", "-parse"], swift, ".swift").returncode, 0)


class FormData(unittest.TestCase):
    def test_form_body(self):
        headers = [("Content-Type", "application/x-www-form-urlencoded")]
        body = b"user=a%40b.test&pw=p%26w"
        self.assertIn("--data-binary 'user=a%40b.test&pw=p%26w'", generate(req("POST", headers=headers, body=body), "curl"))
        self.assertIn("data=%r" % body.decode(), generate(req("POST", headers=headers, body=body), "python"))
        self.assertIn("user=a%40b.test&pw=p%26w", generate(req("POST", headers=headers, body=body), "wget"))

    def test_httpie_raw_body_exact(self):
        out = generate(req("POST", body=b'{"a": 1}'), "httpie")
        argv = shlex.split(out.replace("\\\n", " "))
        self.assertEqual(argv[argv.index("--raw") + 1], '{"a": 1}')
        self.assertNotIn("<<<", out)
        self.assertIn("--ignore-stdin", generate(req(), "httpie"))

    def test_go_imports_only_what_it_uses(self):
        self.assertNotIn('"strings"', generate(req(), "go"))
        self.assertIn('"strings"', generate(req("POST", body=b"x"), "go"))


class MultiValueHeaders(unittest.TestCase):
    headers = [("Accept", "a/1"), ("Accept", "b/2"), ("X-Multi", "1"), ("x-multi", "2"),
               ("Cookie", "sid=abc"), ("Cookie", "theme=dark")]

    def test_joined(self):
        py = generate(req(headers=self.headers), "python", mask_secrets=False)
        self.assertIn("'Accept': 'a/1, b/2'", py)
        self.assertIn("'X-Multi': '1, 2'", py)
        self.assertIn("'Cookie': 'sid=abc; theme=dark'", py)

    def test_cookie_masked(self):
        for target in IDS:
            out = generate(req(headers=self.headers), target)
            self.assertNotIn("sid=abc", out, target)
            self.assertNotIn("theme=dark", out, target)


class BinaryBody(Tools):
    raw = b"\x00\xff\xfe\x80binary"

    def test_base64_everywhere(self):
        encoded = base64.b64encode(self.raw).decode()
        for target in IDS:
            out = generate(req("PUT", headers=[("Content-Type", "application/octet-stream")], body=self.raw), target)
            self.assertIn(encoded, out, target)
            self.assertIn("binary", out.lower(), target)

    def test_curl_pipes_decoded_bytes(self):
        out = generate(req("PUT", body=self.raw), "curl")
        self.assertIn("base64 -d |", out)
        self.assertIn("--data-binary @-", out)
        if shutil.which("bash"):
            stub = out.replace("curl ", "cat >/dev/null; echo ", 1)
            self.assertEqual(subprocess.run(["bash", "-c", stub], capture_output=True, timeout=20).returncode, 0)


class QuotesAndUnicode(unittest.TestCase):
    value = 'say "hi" it\'s $HOME `x`\nline2 é ☃ 日本'

    def test_curl_header_roundtrip(self):
        out = generate(req(headers=[("X-Weird", self.value)]), "curl")
        argv = shlex.split(out.replace("\\\n", " "))
        self.assertIn("X-Weird: " + self.value, argv)

    def test_wget_httpie_roundtrip(self):
        wget = shlex.split(generate(req(headers=[("X-Weird", self.value)]), "wget").replace("\\\n", " "))
        self.assertIn("--header=X-Weird: " + self.value, wget)
        httpie = shlex.split(generate(req(headers=[("X-Weird", self.value)]), "httpie").replace("\\\n", " "))
        self.assertIn("X-Weird:" + self.value, httpie)

    def test_python_roundtrip(self):
        out = generate(req(headers=[("X-Weird", self.value)]), "python")
        tree = ast.parse(out)
        headers = next(k.value for n in ast.walk(tree) if isinstance(n, ast.Call) for k in n.keywords if k.arg == "headers")
        self.assertEqual(ast.literal_eval(headers), {"X-Weird": self.value})

    def test_json_style_targets_roundtrip(self):
        for target in ("java", "go"):
            out = generate(req(headers=[("X-Weird", self.value)]), target)
            line = next(x for x in out.splitlines() if "X-Weird" in x)
            literal = line[line.index('"X-Weird"') + len('"X-Weird", '):]
            literal = literal[:literal.rindex('"') + 1]
            self.assertEqual(json.loads(literal), self.value, target)


if __name__ == "__main__":
    unittest.main()
