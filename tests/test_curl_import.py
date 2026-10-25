"""Copied cURL commands are parsed offline and never sent."""
import base64
import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "addons"))
from curl_import import parse_curl


class CurlImport(unittest.TestCase):
    def test_curl_import_quoting_continuations_headers_and_body(self):
        r = parse_curl("curl 'https://example.test/a?q=1' " + "\\\n" +
                       "-H 'X-Note: two words' --header 'Content-Type: application/json' " + "\\\n" +
                       "--data-raw '{\"a\": 1}' --compressed")
        self.assertEqual(r["spec"]["method"], "POST")
        self.assertEqual(r["spec"]["url"], "https://example.test/a?q=1")
        self.assertEqual(r["spec"]["headers"], [["X-Note", "two words", True], ["Content-Type", "application/json", True]])
        self.assertEqual(r["spec"]["body"], '{"a": 1}')
        self.assertEqual(r["ignored"], [])

    def test_curl_import_methods_data_variants_and_get_query(self):
        for flag in ("-d", "--data", "--data-raw", "--data-binary"):
            self.assertEqual(parse_curl("curl -X PUT %s 'a=1' https://example.test" % flag)["spec"]["method"], "PUT")
        r = parse_curl("curl -G --data-urlencode 'a=two words' -d 'b=3' https://example.test/x?q=0")
        self.assertEqual(r["spec"]["method"], "GET")
        self.assertEqual(r["spec"]["url"], "https://example.test/x?q=0&a=two%20words&b=3")
        self.assertEqual(r["spec"]["body"], "")
        self.assertEqual(parse_curl("curl -G -X PATCH -d x=1 https://example.test")["spec"]["method"], "PATCH")

    def test_curl_import_auth_cookies_ignored_and_errors(self):
        r = parse_curl("curl -u 'a:b' -b 'session=1' -k --insecure --mystery https://example.test")
        self.assertIn(["Authorization", "Basic " + base64.b64encode(b"a:b").decode(), True], r["spec"]["headers"])
        self.assertIn(["Cookie", "session=1", True], r["spec"]["headers"])
        self.assertIn("--mystery", r["ignored"])
        self.assertTrue(any("TLS verification" in x for x in r["ignored"]))
        for command in ("", "wget https://example.test", "curl -H broken https://example.test", "curl 'unterminated",
                        "curl http://", "curl https://"):
            with self.assertRaises(ValueError):
                parse_curl(command)

    def test_chrome_copy_as_curl_ansi_c_strings(self):
        # Chrome DevTools writes bodies as bash $'...' strings; shlex alone said "No closing quotation"
        cmd = ("curl 'https://api.example.com/v1/login' \\\n  -H 'content-type: application/json' \\\n"
               "  --data-raw $'{\"name\":\"O\\'Brien\",\"note\":\"a\\\\nb\",\"e\":\"\\u00e9\"}' \\\n  --compressed")
        spec = parse_curl(cmd)["spec"]
        self.assertEqual(spec["method"], "POST")
        self.assertEqual(json.loads(spec["body"]), {"name": "O'Brien", "note": "a\nb", "e": "\u00e9"})
        self.assertEqual(parse_curl("curl -d $'a\\tb' https://x.example")["spec"]["body"], "a\tb")
        with self.assertRaises(ValueError):
            parse_curl("curl -d $'unterminated https://x.example")

    @staticmethod
    def chrome_cmd(s):
        """Chrome/Edge DevTools' escapeStringWindows, ported as is: what "Copy as cURL (cmd)" writes for each argument."""
        import re as _re
        s = s.replace("\\", "\\\\").replace('"', '\\"')
        s = _re.sub(r"[^a-zA-Z0-9\s_\-:=+~'/.',?;()*`&]", lambda m: "^" + m.group(0), s)
        s = _re.sub(r"%(?=[a-zA-Z0-9_])", "%^", s)
        s = _re.sub(r"\r?\n", "^\n\n", s)
        return '^"' + s + '^"'

    def test_windows_copy_as_curl_cmd(self):
        q = self.chrome_cmd
        body = '{"name":"O\'Brien","path":"C:\\temp","pct":"100%","note":"a^b & c|d <e>","multi":"line1\nline2","id":"%USERNAME%"}'
        url = "https://api.example.test/v1/items?ids=[1,2]&q=caf%C3%A9"
        cmd = " ^\n  ".join(["curl " + q(url).replace("[", "\\[").replace("]", "\\]"),
                              "-H " + q("accept: application/json"), "-H " + q('x-quoted: say "hi"'),
                              "-H " + q("authorization: Bearer a.b-c_d"), "--data-raw " + q(body), "--compressed"])
        r = parse_curl(cmd)
        self.assertEqual(r["spec"]["method"], "POST")
        self.assertEqual(r["spec"]["url"], url)
        self.assertEqual(r["spec"]["headers"], [["accept", "application/json", True], ["x-quoted", 'say "hi"', True],
                                                ["authorization", "Bearer a.b-c_d", True]])
        self.assertEqual(r["spec"]["body"], body)
        self.assertIn("line1\nline2", r["spec"]["body"])                 # a newline inside a value survives
        self.assertEqual(r["ignored"], [])

    def test_windows_cmd_plain_double_quotes_and_curl_exe(self):
        r = parse_curl('curl.exe "https://example.test/a b" -X PUT -H "X-A: 1" -d "{\\"k\\": \\"v\\"}"')
        self.assertEqual(r["spec"]["method"], "PUT")
        self.assertEqual(r["spec"]["url"], "https://example.test/a b")
        self.assertEqual(r["spec"]["body"], '{"k": "v"}')

    def test_bash_copy_keeps_working_and_unescapes_url_globs(self):
        r = parse_curl("curl 'https://example.test/x?ids=\\[1,2\\]&o=\\{a\\}' -H 'a: b'")
        self.assertEqual(r["spec"]["url"], "https://example.test/x?ids=[1,2]&o={a}")

    def test_curl_import_cli_stdin_prints_json(self):
        cli = os.path.join(os.path.dirname(__file__), "..", "addons", "compose_cli.py")
        got = subprocess.run([sys.executable, cli, "from-curl", "-"], input="curl -X DELETE https://example.test/x",
                             text=True, capture_output=True, check=True)
        self.assertEqual(json.loads(got.stdout)["spec"]["method"], "DELETE")


if __name__ == "__main__":
    unittest.main()
