"""Final skeptical review of 0.9.11 (engine/data lane): secrets with generic names, bodies kept byte-for-byte,
the project's private keys never served by a rule, and the descriptor limit raised at start."""
import json
import os
import resource
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _paths  # noqa: F401
import harness
import proxy_common
import proxy_redact as R
import test_cli
import test_scripts


class SecretsWithGenericNames(unittest.TestCase):
    def test_cloud_key_headers_are_masked(self):
        for name in ("Ocp-Apim-Subscription-Key", "x-functions-key", "X-Goog-Api-Key", "X-Vendor-Key", "x-amz-signature"):
            self.assertTrue(R.secret_header(name), name)
        self.assertFalse(R.secret_header("Content-Type"))

    def test_generic_key_and_signature_fields_are_masked_everywhere(self):
        for k in ("key", "accessKey", "access_key", "sig", "signature", "auth", "subscriptionKey", "secretKey"):
            self.assertTrue(R.secret_key(k), k)
        for k in ("monkey", "hockey", "keyboard", "author", "design", "name", "id"):
            self.assertFalse(R.secret_key(k), k)
        masked = R.url("https://x.example.test/p?key=AIzaSyDUMMY&sig=abc123&page=2")
        self.assertNotIn("AIzaSyDUMMY", masked)
        self.assertNotIn("abc123", masked)
        self.assertIn("page=2", masked)
        body = R.text(json.dumps({"key": "K-123456", "keep": "yes"}), "application/json")
        self.assertNotIn("K-123456", body)
        self.assertIn("yes", body)


class BodiesAreNotRewrittenNeedlessly(unittest.TestCase):
    def test_a_json_body_with_nothing_secret_is_kept_exactly(self):
        body = '{"amount": 1.10,  "big": 1e3, "neg": -0.0, "t": "caf\\u00e9"}'
        self.assertEqual(R.text(body, "application/json"), body)

    def test_json_nested_in_a_string_is_kept_when_nothing_is_secret(self):
        body = json.dumps({"payload": '{"amount": 1.10}'})
        self.assertEqual(R.text(body, "application/json"), body)

    def test_a_secret_is_still_masked(self):
        out = R.text('{"amount": 1.10, "password": "hunter2"}', "application/json")
        self.assertNotIn("hunter2", out)
        self.assertIn("1.1", out)


class RuleFilesInsideTheProject(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = os.path.realpath(self.tmp.name)

    def write(self, rel, text="x"):
        path = os.path.join(self.state, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)
        return path

    def test_an_ordinary_project_file_is_served(self):
        path = self.write("mocks/ok.json", "{}")
        self.assertEqual(proxy_common.rule_file_path(self.state, path, "file"), path)

    def test_client_cert_keys_and_login_secrets_are_refused_even_inside_the_project(self):
        for rel in ("client-certs/mtls.example.test.pem", "client-certs/anything.txt", "mocks/server.key",
                    "web-token-8083", "trusted-files.json"):
            path = self.write(rel)
            with self.assertRaises(ValueError, msg=rel):
                proxy_common.rule_file_path(self.state, path, "file")


class ScriptsLeaveUntouchedBodiesAlone(test_scripts.ScriptCase):
    def test_a_header_only_script_does_not_corrupt_a_non_utf8_json_body(self):
        self.install("hdr.py", '''
def on_response(context, url, request, response):
    response["headers"]["X-Seen"] = "1"
    return response
''', match="/json/latin1")
        r = self.fetch("/json/latin1")
        self.assertEqual(r.header("x-seen"), "1")
        self.assertEqual(r.body, b'{"name": "caf\xe9", "n": 1.10}')


class DescriptorLimit(test_cli.CliBase):
    def test_start_raises_a_low_soft_limit(self):
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        low = 256
        resource.setrlimit(resource.RLIMIT_NOFILE, (low, hard))
        try:
            open(os.path.join(self.suite.shimlog, "mitm-argv.log"), "w").close()
            env = dict(self.env, SHIM_DRYRUN="1")
            self.suite.rivis("start", "--no-open", "--no-ios", home=self.home, env=env)
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
        seen = [l for l in self.suite.shim_log("mitm-argv.log").splitlines() if l.startswith("fdlimit ")]
        self.assertTrue(seen, "mitmweb shim did not run")
        self.assertGreaterEqual(int(seen[-1].split()[1]), 10240)


if __name__ == "__main__":
    unittest.main()
