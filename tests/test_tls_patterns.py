"""Wildcard -> regex tests for the TLS allow/ignore lists (proxy_common)."""
import re
import unittest

import _paths  # noqa: F401
from proxy_common import tls_config, tls_covering, tls_host_regex, tls_options, tls_update


def hit(pattern, candidate):
    """How mitmproxy applies the option: re.search, case-insensitive, on a 'host:port' string."""
    return re.search(tls_host_regex(pattern), candidate, re.IGNORECASE) is not None


class Wildcards(unittest.TestCase):
    def test_star_subdomains(self):
        self.assertTrue(hit("*.neo.sa", "backbase-edge-uat.neo.sa:443"))
        self.assertTrue(hit("*.neo.sa", "a.b.neo.sa:8443"))
        self.assertTrue(hit("*.neo.sa", "A.NEO.SA:443"))
        self.assertFalse(hit("*.neo.sa", "neo.sa:443"))                 # bare domain is its own pattern
        self.assertFalse(hit("*.neo.sa", "evil.neo.sa.attacker.test:443"))
        self.assertFalse(hit("*.neo.sa", "xneo.sa:443"))
        self.assertFalse(hit("*.neo.sa", "backbase.neoxsa:443"))        # dots are literal

    def test_exact_host_any_port(self):
        self.assertTrue(hit("api.example.test", "api.example.test:443"))
        self.assertTrue(hit("api.example.test", "api.example.test"))
        self.assertFalse(hit("api.example.test", "xapi.example.test:443"))
        self.assertFalse(hit("api.example.test", "api.example.test.evil:443"))

    def test_explicit_port(self):
        self.assertTrue(hit("api.example.test:8443", "api.example.test:8443"))
        self.assertFalse(hit("api.example.test:8443", "api.example.test:443"))
        self.assertFalse(hit("api.example.test:8443", "api.example.test:84431"))

    def test_question_mark_and_regex_metacharacters(self):
        self.assertTrue(hit("a?.test", "ab.test:443"))
        self.assertFalse(hit("a?.test", "abc.test:443"))
        self.assertFalse(hit("a+b.test", "aab.test:443"))               # '+' is literal
        self.assertTrue(hit("a-b.test", "a-b.test:443"))
        self.assertTrue(hit("*", "anything.test:443"))

    def test_trailing_dot_and_case_normalised(self):
        self.assertEqual(tls_host_regex("API.Example.test."), tls_host_regex("api.example.test"))

    def test_anchored(self):
        regex = tls_host_regex("*.neo.sa")
        self.assertTrue(regex.startswith("^") and regex.endswith("$"))

    def test_invalid(self):
        for bad in ("", "  ", "a/b", "https://x.test", "a b.test", ".x.test", "h:0", "h:70000", ".", "..", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                tls_host_regex(bad)


class Config(unittest.TestCase):
    def test_default_is_all(self):
        self.assertEqual(tls_config({}), {"mode": "all", "allow": [], "ignore": []})
        self.assertEqual(tls_options({}), ([], []))

    def test_modes_map_to_mitmproxy_options(self):
        cfg = {"tls": {"mode": "allow", "allow": ["*.neo.sa", "*.alahli.com"], "ignore": ["x.test"]}}
        self.assertEqual(tls_options(cfg), ([tls_host_regex("*.neo.sa"), tls_host_regex("*.alahli.com")], []))
        cfg["tls"]["mode"] = "ignore"
        self.assertEqual(tls_options(cfg), ([], [tls_host_regex("x.test")]))
        cfg["tls"]["mode"] = "all"
        self.assertEqual(tls_options(cfg), ([], []))      # lists are kept but not applied

    def test_empty_allow_list_decrypts_nothing(self):
        allow, ignore = tls_options({"tls": {"mode": "allow", "allow": []}})
        self.assertTrue(allow)                       # mitmproxy ignores nothing when both lists are empty
        self.assertEqual(ignore, [])
        for host in ("a.neo.sa:443", "", "x", "10.0.0.1:443"):
            self.assertFalse(any(re.search(p, host, re.IGNORECASE) for p in allow), host)

    def test_validation(self):
        for bad in ({"tls": []}, {"tls": {"mode": "some"}}, {"tls": {"allow": "x"}}, {"tls": {"allow": [1]}},
                    {"tls": {"ignore": ["a/b"]}}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                tls_config(bad)

    def test_dedupe_and_lowercase(self):
        out = tls_config({"tls": {"allow": ["A.test", "a.test", " a.test "]}})
        self.assertEqual(out["allow"], ["a.test"])

    def test_update(self):
        cfg = {}
        tls_update(cfg, mode="ignore", add=[("ignore", "Foo.test"), ("ignore", "foo.test"), ("allow", "*.neo.sa")])
        self.assertEqual(cfg["tls"], {"mode": "ignore", "allow": ["*.neo.sa"], "ignore": ["foo.test"]})
        tls_update(cfg, remove=[("ignore", "FOO.test")])
        self.assertEqual(cfg["tls"]["ignore"], [])
        with self.assertRaises(ValueError):
            tls_update(cfg, mode="nope")
        with self.assertRaises(ValueError):
            tls_update(cfg, add=[("block", "x.test")])
        with self.assertRaises(ValueError):
            tls_update(cfg, add=[("allow", "bad/host")])

    def test_covering(self):
        tls = tls_config({"tls": {"ignore": ["*.neo.sa", "other.test"]}})
        self.assertEqual(tls_covering(tls, "x.neo.sa", "ignore"), ["*.neo.sa"])
        self.assertEqual(tls_covering(tls, "neo.sa", "ignore"), [])


if __name__ == "__main__":
    unittest.main()
