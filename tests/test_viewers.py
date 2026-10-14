"""Viewers: JWT discovery (header / cookie / Set-Cookie / body / query), exp handling, hostile depth, GraphQL detection,
gRPC summaries. Pure-function tests plus the same flows live through the panel's `viewer` op."""
import base64
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _paths  # noqa: F401
import harness
from harness import LiveCase, wait_for
from proxy_scripts import decode_grpc_frames, decode_jwt, decode_protobuf, detect_graphql, find_jwts
from upstream import GRPC_BODY, JWT_EXPIRED, JWT_FRESH, make_jwt

now = time.time()


class Jwt(unittest.TestCase):
    def test_decode_exp_relative_and_flags(self):
        fresh = decode_jwt(make_jwt({"sub": "a", "exp": now + 3600, "iat": now - 60, "nbf": now - 60}), now)
        self.assertFalse(fresh["times"]["exp"]["expired"])
        self.assertIn("expires in", fresh["times"]["exp"]["relative"])
        self.assertEqual(set(fresh["times"]), {"exp", "iat", "nbf"})
        old = decode_jwt(make_jwt({"exp": now - 7200}), now)
        self.assertTrue(old["times"]["exp"]["expired"])
        self.assertIn("expired 120 min ago", old["times"]["exp"]["relative"])
        self.assertEqual(old["signature"], "not verified")
        self.assertEqual((old["alg"], old["kid"]), ("HS256", None))

    def test_odd_exp_values_do_not_crash(self):
        for exp in ("soon", None, [1], 1e30, -1e30, True, {"x": 1}):
            d = decode_jwt(make_jwt({"sub": "x", "exp": exp}), now)
            self.assertEqual(d["payload"]["sub"], "x")
        self.assertNotIn("exp", decode_jwt(make_jwt({"sub": "x"}), now)["times"])

    def test_not_a_jwt(self):
        for bad in ("a.b", "a.b.c.d", "e30.e30", "!!!.@@@.###", make_jwt()[:-5] + ".x.y",
                    base64.urlsafe_b64encode(b"[1]").decode().strip("=") + ".e30.sig"):
            with self.assertRaises(ValueError, msg=bad):
                decode_jwt(bad)

    def test_found_in_every_location(self):
        a, b, c, d, e = (make_jwt({"sub": s}) for s in "abcde")
        found = find_jwts(headers=[("Authorization", "Bearer " + a), ("Cookie", "x=1; session=" + b), ("Set-Cookie", "t=" + c + "; Path=/"),
                                   ("X-Other", d)],
                          body=json.dumps({"deep": {"list": [{"tok": e}]}}), content_type="application/json",
                          url="https://h.test/p?access_token=" + make_jwt({"sub": "q"}))
        where = {f["payload"]["sub"]: f["where"] for f in found}
        self.assertEqual(where["a"], "header:authorization")
        self.assertEqual(where["b"], "header:cookie")
        self.assertEqual(where["c"], "header:set-cookie")
        self.assertNotIn("d", where)                                      # arbitrary headers are not scanned
        self.assertEqual(where["e"], "body.deep.list[0].tok")
        self.assertEqual(where["q"], "query.access_token")

    def test_form_and_text_bodies_and_dedupe(self):
        t = make_jwt({"sub": "f"})
        self.assertEqual([x["payload"]["sub"] for x in find_jwts(body="token=%s&x=1&again=%s" % (t, t),
                                                                  content_type="application/x-www-form-urlencoded")], ["f"])
        self.assertEqual(find_jwts(body="plain text " + t, content_type="text/plain"), [])

    def test_false_positives_are_ignored(self):
        self.assertEqual(find_jwts(headers=[("Authorization", "Bearer 1.2.3")], body='{"v": "1.2.3", "ip": "10.0.0.1", "f": "a.b.c"}',
                                   content_type="application/json"), [])

    def test_hostile_inputs_never_raise(self):
        deep = "[" * 5000 + "]" * 5000
        self.assertEqual(find_jwts(body=deep, content_type="application/json"), [])
        nested = ("{\"a\":" * 900) + '"' + JWT_FRESH + '"' + "}" * 900
        self.assertIsInstance(find_jwts(body=nested, content_type="application/json"), list)
        self.assertEqual(find_jwts(body=b"\xff\xfe\x00" * 1000, content_type="application/json"), [])
        self.assertEqual(find_jwts(headers=None, body=None), [])
        self.assertEqual(find_jwts(headers=[("authorization", None)]), [])
        big = ('{"x": "' + "A" * 5_000_000 + '"}').encode()
        t = time.time()
        find_jwts(body=big, content_type="application/json")
        self.assertLess(time.time() - t, 5)

    def test_regex_does_not_backtrack_catastrophically(self):
        t = time.time()
        find_jwts(headers=[("authorization", "." * 200000 + "a." * 50000)])
        find_jwts(headers=[("cookie", "a" * 300000 + "." + "b" * 300000)])
        self.assertLess(time.time() - t, 5)


class GraphQL(unittest.TestCase):
    def test_post_json_operations(self):
        ops = detect_graphql("POST", "https://h/graphql", json.dumps({"query": "query GetUser($id: ID!) { user(id: $id) { name } }",
                                                                       "variables": {"id": 1}}).encode(), "application/json")
        self.assertEqual([(o["type"], o["name"], o["variables"]) for o in ops], [("query", "GetUser", {"id": 1})])
        ops = detect_graphql("POST", "https://h/g", json.dumps({"query": "mutation { x }", "operationName": "Explicit"}), "application/json")
        self.assertEqual((ops[0]["type"], ops[0]["name"]), ("mutation", "Explicit"))
        self.assertEqual(detect_graphql("POST", "https://h/g", '{"query": "{ me { id } }"}', "application/json")[0]["name"], "(anonymous)")
        self.assertEqual(detect_graphql("POST", "https://h/g", '{"query": "# hi\\nsubscription S { x }"}', "")[0]["type"], "subscription")

    def test_batch_get_and_application_graphql(self):
        batch = json.dumps([{"query": "query A { a }"}, {"query": "query B { b }"}, {"nope": 1}])
        self.assertEqual([o["name"] for o in detect_graphql("POST", "https://h/g", batch, "application/json")], ["A", "B"])
        self.assertEqual(detect_graphql("GET", "https://h/g?query=query%20Q%20%7B%20q%20%7D&operationName=Named", None)[0]["name"], "Named")
        self.assertEqual(detect_graphql("POST", "https://h/g", "query Raw { r }", "application/graphql")[0]["name"], "Raw")
        self.assertEqual(detect_graphql("POST", "https://h/g", "anything goes here", "application/graphql")[0]["name"], "(anonymous)")

    def test_rest_query_parameters_are_not_graphql(self):
        for url in ("https://h/search?query=shoes", "https://h/search?query=red+shoes+size+10", "https://h/api?query=", "https://h/search?q=query+x"):
            self.assertEqual(detect_graphql("GET", url, None), [], url)
        self.assertEqual(detect_graphql("POST", "https://h/search", '{"query": "shoes"}', "application/json"), [])
        self.assertEqual(detect_graphql("POST", "https://h/search", '{"filter": {"a": 1}}', "application/json"), [])
        self.assertEqual(detect_graphql("PUT", "https://h/g", '{"query": "{ x }"}', "application/json"), [])

    def test_hostile_input(self):
        for body in ("[" * 5000 + "]" * 5000, "{bad", b"\xff\xfe", "", None, "null", '{"query": 5}', '{"query": ["x"]}'):
            self.assertEqual(detect_graphql("POST", "https://h/g", body, "application/json"), [])
        t = time.time()
        detect_graphql("POST", "https://h/g", '{"query": "' + " " * 3_000_000 + 'query X { x }"}', "application/json")
        self.assertLess(time.time() - t, 5)                              # whitespace-prefixed query: no regex blow-up


class Grpc(unittest.TestCase):
    def test_frames_and_protobuf(self):
        rows = decode_grpc_frames(GRPC_BODY)
        self.assertEqual(len(rows), 1)
        self.assertEqual([(f["field"], f["wire"], f["value"]) for f in rows[0]["fields"]], [(1, 0, 150), (2, 2, "hi")])
        two = GRPC_BODY + b"\x01\x00\x00\x00\x02ab"
        rows = decode_grpc_frames(two)
        self.assertEqual([r["compressed"] for r in rows], [False, True])
        self.assertIsNone(rows[1]["fields"])
        self.assertIn("compressed", rows[1]["note"])

    def test_truncated_and_garbage_raise_value_error_only(self):
        for bad in (b"\x00\x00\x00", b"\x00\x00\x00\x00\x09ab", b"\x00\x00\x00\x00\x02\x00\x00"):
            with self.assertRaises(ValueError):
                decode_grpc_frames(bad)
        for bad in (b"\xff" * 20, b"\x08", b"\x0a\xff\xff\xff\x0f", b"\x07\x00", b"\x00"):
            try:
                decode_protobuf(bad)
            except ValueError:
                pass
        nested = b"\x0a\x04" + b"\x0a\x02" + b"\x08\x01" + b"\x0a\x00"
        self.assertIsInstance(decode_protobuf(nested), list)

    def test_protobuf_wire_types(self):
        data = b"\x09" + (7).to_bytes(8, "little") + b"\x15" + (9).to_bytes(4, "little") + b"\x1a\x03\x01\x02\x03"
        rows = decode_protobuf(data)
        self.assertEqual(rows[0]["value"], {"fixed64": 7})
        self.assertEqual(rows[1]["value"], {"fixed32": 9})
        self.assertTrue(rows[2]["value"])


class LiveViewers(LiveCase):
    def view(self, path, **kw):
        self.fetch(path, **kw)
        return self.panel.ok("viewer", {"flow_id": self.inst.flow_for(path.split("?")[0])["id"]})

    def test_jwt_in_response_header_setcookie_body_and_form(self):
        h = self.view("/jwt/header")
        self.assertEqual([(t["payload"]["sub"], t["where"]) for t in h["tokens"]], [("alice", "header:authorization")])
        c = self.view("/jwt/setcookie")
        self.assertEqual([t["where"] for t in c["tokens"]], ["header:set-cookie"])
        b = self.view("/jwt/body")
        self.assertEqual({t["payload"]["sub"] for t in b["tokens"]}, {"alice", "bob"})
        self.assertTrue(any(t["times"]["exp"]["expired"] for t in b["tokens"] if t["payload"]["sub"] == "bob"))
        self.assertFalse(any(t["times"]["exp"]["expired"] for t in b["tokens"] if t["payload"]["sub"] == "alice"))
        f = self.view("/jwt/form")
        self.assertEqual([t["where"] for t in f["tokens"]], ["body[0].token"])

    def test_jwt_in_request_cookie_query_and_authorization(self):
        v = self.view("/echo?access_token=" + JWT_EXPIRED, headers={"Cookie": "session=" + JWT_FRESH, "Authorization": "Bearer " + make_jwt({"sub": "zed"})})
        where = {t["payload"]["sub"]: t["where"] for t in v["tokens"]}
        self.assertEqual(where, {"bob": "query.access_token", "alice": "header:cookie", "zed": "header:authorization"})

    def test_deeply_nested_json_does_not_crash_anything(self):
        deep = "[" * 2000 + "]" * 2000
        v = self.view("/deep?n=2000")
        self.assertEqual((v["tokens"], v["graphql"]), ([], []))
        v = self.view("/echo?deep=1", method="POST", data=deep, headers={"Content-Type": "application/json"})
        self.assertEqual(v["tokens"], [])
        s = wait_for(lambda: (lambda d: d if d["complete"] else None)(self.panel.ok("viewer_summaries", {"limit": 50})["viewers"]), 20, 0.1, "summaries")
        self.assertIsInstance(s["tokens"], list)
        self.assertEqual(self.fetch("/json/small").status, 200)                       # proxy still fine

    def test_graphql_true_positives_and_rest_false_positive(self):
        q = json.dumps({"query": "query GetViewer { viewer { id name } }"})
        v = self.view("/graphql", method="POST", data=q, headers={"Content-Type": "application/json"})
        self.assertEqual([(o["type"], o["name"]) for o in v["graphql"]], [("query", "GetViewer")])
        self.assertEqual(v["graphql_response"]["data"]["viewer"]["name"], "alice")
        self.assertEqual(v["graphql_response"]["errors"], [])
        bad = json.dumps({"query": "query Failing { fail }"})
        v = self.view("/graphql", method="POST", data=bad, headers={"Content-Type": "application/json"})
        self.assertEqual(v["graphql_response"]["errors"][0]["message"], "boom")
        failed_flow = self.inst.flow_for("/graphql")
        self.assertIn("graphql:error", failed_flow["comment"])
        v = self.view("/graphql?query=query%20FromGet%20%7B%20x%20%7D")
        self.assertEqual(v["graphql"][0]["name"], "FromGet")
        v = self.view("/rest?query=shoes")
        self.assertEqual((v["graphql"], v["graphql_response"]), ([], None))
        sm = self.panel.ok("viewer_summaries", {"limit": 50})["viewers"]
        self.assertEqual({o["name"] for o in sm["graphql_ops"]}, {"GetViewer", "Failing", "FromGet"})
        self.assertEqual(len(sm["graphql_error_ids"]), 1)

    def test_grpc_summary(self):
        v = self.view("/grpc/pkg.Greeter/SayHello", method="POST", data=GRPC_BODY, headers={"Content-Type": "application/grpc"})
        g = v["grpc"]
        self.assertEqual((g["service"], g["method"], g["status"], g["message"], g["content_type"]),
                         ("pkg.Greeter", "SayHello", "0", "OK", "grpc"))
        self.assertEqual([(f["field"], f["value"]) for f in g["request"][0]["fields"]], [(1, 150), (2, "hi")])
        self.assertEqual([(f["field"], f["value"]) for f in g["response"][0]["fields"]], [(1, 150), (2, "hi")])
        v = self.view("/grpc/pkg.Greeter/Broken", method="POST", data=b"\x00\x00\x00", headers={"Content-Type": "application/grpc"})
        self.assertIn("truncated", v["grpc"]["request_error"])                       # summarised, not a 500


if __name__ == "__main__":
    unittest.main(verbosity=2)
