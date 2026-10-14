"""Scripts (Python + JavaScript) live through the proxy: edits, context, mock, errors, timeouts, big/gzip/multi-value
bodies, Node missing, the vm escape attempt."""
import gzip
import hashlib
import json
import os
import shutil
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import Background, Instance, LiveCase, wait_for
from upstream import big_body

NO_NODE = "Node.js is not installed on this machine"
needs_node = unittest.skipUnless(harness.NODE, NO_NODE)


class ScriptCase(LiveCase):
    def setUp(self):
        self.inst.clear_dir("scripts")
        super().setUp()

    def install(self, name, code, match=".", method=None, enabled=True, **cfg):
        """Write a script file + register it in rules.json (what `rivis scripts add` / the panel do), then make sure the
        engine has reloaded it (it re-reads at most once a second, on the next call)."""
        lang = os.path.splitext(name)[1][1:]
        sdir = self.inst.path("scripts")
        os.makedirs(sdir, exist_ok=True)
        path = os.path.join(sdir, name)
        with open(path, "w") as fh:
            fh.write(code)
        os.chmod(path, 0o600)
        entry = {"name": os.path.splitext(name)[0], "file": name, "lang": lang, "enabled": enabled, "match": match,
                 "method": method}
        scripts = self.inst.cfg().get("scripts", []) + [entry]
        self.inst.write_cfg(dict(self.inst.cfg(), scripts=scripts, **cfg), sync=False)
        time.sleep(1.2)
        self.inst.fetch("http://127.0.0.1:1/__probe__", timeout=5)       # any call triggers the reload
        time.sleep(0.3)

    def errors(self):
        return self.panel.state()["script_status"]["errors"]

    def comment_of(self, path):
        return self.inst.flow_for(path)["comment"] or ""


class PythonScripts(ScriptCase):
    def test_request_edits_header_query_body_and_method(self):
        self.install("edit.py", '''
def on_request(context, url, request):
    request["headers"]["X-Script"] = "py"
    request["headers"].pop("X-Drop", None)
    request["queries"]["added"] = "1"
    request["method"] = "PUT"
    request["body"] = {"changed": True}
    return request
''', match="/echo")
        doc = self.fetch("/echo?keep=1", method="POST", data="{}", headers={"X-Drop": "x", "Content-Type": "application/json"}).json()
        hdr = {k.lower(): v for k, v in doc["headers"]}
        self.assertEqual(hdr.get("x-script"), "py")
        self.assertNotIn("x-drop", hdr)
        self.assertEqual(doc["method"], "PUT")
        self.assertEqual(doc["query"], {"keep": ["1"], "added": ["1"]})
        self.assertEqual(json.loads(doc["body"]), {"changed": True})
        self.assertIn("script:edit", self.comment_of("/echo"))

    def test_response_edits_status_header_and_json_body(self):
        self.install("resp.py", '''
def on_response(context, url, request, response):
    response["statusCode"] = 201
    response["headers"]["X-R"] = "1"
    response["body"]["added"] = [1, 2]
    return response
''', match="/json/small")
        r = self.fetch("/json/small")
        self.assertEqual((r.status, r.header("x-r")), (201, "1"))
        self.assertEqual(r.json()["added"], [1, 2])
        self.assertEqual(r.json()["flag"], False)

    def test_context_persists_between_calls_and_has_flow_and_project(self):
        self.install("ctx.py", '''
def on_request(context, url, request):
    context["n"] = context.get("n", 0) + 1
    request["headers"]["X-N"] = str(context["n"])
    request["headers"]["X-Project"] = str(context["project"])
    request["headers"]["X-Flow"] = "yes" if context["flow_id"] else "no"
    return request
''', match="/echo")
        seen = []
        for _ in range(3):
            doc = self.fetch("/echo").json()
            seen.append({k.lower(): v for k, v in doc["headers"]})
        self.assertEqual([h["x-n"] for h in seen], ["1", "2", "3"])
        self.assertEqual({h["x-project"] for h in seen}, {"default"})
        self.assertEqual({h["x-flow"] for h in seen}, {"yes"})

    def test_mock_with_plain_text_answers_locally_and_upstream_is_not_hit(self):
        self.install("mock.py", 'def on_request(context, url, request):\n    return mock(202, "plain mock")\n', match="/echo")
        r = self.fetch("/echo")
        self.assertEqual((r.status, r.text), (202, "plain mock"))
        self.assertEqual(self.up.hits_for("/echo"), [])
        self.assertIn("script:mock", self.comment_of("/echo"))

    @unittest.expectedFailure
    def test_mock_with_json_body_and_headers(self):
        """FOUND-BUGS B7: any mock() that carries headers (or a JSON body → auto Content-Type) raises
        'Header fields must be bytes' — this is the shipped `mock` template."""
        self.install("mockj.py", 'def on_request(context, url, request):\n    return mock(202, {"mocked": True}, {"X-M": "1"})\n', match="/echo")
        r = self.fetch("/echo")
        self.assertEqual((r.status, r.json(), r.header("x-m")), (202, {"mocked": True}, "1"))
        self.assertEqual(self.up.hits_for("/echo"), [])

    def test_method_and_match_filters(self):
        self.install("only_post.py", '''
def on_request(context, url, request):
    request["headers"]["X-Hit"] = "1"
    return request
''', match="/echo", method="post")
        self.assertNotIn("x-hit", [k.lower() for k, _ in self.fetch("/echo").json()["headers"]])
        self.assertIn("x-hit", [k.lower() for k, _ in self.fetch("/echo", method="POST", data="x").json()["headers"]])

    def test_response_hook_error_is_recorded_shown_in_state_and_the_flow_passes_unchanged(self):
        self.install("boom.py", '''
def on_response(context, url, request, response):
    response["headers"]["X-Never"] = "1"
    response["statusCode"] = 500
    raise ValueError("boom")
''', match="/json/small")
        r = self.fetch("/json/small")
        self.assertEqual((r.status, r.header("x-never")), (200, None))                  # the partial edit is not applied
        self.assertEqual(r.json()["flag"], False)
        err = wait_for(lambda: self.errors().get("boom.py"), 5, 0.2, "recorded error")
        self.assertIn("ValueError: boom", err["message"])
        self.assertEqual(err["phase"], "on_response")
        self.assertIn("boom", err["traceback"])
        self.assertTrue(err["time"])
        self.assertNotIn("script:boom", self.comment_of("/json/small"))

    def test_request_hook_error_passes_the_flow_unchanged(self):
        self.install("rboom.py", '''
def on_request(context, url, request):
    request["headers"]["X-Never"] = "1"
    raise ValueError("boom")
''', match="/echo")
        r = self.fetch("/echo")
        self.assertEqual(r.status, 200)
        self.assertNotIn("x-never", [k.lower() for k, _ in r.json()["headers"]])

    @unittest.expectedFailure
    def test_request_hook_error_stays_in_state(self):
        """FOUND-BUGS B8: the same script's (absent) on_response hook of the same flow succeeds and pops the error."""
        self.install("rboom2.py", "def on_request(context, url, request):\n    raise ValueError('boom')\n", match="/echo")
        self.fetch("/echo")
        err = wait_for(lambda: self.errors().get("rboom2.py"), 4, 0.2, "recorded error")
        self.assertIn("ValueError: boom", err["message"])

    def test_syntax_error_at_load_is_reported_and_other_scripts_still_run(self):
        self.install("bad.py", "def on_request(:\n")
        self.install("good.py", 'def on_request(context, url, request):\n    request["headers"]["X-Good"] = "1"\n    return request\n', match="/echo")
        self.assertIn("x-good", [k.lower() for k, _ in self.fetch("/echo").json()["headers"]])
        self.assertIn("SyntaxError", self.errors()["bad.py"]["message"])
        self.assertEqual(self.errors()["bad.py"]["phase"], "load")

    def test_error_clears_when_the_script_is_fixed(self):
        self.install("fix.py", "def on_response(context, url, request, response):\n    raise RuntimeError('x')\n", match="/echo")
        self.fetch("/echo")
        wait_for(lambda: "fix.py" in self.errors(), 5, 0.2, "error shown")
        self.panel.ok("script_put", {"file": "fix.py", "content": "def on_response(context, url, request, response):\n    return None\n", "match": "/echo"})
        self.assertNotIn("fix.py", self.errors())

    def test_sync_script_timeout_is_an_error_and_does_not_block_a_concurrent_call(self):
        self.install("slow.py", "import time\ndef on_response(context, url, request, response):\n    time.sleep(5)\n    response['headers']['X-Late']='1'\n    return response\n",
                     match="/echo\\?slowpy")
        slow = Background(self.fetch, "/echo?slowpy", timeout=20)
        time.sleep(0.5)
        t = time.time()
        self.assertEqual(self.fetch("/json/small").status, 200)
        self.assertLess(time.time() - t, 1.5)
        r = slow.result(20)
        self.assertEqual(r.status, 200)
        self.assertIsNone(r.header("x-late"))                                          # a late result is ignored
        self.assertIn("timed out after 2 s", self.errors()["slow.py"]["message"])

    def test_async_script_timeout(self):
        self.install("aslow.py", "async def on_response(context, url, request, response):\n    await sleep(5000)\n", match="/echo")
        t = time.time()
        r = self.fetch("/echo")
        self.assertEqual(r.status, 200)
        self.assertLess(time.time() - t, 4)
        self.assertIn("aslow.py", self.errors())

    def test_latency_helper_sleep(self):
        self.install("lat.py", "async def on_request(context, url, request):\n    await sleep(400)\n", match="/echo")
        t = time.time()
        self.assertEqual(self.fetch("/echo").status, 200)
        self.assertGreaterEqual(time.time() - t, 0.38)
        self.assertNotIn("lat.py", self.errors())

    def test_gzip_response_body_edit_is_valid_for_the_client(self):
        self.install("gz.py", 'def on_response(context, url, request, response):\n    response["body"]["scripted"] = True\n    return response\n',
                     match="/json/gzip")
        r = self.fetch("/json/gzip", extra=["--compressed"])
        self.assertEqual(r.status, 200)
        self.assertTrue(r.json()["scripted"])
        self.assertTrue(r.json()["gz"])

    def test_large_binary_bodies_pass_through_unchanged(self):
        self.install("big.py", 'def on_response(context, url, request, response):\n    response["headers"]["X-Seen"] = "1"\n    return response\n\n'
                               'def on_request(context, url, request):\n    request["headers"]["X-Req"] = "1"\n    return request\n', match="/(big|echo)")
        want = hashlib.sha256(big_body(3)).hexdigest()
        r = self.fetch("/big?mb=3", timeout=40)
        self.assertEqual((len(r.body), hashlib.sha256(r.body).hexdigest(), r.header("x-seen")), (3 * 1024 * 1024, want, "1"))
        up = big_body(2)
        doc = self.fetch("/echo", method="POST", data=up, timeout=40).json()
        self.assertEqual((doc["body_len"], doc["body_sha256"]), (len(up), hashlib.sha256(up).hexdigest()))

    def test_multi_value_headers_survive_a_script(self):
        self.install("mv.py", 'def on_response(context, url, request, response):\n    response["headers"]["X-List"] = ["a", "b"]\n    return response\n',
                     match="/(multi|cookies)")
        r = self.fetch("/multi")
        self.assertEqual(r.header_all("x-multi"), ["one", "two", "three"])
        self.assertEqual(r.header_all("x-list"), ["a", "b"])
        r = self.fetch("/cookies")
        self.assertEqual(sorted(c.split(";")[0] for c in r.header_all("set-cookie")), ["a=1", "b=2"])

    def test_scripts_run_after_rules_and_skip_locally_answered_calls(self):
        self.install("late.py", 'def on_request(context, url, request):\n    return mock(500, "from script")\n\n'
                                'def on_response(context, url, request, response):\n    response["headers"]["X-Resp-Script"] = "1"\n    return response\n',
                     match="/echo", rules=[self.rule("r", "respond", "/echo", status=203, body="from rule")])
        r = self.fetch("/echo")
        self.assertEqual((r.status, r.text), (203, "from rule"))
        self.assertIsNone(r.header("x-resp-script"))

    def test_disabled_script_does_not_run_and_toggle_works(self):
        self.install("off.py", 'def on_request(context, url, request):\n    return mock(299, "x")\n', match="/echo", enabled=False)
        self.assertEqual(self.fetch("/echo").status, 200)
        self.panel.ok("script_toggle", {"file": "off.py", "enabled": True})
        time.sleep(1.3)
        wait_for(lambda: self.fetch("/echo").status == 299, 8, 0.3, "enabled")

    def test_script_edits_are_not_recorded_but_rules_run_first(self):
        self.install("order.py", 'def on_request(context, url, request):\n    request["headers"]["X-Order"] = request["headers"].get("X-From-Rule", "none")\n    return request\n',
                     match="/echo", rules=[self.rule("hdr", "set_header", "/echo", header="X-From-Rule", value="yes")])
        doc = self.fetch("/echo").json()
        self.assertEqual(dict((k.lower(), v) for k, v in doc["headers"])["x-order"], "yes")


@needs_node
class JavaScriptScripts(ScriptCase):
    def test_request_and_response_edits(self):
        self.install("e.js", '''
async function onRequest(context, url, request) {
  request.headers["X-Js"] = "1";
  request.queries.added = "1";
  return request;
}
async function onResponse(context, url, request, response) {
  response.statusCode = 202;
  if (response.body && typeof response.body === "object") response.body.fromJs = true;
  return response;
}
''', match="/echo")
        r = self.fetch("/echo?k=1")
        self.assertEqual(r.status, 202)
        doc = r.json()
        self.assertTrue(doc["fromJs"])
        self.assertEqual(doc["query"], {"k": ["1"], "added": ["1"]})
        self.assertIn("x-js", [k.lower() for k, _ in doc["headers"]])

    def test_context_persists_between_calls(self):
        self.install("c.js", '''
function onRequest(context, url, request) {
  context.n = (context.n || 0) + 1;
  request.headers["X-N"] = String(context.n);
  return request;
}
''', match="/echo")
        got = [dict((k.lower(), v) for k, v in self.fetch("/echo").json()["headers"])["x-n"] for _ in range(3)]
        self.assertEqual(got, ["1", "2", "3"])

    def test_mock_plain_text(self):
        self.install("m.js", 'async function onRequest(c, u, r) { return mock(201, "js mock"); }\n', match="/echo")
        r = self.fetch("/echo")
        self.assertEqual((r.status, r.text), (201, "js mock"))
        self.assertEqual(self.up.hits_for("/echo"), [])

    @unittest.expectedFailure
    def test_mock_json_with_headers(self):
        """FOUND-BUGS B7 (JavaScript flavour)."""
        self.install("mj.js", 'async function onRequest(c, u, r) { return mock(201, {js: true}, {"X-M": "1"}); }\n', match="/echo")
        r = self.fetch("/echo")
        self.assertEqual((r.status, r.json(), r.header("x-m")), (201, {"js": True}, "1"))

    def test_error_is_recorded_and_flow_unchanged(self):
        self.install("err.js", 'function onResponse(c, u, r, resp) { resp.headers["X-Never"]="1"; throw new Error("js-boom"); }\n', match="/echo")
        r = self.fetch("/echo")
        self.assertEqual(r.status, 200)
        self.assertIsNone(r.header("x-never"))
        err = wait_for(lambda: self.errors().get("err.js"), 5, 0.2, "js error")
        self.assertIn("js-boom", err["message"] + err["traceback"])

    def test_busy_loop_is_cut_off_and_flow_passes(self):
        self.install("spin.js", 'function onResponse(c, u, r, resp) { while (true) {} }\n', match="/echo")
        t = time.time()
        r = self.fetch("/echo", timeout=15)
        self.assertEqual(r.status, 200)
        self.assertLess(time.time() - t, 8)
        self.assertIn("spin.js", wait_for(lambda: self.errors(), 5, 0.2, "error recorded"))
        self.assertEqual(self.fetch("/echo", timeout=15).status, 200)           # the host survived

    def test_slow_async_js_times_out_and_does_not_block_a_concurrent_fast_call(self):
        self.install("slowjs.js", 'async function onResponse(c, u, r, resp) { await sleep(5000); resp.headers["X-Late"]="1"; return resp; }\n', match="/echo\\?slowjs")
        self.install("fastjs.js", 'function onRequest(c, u, r) { r.headers["X-Fast"]="1"; return r; }\n', match="/json/small")
        self.install("fastpy.py", 'def on_request(context, url, request):\n    request["headers"]["X-FastPy"]="1"\n    return request\n', match="/text")
        slow = Background(self.fetch, "/echo?slowjs", timeout=20)
        time.sleep(0.5)
        t = time.time()
        self.assertEqual(self.fetch("/json/small").status, 200)
        self.assertEqual(self.fetch("/text").status, 200)
        self.assertLess(time.time() - t, 1.5)
        r = slow.result(20)
        self.assertEqual(r.status, 200)
        self.assertIsNone(r.header("x-late"))
        self.assertIn("timed out", self.errors()["slowjs.js"]["message"])

    def test_vm_escape_via_constructor_chain_is_blocked(self):
        self.install("esc.js", '''
function onRequest(context, url, request) {
  const out = [];
  for (const probe of [
    () => log.constructor.constructor("return process")(),
    () => (function(){}).constructor("return process")(),
    () => this.constructor.constructor("return process")(),
    () => request.constructor.constructor("return process")(),
    () => eval("process"),
    () => require("fs"),
    () => typeof process,
  ]) {
    try { const v = probe(); out.push(typeof v === "object" && v && v.version ? "ESCAPED" : "no:" + String(v)); }
    catch (e) { out.push("blocked:" + e.name); }
  }
  request.headers["X-Probe"] = out.join(",");
  return request;
}
''', match="/echo")
        doc = self.fetch("/echo").json()
        probe = dict((k.lower(), v) for k, v in doc["headers"])["x-probe"]
        self.assertNotIn("ESCAPED", probe)
        self.assertTrue(probe.startswith("blocked:EvalError,blocked:EvalError"), probe)
        self.assertIn("no:undefined", probe)                      # typeof process → "undefined" is fine, a string probe
        self.assertEqual(self.errors().get("esc.js"), None)

    def test_gzip_big_and_multi_value_through_js(self):
        self.install("g.js", 'async function onResponse(c, u, r, resp) { resp.headers["X-J"] = ["a","b"]; return resp; }\n', match="/(json/gzip|big|multi)")
        r = self.fetch("/json/gzip", extra=["--compressed"])
        self.assertTrue(r.json()["gz"])
        self.assertEqual(r.header_all("x-j"), ["a", "b"])
        big = self.fetch("/big?mb=3", timeout=40)
        self.assertEqual(hashlib.sha256(big.body).hexdigest(), hashlib.sha256(big_body(3)).hexdigest())
        self.assertEqual(self.fetch("/multi").header_all("x-multi"), ["one", "two", "three"])


class NodeMissing(LiveCase):
    """This Mac has Node at /opt/homebrew/bin, and find_node() has hard-coded fallbacks, so RIVIS_NODE=/nonexistent alone
    cannot hide it. The environment is simulated with a throw-away copy of the product whose Node candidate list is empty,
    started with a PATH that has no node."""
    SIM = None

    @classmethod
    def make_instance(cls):
        root = os.path.join(cls.suite.root, "product-copy")
        shutil.copytree(harness.REPO, root, ignore=shutil.ignore_patterns("tests", ".git", "__pycache__"))
        path = os.path.join(root, "addons", "proxy_scripts.py")
        src = open(path).read()
        start = src.index("NODE_CANDIDATES = (")
        end = src.index(")\n", start) + 2
        open(path, "w").write(src[:start] + "NODE_CANDIDATES = ()\n" + src[end:])
        cls.SIM = root
        shim = cls.suite.shim
        return Instance(cls.suite, "nonode", rivis_bin=os.path.join(root, "rivis"),
                        extra_env={"RIVIS_NODE": "/nonexistent", "PATH": shim + ":/usr/bin:/bin:/usr/sbin:/sbin"})

    def setUp(self):
        self.inst.clear_dir("scripts")
        super().setUp()

    def write_script(self, name, code, match):
        sdir = self.inst.path("scripts")
        os.makedirs(sdir, exist_ok=True)
        with open(os.path.join(sdir, name), "w") as fh:
            fh.write(code)
        entry = {"name": os.path.splitext(name)[0], "file": name, "lang": name.rsplit(".", 1)[1], "enabled": True, "match": match,
                 "method": None}
        self.inst.write_cfg(dict(self.inst.cfg(), scripts=self.inst.cfg().get("scripts", []) + [entry]), sync=False)
        time.sleep(1.2)
        self.inst.fetch("http://127.0.0.1:1/__probe__", timeout=5)
        time.sleep(0.3)

    def test_state_says_why_python_still_works_and_js_fails_visibly(self):
        st = self.panel.state()["script_status"]
        self.assertFalse(st["node"])
        self.assertIn("Node.js not installed", st["node_message"])
        self.write_script("p.py", 'def on_request(context, url, request):\n    request["headers"]["X-Py"] = "ok"\n    return request\n', "/echo")
        self.write_script("j.js", 'function onRequest(c,u,r){ r.headers["X-Js"]="x"; return r; }\n', "/echo")
        doc = self.fetch("/echo").json()
        names = [k.lower() for k, _ in doc["headers"]]
        self.assertIn("x-py", names)
        self.assertNotIn("x-js", names)
        err = wait_for(lambda: self.panel.state()["script_status"]["errors"].get("j.js"), 5, 0.2, "js error")
        self.assertIn("Node.js not installed", err["message"])

    def test_find_node_honours_override_then_falls_back(self):
        sys.path.insert(0, os.path.join(harness.REPO, "addons"))
        import proxy_scripts
        old = os.environ.get("RIVIS_NODE")
        try:
            os.environ["RIVIS_NODE"] = "/usr/bin/true"
            self.assertEqual(proxy_scripts.find_node(), "/usr/bin/true")
            os.environ["RIVIS_NODE"] = "/nonexistent"
            self.assertNotEqual(proxy_scripts.find_node(), "/nonexistent")       # invalid override: falls back, never crashes
        finally:
            if old is None:
                os.environ.pop("RIVIS_NODE", None)
            else:
                os.environ["RIVIS_NODE"] = old


if __name__ == "__main__":
    unittest.main(verbosity=2)
