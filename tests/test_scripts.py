"""Scripts (Python + JavaScript) live through the proxy: edits, context, mock, errors, timeouts, big/gzip/multi-value
bodies, Node missing, the vm escape attempt."""
import base64
import gzip
import hashlib
import json
import os
import shutil
import socket
import sys
import threading
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
        # sync=True writes rules.json and fetches a probe, which also makes the scripts engine re-read (it
        # used to sleep 1.2 s for the once-a-second stat).
        self.inst.write_cfg(dict(self.inst.cfg(), scripts=scripts, **cfg), sync=True)

    def errors(self):
        return self.panel.state()["script_status"]["errors"]

    def comment_of(self, path):
        return self.inst.flow_for(path)["comment"] or ""


class PythonScripts(ScriptCase):
    def test_a_just_saved_script_applies_to_the_very_next_call(self):
        # The scripts file was stat-ed at most once a second, so the first call after `scripts add` /
        # install() reached the server without the new header (same class of bug as rules R7B-02).
        self.reset_state(scripts=[])
        sdir = self.inst.path("scripts")
        os.makedirs(sdir, exist_ok=True)
        with open(os.path.join(sdir, "immediate.py"), "w") as fh:
            fh.write('def on_request(context, url, request):\n    request["headers"]["X-Immediate"] = "1"\n    return request\n')
        entry = {"name": "immediate", "file": "immediate.py", "lang": "py", "enabled": True, "match": "/echo\\?imm",
                 "method": None}
        self.inst.write_cfg(dict(self.inst.cfg(), scripts=[entry]), sync=False)
        hdr = {k.lower(): v for k, v in self.fetch("/echo?imm").json()["headers"]}
        self.assertEqual(hdr.get("x-immediate"), "1",
                         "the first call after saving a script must already run it (got %r)" % hdr)

    def test_log_helper_works_at_load_and_in_hook(self):
        self.install("logger.py", 'log("loaded")\ndef on_request(context, url, request):\n    log("called")\n    return request\n', match="/echo")
        import subprocess
        host = os.path.join(harness.REPO, "addons", "python_host.py")
        calls = [dict(op="load", name="logger", path=self.inst.path("scripts", "logger.py")),
                 dict(op="call", hook="on_request", context={}, url="http://example.test/echo", request={}, response=None)]
        result = subprocess.run([sys.executable, host], input="\n".join(json.dumps(x) for x in calls) + "\n",
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        replies = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([r["logs"] for r in replies], [["loaded"], ["called"]])

    def test_c_regex_timeout_keeps_other_traffic_and_panel_responsive(self):
        self.install("regex.py", 'import re\ndef on_response(context, url, request, response):\n    re.match(r"(a+)+$", "a" * 40 + "b")\n    response["headers"]["X-Late"] = "1"\n    return response\n', match="/echo\\?regex")
        slow = Background(self.fetch, "/echo?regex", timeout=15)
        time.sleep(0.3)
        t = time.monotonic()
        self.assertEqual(self.fetch("/json/small", timeout=5).status, 200)
        self.assertIn("script_status", self.panel.state())
        self.assertLess(time.monotonic() - t, 4)
        self.assertIsNone(slow.result(15).header("x-late"))
        self.assertIn("timed out after 2 s", self.errors()["regex.py"]["message"])
        self.assertEqual(self.fetch("/echo?regex", timeout=10).status, 200)

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

    def test_shared_state_token_from_response_is_used_on_the_next_request(self):
        # Capture a login-shaped field on /json/small, then attach it as Authorization on /echo.
        self.install("tok.py", '''
def on_request(context, url, request):
    token = shared_state.get("token")
    if token:
        request["headers"]["Authorization"] = "Bearer " + token
    return request

def on_response(context, url, request, response):
    body = response.get("body")
    if isinstance(body, dict) and isinstance(body.get("user"), dict) and body["user"].get("name"):
        shared_state["token"] = body["user"]["name"]
    return response
''', match=r"/json/small|/echo")
        self.assertEqual(self.fetch("/json/small").json()["user"]["name"], "alice")
        doc = self.fetch("/echo").json()
        hdr = {k.lower(): v for k, v in doc["headers"]}
        self.assertEqual(hdr.get("authorization"), "Bearer alice")

    def test_shared_state_is_shared_across_scripts(self):
        self.install("a_writer.py", '''
def on_response(context, url, request, response):
    shared_state["cross"] = "from-a"
    return response
''', match="/json/small")
        self.install("b_reader.py", '''
def on_request(context, url, request):
    if shared_state.get("cross"):
        request["headers"]["X-Cross"] = shared_state["cross"]
    return request
''', match="/echo")
        self.fetch("/json/small")
        hdr = {k.lower(): v for k, v in self.fetch("/echo").json()["headers"]}
        self.assertEqual(hdr.get("x-cross"), "from-a")

    def test_shared_state_cap_records_a_plain_error_and_keeps_prior_values(self):
        self.install("cap.py", '''
def on_request(context, url, request):
    if "seed" in url:
        shared_state["keep"] = "yes"
        request["headers"]["X-Keep"] = shared_state["keep"]
        return request
    if "blow" in url:
        shared_state["pad"] = "x" * (300 * 1024)
        return request
    request["headers"]["X-Keep"] = str(shared_state.get("keep") or "")
    return request
''', match="/echo")
        seed = {k.lower(): v for k, v in self.fetch("/echo?seed=1").json()["headers"]}
        self.assertEqual(seed.get("x-keep"), "yes")
        self.fetch("/echo?blow=1")
        err = wait_for(lambda: self.errors().get("cap.py"), 5, 0.2, "cap error")
        self.assertIn("shared state is full", err["message"])
        after = {k.lower(): v for k, v in self.fetch("/echo?after=1").json()["headers"]}
        self.assertEqual(after.get("x-keep"), "yes", "a rejected over-size write must leave earlier keys")

    def test_panel_clear_shared_state_forgets_tokens(self):
        self.install("clr.py", '''
def on_request(context, url, request):
    if "set" in url:
        shared_state["token"] = "t1"
    request["headers"]["X-Tok"] = str(shared_state.get("token") or "")
    return request
''', match="/echo")
        self.assertEqual({k.lower(): v for k, v in self.fetch("/echo?set=1").json()["headers"]}.get("x-tok"), "t1")
        self.panel.ok("script_shared_clear", {})
        self.assertEqual({k.lower(): v for k, v in self.fetch("/echo?after=1").json()["headers"]}.get("x-tok"), "")

    def test_shared_state_clears_on_project_switch(self):
        self.install("sw.py", '''
def on_request(context, url, request):
    if "set" in url:
        shared_state["token"] = "alive"
    request["headers"]["X-Tok"] = str(shared_state.get("token") or "")
    return request
''', match="/echo")
        self.assertEqual({k.lower(): v for k, v in self.fetch("/echo?set=1").json()["headers"]}.get("x-tok"), "alive")
        neo = os.path.join(self.inst.home, ".rivis", "projects", "neo")
        os.makedirs(os.path.join(neo, "scripts"), mode=0o700, exist_ok=True)
        with open(os.path.join(neo, "rules.json"), "w") as fh:
            json.dump({"rules": [], "scripts": []}, fh)
        default_rules = self.inst.rules_path
        try:
            # Same live switch path as client-certs: changing proxy_project runs ProxyScripts.configure.
            self.panel.set_option("proxy_project", "neo")
            self.panel.set_option("proxy_rules_file", os.path.join(neo, "rules.json"))
            wait_for(lambda: self.panel.option("proxy_project") == "neo", 5, 0.1, "option is neo")
            self.panel.set_option("proxy_project", "default")
            self.panel.set_option("proxy_rules_file", default_rules)
            wait_for(lambda: self.panel.option("proxy_project") == "default", 5, 0.1, "option is default")
            hdr = {k.lower(): v for k, v in self.fetch("/echo?after=1").json()["headers"]}
            self.assertEqual(hdr.get("x-tok"), "", "project switch must clear shared_state")
        finally:
            self.panel.set_option("proxy_project", "default")
            self.panel.set_option("proxy_rules_file", default_rules)

    def test_mock_with_plain_text_answers_locally_and_upstream_is_not_hit(self):
        self.install("mock.py", 'def on_request(context, url, request):\n    return mock(202, "plain mock")\n', match="/echo")
        r = self.fetch("/echo")
        self.assertEqual((r.status, r.text), (202, "plain mock"))
        self.assertEqual(self.up.hits_for("/echo"), [])
        self.assertIn("script:mock", self.comment_of("/echo"))

    def test_mock_with_json_body_and_headers(self):
        """FOUND-BUGS B7: any mock() that carries headers (or a JSON body → auto Content-Type) raises
        'Header fields must be bytes' — this is the shipped `mock` template."""
        self.install("mockj.py", 'def on_request(context, url, request):\n    return mock(202, {"mocked": True}, {"X-M": "1"})\n', match="/echo")
        r = self.fetch("/echo")
        self.assertEqual((r.status, r.json(), r.header("x-m")), (202, {"mocked": True}, "1"))
        self.assertEqual(self.up.hits_for("/echo"), [])

    def test_mock_preserves_duplicate_set_cookie_headers(self):
        self.install("cookies.py", 'def on_request(context, url, request):\n    return mock(200, "ok", {"Set-Cookie": ["a=1; Path=/", "b=2; Path=/"]})\n', match="/echo")
        self.assertEqual(self.fetch("/echo").header_all("set-cookie"), ["a=1; Path=/", "b=2; Path=/"])

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

    def test_request_hook_error_stays_in_state(self):
        """FOUND-BUGS B8: the same script's (absent) on_response hook of the same flow succeeds and pops the error."""
        self.install("rboom2.py", "def on_request(context, url, request):\n    raise ValueError('boom')\n", match="/echo")
        self.fetch("/echo")
        err = wait_for(lambda: self.errors().get("rboom2.py"), 4, 0.2, "recorded error")
        self.assertIn("ValueError: boom", err["message"])

    def test_cli_list_shows_the_running_scripts_last_error(self):
        # R1A-03: ON alone concealed a script that raised on every matching call.
        self.install("listboom.py", "def on_request(context, url, request):\n    raise RuntimeError('list boom')\n", match="/echo")
        self.fetch("/echo")
        wait_for(lambda: self.errors().get("listboom.py"), 5, 0.2, "script error in panel state")
        listed = self.suite.rivis("scripts", "list", home=self.inst.home, env=self.inst.env)
        self.assertEqual(listed.returncode, 0, listed.stderr)
        line = next(line for line in listed.stdout.splitlines() if "listboom" in line)
        self.assertIn("ON", line)
        self.assertIn("ERROR: RuntimeError: list boom", line)

    def test_javascript_syntax_error_in_cli_has_reason(self):
        # R3A-06: Node's first line is a location; the useful SyntaxError follows it.
        if not harness.NODE: self.skipTest("Node.js unavailable")
        self.install("bad-r3.js", 'async function onRequest(c,u,r) { let x = ; }\n', match="/echo")
        self.fetch("/echo")
        wait_for(lambda: self.errors().get("bad-r3.js"), 5, 0.2, "JavaScript syntax error")
        listed = self.suite.rivis("scripts", "list", home=self.inst.home, env=self.inst.env)
        self.assertIn("SyntaxError:", listed.stdout)

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

    def test_scripts_run_after_rules_on_locally_answered_calls(self):
        self.install("late.py", 'def on_request(context, url, request):\n    return mock(500, "from script")\n\n'
                                'def on_response(context, url, request, response):\n    response["headers"]["X-Resp-Script"] = "1"\n    return response\n',
                     match="/echo", rules=[self.rule("r", "respond", "/echo", status=203, body="from rule")])
        r = self.fetch("/echo")
        self.assertEqual((r.status, r.text), (203, "from rule"))
        self.assertEqual(r.header("x-resp-script"), "1")

    def test_response_script_runs_on_map_local_reply(self):
        path = self.inst.path("mock.json")
        with open(path, "w") as fh:
            fh.write('{"from":"map-local"}')
        self.install("mapped.py", 'def on_response(context, url, request, response):\n    response["headers"]["X-QA-Response"] = "scripted"\n    return response\n',
                     match="/json/small", rules=[self.rule("local", "map_local", "/json/small", file=path)])
        r = self.fetch("/json/small")
        self.assertEqual(r.json(), {"from": "map-local"})
        self.assertEqual(r.header("x-qa-response"), "scripted")

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

    def test_shared_state_token_survives_an_edit_of_the_script(self):
        # One script keeps its own globals in one VM, so a token test inside one unchanged script proves nothing.
        # Saving an edit starts a fresh VM: only the proxy-held sharedState can still hand the token over.
        self.install("tok.js", '''
function onResponse(context, url, request, response) {
  if (response.body && response.body.user && response.body.user.name)
    sharedState.token = response.body.user.name;
  return response;
}
''', match=r"/json/small|/echo")
        self.assertEqual(self.fetch("/json/small").json()["user"]["name"], "alice")
        with open(os.path.join(self.inst.path("scripts"), "tok.js"), "w") as fh:
            fh.write('''
function onRequest(context, url, request) {
  request.headers["X-V"] = "2";
  if (sharedState.token) request.headers["Authorization"] = "Bearer " + sharedState.token;
  return request;
}
''')
        hdr = wait_for(lambda: (lambda h: h if h.get("x-v") == "2" else None)(
            {k.lower(): v for k, v in self.fetch("/echo").json()["headers"]}), 10, 0.3, "edited script in use")
        self.assertEqual(hdr.get("authorization"), "Bearer alice")

    def test_a_script_that_nulls_shared_state_does_not_wipe_other_scripts_keys(self):
        self.install("a_keep.js", '''
function onResponse(context, url, request, response) { sharedState.keep = "k"; return response; }
''', match="/json/small")
        self.install("n_null.js", '''
function onRequest(context, url, request) { sharedState = null; return request; }
''', match="/text")
        self.install("r_read.js", '''
function onRequest(context, url, request) { request.headers["X-Keep"] = String(sharedState.keep || ""); return request; }
''', match="/echo")
        self.fetch("/json/small")
        self.fetch("/text")
        err = wait_for(lambda: self.errors().get("n_null.js"), 5, 0.2, "null error")
        self.assertIn("dictionary", err["message"])
        hdr = {k.lower(): v for k, v in self.fetch("/echo").json()["headers"]}
        self.assertEqual(hdr.get("x-keep"), "k")

    def test_shared_state_is_shared_across_scripts(self):
        # Two JS VMs: without the proxy bag, the reader never sees the writer's key.
        self.install("a_writer.js", '''
function onResponse(context, url, request, response) {
  sharedState.cross = "from-a-js";
  return response;
}
''', match="/json/small")
        self.install("b_reader.js", '''
function onRequest(context, url, request) {
  if (sharedState.cross) request.headers["X-Cross"] = sharedState.cross;
  return request;
}
''', match="/echo")
        self.fetch("/json/small")
        hdr = {k.lower(): v for k, v in self.fetch("/echo").json()["headers"]}
        self.assertEqual(hdr.get("x-cross"), "from-a-js")

    def test_mock_plain_text(self):
        self.install("m.js", 'async function onRequest(c, u, r) { return mock(201, "js mock"); }\n', match="/echo")
        r = self.fetch("/echo")
        self.assertEqual((r.status, r.text), (201, "js mock"))
        self.assertEqual(self.up.hits_for("/echo"), [])

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
        self.inst.write_cfg(dict(self.inst.cfg(), scripts=self.inst.cfg().get("scripts", []) + [entry]), sync=True)

    def test_state_says_why_python_still_works_and_js_fails_visibly(self):
        st = self.panel.state()["script_status"]
        self.assertFalse(st["node"])
        self.assertIn("Node.js not installed", st["node_message"])
        self.assertIn("https://nodejs.org", st["node_message"])
        self.write_script("p.py", 'def on_request(context, url, request):\n    request["headers"]["X-Py"] = "ok"\n    return request\n', "/echo")
        self.write_script("j.js", 'function onRequest(c,u,r){ r.headers["X-Js"]="x"; return r; }\n', "/echo")
        doc = self.fetch("/echo").json()
        names = [k.lower() for k, _ in doc["headers"]]
        self.assertIn("x-py", names)
        self.assertNotIn("x-js", names)
        err = wait_for(lambda: self.panel.state()["script_status"]["errors"].get("j.js"), 5, 0.2, "js error")
        self.assertIn("Node.js not installed", err["message"])
        self.assertIn("https://nodejs.org", err["message"])

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



class SharedStateUnit(unittest.TestCase):
    def test_prepare_shared_state_rejects_oversize_and_non_dicts(self):
        sys.path.insert(0, os.path.join(harness.REPO, "addons"))
        import proxy_scripts
        self.assertEqual(proxy_scripts.prepare_shared_state({"a": 1}), {"a": 1})
        with self.assertRaises(proxy_scripts.ScriptFailure) as bad:
            proxy_scripts.prepare_shared_state(["not", "a", "dict"])
        self.assertIn("dictionary", str(bad.exception))
        with self.assertRaises(proxy_scripts.ScriptFailure) as full:
            proxy_scripts.prepare_shared_state({"pad": "x" * (proxy_scripts.MAX_SHARED_STATE_BYTES)})
        self.assertIn("shared state is full", str(full.exception))
        with self.assertRaises(proxy_scripts.ScriptFailure):
            proxy_scripts.prepare_shared_state(None)          # JS sharedState = null / undefined

    def _scripts(self):
        sys.path.insert(0, os.path.join(harness.REPO, "addons"))
        import proxy_scripts
        ps = proxy_scripts.ProxyScripts.__new__(proxy_scripts.ProxyScripts)
        ps.shared_state, ps._shared_generation, ps._shared_guard = {}, 0, threading.Lock()
        return proxy_scripts, ps

    def test_overlapping_hooks_keep_each_others_keys(self):
        _, ps = self._scripts()
        ps.shared_state = {"token": "T"}
        a, b = ps._shared_snapshot(), ps._shared_snapshot()            # two hooks start on the same bag
        ps._shared_commit(a, {"token": "U"})                          # A refreshes the token
        ps._shared_commit(b, {"token": "T"})                          # B only read it: must not roll A back
        self.assertEqual(ps.shared_state, {"token": "U"})
        c, d = ps._shared_snapshot(), ps._shared_snapshot()
        ps._shared_commit(c, {"token": "U", "counter": 1})
        ps._shared_commit(d, {"token": "U", "other": "x"})
        self.assertEqual(ps.shared_state, {"token": "U", "counter": 1, "other": "x"})
        e = ps._shared_snapshot()
        ps._shared_commit(e, {"counter": 1, "other": "x"})            # a hook that deleted token
        self.assertEqual(ps.shared_state, {"counter": 1, "other": "x"})

    def test_clear_wins_over_a_hook_in_flight_and_a_null_bag_changes_nothing(self):
        proxy_scripts, ps = self._scripts()
        ps.shared_state = {"token": "t1"}
        inflight = ps._shared_snapshot()
        ps.clear_shared_state()
        ps._shared_commit(inflight, {"token": "t1", "late": True})
        self.assertEqual(ps.shared_state, {})
        ps.shared_state = {"keep": "k"}
        with self.assertRaises(proxy_scripts.ScriptFailure):
            ps._shared_commit(ps._shared_snapshot(), None)
        self.assertEqual(ps.shared_state, {"keep": "k"})

    def test_the_cap_applies_to_the_merged_bag(self):
        proxy_scripts, ps = self._scripts()
        half = "x" * (proxy_scripts.MAX_SHARED_STATE_BYTES // 2)
        a, b = ps._shared_snapshot(), ps._shared_snapshot()
        ps._shared_commit(a, {"a": half})
        with self.assertRaises(proxy_scripts.ScriptFailure):
            ps._shared_commit(b, {"b": half + "y" * 100})
        self.assertEqual(list(ps.shared_state), ["a"])


class ScriptBodyEncoding(unittest.TestCase):
    """JSON scalars returned from a script must stay JSON on the wire (same class of bug as rules respond)."""

    class _Msg:
        def __init__(self, raw=b'{"x":1}', headers=None):
            self.raw_content = raw
            self.status_code = 200
            self.headers = ScriptBodyEncoding._Headers(headers or {"content-type": "application/json"})

        def get_content(self, strict=False):
            return self.raw_content

        def set_content(self, content):
            self.raw_content = content

    class _Headers(dict):
        def items(self, multi=True):
            return list(dict.items(self))

        def set_all(self, name, values):
            self[name] = values[0] if len(values) == 1 else values

    def test_apply_json_null_false_true_and_number_stay_json(self):
        sys.path.insert(0, os.path.join(harness.REPO, "addons"))
        import proxy_scripts
        for value, expected in ((None, b"null"), (False, b"false"), (True, b"true"), (0, b"0"), (1.5, b"1.5")):
            msg = self._Msg()
            changed = proxy_scripts.ProxyScripts._apply(
                msg, {"body": value, "headers": {"content-type": "application/json"}}, response=True)
            self.assertTrue(changed, repr(value))
            self.assertEqual(msg.raw_content, expected, repr(value))

    def test_apply_bytes_body_is_not_str_repr(self):
        sys.path.insert(0, os.path.join(harness.REPO, "addons"))
        import proxy_scripts
        msg = self._Msg(raw=b"old")
        proxy_scripts.ProxyScripts._apply(msg, {"body": b"raw-bytes"}, response=True)
        self.assertEqual(msg.raw_content, b"raw-bytes")


class ListErrorsThroughSymlink(unittest.TestCase):
    def test_live_error_is_shown_when_the_rules_path_goes_through_a_symlink(self):
        # review 0.9.7 #6: the CLI passes the rules path as given (abspath) and the proxy reports its realpath
        import subprocess
        import tempfile
        base = tempfile.mkdtemp(prefix="rivis-t-%s-symlink-" % os.environ.get("RIVIS_TEST_RUN", "x"))
        try:
            real = os.path.join(base, "real")
            os.makedirs(real)
            os.symlink(real, os.path.join(base, "link"))
            with open(os.path.join(real, "rules.json"), "w") as fh:
                json.dump({"rules": [], "scripts": [{"name": "boom", "file": "boom.py", "lang": "py", "enabled": True}]}, fh)
            state = {"rules_file": os.path.realpath(os.path.join(real, "rules.json")),
                     "script_status": {"errors": {"boom.py": {"message": "NameError: oops\nTraceback"}}}}
            r = subprocess.run([sys.executable, "-I", os.path.join(harness.REPO, "addons", "scripts_cli.py"),
                                os.path.join(base, "link", "rules.json"), "list", "--errors-stdin"],
                               input=json.dumps(state), capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("ERROR: NameError: oops", r.stdout)
        finally:
            shutil.rmtree(base, ignore_errors=True)


# review 0.9.7 #9: a script that finishes right at the timeout must not get its pool thread's NEXT script stopped.
# Deterministic: wait_for lets the first job finish, starts a second job on the same (single) worker thread, and only
# then reports the timeout, exactly the window the review describes.
_STOP_RACE_PROBE = r"""
import asyncio, concurrent.futures, sys, threading, time
sys.path.insert(0, sys.argv[1])
import proxy_scripts as ps
ps._py_pool = concurrent.futures.ThreadPoolExecutor(1)
started, result = threading.Event(), {}
def second():
    started.set()
    try:
        end = time.monotonic() + 1.5
        while time.monotonic() < end:
            pass
        result["second"] = "clean"
    except ps.ScriptTimeout:
        result["second"] = "stopped by the first script's timeout"
real_wait_for = asyncio.wait_for
async def finished_at_the_deadline(aw, timeout):
    await aw
    fut = ps._py_pool.submit(second)
    while not started.is_set():
        await asyncio.sleep(0.01)
    raise asyncio.TimeoutError()
async def main():
    asyncio.wait_for = finished_at_the_deadline
    try:
        await ps._in_worker(lambda: "first", ())
    except asyncio.TimeoutError:
        pass
    asyncio.wait_for = real_wait_for
asyncio.run(main())
ps._py_pool.shutdown(wait=True)
print(result.get("second"))
"""


class StopRace(unittest.TestCase):
    def test_timeout_never_lands_on_the_next_script_in_the_same_worker(self):
        import subprocess
        r = subprocess.run([sys.executable, "-I", "-c", _STOP_RACE_PROBE, os.path.join(harness.REPO, "addons")],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip().splitlines()[-1], "clean", r.stdout + r.stderr)


def _ws_echo_through_proxy(proxy_port, path="/ws", payload=b"hello-ws"):
    """Open a WebSocket through the proxy to a local echo server; return once one text frame has round-tripped."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    done = threading.Event()

    def ws_server():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            req = b""
            while b"\r\n\r\n" not in req:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                req += chunk
            key = [line.split(b":", 1)[1].strip() for line in req.split(b"\r\n")
                   if line.lower().startswith(b"sec-websocket-key")][0]
            accept = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                         b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")
            data = conn.recv(4096)
            ln = data[1] & 0x7F
            mask, body = data[2:6], data[6:6 + ln]
            text = bytes(b ^ mask[i % 4] for i, b in enumerate(body))
            conn.sendall(b"\x81" + bytes([len(text)]) + text)
            done.wait(2)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    threading.Thread(target=ws_server, daemon=True).start()
    proxy = socket.create_connection(("127.0.0.1", proxy_port), 5)
    try:
        proxy.sendall(("GET http://127.0.0.1:%d%s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                       "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
                       % (port, path, port)).encode())
        proxy.settimeout(5)
        head = b""
        while b"\r\n\r\n" not in head:
            head += proxy.recv(4096)
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise AssertionError("WebSocket upgrade failed: %r" % head.split(b"\r\n")[0])
        mask = b"\x01\x02\x03\x04"
        proxy.sendall(b"\x81" + bytes([0x80 | len(payload)]) + mask +
                      bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
        frame = head.split(b"\r\n\r\n", 1)[1]
        while len(frame) < 2 + len(payload):
            frame += proxy.recv(4096)
        if frame[2:2 + len(payload)] != payload:
            raise AssertionError("echo mismatch: got %r" % frame[2:2 + len(payload)])
    finally:
        done.set()
        try:
            proxy.close()
        except OSError:
            pass
        srv.close()


class WebsocketScripts(ScriptCase):
    def test_on_websocket_sees_payload_and_tags_the_flow(self):
        # Without the hook, an enabled script never runs for WebSocket frames — chat bugs stay invisible.
        # Context + a follow-up HTTP call proves the frame text was seen (mitmweb's info log is not always in the
        # process capture); the flow comment proves the hook ran.
        self.install("wslog.py", '''
def on_websocket(context, url, message):
    log("[%s] %s: %s" % (message["from"], message["type"], message["data"]))
    context["last_ws"] = message["data"]

def on_request(context, url, request):
    if "/echo" in url and "last_ws" in context:
        request["headers"]["X-Last-Ws"] = context["last_ws"]
        return request
''', match=r"wslog=1|/echo\?afterws")
        _ws_echo_through_proxy(self.inst.proxy_port, path="/ws?wslog=1", payload=b"chat-payload-42")
        flow = wait_for(lambda: self.inst.flow_for("wslog=1"), 10, 0.1, "websocket flow")
        self.assertIn("script:wslog", flow.get("comment") or "",
                      "on_websocket must tag the call the way on_request does")
        doc = self.fetch("/echo?afterws=1").json()
        hdr = {k.lower(): v for k, v in doc["headers"]}
        self.assertEqual(hdr.get("x-last-ws"), "chat-payload-42",
                         "on_websocket must see the text frame payload (got %r)" % hdr)

    def test_websocket_template_source_logs_messages(self):
        made = self.panel.ok("script_new", {"name": "ws-tpl", "lang": "py", "template": "websocket",
                                            "match": "/never-ws"})
        self.assertEqual(made["file"], "ws-tpl.py")
        content = self.panel.ok("script_get", {"file": "ws-tpl.py"})["content"]
        self.assertIn("on_websocket", content)
        self.assertIn("message", content)
        self.assertIn("log(", content)
        js = self.panel.ok("script_new", {"name": "ws-tpl-js", "lang": "js", "template": "websocket",
                                          "match": "/never-ws"})
        js_src = self.panel.ok("script_get", {"file": js["file"]})["content"]
        self.assertIn("onWebsocket", js_src)

    @needs_node
    def test_javascript_onWebsocket_sees_payload(self):
        self.install("wslog.js", '''
async function onWebsocket(context, url, message) {
  log(`[${message.from}] ${message.type}: ${message.data}`);
  context.last_ws = message.data;
}
async function onRequest(context, url, request) {
  if (url.includes("/echo") && context.last_ws) {
    request.headers["X-Last-Ws"] = context.last_ws;
    return request;
  }
}
''', match=r"wslogjs=1|/echo\?afterwsjs")
        _ws_echo_through_proxy(self.inst.proxy_port, path="/ws?wslogjs=1", payload=b"js-frame-99")
        flow = wait_for(lambda: self.inst.flow_for("wslogjs=1"), 10, 0.1, "websocket flow")
        self.assertIn("script:wslog", flow.get("comment") or "")
        doc = self.fetch("/echo?afterwsjs=1").json()
        hdr = {k.lower(): v for k, v in doc["headers"]}
        self.assertEqual(hdr.get("x-last-ws"), "js-frame-99")


if __name__ == "__main__":
    unittest.main(verbosity=2)
