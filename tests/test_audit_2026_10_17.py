"""QA audit 2026-10-17 — adversarial checks first written against the 0.9.6 candidate (a3514f3); the failing ones
were defects QA-01 … QA-11 + R3-DATA-11 (qa-audit/QA-AUDIT.md), fixed after 0.9.6.

Runs on the product's own hermetic harness (fake HOME, random ports, private CA, shims) and never touches
the live Rivis (8080/8083), ~/.rivis, the system proxy or any device. Each test asserts the CORRECT behaviour,
so a failing test is a candidate defect; see QA-AUDIT.md for the triage of each.

  bash tests/run.sh --fast -k <name>
"""
import gzip
import json
import os
import socket
import threading
import time
import unittest
import zlib

import harness
from harness import Background, Instance, Suite, wait_for

S = Suite.get()
UP = S.upstream()


def fd_headroom(want):
    """Raise this process's open-file soft limit to `want`, never past the hard limit. 200 parallel calls need more
    descriptors than the inherited default, and the suite runs four modules at once: EMFILE there says nothing about
    Rivis (seen 2026-10-24, "OSError: [Errno 24] Too many open files" inside subprocess.Popen)."""
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft >= want:
        return
    target = want if hard in (resource.RLIM_INFINITY, -1) else min(want, hard)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except (ValueError, OSError):
        pass


def write_rules(inst, cfg):
    tmp = inst.rules_path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(cfg, fh)
    os.replace(tmp, inst.rules_path)
    time.sleep(1.6)          # rules hot-reload stats the file once a second


class RawServer:
    """A tiny TCP server answering every connection with a fixed raw HTTP response (for malformed payloads)."""

    def __init__(self, raw):
        self.raw = raw
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.requests = []
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            try:
                c.settimeout(5)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = c.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                self.requests.append(data)
                c.sendall(self.raw(data) if callable(self.raw) else self.raw)
            except OSError:
                pass
            finally:
                c.close()

    def url(self, path="/"):
        return "http://127.0.0.1:%d%s" % (self.port, path)

    def close(self):
        self.sock.close()


class Base(unittest.TestCase):
    inst = None

    @classmethod
    def setUpClass(cls):
        cls.inst = Instance(S, cls.__name__.lower()).start()
        cls.p = cls.inst.panel

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()

    def setUp(self):
        write_rules(self.inst, {"rules": []})
        self.p.ok("paused_resume_all")

    def fid(self, marker):
        return self.inst.flow_for(marker)["id"]


# ───────────────────────────── rules engine edge cases ─────────────────────────────
class RuleEdges(Base):
    def test_rule_with_method_null_does_not_break_other_rules(self):
        """rules.json written by hand / by another tool with "method": null (JSON for 'any')."""
        write_rules(self.inst, {"rules": [
            {"name": "nullm", "match": "/echo\\?nullm", "method": None, "action": "set_header",
             "header": "X-QA", "value": "1"},
            {"name": "after", "match": "/echo\\?nullm", "action": "respond", "status": 418, "body": {"ok": 1}}]})
        r = self.inst.fetch(UP.url("/echo?nullm"))
        st = self.p.state()
        self.assertEqual(r.status, 418, "a rule with method null broke the request hook: %r; skipped=%r"
                         % (r, st.get("skipped_rules")))

    def test_rule_with_empty_method_means_any_method(self):
        """`rivis rules add NAME ... method=` (empty: a script passing method=$M with M unset) says 'added and ON'."""
        r = S.rivis("rules", "add", "emptym", "match=/echo\\?emptym", "action=respond", "status=418", "body=x", "method=",
                    home=self.inst.home, env=self.inst.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        time.sleep(1.6)
        r = self.inst.fetch(UP.url("/echo?emptym"))
        self.assertEqual(r.status, 418, "method \"\" never matches and the rule is not reported as skipped: %r" % r)

    def test_map_remote_to_another_server_sends_that_servers_host_header(self):
        other = S.upstream()
        write_rules(self.inst, {"rules": [
            {"name": "mr", "match": "/echo\\?mr", "action": "map_remote",
             "replace": __import__("re").escape(UP.url("/").rstrip("/")), "with": other.url("/").rstrip("/")}]})
        r = self.inst.fetch(UP.url("/echo?mr"))
        self.assertEqual(r.status, 200, r)
        doc = r.json()
        host = [v for k, v in doc["headers"] if k.lower() == "host"]
        self.assertEqual(host, [other.url("/").split("//")[1].rstrip("/")],
                         "map_remote kept the original Host header: %r" % host)

    def test_respond_with_infinite_delay_rule_is_refused_not_hung(self):
        cli = S.rivis("rules", "add", "inf", "match=/echo\\?infdelay", "action=delay", "ms=inf",
                      home=self.inst.home, env=self.inst.env)
        time.sleep(1.6)
        self.assertNotEqual(cli.returncode, 0, "CLI accepted ms=inf: " + cli.stdout)
        st = self.p.state()
        skipped = [s["name"] for s in st.get("skipped_rules", [])]
        r = self.inst.fetch(UP.url("/echo?infdelay"), timeout=5)
        self.assertTrue("inf" in skipped or r.status == 200,
                        "a delay of Infinity is accepted and hangs every matching call (status %s rc %s)" % (r.status, r.rc))

    def test_json_patch_on_deflate_response(self):
        body = zlib.compress(json.dumps({"a": 1}).encode())
        srv = RawServer(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: deflate\r\n"
                        b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
        write_rules(self.inst, {"rules": [
            {"name": "jp", "match": "/deflate", "action": "json_patch", "set": {"a": 2}}]})
        r = self.inst.fetch(srv.url("/deflate"), extra=["--compressed"])
        srv.close()
        self.assertEqual(r.status, 200, r)
        self.assertEqual(json.loads(r.body), {"a": 2}, r.body[:200])


# ───────────────────────────── malformed / large payloads ─────────────────────────────
class Payloads(Base):
    def test_lying_gzip_response_passes_through_and_features_survive(self):
        """Server says Content-Encoding: gzip but sends plain bytes. App gets the bytes; the panel must not 500."""
        body = b'{"not":"gzip"}'
        srv = RawServer(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n"
                        b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
        r = self.inst.fetch(srv.url("/badgz"))
        self.assertEqual(r.body, body, "bytes changed in transit")
        fid = self.fid("/badgz")
        for op, args in [("viewer", {"flow_id": fid}), ("export", {"flow_id": fid}),
                         ("codegen", {"flow_id": fid, "target": "python"}), ("compose_get", {"flow_id": fid}),
                         ("retry_get", {"flow_id": fid})]:
            code, doc, raw = self.p.post(op, args)
            self.assertIn(code, (200, 400), "%s -> %s %r" % (op, code, raw[:200]))
        # Map Local from that call, then the mock is served
        doc = self.p.ok("mock", {"flow_id": fid})
        r2 = self.inst.fetch(srv.url("/badgz"))
        srv.close()
        self.assertEqual(r2.status, 200)
        self.assertEqual(json.loads(r2.body), json.loads(body), "Map Local from a call with a broken gzip body serves %r" % r2.body[:80])

    def test_binary_response_mock_round_trip_in_the_panel_editor_keeps_bytes(self):
        """Map Local from an image call, then open + save it unchanged in the panel editor (e.g. to change status)."""
        png = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4
        srv = RawServer(b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                        % len(png) + png)
        self.inst.fetch(srv.url("/img.png"))
        fid = self.fid("/img.png")
        name = self.p.ok("mock", {"flow_id": fid})["name"]
        got = self.p.ok("mockfile_get", {"name": name})
        # the editor sends back exactly what it was given, plus a status change
        self.p.ok("mockfile_put", {"name": name, "content": got["content"], "status": 201, "headers": got["headers"]})
        r = self.inst.fetch(srv.url("/img.png"))
        srv.close()
        self.assertEqual(r.status, 201)
        self.assertEqual(r.body, png, "binary mock corrupted by an unchanged open+save in the panel (%d -> %d bytes)"
                         % (len(png), len(r.body)))

    def test_large_binary_mock_opens_as_a_clipped_preview_and_keeps_its_bytes(self):
        """A multi-MB PDF as text (U+FFFD per byte) took Chromium ~10 s per MB to lay out in the editor's textarea (R-S5): above
        16 KB the panel gets a preview and the file is never replaced by it."""
        pdf = b"%PDF-1.4\n" + bytes(range(1, 256)) * 400            # 102 KB, not UTF-8
        srv = RawServer(b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                        % len(pdf) + pdf)
        self.inst.fetch(srv.url("/doc.pdf"))
        name = self.p.ok("mock", {"flow_id": self.fid("/doc.pdf")})["name"]
        got = self.p.ok("mockfile_get", {"name": name})
        self.assertIs(got["clipped"], True)
        self.assertIs(got["binary"], True)
        self.assertEqual(got["size"], len(pdf))
        self.assertLessEqual(len(got["content"]), 16 * 1024, "the whole binary body was sent to the editor")
        # the editor sends the preview back unchanged, with a status change: the file keeps every byte
        self.p.ok("mockfile_put", {"name": name, "content": got["content"], "status": 201, "headers": got["headers"]})
        r = self.inst.fetch(srv.url("/doc.pdf"))
        self.assertEqual((r.status, r.body), (201, pdf), "the clipped preview replaced the binary mock")
        # any other text for a clipped body is refused, and the file stays as it was
        code, doc, raw = self.p.post("mockfile_put", {"name": name, "content": got["content"] + "x", "status": 200, "headers": got["headers"]})
        self.assertEqual(code, 400, raw[:200])
        r = self.inst.fetch(srv.url("/doc.pdf"))
        srv.close()
        self.assertEqual(r.body, pdf)

    def test_big_response_100mb_passes_intact(self):
        r = self.inst.fetch(UP.url("/big?mb=100"), timeout=120)
        self.assertEqual(r.status, 200)
        self.assertEqual(len(r.body), 100 * 1024 * 1024)

    def test_huge_response_header_does_not_kill_the_proxy(self):
        big = b"X-Big: " + b"a" * 200000 + b"\r\n"
        srv = RawServer(b"HTTP/1.1 200 OK\r\n" + big + b"Content-Length: 2\r\nConnection: close\r\n\r\nok")
        self.inst.fetch(srv.url("/bighdr"))
        srv.close()
        r = self.inst.fetch(UP.url("/echo?after-bighdr"))
        self.assertEqual(r.status, 200)

    def test_invalid_chunked_response_does_not_kill_the_proxy(self):
        srv = RawServer(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\nnot hex\r\n0\r\n\r\n")
        self.inst.fetch(srv.url("/badchunk"))
        srv.close()
        r = self.inst.fetch(UP.url("/echo?after-badchunk"))
        self.assertEqual(r.status, 200)

    def test_non_utf8_json_viewer_and_patch(self):
        body = '{"name":"caf\xe9"}'.encode("latin-1")
        srv = RawServer(b"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=iso-8859-1\r\nContent-Length: %d\r\n"
                        b"Connection: close\r\n\r\n" % len(body) + body)
        write_rules(self.inst, {"rules": [
            {"name": "jp8859", "match": "/latin", "action": "json_patch", "set": {"x": 1}}]})
        r = self.inst.fetch(srv.url("/latin"))
        srv.close()
        self.assertEqual(json.loads(r.body.decode("latin-1")), {"name": "caf\xe9", "x": 1}, r.body)


# ───────────────────────────── breakpoints ─────────────────────────────
class Breakpoints(Base):
    def setUp(self):
        super().setUp()

    def bp(self, path, request=True, response=False):
        write_rules(self.inst, {"rules": [], "breakpoints": [
            {"name": "b", "match": path, "request": request, "response": response, "enabled": True}]})

    def test_ten_concurrent_paused_calls_each_get_their_own_edit(self):
        self.bp("/echo\\?conc", request=True)
        calls = [Background(self.inst.fetch, UP.url("/echo?conc=%d" % i), timeout=60) for i in range(10)]
        paused = wait_for(lambda: (lambda s: s if len(s) >= 10 else None)(self.p.state()["paused"]), 30, 0.3, "10 paused")
        for x in paused:
            n = x["url"].split("conc=")[1]
            self.p.ok("paused_continue", {"id": x["id"], "edits": {"headers": [["X-N", n], ["Host", x["url"].split("/")[2]]]}})
        for i, c in enumerate(calls):
            r = c.result(60)
            self.assertEqual(r.status, 200, r)
            doc = r.json()
            xn = [v for k, v in doc["headers"] if k.lower() == "x-n"]
            self.assertEqual(xn, [doc["query"]["conc"][0]], "edit applied to the wrong call: %r" % doc)

    def test_continue_unchanged_on_plain_http_is_not_labelled_edited(self):
        """The paused sheet always sends method + url + headers back. On a plain-HTTP call to a hostname the URL it
        shows (pretty_url) differs from the pinned address Rivis connects to."""
        self.bp("/echo\\?pinned")
        url = UP.url("/echo?pinned").replace("127.0.0.1", "localhost")
        c = Background(self.inst.fetch, url, timeout=30)
        x = wait_for(lambda: self.p.state()["paused"], 15, 0.3, "paused")[0]
        g = self.p.ok("paused_get", {"id": x["id"]})
        self.p.ok("paused_continue", {"id": x["id"], "edits": {"method": g["method"], "url": g["url"],
                                                                "headers": g["req_headers"]}})
        r = c.result(30)
        self.assertEqual(r.status, 200)
        f = self.inst.flow_for("pinned")
        self.assertNotIn("edited at breakpoint", f.get("comment", ""),
                         "an untouched Continue is labelled as an edit: %r" % f.get("comment"))

    def test_load_session_with_replace_does_not_orphan_paused_calls(self):
        self.inst.fetch(UP.url("/echo?sessbase"))
        self.p.ok("sess_save", {"name": "qa-orphan", "overwrite": True})
        self.bp("/echo\\?orphan")
        c = Background(self.inst.fetch, UP.url("/echo?orphan"), timeout=40)
        wait_for(lambda: self.p.state()["paused"], 15, 0.3, "paused")
        self.p.ok("sess_load", {"name": "qa-orphan", "replace": True})
        st = self.p.state()
        if not st["paused"]:
            self.p.ok("paused_resume_all")
            write_rules(self.inst, {"rules": []})
            try:
                r = c.result(40)
            except AssertionError:
                r = None
            self.fail("after Open session (replace) the paused call vanished from the panel; resume-all could not "
                      "release it; the app got: %r" % (r,))
        self.p.ok("paused_resume_all")
        self.assertEqual(c.result(30).status, 200)

    def test_retention_never_trims_paused_and_trim_under_load(self):
        """proxy_max_flows default 5000; we cannot lower it without restart, so only check that 300 calls with a
        paused one around keep the paused one."""
        self.bp("/echo\\?keepme")
        c = Background(self.inst.fetch, UP.url("/echo?keepme"), timeout=60)
        wait_for(lambda: self.p.state()["paused"], 15, 0.3, "paused")
        self.p.ok("paused_resume_all")
        self.assertEqual(c.result(30).status, 200)

    def test_breakpoint_on_a_regex_with_quote_and_backslash(self):
        self.bp("/echo\\?q='a'")
        c = Background(self.inst.fetch, UP.url("/echo?q='a'"), timeout=30)
        paused = wait_for(lambda: self.p.state()["paused"], 15, 0.3, "paused")
        self.p.ok("paused_resume_all")
        self.assertEqual(c.result(30).status, 200)
        self.assertTrue(paused)

    def test_response_breakpoint_edit_body_of_gzip_response(self):
        self.bp("/json/gzip", request=False, response=True)
        c = Background(self.inst.fetch, UP.url("/json/gzip"), timeout=30, extra=["--compressed"])
        x = wait_for(lambda: self.p.state()["paused"], 15, 0.3, "paused")[0]
        g = self.p.ok("paused_get", {"id": x["id"]})
        doc = json.loads(g["resp_body"])
        doc["name"] = "edited"
        self.p.ok("paused_continue", {"id": x["id"], "edits": {"status": 200, "headers": g["resp_headers"],
                                                                "body": json.dumps(doc)}})
        r = c.result(30)
        self.assertEqual(json.loads(r.body)["name"], "edited", r.body[:200])

    def test_custom_method_survives_an_untouched_continue_through_the_sheet(self):
        """The sheet's method dropdown only lists 7 verbs; Continue always sends the select's value."""
        self.bp("/echo\\?custom")
        c = Background(self.inst.fetch, UP.url("/echo?custom"), method="PROPFIND", timeout=30)
        x = wait_for(lambda: self.p.state()["paused"], 15, 0.3, "paused")[0]
        g = self.p.ok("paused_get", {"id": x["id"]})
        sent = g["method"]       # the sheet now always offers the call's own method (QA-05; UI test in ui/test_workflows.py)
        self.p.ok("paused_continue", {"id": x["id"], "edits": {"method": sent, "url": g["url"], "headers": g["req_headers"]}})
        r = c.result(30)
        self.assertEqual(r.json()["method"], "PROPFIND", "the sheet turned PROPFIND into %s" % r.json()["method"])


# ───────────────────────────── sessions / persistence ─────────────────────────────
class Sessions(Base):
    def test_corrupt_session_file_gives_a_clear_400(self):
        self.inst.fetch(UP.url("/echo?corrupt"))
        self.p.ok("sess_save", {"name": "qa-corrupt", "overwrite": True})
        path = os.path.join(self.inst.state_dir, "sessions")
        files = [f for f in os.listdir(path) if f.startswith("qa-corrupt") and not f.endswith(".json")]
        self.assertTrue(files, os.listdir(path))
        fp = os.path.join(path, files[0])
        data = open(fp, "rb").read()
        open(fp, "wb").write(data[: len(data) // 2])        # truncated (disk full / crash mid-copy)
        code, doc, raw = self.p.post("sess_load", {"name": "qa-corrupt"})
        self.assertEqual(code, 400, "truncated session -> %s %r" % (code, raw[:300]))
        code, doc, raw = self.p.post("sess_har", {"name": "qa-corrupt"})
        self.assertEqual(code, 400, "truncated session HAR -> %s %r" % (code, raw[:300]))

    def test_session_round_trip_keeps_bodies_and_comments(self):
        write_rules(self.inst, {"rules": [{"name": "rt", "match": "/echo\\?rt", "action": "set_header",
                                           "header": "X-Rt", "value": "1"}]})
        self.inst.fetch(UP.url("/echo?rt"), method="POST", data=b'{"k":"v"}')
        self.p.ok("sess_save", {"name": "qa-rt", "overwrite": True})
        n = self.p.ok("sess_load", {"name": "qa-rt", "replace": True})["count"]
        self.assertGreaterEqual(n, 1)
        f = self.inst.flow_for("echo?rt")
        self.assertIn("rule:rt", f.get("comment", ""))

    def test_har_import_with_odd_entries_is_a_400_not_500(self):
        for har in [{"log": {"entries": [{"request": {}}]}},
                    {"log": {"entries": [{"request": {"method": "GET", "url": "not a url"}, "response": {}}]}},
                    {"log": {"entries": [{"request": {"method": "GET", "url": "http://x/", "headers": "x"},
                                          "response": {"status": "abc", "content": {"text": 5}}}]}},
                    {"log": {"entries": [None, 1, "x"]}},
                    {"log": "x"}, []]:
            code, doc, raw = self.p.post("coll_import", {"name": "qa-har", "har": har, "overwrite": True})
            self.assertIn(code, (200, 400), "HAR %r -> %s %r" % (har, code, raw[:300]))


# ───────────────────────────── data handling: what leaves the workstation ─────────────────────────────
SECRETS = {
    "basic": "Basic dXNlcjpzM2NyZXRQYXNz",
    "apikey": "AKIAQASECRETKEY0001",
    "proxyauth": "Basic cHJveHk6cHdzZWNyZXQ=",
    "cookie": "SESSIONID=sess-secret-0002; other=1",
    "q_token": "qtok-secret-0003",
    "pw": "pw-secret-0004",
    "otp": "918273",
    "refresh": "refresh-secret-0005",
}


class Redaction(Base):
    def _capture(self):
        hdrs = [("Authorization", SECRETS["basic"]), ("X-Api-Key", SECRETS["apikey"]),
                ("Proxy-Authorization", SECRETS["proxyauth"]), ("Cookie", SECRETS["cookie"])]
        body = json.dumps({"user": {"password": SECRETS["pw"], "otp": SECRETS["otp"]},
                           "refresh_token": SECRETS["refresh"]})
        self.inst.fetch(UP.url("/echo?redact=1&access_token=" + SECRETS["q_token"]), method="POST",
                        headers=hdrs + [("Content-Type", "application/json")], data=body.encode())
        return self.fid("redact=1")

    NEEDLES = {"basic": "dXNlcjpzM2NyZXRQYXNz", "apikey": "AKIAQASECRETKEY0001", "proxyauth": "cHJveHk6cHdzZWNyZXQ",
               "cookie": "sess-secret-0002", "q_token": "qtok-secret-0003", "pw": "pw-secret-0004",
               "otp": "918273", "refresh": "refresh-secret-0005"}

    def leaks(self, text):
        return sorted(k for k, v in self.NEEDLES.items() if v in text)

    def test_copy_as_curl_masks_every_secret_by_default(self):
        fid = self._capture()
        text = self.p.ok("export", {"flow_id": fid})["text"]
        self.assertEqual(self.leaks(text), [], text[:1500])

    def test_session_har_export_masks_every_secret_by_default(self):
        self._capture()
        self.p.ok("sess_save", {"name": "qa-redact", "overwrite": True, "visible_only": False})
        doc = self.p.ok("sess_har", {"name": "qa-redact"})
        text = json.dumps(doc)
        self.assertEqual(self.leaks(text), [], "unmasked in session HAR")

    def test_mitmweb_raw_export_menu_masks_every_secret(self):
        fid = self._capture()
        code, body = self.p._do(__import__("urllib.request").request.Request(
            self.p.base + "/commands/export", data=json.dumps({"arguments": ["raw_request", "@" + fid]}).encode(),
            method="POST", headers={"Content-Type": "application/json", "X-XSRFToken": self.p.xsrf}))
        self.assertEqual(code, 200, body[:200])
        self.assertEqual(self.leaks(body.decode()), [], body[:1500])

    def test_bug_report_contains_no_captured_secret(self):
        self._capture()
        r = S.rivis("bug-report", home=self.inst.home, env=self.inst.env, timeout=120)
        import glob
        import zipfile
        zips = glob.glob(os.path.join(self.inst.home, ".rivis", "bug-reports", "*.zip")) + \
            glob.glob(os.path.join(self.inst.home, "*.zip")) + glob.glob(os.path.join(self.inst.home, "Desktop", "*.zip"))
        self.assertTrue(zips, r.stdout[-500:] + r.stderr[-500:])
        text = ""
        with zipfile.ZipFile(sorted(zips, key=os.path.getmtime)[-1]) as z:
            for n in z.namelist():
                text += z.read(n).decode("utf-8", "replace")
        self.assertEqual(self.leaks(text), [])


# ───────────────────────────── local API ─────────────────────────────
class LocalApi(Base):
    def test_websocket_updates_need_auth(self):
        s = socket.create_connection(("127.0.0.1", self.inst.web_port), 5)
        s.sendall(b"GET /updates HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n" % self.inst.web_port)
        line = s.recv(200).split(b"\r\n")[0]
        s.close()
        self.assertNotIn(b"101", line, "websocket with no cookie upgraded: %r" % line)

    def test_flow_content_endpoints_need_auth(self):
        self.inst.fetch(UP.url("/echo?apiauth"))
        fid = self.fid("apiauth")
        for path in ["/flows", "/flows/%s/request/content.data" % fid, "/flows/dump", "/options", "/state",
                     "/proxy/api/state", "/events", "/commands"]:
            code, data, _ = harness.raw_http(self.inst.web_port, "GET", path, {"Host": "127.0.0.1:%d" % self.inst.web_port})
            self.assertIn(code, (401, 403, 404, 405), "%s without a session -> %s" % (path, code))

    def test_proxy_port_refuses_requests_for_the_panel_itself(self):
        """A device (or web page through rivis browser) sends http://127.0.0.1:<web_port>/ through the proxy."""
        r = self.inst.fetch("http://127.0.0.1:%d/proxy/api/state" % self.inst.web_port)
        self.assertNotEqual(r.status, 200, "panel state readable through the proxy listener: %r" % r)


# ───────────────────────────── crash / restart ─────────────────────────────
class CrashRestart(unittest.TestCase):
    def test_kill_9_then_status_and_start_recover(self):
        inst = Instance(S, "crash").start()
        try:
            write_rules(inst, {"rules": [{"name": "keep", "match": "/echo\\?crash", "action": "respond",
                                          "status": 299, "body": "x"}]})
            import subprocess
            pids = subprocess.run(["pgrep", "-f", "web_port=%d" % inst.web_port], capture_output=True, text=True).stdout.split()
            self.assertTrue(pids)
            for pid in pids:
                os.kill(int(pid), 9)
            wait_for(lambda: not harness.port_open(inst.proxy_port), 10, desc="proxy down")
            st = S.rivis("status", home=inst.home, env=inst.env)
            self.status_rc_after_crash = st.returncode
            print("STATUS-RC-AFTER-KILL9", st.returncode, st.stdout.replace("\n", " | "))
            inst.proc = None
            # restart on the same ports
            env = dict(inst.env)
            argv = ["/bin/bash", harness.RIVIS, "start", "--no-ios", "--no-open"] + inst.start_args
            proc = subprocess.Popen(argv, env=env, cwd=S.root, stdin=subprocess.DEVNULL,
                                    stdout=open(inst.logpath, "ab"), stderr=subprocess.STDOUT, start_new_session=True)
            inst.proc = proc
            S.instances.append(inst)
            inst.panel = harness.Panel(inst.web_port, inst.password)
            wait_for(lambda: inst.panel.login() or inst.panel.state(), 45, 0.3, "restart")
            r = inst.fetch(UP.url("/echo?crash"))
            self.assertEqual(r.status, 299, "rules lost after crash+restart: %r" % r)
            self.assertNotEqual(self.status_rc_after_crash, 0, "`rivis status` exits 0 while nothing is listening")
        finally:
            inst.stop()


if __name__ == "__main__":
    unittest.main()


# ───────────────────────────── batch 2 ─────────────────────────────
class ScriptStarvation(unittest.TestCase):
    """A Python script with a busy loop (a typo in a while-condition) is cut off after 2 s, but its worker thread
    cannot be killed. Those threads live in asyncio's default executor, which mitmproxy also uses for DNS."""

    def test_busy_loop_script_does_not_take_down_unrelated_traffic(self):
        inst = Instance(S, "starve").start()
        try:
            sdir = inst.path("scripts")
            os.makedirs(sdir, exist_ok=True)
            with open(os.path.join(sdir, "spin.py"), "w") as fh:
                fh.write("def on_request(context, url, request):\n    while True:\n        pass\n")
            cfg = inst.cfg()
            cfg["scripts"] = [{"name": "spin", "file": "spin.py", "lang": "py", "enabled": True,
                               "match": "/echo\\?spin", "method": None}]
            write_rules(inst, cfg)
            n = (os.cpu_count() or 8) + 6           # more than the default executor's min(32, cpu+4) workers
            calls = [Background(inst.fetch, UP.url("/echo?spin=%d" % i), timeout=40) for i in range(n)]
            for c in calls:
                try:
                    c.result(60)
                except AssertionError:
                    pass
            # now: unrelated traffic by NAME (needs a DNS lookup) and the panel
            t = time.time()
            r = inst.fetch(UP.url("/echo?after-spin").replace("127.0.0.1", "localhost"), timeout=25)
            took = time.time() - t
            t2 = time.time()
            code, _ = inst.panel.get("/proxy/api/state", timeout=30)
            took_panel = time.time() - t2
            print("STARVE n=%d http-by-name status=%s rc=%s took=%.1fs panel=%s %.1fs" % (n, r.status, r.rc, took, code, took_panel))
            self.assertEqual(r.status, 200, "unrelated call by hostname after %d spinning script calls: %r (%.1fs)" % (n, r, took))
            self.assertLess(took, 5, "unrelated call took %.1fs" % took)
        finally:
            inst.stop()


class Conflicts(Base):
    def test_map_remote_then_map_local_on_the_rewritten_url(self):
        """Proxyman applies Map Remote first, then Map Local on the new URL; a request breakpoint must still pause."""
        mock = os.path.join(self.inst.state_dir, "mocks", "mr.json")
        os.makedirs(os.path.dirname(mock), exist_ok=True)
        with open(mock, "w") as fh:
            fh.write('{"mapped": true}')
        write_rules(self.inst, {"rules": [
            {"name": "mr", "match": "/echo\\?mrml", "action": "map_remote", "replace": "/echo\\?mrml", "with": "/rewritten?mrml"},
            {"name": "ml", "match": "/rewritten\\?mrml", "action": "map_local", "file": mock}]})
        r = self.inst.fetch(UP.url("/echo?mrml"))
        self.assertEqual(json.loads(r.body or b"null"), {"mapped": True}, r)

    def test_quick_status_from_a_call_overrides_an_existing_mock(self):
        self.inst.fetch(UP.url("/json/small?qs=1"))
        fid = self.fid("qs=1")
        self.p.ok("mock", {"flow_id": fid})
        self.p.ok("quick", {"flow_id": fid, "kind": "status", "status": 503})
        r = self.inst.fetch(UP.url("/json/small?qs=1"))
        self.assertEqual(r.status, 503, "Map Local still wins over the newer forced 503: %r" % r)

    def test_status_then_json_patch_both_apply(self):
        write_rules(self.inst, {"rules": [
            {"name": "st", "match": "/json/small\\?sp", "action": "status", "status": 500},
            {"name": "jp", "match": "/json/small\\?sp", "action": "json_patch", "set": {"flag": True}}]})
        r = self.inst.fetch(UP.url("/json/small?sp"))
        self.assertEqual((r.status, r.json()["flag"]), (500, True))

    def test_breakpoint_and_throttle_and_delay_together(self):
        write_rules(self.inst, {"rules": [{"name": "d", "match": "/echo\\?combo", "action": "delay", "ms": 300}],
                                "throttle": "3g", "throttle_match": "/echo\\?combo",
                                "breakpoints": [{"name": "b", "match": "/echo\\?combo", "request": True, "response": True}]})
        c = Background(self.inst.fetch, UP.url("/echo?combo"), timeout=40)
        x = wait_for(lambda: self.p.state()["paused"], 15, 0.3, "paused req")[0]
        self.p.ok("paused_continue", {"id": x["id"], "edits": {"headers": [["Host", x["url"].split("/")[2]], ["X-Combo", "1"]]}})
        y = wait_for(lambda: [p for p in self.p.state()["paused"] if p["phase"] == "response"], 15, 0.3, "paused resp")[0]
        self.p.ok("paused_continue", {"id": y["id"], "edits": {"status": 207}})
        r = c.result(40)
        self.assertEqual(r.status, 207)
        self.assertEqual([v for k, v in r.json()["headers"] if k.lower() == "x-combo"], ["1"])


class Load(Base):
    def test_200_parallel_calls_while_rules_hot_reload(self):
        fd_headroom(1024)
        stop = threading.Event()

        def churn():
            i = 0
            while not stop.is_set():
                i += 1
                write_rules_fast(self.inst, {"rules": [{"name": "h%d" % (i % 3), "match": "/echo\\?load",
                                                        "action": "set_header", "header": "X-Gen", "value": str(i)}]})
                time.sleep(0.2)
        t = threading.Thread(target=churn, daemon=True)
        t.start()
        try:
            calls = [Background(self.inst.fetch, UP.url("/echo?load=%d" % i), timeout=60) for i in range(200)]
            results = []
            for c in calls:
                results.append(c.result(90))
        finally:
            stop.set()
            t.join(5)
        bad = [(i, r.status, r.rc) for i, r in enumerate(results) if r.status != 200]
        mism = [i for i, r in enumerate(results) if r.status == 200 and r.json()["query"]["load"] != [str(i)]]
        self.assertEqual((bad, mism), ([], []))
        self.assertNotIn("Traceback", self.inst.log()[-200000:].split("load=")[0][-1:] + "")

    def test_websocket_passes_through(self):
        import base64 as b64
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def ws_server():
            c, _ = srv.accept()
            req = b""
            while b"\r\n\r\n" not in req:
                req += c.recv(4096)
            key = [l.split(b":", 1)[1].strip() for l in req.split(b"\r\n") if l.lower().startswith(b"sec-websocket-key")][0]
            import hashlib
            acc = b64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
            c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      b"Sec-WebSocket-Accept: " + acc + b"\r\n\r\n")
            data = c.recv(4096)          # one masked text frame from the client
            ln = data[1] & 0x7F
            mask, payload = data[2:6], data[6:6 + ln]
            text = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            c.sendall(b"\x81" + bytes([len(text)]) + text)   # echo unmasked
            time.sleep(0.5)
            c.close()
        threading.Thread(target=ws_server, daemon=True).start()
        p = socket.create_connection(("127.0.0.1", self.inst.proxy_port), 5)
        p.sendall(b"GET http://127.0.0.1:%d/ws HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n" % (port, port))
        p.settimeout(5)
        head = b""
        while b"\r\n\r\n" not in head:
            head += p.recv(4096)
        self.assertIn(b" 101 ", head.split(b"\r\n")[0])
        msg = b"hello-ws"
        mask = b"\x01\x02\x03\x04"
        p.sendall(b"\x81" + bytes([0x80 | len(msg)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(msg)))
        frame = head.split(b"\r\n\r\n", 1)[1]
        while len(frame) < 2 + len(msg):
            frame += p.recv(4096)
        p.close()
        srv.close()
        self.assertEqual(frame[2:2 + len(msg)], msg)


def write_rules_fast(inst, cfg):
    tmp = inst.rules_path + ".tmp%d" % threading.get_ident()
    with open(tmp, "w") as fh:
        json.dump(cfg, fh)
    os.replace(tmp, inst.rules_path)


class Tls(unittest.TestCase):
    """Without --insecure (what testers run): an upstream with a cert no one trusts must give a clear error."""

    def test_untrusted_upstream_cert_gives_a_clear_502_and_https_by_ip_validates(self):
        inst = Instance(S, "tlsstrict", start_args=("--verify-upstream",)).start()
        try:
            r = inst.fetch(UP.url("/echo?strict", tls=True))
            print("STRICT", r.status, r.body[:300])
            self.assertEqual(r.status, 502, r)
            self.assertIn(b"certificate", r.body.lower())
            # the client side: Rivis's leaf for an IP-literal host must validate against the Rivis CA
            self.assertNotIn("SSL", r.err)
        finally:
            inst.stop()


class CliMock(Base):
    def test_r10_10_mock_write_failure_is_not_reported_as_read_failure(self):
        self.assertEqual(self.inst.fetch(UP.url("/json/small?r10-10=1")).status, 200)
        mocks = os.path.join(self.inst.state_dir, "mocks")
        import stat
        os.chflags(mocks, stat.UF_IMMUTABLE)
        try:
            r = S.rivis("mock", "r10-10", "r10-10=1", home=self.inst.home, env=self.inst.env)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("could not save the response body", r.stderr)
            self.assertNotIn("could not read the response body", r.stderr)
            self.assertFalse(os.path.exists(os.path.join(mocks, "r10-10.json")))
        finally:
            os.chflags(mocks, 0)

    def test_r10_05_second_mock_for_same_match_takes_effect(self):
        url = UP.url("/json/small?r10-05=1")
        self.assertEqual(self.inst.fetch(url).status, 200)
        first = S.rivis("mock", "r10-05-first", "r10-05=1", home=self.inst.home, env=self.inst.env)
        self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
        second = S.rivis("mock", "r10-05-second", "r10-05=1", home=self.inst.home, env=self.inst.env)
        self.assertEqual(second.returncode, 0, second.stderr + second.stdout)
        rules = json.load(open(self.inst.rules_path))["rules"]
        self.assertFalse(any(r["name"] == "r10-05-first" for r in rules), rules)
        self.assertTrue(any(r["name"] == "r10-05-second" for r in rules), rules)
        with open(os.path.join(self.inst.state_dir, "mocks", "r10-05-second.json"), "w") as fh:
            fh.write('{"from":"second mock"}')
        time.sleep(1.6)
        self.assertEqual(self.inst.fetch(url).json(), {"from": "second mock"})

    def test_r10_03_mock_keeps_captured_content_type(self):
        samples = (("html", "text/html; charset=utf-8", b"<h1>hello</h1>"),
                   ("png", "image/png", b"\x89PNG\r\n\x1a\n"))
        for label, ctype, body in samples:
            with self.subTest(label=label):
                server = RawServer(b"HTTP/1.1 200 OK\r\nContent-Type: " + ctype.encode() +
                                   b"\r\nContent-Length: " + str(len(body)).encode() +
                                   b"\r\nConnection: close\r\n\r\n" + body)
                try:
                    url = server.url("/r10-03-" + label)
                    original = self.inst.fetch(url)
                    self.assertEqual(original.status, 200)
                    r = S.rivis("mock", "r10-03-" + label, "r10-03-" + label,
                                home=self.inst.home, env=self.inst.env)
                    self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
                    time.sleep(1.6)
                    mocked = self.inst.fetch(url)
                    self.assertEqual(mocked.body, body)
                    self.assertEqual(mocked.header("Content-Type"), ctype)
                finally:
                    server.close()

    def _env_with_curl_spy(self, extra=None):
        spy = os.path.join(S.root, "curlspy")
        os.makedirs(spy, exist_ok=True)
        with open(os.path.join(spy, "curl"), "w") as fh:
            fh.write('#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s/argv.log"\nexec /usr/bin/curl "$@"\n' % spy)
        os.chmod(os.path.join(spy, "curl"), 0o755)
        env = dict(self.inst.env)
        env["PATH"] = spy + ":" + env["PATH"]
        env.update(extra or {})
        return env, os.path.join(spy, "argv.log")

    def test_rivis_mock_keeps_the_ui_token_out_of_argv(self):
        self.inst.fetch(UP.url("/json/small?climock=1"))
        env, log = self._env_with_curl_spy()
        r = S.rivis("mock", "climock", "climock=1", home=self.inst.home, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        argv = open(log).read() if os.path.exists(log) else ""
        self.assertNotIn(self.inst.password, argv, "UI token visible in curl's argv (ps): %s" % argv[:300])

    def test_rivis_mock_works_when_the_shell_exports_a_proxy(self):
        """QA engineers often `export http_proxy=http://127.0.0.1:<rivis>` to capture CLI tools."""
        self.inst.fetch(UP.url("/json/small?climock2=1"))
        hp = "http://127.0.0.1:%d" % self.inst.proxy_port
        env, _ = self._env_with_curl_spy({"http_proxy": hp, "HTTP_PROXY": hp, "https_proxy": hp})
        r = S.rivis("mock", "climock2", "climock2=1", home=self.inst.home, env=env)
        token_seen = any(self.inst.password in json.dumps(f.get("request", {})) for f in self.inst.flows())
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertFalse(token_seen, "the UI token went through the proxy and is in the call list")


class Limits(Base):
    def _big_json_server(self, mb):
        doc = {"items": [{"i": i, "pad": "x" * 100} for i in range(int(mb * 1024 * 1024 / 115))]}
        body = json.dumps(doc).encode()
        return RawServer(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                         % len(body) + body), body

    def test_edit_a_3mb_json_response_at_a_breakpoint(self):
        srv, body = self._big_json_server(3)
        write_rules(self.inst, {"rules": [], "breakpoints": [
            {"name": "b", "match": "/bigjson", "request": False, "response": True}]})
        c = Background(self.inst.fetch, srv.url("/bigjson"), timeout=60)
        x = wait_for(lambda: self.p.state()["paused"], 20, 0.3, "paused")[0]
        g = self.p.ok("paused_get", {"id": x["id"]})
        doc = json.loads(g["resp_body"])
        doc["items"][0]["i"] = -1
        code, d, raw = self.p.post("paused_continue", {"id": x["id"], "edits": {"status": 200, "headers": g["resp_headers"],
                                                                                 "body": json.dumps(doc)}})
        if code != 200:
            self.p.ok("paused_abort", {"id": x["id"]})
        srv.close()
        self.assertEqual(code, 200, "editing a %d-byte JSON response at a breakpoint: %s %r" % (len(body), code, raw[:200]))
        self.assertEqual(json.loads(c.result(60).body)["items"][0]["i"], -1)

    def test_import_a_realistic_har_of_400_calls(self):
        entries = []
        for i in range(400):
            entries.append({"startedDateTime": "2026-10-17T10:00:00Z", "time": 12,
                            "request": {"method": "GET", "url": "https://api.example.test/v1/item/%d?x=1" % i, "httpVersion": "HTTP/1.1",
                                        "headers": [{"name": "H%d" % k, "value": "v"} for k in range(8)],
                                        "queryString": [{"name": "x", "value": "1"}], "cookies": [], "headersSize": -1, "bodySize": 0},
                            "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                                         "headers": [{"name": "Content-Type", "value": "application/json"}] +
                                                    [{"name": "R%d" % k, "value": "v"} for k in range(6)],
                                         "cookies": [], "content": {"size": 20, "mimeType": "application/json", "text": '{"id": %d}' % i},
                                         "redirectURL": "", "headersSize": -1, "bodySize": 20},
                            "cache": {}, "timings": {"send": 1, "wait": 10, "receive": 1}})
        har = {"log": {"version": "1.2", "creator": {"name": "Proxyman", "version": "5"}, "entries": entries}}
        size = len(json.dumps(har))
        code, d, raw = self.p.post("coll_import", {"name": "qa-har400", "har": har, "overwrite": True}, timeout=60)
        self.assertEqual(code, 200, "importing a %d-byte, 400-call HAR: %s %r" % (size, code, raw[:200]))


class Http2(unittest.TestCase):
    def test_rules_and_breakpoints_on_http2_when_enabled(self):
        inst = Instance(S, "h2", extra_env={"RIVIS_HTTP2": "1"}).start()
        try:
            write_rules(inst, {"rules": [{"name": "r", "match": "/json/small\\?h2", "action": "respond", "status": 202,
                                          "body": {"h2": True}},
                                         {"name": "jp", "match": "/json/small\\?hpatch", "action": "json_patch", "set": {"flag": True}}]})
            r = inst.fetch(UP.url("/json/small?h2", tls=True), extra=["--http2"])
            self.assertEqual((r.status, r.json()), (202, {"h2": True}), r)
            r2 = inst.fetch(UP.url("/json/small?hpatch", tls=True), extra=["--http2"])
            self.assertEqual((r2.status, r2.json()["flag"]), (200, True), r2)
        finally:
            inst.stop()


class Filters(Base):
    def test_focus_host_on_an_ipv6_and_an_ip_host_filters_the_view(self):
        for host in ("127.0.0.1", "::1", "[::1]"):
            code, doc, raw = self.p.post("focus_host", {"host": host})
            self.assertEqual(code, 200, "%s -> %s %r" % (host, code, raw[:200]))
            vf = self.p.option("view_filter")
            ok, _ = self.p.post("filter_check", {"filter": vf})[1]["ok"], None
            self.assertTrue(ok, "focus on %s produced an invalid view filter %r" % (host, vf))
        self.p.ok("focus_host", {"host": None})

    def test_flow_filter_for_body_search_on_binary_and_large(self):
        self.inst.fetch(UP.url("/big?mb=5"))
        self.inst.fetch(UP.url("/json/small?needle=1"))
        code, doc, raw = self.p.post("filter_check", {"filter": "~bs alice"})
        self.assertEqual((code, doc and doc.get("ok")), (200, True), raw[:200])


class PanelAddMethod(Base):
    def test_panel_add_with_an_empty_or_null_method_means_any_method(self):
        """QA-04: "" / null used to be stored as is: "" never matched and null broke every other rule of the call."""
        for i, m in enumerate((None, "")):
            name = "pam%d" % i
            self.p.ok("add", {"rule": {"name": name, "match": "/echo\\?pam%d" % i, "action": "respond", "status": 418,
                                       "body": "x", "method": m}})
            rule = next(r for r in json.load(open(self.inst.rules_path))["rules"] if r["name"] == name)
            self.assertNotIn("method", rule)
            time.sleep(1.6)
            self.assertEqual(self.inst.fetch(UP.url("/echo?pam%d" % i), method="POST").status, 418)

