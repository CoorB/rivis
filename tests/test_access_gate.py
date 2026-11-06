"""IT approval (addons/access.py): with product.json "access_required", only an account that may read the Rivis feed
in Azure DevOps (IT's readers group) may use Rivis. A fake Azure DevOps answers the feed request; the sign-in token
lives in a private file (RIVIS_TOKEN_FILE), never the Keychain. No test uses the network."""
import base64
import datetime
import http.server
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import REPO, Instance, LiveCase, wait_for

ORG, PROJECT, FEED, TENANT, CLIENT = "org1", "Proj1", "rivis", "tenant-1", "client-1"
FEED_PATH = "/%s/%s/_apis/packaging/feeds/%s?api-version=7.1" % (ORG, PROJECT, FEED)


def jwt(**claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return "%s.%s.sig" % (enc({"alg": "none"}), enc(claims))


TOKEN = jwt(upn="ada@example.test", name="Ada Lovelace")


class FakeDevOps:
    """The feed: 200 JSON for an approved reader, or whatever `answer` says (code, content type, body, location)."""

    def __init__(self):
        self.gets = []
        self.answer = None
        self.pending = 10 ** 6       # device-code polls answered "authorization_pending" before the sign-in completes
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):               # Entra ID: device code, then the token once `pending` runs out
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if self.path == "/%s/oauth2/v2.0/devicecode" % TENANT:
                    doc, code = {"device_code": "dc-1", "user_code": "ABCD1234", "interval": 1, "expires_in": 900,
                                 "verification_uri": "https://microsoft.com/devicelogin"}, 200
                elif self.path == "/%s/oauth2/v2.0/token" % TENANT and outer.pending > 0:
                    outer.pending -= 1
                    doc, code = {"error": "authorization_pending"}, 400
                elif self.path == "/%s/oauth2/v2.0/token" % TENANT:
                    doc, code = {"access_token": TOKEN, "expires_in": 3600, "refresh_token": "r-1"}, 200
                else:
                    doc, code = {"error": "nope"}, 404
                body = json.dumps(doc).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                outer.gets.append((self.path, self.headers.get("Authorization")))
                if outer.answer:
                    code, ctype, body, location = outer.answer
                elif self.path == FEED_PATH and self.headers.get("Authorization") == "Bearer " + TOKEN:
                    code, ctype, location = 200, "application/json; charset=utf-8", None
                    body = json.dumps({"id": "2ffc6d14", "name": FEED, "url": "x"}).encode()
                else:
                    code, ctype, body, location = 401, "application/json", b'{"message":"no"}', None
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                if location:
                    self.send_header("Location", location)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def tree_copy(feeds_url, required=True, ids=True, **extra):
    root = tempfile.mkdtemp(prefix="rivis-t-access-")
    tree = os.path.join(root, "tool")
    shutil.copytree(REPO, tree, ignore=shutil.ignore_patterns(".git", "tests", ".artifacts", "__pycache__", "*.pyc"))
    p = os.path.join(tree, "product.json")
    doc = json.load(open(p))
    doc.update(access_required=required, azure_feeds_url=feeds_url, azure_login_url=feeds_url, update_source="azure",
               azure_updates={"org": ORG, "project": PROJECT, "feed": FEED, "view": "Release", "package": "rivis",
                              "tenant": TENANT if ids else "", "client_id": CLIENT if ids else ""}, **extra)
    json.dump(doc, open(p, "w"))
    return root, tree


def write_token(path, token=TOKEN):
    tok = {"access_token": token, "refresh_token": "r-1", "expires_at": time.time() + 3600, "refresh_expires_at": None}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(base64.b64encode(json.dumps(tok).encode()).decode())


def iso(days_ago=0, hours_ago=0):
    return (datetime.datetime.now().astimezone()
            - datetime.timedelta(days=days_ago, hours=hours_ago)).isoformat(timespec="seconds")


class AccessBase(unittest.TestCase):
    def setUp(self):
        self.suite = harness.Suite.get()
        self.home = self.suite.new_home("access")
        self.fake = FakeDevOps()
        self.addCleanup(self.fake.close)
        self.root, self.tree = tree_copy(self.fake.url)
        self.addCleanup(shutil.rmtree, self.root, True)
        self.token_file = os.path.join(self.root, "token")

    def configure(self, **over):
        p = os.path.join(self.tree, "product.json")
        doc = json.load(open(p))
        doc.update(over)
        json.dump(doc, open(p, "w"))

    def env(self):
        return dict(self.suite.env(self.home), RIVIS_TOKEN_FILE=self.token_file)

    def acc(self, *args):
        r = subprocess.run(["/usr/bin/python3", "-I", os.path.join(self.tree, "addons", "access.py")] + list(args),
                           env=self.env(), capture_output=True, text=True, timeout=60)
        return r.returncode, (json.loads(r.stdout) if "--json" in args else r.stdout + r.stderr)

    @property
    def record(self):
        return os.path.join(self.home, ".rivis-access.json")

    def put_record(self, **doc):
        with open(self.record, "w") as fh:
            json.dump(doc, fh)


class AccessModule(AccessBase):
    def test_off_unless_the_build_requires_it(self):
        self.configure(access_required=False)
        rc, st = self.acc("check", "--json", "--force")
        self.assertEqual((rc, st["state"], st["allowed"]), (0, "off", True))
        self.assertEqual(self.fake.gets, [])
        self.configure(access_required="yes")            # only a real true turns it on
        self.assertEqual(self.acc("status", "--json")[1]["state"], "off")

    def test_a_build_that_requires_it_without_sign_in_ids_is_locked(self):
        self.configure(azure_updates={"org": ORG, "project": PROJECT, "feed": FEED, "tenant": "", "client_id": ""})
        rc, st = self.acc("check", "--json", "--force")
        self.assertEqual((rc, st["state"]), (13, "unconfigured"))
        self.assertIn("reinstall", st["reason"])
        self.assertEqual(self.fake.gets, [])

    def test_not_signed_in_asks_for_a_sign_in_and_asks_nobody(self):
        rc, st = self.acc("check", "--json")
        self.assertEqual((rc, st["state"], st["check"]), (13, "sign_in", "signin"))
        self.assertIn("rivis access", st["reason"])
        self.assertEqual(self.fake.gets, [])

    def test_an_approved_reader_is_recorded_and_not_asked_again_until_due(self):
        write_token(self.token_file)
        rc, st = self.acc("check", "--json")
        self.assertEqual((rc, st["state"], st["check"], st["account"]), (0, "ok", "approved", "ada@example.test"), st)
        self.assertEqual(self.fake.gets, [(FEED_PATH, "Bearer " + TOKEN)])
        self.assertEqual(stat.S_IMODE(os.stat(self.record).st_mode), 0o600)
        rec = json.load(open(self.record))
        self.assertEqual((rec["result"], rec["name"]), ("approved", "Ada Lovelace"))
        rc, st = self.acc("check", "--json")
        self.assertEqual((rc, st["check"]), (0, "skipped"))
        self.assertEqual(len(self.fake.gets), 1)
        self.assertIn("approved by IT: ada@example.test", self.acc("status")[1])

    def test_not_in_the_readers_group_is_refused_and_the_sign_in_is_kept(self):
        write_token(self.token_file)
        for answer in ((403, "application/json", b'{"message":"denied"}', None),
                       (404, "application/json", b'{"message":"feed not found"}', None),
                       (401, "application/json", b'{"message":"TF400813: The user is not authorized"}', None)):
            self.fake.answer = answer
            rc, st = self.acc("check", "--json", "--force")
            self.assertEqual((rc, st["state"], st["check"]), (13, "refused", "refused"), answer)
            self.assertIn("ada@example.test is not approved", st["reason"])
            self.assertIn("confirmation form", st["reason"])
            self.assertTrue(os.path.exists(self.token_file), "a refusal must not throw the sign-in away")
        self.fake.answer = None                             # IT added them: the next check lets them in
        rc, st = self.acc("check", "--json")
        self.assertEqual((rc, st["state"]), (0, "ok"))
        self.assertEqual(json.load(open(self.record))["history"][-1]["result"], "refused")

    def test_a_stale_sign_in_is_never_followed_to_the_login_page_and_never_counts(self):
        write_token(self.token_file)
        self.fake.answer = (302, "text/html", b"", self.fake.url + "/_signin")
        rc, st = self.acc("check", "--json", "--force")
        self.assertEqual((rc, st["state"], st["check"]), (13, "sign_in", "signin"))
        self.assertEqual([g[0] for g in self.fake.gets], [FEED_PATH], "the redirect must not be followed")
        self.assertFalse(os.path.exists(self.token_file), "a token Azure DevOps rejects is forgotten")
        write_token(self.token_file)
        for answer in ((203, "text/html", b"<html>sign in</html>", None),
                       (401, "application/json", b'{"message":"expired"}', None)):
            self.fake.answer = answer
            self.assertEqual(self.acc("check", "--json", "--force")[1]["state"], "sign_in", answer)
            write_token(self.token_file)
        self.fake.answer = (200, "text/html", b"<html>welcome</html>", None)      # a page, not the feed
        rc, st = self.acc("check", "--json", "--force")
        self.assertEqual((rc, st["check"]), (13, "unknown"))
        self.fake.answer = (200, "application/json", json.dumps({"id": "x", "name": "otherfeed"}).encode(), None)
        self.assertEqual(self.acc("check", "--json", "--force")[1]["check"], "unknown")
        self.assertFalse(os.path.exists(self.record))

    def test_offline_keeps_working_for_the_allowance_then_locks(self):
        write_token(self.token_file)
        self.configure(azure_feeds_url="http://127.0.0.1:9")          # nothing listens there
        self.put_record(result="approved", account="ada@example.test", approved_at=iso(days_ago=3),
                        checked_at=iso(days_ago=3))
        rc, st = self.acc("check", "--json")
        self.assertEqual((rc, st["state"], st["check"]), (0, "ok", "unknown"))
        self.assertIn("could not reach", st["error"])
        self.assertTrue(json.load(open(self.record)).get("tried_at"))
        self.assertEqual(self.acc("check", "--json")[1]["check"], "skipped", "retries wait an hour, not every command")
        self.put_record(result="approved", account="ada@example.test", approved_at=iso(days_ago=8),
                        checked_at=iso(days_ago=8))
        rc, st = self.acc("check", "--json")
        self.assertEqual((rc, st["state"]), (13, "expired"))
        self.assertIn("could not confirm your approval for 8 days", st["reason"])
        self.configure(access_offline_days=10)
        self.assertEqual(self.acc("status", "--json")[1]["state"], "ok")

    def test_removed_from_the_group_locks_at_the_next_daily_check(self):
        write_token(self.token_file)
        self.put_record(result="approved", account="ada@example.test", approved_at=iso(hours_ago=25),
                        checked_at=iso(hours_ago=25))
        self.fake.answer = (403, "application/json", b"{}", None)
        rc, st = self.acc("gate")
        self.assertEqual(rc, 13)
        self.assertTrue(st.startswith("refused\t"), st)


class AccessCli(AccessBase):
    def cli(self, *args):
        env = dict(self.suite.cli_env(self.home), RIVIS_TOKEN_FILE=self.token_file)
        return subprocess.run(["/bin/bash", os.path.join(self.tree, "rivis")] + list(args), env=env,
                              capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)

    def test_capture_commands_wait_for_approval_and_undo_commands_always_work(self):
        r = self.cli("rules", "list")
        self.assertEqual(r.returncode, 13, r.stdout + r.stderr)
        self.assertIn("sign in with your organisation account", r.stderr)
        for args in (("status",), ("stop",), ("version",), ("android", "off"), ("ios", "off"), ("terms", "status")):
            r = self.cli(*args)
            self.assertNotEqual(r.returncode, 13, "%s was gated: %s" % (args, r.stdout + r.stderr))
        r = self.cli("access", "status")              # reports (exit 13 = not approved), like `terms status`
        self.assertEqual(r.returncode, 13)
        self.assertIn("sign in with your organisation account", r.stdout)
        self.assertEqual(self.fake.gets, [], "status never asks Azure DevOps")
        write_token(self.token_file)
        r = self.cli("access")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("approved by IT: ada@example.test", r.stdout)
        self.assertEqual(self.cli("rules", "list").returncode, 0)
        self.fake.answer = (403, "application/json", b"{}", None)
        r = self.cli("access")
        self.assertEqual(r.returncode, 13)
        self.assertIn("not approved", r.stdout + r.stderr)
        r = self.cli("rules", "list")
        self.assertEqual(r.returncode, 13)
        self.assertIn("confirmation form", r.stderr)
        r = self.cli("doctor")                       # never gated, and it says why Rivis is locked
        self.assertIn("IT approval", r.stdout + r.stderr)
        self.assertIn("rivis access", r.stdout + r.stderr)

    def test_the_release_build_turns_the_check_on(self):
        script = os.path.join(os.path.dirname(REPO), "release-tools", "inject-azure-ids.sh")
        if not os.path.isfile(script):
            self.skipTest("release tools live outside this checkout")
        self.configure(access_required=False)
        self.assertEqual(self.acc("status", "--json")[1]["state"], "off")
        private = os.path.join(os.path.dirname(REPO), "private", "azure-updates.json")
        if not os.path.isfile(private):
            self.skipTest("no private sign-in ids on this machine")
        r = subprocess.run(["/bin/bash", script, self.tree], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIs(json.load(open(os.path.join(self.tree, "product.json")))["access_required"], True)


class AccessPowerShell(AccessBase):
    def test_the_powershell_cli_has_the_same_gate(self):
        from test_powershell import PWSH
        if not PWSH or not os.path.exists(PWSH):
            self.skipTest("no PowerShell")
        env = dict(self.suite.cli_env(self.home), RIVIS_TOKEN_FILE=self.token_file)
        run = lambda *a: self.suite.run([PWSH, "-NoProfile", "-NonInteractive", "-File",
                                         os.path.join(self.tree, "rivis.ps1")] + list(a), home=self.home, env=env, timeout=120)
        cp = run("rules", "list")
        self.assertEqual(cp.returncode, 13, cp.stdout + cp.stderr)
        self.assertIn("sign in with your organisation account", cp.stdout + cp.stderr)
        for args in (("status",), ("terms", "status"), ("help",)):
            cp = run(*args)
            self.assertNotEqual(cp.returncode, 13, "%s was gated: %s" % (args, cp.stdout + cp.stderr))
        write_token(self.token_file)
        cp = run("access")
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("approved by IT", cp.stdout)
        self.assertNotEqual(run("rules", "list").returncode, 13)


class AccessLocksTheProxy(LiveCase):
    """Started from the Mac app (no terminal) before approval: the proxy runs LOCKED and the window asks."""

    @classmethod
    def make_instance(cls):
        cls.fake = FakeDevOps()
        cls.root, tree = tree_copy(cls.fake.url)
        cls.token_file = os.path.join(cls.root, "token")
        return Instance(cls.suite, "accesslive", rivis_bin=os.path.join(tree, "rivis"),
                        extra_env={"RIVIS_TOKEN_FILE": cls.token_file})

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls.fake.close()
        shutil.rmtree(cls.root, ignore_errors=True)

    def setUp(self):
        pass        # reset_state proves reloads with a call through the proxy, which is locked here

    def test_locked_until_approval_is_confirmed_then_traffic_flows_and_a_refusal_locks_again(self):
        a = self.panel.state()["access"]
        self.assertEqual((a["state"], a["allowed"]), ("sign_in", False))
        r = self.fetch("/json/small")
        self.assertEqual(r.status, 403)
        self.assertIn(b"IT approved you", r.body)
        self.assertEqual(len(self.up.hits_for("/json/small")), 0)
        write_token(self.token_file)                          # what the window's sign-in leaves behind
        self.panel.ok("access_check", {})
        wait_for(lambda: self.panel.state()["access"]["allowed"], 20, 0.3, "approval confirmed")
        wait_for(lambda: self.fetch("/json/small").status == 200, 70, 0.5, "traffic flows once approved")
        rec = json.load(open(os.path.join(self.inst.home, ".rivis-access.json")))
        self.assertEqual((rec["result"], rec["account"]), ("approved", "ada@example.test"))
        self.fake.answer = (403, "application/json", b"{}", None)
        self.panel.ok("access_check", {})
        wait_for(lambda: self.panel.state()["access"]["state"] == "refused", 20, 0.3, "refusal seen")
        r = self.fetch("/json/small?after=1")
        self.assertEqual(r.status, 403)
        self.assertIn(b"not approved", r.body)

    def test_z_signing_in_from_the_window_shows_the_device_code(self):
        a = self.panel.ok("access_signin", {})["access"]
        self.assertIn(a["login"]["status"], ("starting", "waiting"))
        wait_for(lambda: (self.panel.state()["access"]["login"] or {}).get("user_code") == "ABCD1234", 20, 0.3,
                 "device code shown")
        self.assertNotIn("device_code", self.panel.state()["access"]["login"], "the device code never reaches the page")


if __name__ == "__main__":
    unittest.main()
