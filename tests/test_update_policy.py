"""Force update (addons/update_policy.py) and the mitmproxy watch (addons/mitm_watch.py).

Force update: the newest signed release manifest may say min_version / required_after. Below the minimum Rivis warns,
and from the date on it refuses everything except stop / status / off / update / terms, and the proxy passes nothing.
The kept manifest is verified on every read, so a hand-written (or edited) one is ignored.
mitmproxy watch: reports a newer mitmproxy and the pinned version's advisories; never installs anything."""
import datetime
import http.server
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import Instance, LiveCase, wait_for

REPO = harness.REPO


def make_key(root):
    key = os.path.join(root, "release-key")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", key], check=True)
    pub = open(key + ".pub").read().strip()
    return key, 'rivis-release namespaces="rivis-release" %s\n' % pub


def sign(key, data, root):
    path = os.path.join(root, "m-%d.json" % len(os.listdir(root)))
    with open(path, "wb") as fh:
        fh.write(data)
    subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", key, "-n", "rivis-release", path], check=True,
                   capture_output=True)
    return open(path + ".sig", "rb").read()


def tree_copy(signers, version="0.9.11", extra_product=None):
    """An installed-looking copy of this checkout (VERSION at its root) whose release key is a test key."""
    root = tempfile.mkdtemp(prefix="rivis-t-policy-tree-")
    tree = os.path.join(root, "tool")
    shutil.copytree(REPO, tree, ignore=shutil.ignore_patterns(".git", "tests", ".artifacts", "__pycache__", "*.pyc"))
    with open(os.path.join(tree, "addons", "release-signers"), "w") as fh:
        fh.write(signers)
    with open(os.path.join(tree, "VERSION"), "w") as fh:
        fh.write(version + "\n")
    if extra_product:
        with open(os.path.join(tree, "product.json")) as fh:
            doc = json.load(fh)
        doc.update(extra_product)
        with open(os.path.join(tree, "product.json"), "w") as fh:
            json.dump(doc, fh)
    return root, tree


def put_policy(home, manifest_bytes, sig_bytes):
    d = os.path.join(home, ".rivis", "update-policy")
    os.makedirs(d, mode=0o700, exist_ok=True)
    with open(os.path.join(d, "manifest.json"), "wb") as fh:
        fh.write(manifest_bytes)
    with open(os.path.join(d, "manifest.json.sig"), "wb") as fh:
        fh.write(sig_bytes)


def manifest(**kw):
    doc = {"product": "rivis", "version": "0.9.12", "zip": "rivis-installer-0.9.12.zip", "sha256": "0" * 64, "notes": ""}
    doc.update(kw)
    return json.dumps(doc).encode()


class Policy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = harness.Suite.get()
        cls.keydir = tempfile.mkdtemp(prefix="rivis-t-policy-key-")
        cls.key, signers = make_key(cls.keydir)
        cls.other_key, _ = make_key(tempfile.mkdtemp(prefix="rivis-t-policy-other-"))
        cls.root, cls.tree = tree_copy(signers)
        cls.off_root, cls.off_tree = tree_copy(signers, extra_product={"update_offline_days": 3})

    @classmethod
    def tearDownClass(cls):
        for d in (cls.keydir, cls.root, cls.off_root):
            shutil.rmtree(d, ignore_errors=True)

    def setUp(self):
        self.home = self.suite.new_home("policy")
        self.signdir = tempfile.mkdtemp(prefix="rivis-t-policy-sign-")
        self.addCleanup(shutil.rmtree, self.signdir, True)

    def status(self, tree=None):
        r = subprocess.run(["/usr/bin/python3", "-I", os.path.join(tree or self.tree, "addons", "update_policy.py"),
                            "status", "--json"], env=dict(os.environ, HOME=self.home), capture_output=True, text=True,
                           timeout=60)
        return r.returncode, json.loads(r.stdout)

    def policy(self, key=None, **kw):
        m = manifest(**kw)
        put_policy(self.home, m, sign(key or self.key, m, self.signdir))

    def test_no_policy_or_a_minimum_this_version_meets_is_fine(self):
        self.assertEqual(self.status()[0], 0)
        self.policy(min_version="0.9.11")
        self.assertEqual(self.status()[0], 0)
        self.policy(min_version="0.9.2")                       # numeric, not text order: 0.9.11 > 0.9.2
        self.assertEqual(self.status()[0], 0)

    def test_below_the_minimum_it_warns_before_the_date_and_refuses_after_it(self):
        later = (datetime.date.today() + datetime.timedelta(days=5)).isoformat()
        self.policy(min_version="0.9.12", required_after=later)
        rc, st = self.status()
        self.assertEqual((rc, st["state"], st["min_version"]), (12, "due", "0.9.12"))
        self.assertIn(later, st["reason"])
        self.policy(min_version="0.9.12", required_after="2020-01-01")
        rc, st = self.status()
        self.assertEqual((rc, st["state"]), (11, "required"))
        self.assertIn("rivis update", st["reason"])
        self.policy(min_version="0.9.12")                      # no date: required at once
        self.assertEqual(self.status()[0], 11)

    def test_an_edited_or_foreign_manifest_is_ignored(self):
        m = manifest(min_version="0.9.12")
        sig = sign(self.key, m, self.signdir)
        put_policy(self.home, m.replace(b"0.9.12", b"0.9.13"), sig)            # edited after signing
        self.assertEqual(self.status()[0], 0)
        self.policy(key=self.other_key, min_version="0.9.12")                # signed by another key
        self.assertEqual(self.status()[0], 0)
        self.policy(min_version="0.9.12", product="other")                   # another product's manifest
        self.assertEqual(self.status()[0], 0)
        self.policy(min_version="nine")                                       # unusable field
        self.assertEqual(self.status()[0], 0)

    def test_offline_limit_counts_as_required_when_the_product_sets_one(self):
        d = os.path.join(self.home, ".rivis", "update-policy")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "last-check"), "w") as fh:
            fh.write((datetime.datetime.now().astimezone() - datetime.timedelta(days=5)).isoformat())
        rc, st = self.status(self.off_tree)
        self.assertEqual((rc, st["state"]), (11, "required"))
        self.assertIn("5 days", st["reason"])
        self.assertEqual(self.status(self.tree)[0], 0)                       # default: no offline limit

    def test_the_cli_refuses_capture_commands_but_never_stop_status_update_or_off(self):
        self.policy(min_version="0.9.12")
        env = self.suite.cli_env(self.home)
        run = lambda *a: self.suite.run(["/bin/bash", os.path.join(self.tree, "rivis")] + list(a), home=self.home, env=env)
        r = run("rules", "list")
        self.assertEqual(r.returncode, 11, r.stdout + r.stderr)
        self.assertIn("update required", r.stderr)
        for args in (("status",), ("stop",), ("update", "status"), ("terms", "status"), ("android", "off"), ("version",)):
            self.assertNotEqual(run(*args).returncode, 11, args)
        later = (datetime.date.today() + datetime.timedelta(days=5)).isoformat()
        self.policy(min_version="0.9.12", required_after=later)
        r = run("rules", "list")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("warning", r.stderr)


class PolicyLocksTheProxy(LiveCase):
    @classmethod
    def make_instance(cls):
        cls.keydir = tempfile.mkdtemp(prefix="rivis-t-policy-live-")
        cls.key, signers = make_key(cls.keydir)
        cls.root, tree = tree_copy(signers)
        return Instance(cls.suite, "policylive", rivis_bin=os.path.join(tree, "rivis"))

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        for d in (cls.keydir, cls.root):
            shutil.rmtree(d, ignore_errors=True)

    def setUp(self):
        pass        # reset_state proves reloads with a call through the proxy, which is locked here

    def test_a_required_update_locks_the_proxy_and_the_window_is_told(self):
        # `rivis start` itself refuses while an update is required; a proxy that is ALREADY running when an update
        # check brings the requirement locks at once (the check writes the signed manifest it keeps)
        self.assertEqual(self.fetch("/json/small?before=1").status, 200)
        m = manifest(min_version="0.9.12")
        put_policy(self.inst.home, m, sign(self.key, m, self.keydir))
        r = self.fetch("/json/small")
        self.assertEqual(r.status, 403)
        self.assertIn(b"update is required", r.body)
        self.assertEqual([h["path"] for h in self.up.hits_for("/json/small")], ["/json/small?before=1"])   # the locked call never left
        wait_for(lambda: self.panel.state()["update_policy"]["state"] == "required", 10, 0.3, "window told")


class FakePyPI:
    def __init__(self, latest="12.3.1", vulns=None):
        doc = {"/pypi/mitmproxy/json": {"info": {"version": latest}},
               "/pypi/mitmproxy/12.2.3/json": {"info": {"version": "12.2.3"}, "vulnerabilities": vulns or []}}

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                found = doc.get(self.path)
                m = re.fullmatch(r"/pypi/mitmproxy/([0-9.]+)/json", self.path)
                if found is None and m:                     # any other release: no advisories
                    found = {"info": {"version": m.group(1)}, "vulnerabilities": []}
                body = json.dumps(found).encode() if found is not None else b"{}"
                self.send_response(200 if found is not None else 404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


VULN = [{"id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["CVE-2026-0001"], "summary": "header smuggling", "fixed_in": ["12.3.0"]}]


class MitmWatch(unittest.TestCase):
    def setUp(self):
        self.suite = harness.Suite.get()
        self.home = self.suite.new_home("mitmwatch")
        self.fake = FakePyPI(vulns=VULN)
        self.addCleanup(self.fake.close)

    def run_watch(self, *args, url=None):
        env = dict(os.environ, HOME=self.home, RIVIS_MITM_WATCH_URL=url or self.fake.url)
        return subprocess.run(["/usr/bin/python3", "-I", os.path.join(REPO, "addons", "mitm_watch.py")] + list(args),
                              env=env, capture_output=True, text=True, timeout=60)

    def test_a_newer_release_and_advisories_are_reported_and_cached(self):
        r = self.run_watch("check", "12.2.3")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("A newer mitmproxy (12.3.1) is out", r.stdout)
        self.assertIn("CVE-2026-0001", r.stdout)
        cache = json.load(open(os.path.join(self.home, ".rivis", "mitm-watch.json")))
        self.assertEqual((cache["latest"], cache["newer"], len(cache["advisories"])), ("12.3.1", True, 1))
        self.assertIn("(12.3.1) is out", self.run_watch("status", url="off").stdout)    # status reads the cache only

    def test_up_to_date_off_and_unreachable(self):
        r = self.run_watch("check", "12.3.1")
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("is out", r.stdout)
        r = self.run_watch("check", "12.2.3", url="off")
        self.assertEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.home, ".rivis", "mitm-watch.json.never")))
        r = self.run_watch("check", "12.2.3", url="http://127.0.0.1:9")                 # nothing listens there
        self.assertEqual(r.returncode, 1)
        self.assertIn("could not check", r.stdout)


class MitmWatchInTheWindow(LiveCase):
    @classmethod
    def make_instance(cls):
        cls.fake = FakePyPI(vulns=VULN)
        return Instance(cls.suite, "mitmwatchlive", extra_env={"RIVIS_MITM_WATCH_URL": cls.fake.url})

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls.fake.close()

    def test_the_running_rivis_checks_in_the_background_and_reports_it(self):
        st = wait_for(lambda: (self.panel.state().get("mitm_watch") or {}).get("latest") and self.panel.state()["mitm_watch"],
                      20, 0.3, "background mitmproxy check")
        self.assertEqual(st["latest"], "12.3.1")
        self.assertIn("is out", st["summary"])
        r = self.suite.run(["/bin/bash", harness.RIVIS, "doctor"], home=self.inst.home, env=self.inst.env, timeout=120)
        self.assertIn("security advisor", r.stdout)


if __name__ == "__main__":
    unittest.main()
