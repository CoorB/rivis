"""In-app updates (addons/updater.py, addons/update_install.sh, `rivis update`): GitHub device-flow sign-in, signed
release manifests, SHA-256-checked downloads, and an install that only restarts the proxy after it succeeded.

A fake GitHub (API + sign-in + a separate storage host for downloads) and a throwaway signing key make every check
real: ssh-keygen verifies the signatures, the token is kept in a private file (RIVIS_TOKEN_FILE, never the Keychain).
"""
import hashlib
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
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import Suite

NEW = "9.9.9"


class FakeGitHub:
    """Two servers: the API/sign-in host and a 'storage' host that release downloads redirect to."""

    def __init__(self):
        self.calls, self.blob_headers = [], []
        self.files = {}                 # asset name -> bytes
        self.token_grants = []          # bodies posted to /login/oauth/access_token
        self.pending = 1                # device polls answered "authorization_pending" before success
        outer = self

        class Storage(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.blob_headers.append({k.lower(): v for k, v in self.headers.items()})
                body = outer.files.get(self.path.rsplit("/", 1)[-1], b"")
                self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
                self.wfile.write(body)

        class Api(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, code, doc=None, raw=None, headers=()):
                body = raw if raw is not None else json.dumps(doc).encode()
                self.send_response(code)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

            def do_POST(self):
                form = dict(x.split("=", 1) for x in self.rfile.read(int(self.headers.get("Content-Length", 0))).decode().split("&") if "=" in x)
                outer.calls.append(("POST", self.path, form))
                if self.path == "/login/device/code":
                    return self.reply(200, {"device_code": "dev-code", "user_code": "WXYZ-1234", "interval": 1,
                                            "verification_uri": "https://github.com/login/device", "expires_in": 900})
                if self.path == "/login/oauth/access_token":
                    outer.token_grants.append(form)
                    if form.get("grant_type", "").endswith("device_code"):
                        if outer.pending > 0:
                            outer.pending -= 1
                            return self.reply(200, {"error": "authorization_pending"})
                        return self.reply(200, {"access_token": "tok-1", "expires_in": 28800, "refresh_token": "ref-1",
                                                "refresh_token_expires_in": 15897600})
                    if form.get("grant_type") == "refresh_token":
                        return self.reply(200, {"access_token": "tok-2", "expires_in": 28800, "refresh_token": "ref-2",
                                                "refresh_token_expires_in": 15897600})
                return self.reply(404, {"error": "nope"})

            def do_GET(self):
                outer.calls.append(("GET", self.path, {k.lower(): v for k, v in self.headers.items()}))
                if self.headers.get("Authorization") not in ("Bearer tok-1", "Bearer tok-2"):
                    return self.reply(401, {"message": "Bad credentials"})
                if self.path.startswith("/repos/CoorB/rivis/releases?"):
                    names = sorted(outer.files)
                    return self.reply(200, [{"draft": False, "html_url": "https://example/rel",
                                             "assets": [{"id": i + 1, "name": n} for i, n in enumerate(names)]}])
                if self.path.startswith("/repos/CoorB/rivis/releases/assets/"):
                    names = sorted(outer.files)
                    name = names[int(self.path.rsplit("/", 1)[-1]) - 1]
                    if name.endswith(".zip"):                     # like GitHub: the binary comes from a storage host
                        return self.reply(302, raw=b"", headers=[("Location", "http://127.0.0.1:%d/blob/%s" % (outer.storage_port, name))])
                    return self.reply(200, raw=outer.files[name])
                return self.reply(404, {"message": "Not Found"})

        self.api = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Api)
        self.storage = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Storage)
        self.port, self.storage_port = self.api.server_address[1], self.storage.server_address[1]
        for srv in (self.api, self.storage):
            threading.Thread(target=srv.serve_forever, daemon=True).start()

    def close(self):
        for srv in (self.api, self.storage):
            srv.shutdown(); srv.server_close()


class UpdaterBase(unittest.TestCase):
    def setUp(self):
        self.suite = Suite.get()
        self.root = tempfile.mkdtemp(dir=self.suite.root, prefix="upd-")
        self.home = self.suite.new_home("upd")
        self.gh = FakeGitHub()
        self.addCleanup(self.gh.close)
        # a copy of the tool configured for the fake GitHub, with a throwaway release key
        self.tool = os.path.join(self.root, "tool")
        shutil.copytree(harness.REPO, self.tool, ignore=shutil.ignore_patterns("tests", ".git", "__pycache__"))
        self.key = os.path.join(self.root, "release-key")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", self.key], check=True)
        self.set_signer(self.key)
        p = os.path.join(self.tool, "product.json")
        prod = json.load(open(p))
        prod.update(github_app_client_id="Iv-test", update_api="http://127.0.0.1:%d" % self.gh.port,
                    update_login="http://127.0.0.1:%d" % self.gh.port)
        json.dump(prod, open(p, "w"))
        self.token_file = os.path.join(self.root, "token")
        self.current = open(os.path.join(harness.REPO, "install", "VERSION")).read().strip()

    def set_signer(self, key):
        pub = open(key + ".pub").read().split()
        with open(os.path.join(self.tool, "addons", "release-signers"), "w") as fh:
            fh.write('rivis-release namespaces="rivis-release" %s %s\n' % (pub[0], pub[1]))

    def env(self, **extra):
        env = self.suite.env(self.home, extra={"RIVIS_TOKEN_FILE": self.token_file})
        env.update(extra)
        return env

    def upd(self, *args):
        r = subprocess.run(["/usr/bin/python3", "-I", os.path.join(self.tool, "addons", "updater.py"), *args],
                           capture_output=True, text=True, env=self.env(), timeout=60)
        try:
            return r.returncode, json.loads(r.stdout or "{}")
        except ValueError:
            self.fail("not JSON: %r %r" % (r.stdout, r.stderr))

    def sign_in(self, **tok):
        import base64
        tok = dict({"access_token": "tok-1", "refresh_token": "ref-1", "expires_at": time.time() + 3600,
                    "refresh_expires_at": time.time() + 86400}, **tok)
        fd = os.open(self.token_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(base64.b64encode(json.dumps(tok).encode()).decode())

    def publish(self, version=NEW, zip_bytes=b"PK fake installer", tamper=False, sha=None, product="rivis"):
        zname = "rivis-installer-%s.zip" % version
        man = json.dumps({"product": product, "version": version, "zip": zname,
                          "sha256": sha or hashlib.sha256(zip_bytes).hexdigest(), "notes": "Faster everything."}).encode()
        mpath = os.path.join(self.root, "rivis-update.json")
        open(mpath, "wb").write(man)
        subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", self.key, "-n", "rivis-release", mpath], check=True)
        sig = open(mpath + ".sig", "rb").read()
        self.gh.files = {"rivis-update.json": man.replace(b"Faster", b"Evil") if tamper else man,
                         "rivis-update.json.sig": sig, zname: zip_bytes}


class SignIn(UpdaterBase):
    def test_device_flow_signs_in_with_the_client_id_only_and_keeps_the_token_private(self):
        rc, s = self.upd("login-start")
        self.assertEqual((rc, s["user_code"]), (0, "WXYZ-1234"), s)
        self.assertEqual(self.upd("login-poll", s["device_code"])[1], {"result": "pending"})
        self.assertEqual(self.upd("login-poll", s["device_code"])[1], {"result": "ok"})
        self.assertTrue(all("client_secret" not in g for g in self.gh.token_grants), self.gh.token_grants)
        self.assertEqual(stat.S_IMODE(os.stat(self.token_file).st_mode), 0o600)
        self.assertNotIn("tok-1", open(self.token_file).read())      # not stored as plain text
        self.assertTrue(self.upd("status")[1]["signed_in"])
        self.assertEqual(self.upd("logout")[0], 0)
        self.assertFalse(os.path.exists(self.token_file))

    def test_an_expired_token_is_refreshed_without_a_secret(self):
        self.sign_in(expires_at=time.time() - 10)
        self.publish()
        rc, j = self.upd("check")
        self.assertEqual(rc, 0, j)
        grant = [g for g in self.gh.token_grants if g.get("grant_type") == "refresh_token"]
        self.assertEqual(len(grant), 1)
        self.assertNotIn("client_secret", grant[0])
        self.assertIn("Bearer tok-2", [c[2].get("authorization") for c in self.gh.calls if c[0] == "GET"])


class Check(UpdaterBase):
    def test_a_newer_signed_release_is_offered_with_its_notes(self):
        self.sign_in(); self.publish()
        rc, j = self.upd("check")
        self.assertEqual(rc, 0, j)
        self.assertEqual((j["current"], j["available"]["version"], j["available"]["notes"]), (self.current, NEW, "Faster everything."))

    def test_the_same_version_is_not_offered(self):
        self.sign_in(); self.publish(version=self.current)
        self.assertIsNone(self.upd("check")[1]["available"])

    def test_a_tampered_manifest_is_refused(self):
        self.sign_in(); self.publish(tamper=True)
        rc, j = self.upd("check")
        self.assertEqual(rc, 1)
        self.assertIn("signature", j["error"])

    def test_a_manifest_signed_by_another_key_is_refused(self):
        other = os.path.join(self.root, "other-key")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", other], check=True)
        self.set_signer(other)                                  # the build trusts a different key
        self.sign_in(); self.publish()
        rc, j = self.upd("check")
        self.assertEqual(rc, 1)
        self.assertIn("signature", j["error"])

    def test_a_build_without_a_release_key_never_offers_updates(self):
        open(os.path.join(self.tool, "addons", "release-signers"), "w").write("# no key yet\n")
        self.sign_in(); self.publish()
        self.assertFalse(self.upd("status")[1]["configured"])
        rc, j = self.upd("check")
        self.assertEqual(rc, 1)
        self.assertIn("not set up", j["error"])
        self.assertEqual([c for c in self.gh.calls if c[0] == "GET"], [], "it must not even ask GitHub")

    def test_not_signed_in_is_reported_and_nothing_is_fetched(self):
        self.publish()
        rc, j = self.upd("check")
        self.assertEqual((rc, j["error"]), (1, "not signed in to GitHub"))


class Download(UpdaterBase):
    def test_the_installer_is_verified_and_the_token_never_reaches_the_storage_host(self):
        self.sign_in(); self.publish(zip_bytes=b"PK real bytes")
        rc, j = self.upd("download")
        self.assertEqual(rc, 0, j)
        self.assertEqual(open(j["path"], "rb").read(), b"PK real bytes")
        self.assertEqual(stat.S_IMODE(os.stat(j["path"]).st_mode), 0o600)
        self.assertTrue(self.gh.blob_headers, "the download should come from the storage host")
        self.assertTrue(all("authorization" not in h for h in self.gh.blob_headers), self.gh.blob_headers)

    def test_a_wrong_sha256_is_refused_and_nothing_is_kept(self):
        self.sign_in(); self.publish(zip_bytes=b"PK real bytes", sha="0" * 64)
        rc, j = self.upd("download")
        self.assertEqual(rc, 1)
        self.assertIn("SHA-256", j["error"])
        d = os.path.join(self.home, ".rivis", "updates", NEW)
        self.assertFalse(os.path.isdir(d) and any(f.endswith(".zip") for f in os.listdir(d)))


class InstallStep(unittest.TestCase):
    """addons/update_install.sh with a fake installer and a fake installed CLI that records every call."""

    def setUp(self):
        self.suite = Suite.get()
        self.home = self.suite.new_home("updinst")
        self.log = os.path.join(self.home, "calls.log")
        bin_ = os.path.join(self.home, ".local", "bin")
        os.makedirs(bin_)
        with open(os.path.join(bin_, "rivis"), "w") as fh:
            fh.write('#!/bin/sh\necho "cli $* port=${RIVIS_PORT:-} web=${RIVIS_WEB_PORT:-}" >> "%s"\n'
                     'case "$1" in status) [ -f "%s/running" ] && echo "proxy :8080     mitmweb pid 42" ;; '
                     '--version) echo "rivis 9.9.9" ;; esac\nexit 0\n' % (self.log, self.home))
        os.chmod(os.path.join(bin_, "rivis"), 0o755)
        os.makedirs(os.path.join(self.home, ".rivis"))
        with open(os.path.join(self.home, ".rivis", "last-start"), "w") as fh:
            fh.write("START_PORT=18080\nSTART_WEB_PORT=18083\nSTART_ARGS=(--project neo start --background --no-open --insecure )\n")

    def make_zip(self, rc=0):
        z = os.path.join(self.home, "rivis-installer-9.9.9.zip")
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("rivis-installer-9.9.9/install.sh",
                        '#!/bin/bash\necho "install $*" >> "%s"\nexit %d\n' % (self.log, rc))
        return z

    def run_it(self, z):
        env = self.suite.env(self.home)
        env.pop("RIVIS_WEB_PORT", None)     # R4A-05: as started on the default UI port, whose start is saved in last-start
        return subprocess.run(["/bin/bash", os.path.join(harness.REPO, "addons", "update_install.sh"), z],
                              capture_output=True, text=True, env=env, timeout=60)

    def calls(self):
        return open(self.log).read().splitlines() if os.path.exists(self.log) else []

    def test_installs_first_then_restarts_exactly_as_it_was_started(self):
        open(os.path.join(self.home, "running"), "w").close()
        r = self.run_it(self.make_zip())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        steps = [c for c in self.calls() if not c.startswith("cli status") and not c.startswith("cli --version")]
        self.assertEqual(steps[0], "install --yes --skip-local-capture")
        self.assertEqual(steps[1], "cli stop port=18080 web=18083")
        self.assertEqual(steps[2], "cli --project neo start --background --no-open --insecure port=18080 web=18083")

    def test_no_second_restart_when_the_installer_already_restarted_it(self):
        # R4A-01: install.sh restarts running instances itself; the updater must not stop/start them again
        open(os.path.join(self.home, "running"), "w").close()
        z = os.path.join(self.home, "rivis-installer-9.9.9.zip")
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("rivis-installer-9.9.9/install.sh", '#!/bin/bash\necho "install $*" >> "%s"\n'
                        'echo "  restarted :18080/:18083 on Rivis 9.9.9"\nexit 0\n' % self.log)
        r = self.run_it(z)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse([c for c in self.calls() if c.startswith("cli stop") or " start " in c], self.calls())

    def test_restarts_a_second_instance_from_its_own_ports_start(self):
        # R4A-05: an update from the panel on another UI port restarts THAT instance, not the default one's settings
        open(os.path.join(self.home, "running"), "w").close()
        with open(os.path.join(self.home, ".rivis", "last-start-28083"), "w") as fh:
            fh.write("START_PORT=28080\nSTART_WEB_PORT=28083\nSTART_ARGS=(--project b start --background --no-open )\n")
        env = dict(self.suite.env(self.home), RIVIS_WEB_PORT="28083")
        r = subprocess.run(["/bin/bash", os.path.join(harness.REPO, "addons", "update_install.sh"), self.make_zip()],
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("cli --project b start --background --no-open port=28080 web=28083", self.calls())

    def test_restart_path_removes_its_temp_dir_and_nothing_else(self):
        # review 0.9.7 #5: the web port reused $W, so the EXIT trap ran `rm -rf 8083` and leaked the unzipped installer
        open(os.path.join(self.home, "running"), "w").close()
        tmp = os.path.join(self.home, "tmp")
        os.makedirs(tmp)
        os.makedirs(os.path.join(self.home, "8083"))
        env = self.suite.env(self.home)
        env.pop("RIVIS_WEB_PORT", None)
        env["TMPDIR"] = tmp
        r = subprocess.run(["/bin/bash", os.path.join(harness.REPO, "addons", "update_install.sh"), self.make_zip()],
                           capture_output=True, text=True, env=env, cwd=self.home, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("cli --project neo start --background --no-open --insecure port=18080 web=18083", self.calls())
        self.assertEqual(os.listdir(tmp), [], "the update's temp dir was left behind")
        self.assertTrue(os.path.isdir(os.path.join(self.home, "8083")), "the EXIT trap removed ./8083")

    def test_a_failed_install_leaves_the_running_version_alone(self):
        open(os.path.join(self.home, "running"), "w").close()
        r = self.run_it(self.make_zip(rc=1))
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse([c for c in self.calls() if c.startswith("cli stop") or " start " in c], self.calls())
        self.assertIn("previous version is still installed", r.stdout)

    def test_a_proxy_that_was_not_running_is_not_started(self):
        r = self.run_it(self.make_zip())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse([c for c in self.calls() if c.startswith("cli stop") or " start " in c], self.calls())


class Cli(UpdaterBase):
    def test_start_records_how_to_restart_it(self):
        home = self.suite.new_home("updstart")
        env = dict(self.suite.cli_env(home), SHIM_DRYRUN="1")
        self.suite.rivis("--project", "neo", "start", "--background", "--no-open", "--no-ios", home=home, env=env)
        web = env["RIVIS_WEB_PORT"]                     # R4A-05: each web port saves its own start
        f = os.path.join(home, ".rivis", "last-start" if web == "8083" else "last-start-" + web)
        self.assertTrue(os.path.isfile(f))
        self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o600)
        text = open(f).read()
        self.assertIn("START_PORT=%s" % env["RIVIS_PORT"], text)
        self.assertIn("--project neo start --background --no-open --no-ios", text)

    def test_a_source_checkout_refuses_to_update_itself(self):
        self.sign_in(); self.publish()
        r = subprocess.run([os.path.join(self.tool, "rivis"), "update", "install"], capture_output=True, text=True,
                           env=self.env(), timeout=120, stdin=subprocess.DEVNULL)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("source checkout", r.stdout + r.stderr)
        self.assertFalse(self.gh.blob_headers, "nothing may be downloaded for a source checkout")


if __name__ == "__main__":
    unittest.main(verbosity=2)
