"""In-app updates from the organisation's Azure DevOps feed (addons/updater.py, product.json update_source "azure").

A fake Entra ID (device-code sign-in) and a fake Azure Artifacts npm registry serve an npm-type release package
holding rivis-update.json, its .sig and the installer zip; a throwaway release key makes every signature check real.
The token is kept in a private file (RIVIS_TOKEN_FILE), never the Keychain.
"""
import base64
import hashlib
import http.server
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: F401
from test_updater import NEW, UpdaterBase

TENANT, CLIENT = "tenant-1", "client-1"
REGISTRY = "/org1/Proj1/_packaging/rivis@Release/npm/registry"


def npm_tgz(files, symlink=None):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo("package/" + name); ti.size = len(data); ti.mtime = int(time.time())
            tf.addfile(ti, io.BytesIO(data))
        if symlink:
            ti = tarfile.TarInfo("package/" + symlink); ti.type = tarfile.SYMTYPE; ti.linkname = "/etc/passwd"
            tf.addfile(ti)
    return buf.getvalue()


class FakeAzure:
    def __init__(self):
        self.calls, self.grants = [], []
        self.packages = {}          # version -> {"tgz": bytes, "meta": extra package.json fields}
        self.pending = 1
        self.answer = None          # force a status code for registry GETs
        self.token_status = None    # force a status code for the sign-in service (device code, token, refresh)
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, code, doc=None, raw=None, ctype="application/json"):
                body = raw if raw is not None else json.dumps(doc).encode()
                self.send_response(code); self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                form = dict(x.split("=", 1) for x in self.rfile.read(n).decode().split("&") if "=" in x)
                form = {k: __import__("urllib.parse").parse.unquote_plus(v) for k, v in form.items()}
                outer.calls.append(("POST", self.path, form))
                if outer.token_status:
                    return self.reply(outer.token_status, raw=b"<html>busy</html>", ctype="text/html")
                if self.path == "/%s/oauth2/v2.0/devicecode" % TENANT:
                    return self.reply(200, {"device_code": "dc-1", "user_code": "ABCD1234", "interval": 1,
                                            "verification_uri": "https://microsoft.com/devicelogin", "expires_in": 900})
                if self.path == "/%s/oauth2/v2.0/token" % TENANT:
                    outer.grants.append(form)
                    if form.get("grant_type", "").endswith("device_code"):
                        if outer.pending > 0:
                            outer.pending -= 1
                            return self.reply(400, {"error": "authorization_pending"})
                        return self.reply(200, {"access_token": "az-1", "expires_in": 3600, "refresh_token": "azr-1"})
                    if form.get("grant_type") == "refresh_token":
                        return self.reply(200, {"access_token": "az-2", "expires_in": 3600, "refresh_token": "azr-2"})
                return self.reply(404, {"error": "nope"})

            def do_GET(self):
                outer.calls.append(("GET", self.path, {k.lower(): v for k, v in self.headers.items()}))
                if outer.answer:
                    return self.reply(outer.answer, raw=b"<html>sign in</html>", ctype="text/html")
                if self.headers.get("Authorization") not in ("Bearer az-1", "Bearer az-2"):
                    return self.reply(401, {"message": "unauthorized"})
                if self.path == REGISTRY + "/rivis":
                    if not outer.packages:
                        return self.reply(404, {"error": "not found"})
                    return self.reply(200, {"name": "rivis", "versions": {
                        v: dict({"name": "rivis", "version": v,
                                 "dist": {"tarball": "https://elsewhere.invalid/x.tgz"}}, **p["meta"])
                        for v, p in outer.packages.items()}})
                for v, p in outer.packages.items():
                    if self.path == "%s/rivis/-/rivis-%s.tgz" % (REGISTRY, v):
                        return self.reply(200, raw=p["tgz"], ctype="application/octet-stream")
                return self.reply(404, {"error": "not found"})

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown(); self.srv.server_close()

    def gets(self):
        return [c for c in self.calls if c[0] == "GET"]


class AzureBase(UpdaterBase):
    def setUp(self):
        super().setUp()
        self.az = FakeAzure()
        self.addCleanup(self.az.close)
        self.configure()

    def configure(self, **over):
        p = os.path.join(self.tool, "product.json")
        prod = json.load(open(p))
        url = "http://127.0.0.1:%d" % self.az.port
        prod.update(update_source="azure", azure_pkgs_url=url, azure_login_url=url,
                    azure_updates=dict({"org": "org1", "project": "Proj1", "feed": "rivis", "view": "Release",
                                        "package": "rivis", "tenant": TENANT, "client_id": CLIENT}, **over))
        json.dump(prod, open(p, "w"))

    def sign_in(self, **tok):
        super().sign_in(**dict({"access_token": "az-1", "refresh_token": "azr-1", "refresh_expires_at": None}, **tok))

    def release(self, version=NEW, zip_bytes=b"PK fake installer", sha=None, tamper=False, in_meta=True,
                man_version=None, zname=None, symlink_zip=False):
        zname = zname or "rivis-installer-%s.zip" % version
        man = json.dumps({"product": "rivis", "version": man_version or version, "zip": zname,
                          "sha256": sha or hashlib.sha256(zip_bytes).hexdigest(), "notes": "Faster everything."}).encode()
        mpath = os.path.join(self.root, "rivis-update-%s.json" % version)
        open(mpath, "wb").write(man)
        subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", self.key, "-n", "rivis-release", mpath], check=True)
        sig = open(mpath + ".sig", "rb").read()
        if tamper:
            man = man.replace(b"Faster", b"Evil")
        files = {"package.json": json.dumps({"name": "rivis", "version": version}).encode(),
                 "rivis-update.json": man, "rivis-update.json.sig": sig}
        if not symlink_zip:
            files[zname] = zip_bytes
        meta = {"rivisUpdate": {"manifest": base64.b64encode(man).decode(),
                                "signature": base64.b64encode(sig).decode()}} if in_meta else {}
        self.az.packages[version] = {"tgz": npm_tgz(files, symlink=zname if symlink_zip else None), "meta": meta}


class AzureSignIn(AzureBase):
    def test_device_code_sign_in_asks_for_azure_devops_and_keeps_the_token(self):
        rc, start = self.upd("login-start")
        self.assertEqual(rc, 0, start)
        self.assertEqual(start["user_code"], "ABCD1234")
        post = [c for c in self.az.calls if c[1].endswith("/devicecode")][0][2]
        self.assertEqual(post["client_id"], CLIENT)
        self.assertIn("499b84ac-1321-427f-aa17-267ca6975798/.default", post["scope"])
        self.assertIn("offline_access", post["scope"])
        self.assertEqual(self.upd("login-poll", start["device_code"])[1]["result"], "pending")
        self.assertEqual(self.upd("login-poll", start["device_code"])[1]["result"], "ok")
        self.assertTrue(self.upd("status")[1]["signed_in"])
        self.assertEqual(stat.S_IMODE(os.stat(self.token_file).st_mode), 0o600)

    def test_an_expired_token_is_refreshed_without_a_secret(self):
        self.sign_in(expires_at=time.time() - 10); self.release()
        rc, j = self.upd("check")
        self.assertEqual(rc, 0, j)
        g = self.az.grants[-1]
        self.assertEqual((g["grant_type"], g["client_id"], g["refresh_token"]), ("refresh_token", CLIENT, "azr-1"))
        self.assertNotIn("client_secret", g)
        self.assertEqual(self.az.gets()[-1][2]["authorization"], "Bearer az-2")

    def test_missing_sign_in_details_mean_not_set_up(self):
        self.configure(tenant="", client_id="")
        self.assertFalse(self.upd("status")[1]["configured"])
        rc, j = self.upd("login-start")
        self.assertEqual(rc, 1)
        self.assertIn("not set up", j["error"])
        self.assertEqual(self.az.calls, [])


class AzureCheck(AzureBase):
    def test_not_signed_in_asks_for_sign_in_and_fetches_nothing(self):
        self.release()
        rc, j = self.upd("check")
        self.assertEqual(rc, 1)
        self.assertIn("update login", j["error"])
        self.assertEqual(self.az.gets(), [])

    def test_a_newer_approved_release_is_offered_from_the_release_view(self):
        self.sign_in(); self.release()
        rc, j = self.upd("check")
        self.assertEqual(rc, 0, j)
        self.assertEqual((j["current"], j["available"]["version"], j["available"]["notes"]), (self.current, NEW, "Faster everything."))
        paths = [c[1] for c in self.az.gets()]
        self.assertEqual(paths, [REGISTRY + "/rivis"], "with the manifest in the package metadata no package is downloaded")
        self.assertTrue(os.path.isfile(os.path.join(self.home, ".rivis", "update-policy", "manifest.json")))

    def test_without_metadata_the_manifest_is_read_from_the_package(self):
        self.sign_in(); self.release(in_meta=False)
        rc, j = self.upd("check")
        self.assertEqual(rc, 0, j)
        self.assertEqual(j["available"]["version"], NEW)
        self.assertIn("%s/rivis/-/rivis-%s.tgz" % (REGISTRY, NEW), [c[1] for c in self.az.gets()])

    def test_the_tarball_url_from_the_feed_is_never_followed(self):
        self.sign_in(); self.release(in_meta=False)
        self.upd("check")
        self.assertFalse(any("elsewhere" in c[1] for c in self.az.calls))

    def test_the_newest_version_wins_and_older_are_ignored(self):
        self.sign_in(); self.release(version="9.9.8"); self.release(version="9.10.0")
        self.assertEqual(self.upd("check")[1]["available"]["version"], "9.10.0")

    def test_the_same_version_is_not_offered(self):
        self.sign_in(); self.release(version=self.current)
        self.assertIsNone(self.upd("check")[1]["available"])

    def test_nothing_promoted_yet_is_no_update(self):
        self.sign_in()
        rc, j = self.upd("check")
        self.assertEqual((rc, j["available"]), (0, None))

    def test_a_tampered_manifest_is_refused(self):
        self.sign_in(); self.release(tamper=True)
        rc, j = self.upd("check")
        self.assertEqual(rc, 1)
        self.assertIn("signature", j["error"])

    def test_a_manifest_for_another_version_is_refused(self):
        self.sign_in(); self.release(man_version="9.9.7")
        rc, j = self.upd("check")
        self.assertEqual(rc, 1)
        self.assertIn("incomplete", j["error"])

    def test_a_zip_name_with_a_path_is_refused(self):
        self.sign_in(); self.release(zname="../evil.zip")
        rc, j = self.upd("check")
        self.assertEqual(rc, 1)
        self.assertIn("incomplete", j["error"])

    def test_no_read_access_names_the_readers_group(self):
        self.sign_in(); self.release(); self.az.answer = 403
        rc, j = self.upd("check")
        self.assertEqual(rc, 1)
        self.assertIn("readers group", j["error"])

    def test_a_sign_in_page_answer_forgets_the_token(self):
        self.sign_in(); self.release(); self.az.answer = 203
        rc, j = self.upd("check")
        self.assertEqual(rc, 1)
        self.assertIn("no longer valid", j["error"])
        self.assertFalse(os.path.exists(self.token_file))


class AzureDownload(AzureBase):
    def test_the_installer_is_verified_kept_private_and_the_package_dropped(self):
        self.sign_in(); self.release(zip_bytes=b"PK real bytes")
        rc, j = self.upd("download")
        self.assertEqual(rc, 0, j)
        self.assertEqual(open(j["path"], "rb").read(), b"PK real bytes")
        self.assertEqual(stat.S_IMODE(os.stat(j["path"]).st_mode), 0o600)
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(j["path"]), "package.tgz")))

    def test_a_wrong_sha256_is_refused_and_nothing_is_kept(self):
        self.sign_in(); self.release(zip_bytes=b"PK real bytes", sha="0" * 64)
        rc, j = self.upd("download")
        self.assertEqual(rc, 1)
        self.assertIn("SHA-256", j["error"])
        d = os.path.join(self.home, ".rivis", "updates", NEW)
        self.assertFalse(os.path.isdir(d) and os.listdir(d), os.listdir(d) if os.path.isdir(d) else None)

    def test_a_link_in_place_of_the_installer_is_refused(self):
        self.sign_in(); self.release(symlink_zip=True)
        rc, j = self.upd("download")
        self.assertEqual(rc, 1)
        self.assertIn("not a plain file", j["error"])


class AzureFailureModes(AzureBase):
    def test_no_network_is_one_plain_sentence_not_a_traceback(self):
        self.configure()
        p = os.path.join(self.tool, "product.json")
        prod = json.load(open(p)); prod["azure_login_url"] = "http://127.0.0.1:9"; json.dump(prod, open(p, "w"))
        r = subprocess.run(["/usr/bin/python3", "-I", os.path.join(self.tool, "addons", "updater.py"), "login-start"],
                           capture_output=True, text=True, env=self.env(), timeout=60)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("cannot reach 127.0.0.1:9", json.loads(r.stdout)["error"])
        self.assertIn("network or VPN", json.loads(r.stdout)["error"])

    def test_a_busy_sign_in_service_keeps_the_sign_in(self):
        # a 503 on the refresh is the service having a moment, not the sign-in being revoked
        self.sign_in(expires_at=time.time() - 10, refresh_expires_at=time.time() + 86400)
        self.az.token_status = 503
        rc, j = self.upd("check")
        self.assertEqual(rc, 1)
        self.assertIn("did not answer", j["error"])
        self.assertTrue(os.path.exists(self.token_file), "the sign-in must survive a 5xx")

    def test_a_redirect_from_https_to_http_never_carries_the_token(self):
        code = ("import sys, urllib.request; sys.path.insert(0, sys.argv[1]); sys.dont_write_bytecode = True\n"
                "import updater\n"
                "h = updater._NoAuthOnRedirect()\n"
                "req = urllib.request.Request('https://pkgs.dev.azure.com/a', headers={'Authorization': 'Bearer secret'})\n"
                "def go(url):\n"
                "    n = h.redirect_request(req, None, 302, 'Found', {}, url)\n"
                "    return 'Authorization' in {k.title() for k in dict(n.header_items())}\n"
                "print(go('http://pkgs.dev.azure.com/x'), go('https://other.example/x'), go('https://pkgs.dev.azure.com/y'))\n")
        r = subprocess.run(["/usr/bin/python3", "-I", "-c", code, os.path.join(self.tool, "addons")],
                           capture_output=True, text=True, env=self.env(), timeout=30)
        self.assertEqual(r.stdout.strip(), "False False True", r.stdout + r.stderr)

    def test_the_device_code_is_read_from_the_environment_not_the_command_line(self):
        self.az.pending = 5
        rc, start = self.upd("login-start")
        self.assertEqual(rc, 0, start)
        r = subprocess.run(["/usr/bin/python3", "-I", os.path.join(self.tool, "addons", "updater.py"), "login-poll"],
                           capture_output=True, text=True, timeout=30,
                           env=dict(self.env(), RIVIS_DEVICE_CODE=start["device_code"]))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(json.loads(r.stdout)["result"], "pending")
        self.assertTrue(any(c[0] == "POST" and c[2].get("device_code") == "dc-1" for c in self.az.calls))


@unittest.skipUnless(os.path.exists("/usr/bin/security"), "needs the macOS Keychain")
class AzureTokenInKeychain(unittest.TestCase):
    """A real Entra access + refresh token pair is bigger than the ~4 KB line `security -i` accepts: it is kept in
    chunks and read back to prove it. Uses a throwaway keychain file, never the user's."""

    def test_large_tokens_round_trip_shrink_cleanly_and_delete(self):
        import tempfile
        d = tempfile.mkdtemp(prefix="kc-")
        kc = os.path.join(d, "t.keychain-db")
        subprocess.run(["security", "create-keychain", "-p", "pw", kc], check=True, capture_output=True)
        self.addCleanup(lambda: subprocess.run(["security", "delete-keychain", kc], capture_output=True))
        subprocess.run(["security", "unlock-keychain", "-p", "pw", kc], check=True, capture_output=True)
        code = (
            "import sys; sys.path.insert(0, sys.argv[1]); sys.dont_write_bytecode = True\n"
            "import updater\n"
            "tok = lambda a, r: {'access_token': 'a' * a, 'refresh_token': 'r' * r, 'expires_at': 1.0e9, 'refresh_expires_at': None}\n"
            "out = []\n"
            "for a, r in ((100, 100), (2400, 1800), (6000, 4000), (9000, 9000)):\n"
            "    updater.token_save(tok(a, r)); out.append(updater.token_load() == tok(a, r))\n"
            "updater.token_save(tok(50, 50)); out.append(updater.token_load() == tok(50, 50))   # no stale chunk is read\n"
            "updater.token_delete(); out.append(updater.token_load() is None)\n"
            "print(out)\n")
        r = subprocess.run(["/usr/bin/python3", "-I", "-c", code, os.path.join(harness.REPO, "addons")],
                           capture_output=True, text=True, timeout=120,
                           env={"HOME": d, "PATH": "/usr/bin:/bin", "RIVIS_KEYCHAIN": kc})
        self.assertEqual(r.stdout.strip(), str([True] * 6), r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
