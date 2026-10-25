"""Folder Map Local lookup, confinement, HTTP response files and CLI creation."""
import os
import shutil
import subprocess
import unittest

from harness import REPO, LiveCase


class MapLocalFolder0910(LiveCase):
    def setUp(self):
        super().setUp()
        self.folder = self.inst.path("mocks", "folder-0910")
        os.makedirs(os.path.join(self.folder, "nested"), exist_ok=True)
        self.base = self.up.url("/v1/")
        self.reset_state(rules=[self.rule("folder-0910", "map_local", "^" + __import__("re").escape(self.base),
                                          file=self.folder, base=self.base)])

    def write(self, relative, body):
        path = os.path.join(self.folder, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(body)

    def test_candidates_query_and_disk_reload(self):
        self.write("plain", b"plain")
        self.write("json.json", b'{"one":1}')
        self.write("nested/index.json", b'{"index":1}')
        self.write("last", b"last segment")
        self.assertEqual(self.fetch("/v1/plain?ignored=1").text, "plain")
        self.assertEqual(self.fetch("/v1/json").json(), {"one": 1})
        self.assertIn("application/json", self.fetch("/v1/json").header("Content-Type"))
        self.assertEqual(self.fetch("/v1/nested").json(), {"index": 1})
        self.assertEqual(self.fetch("/v1/deep/last").text, "last segment")
        self.write("plain", b"new")
        self.assertEqual(self.fetch("/v1/plain").text, "new")

    def test_missing_passes_through_with_comment(self):
        response = self.fetch("/v1/missing")
        self.assertEqual(response.status, 404)
        self.assertIn("map-local folder: no file for missing", self.comment("/v1/missing"))
        self.assertEqual(len(self.up.hits_for("/v1/missing")), 1)

    def test_escape_is_refused(self):
        outside = self.inst.path("mocks", "outside.json")
        with open(outside, "wb") as fh:
            fh.write(b"outside")
        os.symlink(outside, os.path.join(self.folder, "link"))
        self.assertEqual(self.fetch("/v1/link").status, 502)
        self.assertEqual(self.fetch("/v1/%2e%2e/outside.json", extra=("--path-as-is",)).status, 502)
        self.assertEqual(self.fetch("/v1/%2Foutside.json", extra=("--path-as-is",)).status, 502)
        self.assertEqual(len(self.up.hits_for("/v1/link")), 0)

    def test_http_response_file_and_header_filter(self):
        self.write("saved.json", b"HTTP/1.1 203 Non-Authoritative Information\r\nContent-Type: application/json\r\nConnection: close, X-Private\r\nX-Private: no\r\nX-Saved: yes\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n{\"saved\":true}")
        response = self.fetch("/v1/saved")
        self.assertEqual(response.status, 203)
        self.assertEqual(response.json(), {"saved": True})
        self.assertEqual(response.header("X-Saved"), "yes")
        for name in ("Connection", "X-Private", "Transfer-Encoding", "Content-Encoding"):
            self.assertIsNone(response.header(name))
        single = self.inst.path("mocks", "single.http")
        with open(single, "wb") as fh:
            fh.write(b"HTTP/1.1 418 Teapot\nContent-Type: text/plain\nX-Saved: single\n\nsingle")
        self.reset_state(rules=[self.rule("single", "map_local", "/v1/single", file=single)])
        self.assertEqual(self.fetch("/v1/single").status, 418)
        self.assertEqual(self.fetch("/v1/single").header("X-Saved"), "single")

    def test_cli_add_folder_and_doctor_validation(self):
        self.reset_state()
        cp = self.suite.rivis("rules", "add", "cli-folder", "match=/v1/", "action=map_local",
                              "file=" + self.folder, "base=" + self.base, home=self.inst.home)
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertEqual(next(r for r in self.inst.cfg()["rules"] if r["name"] == "cli-folder")["base"], self.base)
        self.assertFalse(any(r.get("name") == "cli-folder" for r in self.panel.state()["skipped_rules"]))


if __name__ == "__main__":
    unittest.main()


class PanelOps0910(LiveCase):
    """The two Rules-tab controls, at the panel API the buttons post to."""

    def test_maplocal_folder_add_serves_the_folder_and_refuses_bad_input(self):
        folder = self.inst.path("mocks", "panel-folder")
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "cards.json"), "w") as fh:
            fh.write('{"cards": 3}')
        base = self.up.url("/v2/")
        self.panel.ok("maplocal_folder_add", {"name": "panel-folder", "base": base, "folder": folder})
        self.inst.write_cfg(self.inst.cfg())
        self.assertEqual(self.fetch("/v2/cards").json(), {"cards": 3})
        code, doc, _raw = self.panel.post("maplocal_folder_add", {"name": "panel-folder", "base": base, "folder": folder})
        self.assertEqual((code, doc["error"]), (400, "a rule with that name exists"))
        code, doc, _raw = self.panel.post("maplocal_folder_add", {"name": "gone", "base": base, "folder": folder + "-gone"})
        self.assertEqual(code, 400)
        self.assertIn("folder not found", doc["error"])

    def test_proxyman_import_reads_proxymans_own_folder(self):
        code, doc, _raw = self.panel.post("proxyman_import", {})
        self.assertEqual(code, 400, "no Proxyman on this (test) Mac: a reason, not a crash")
        self.assertIn("Proxyman import", doc["error"])
        here = os.path.join(self.inst.home, "Library", "Application Support", "com.proxyman.NSProxy", "user-data")
        shutil.copytree(os.path.join(REPO, "tests", "fixtures", "proxyman"), here)
        summary = self.panel.ok("proxyman_import", {})["summary"]
        self.assertIn("imported 4, skipped 1", summary)
        self.assertIn("exact", {r["name"] for r in self.inst.cfg()["rules"]})
