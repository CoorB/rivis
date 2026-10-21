"""0.9.9 review batch B (M2, m1, m2, m3): each test runs the user's own command or panel call, no extra flags."""
import glob
import os
import sys
import time
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import LiveCase, Suite, wait_for

SECRET = "SEKRET9999zz"


class ReviewB(LiveCase):
    def cli(self, *args):
        return Suite.get().rivis(*args, home=self.inst.home, env=self.inst.env, timeout=120)

    def zip_text(self, out):
        zips = glob.glob(os.path.join(self.inst.home, ".rivis", "bug-reports", "*.zip"))
        self.assertTrue(zips, out.stdout[-400:] + out.stderr[-400:])
        with zipfile.ZipFile(max(zips, key=os.path.getmtime)) as z:
            return "\n".join(z.read(n).decode("utf-8", "replace") for n in z.namelist() if n == "logs.txt")

    def test_M2_addon_warning_reaches_the_bug_report_with_tokens_masked(self):
        # an add-on warning (a rule the proxy refuses to load) whose text carries a token
        bad = "tok-access_token=%s" % SECRET
        self.inst.write_cfg({"rules": [{"name": bad, "enabled": True, "match": "([unclosed", "action": "block"}]})
        wait_for(lambda: "skipping rule" in self.logs(), 20, 0.5, "add-on warning in rivis.log")
        text = self.zip_text(self.cli("bug-report"))
        self.assertIn("skipping rule", text)
        self.assertNotIn(SECRET, text)
        self.assertRegex(text, r"(?i)<redacted>|\[redacted\]")

    def logs(self):
        out = ""
        for p in glob.glob(os.path.join(self.inst.home, ".rivis", "logs", "rivis.log*")):
            with open(p, encoding="utf-8", errors="replace") as fh:
                out += fh.read()
        return out

    def test_m1_panel_edits_url_scope_of_a_cli_throttle_preset(self):
        for preset in ("3g", "lte", "edge", "slow", "500ms"):
            self.assertEqual(self.cli("throttle", preset).returncode, 0)
            code, doc, raw = self.panel.post("profile", {"id": preset, "match": "/echo"})
            self.assertEqual(code, 200, "%s -> %s" % (preset, raw[:200]))
            cfg = self.inst.cfg()
            self.assertEqual((cfg["throttle"], cfg["throttle_match"]), (preset, "/echo"))
        code, _, _ = self.panel.post("profile", {"id": "not-a-profile"})
        self.assertEqual(code, 400)               # a name that is neither a panel profile nor the current one

    def test_m2_rules_on_clears_the_draft_flag(self):
        self.fetch("/json/small?m2=1")
        fid = self.inst.flow_for("/json/small?m2=1")["id"]
        name = self.panel.ok("mock", {"flow_id": fid, "draft": True})["name"]
        self.assertTrue(next(r for r in self.inst.cfg()["rules"] if r["name"] == name).get("draft"))
        self.assertEqual(self.cli("rules", "on", name).returncode, 0)
        rule = next(r for r in self.inst.cfg()["rules"] if r["name"] == name)
        self.assertTrue(rule["enabled"])
        self.assertNotIn("draft", rule)

    def test_m3_copy_url_masks_secrets_when_mask_is_on(self):
        path = "/echo?access_token=%s&otp=123456&keep=yes" % SECRET
        self.fetch(path)
        fid = self.inst.flow_for("keep=yes")["id"]
        masked = self.panel.ok("export", {"flow_id": fid, "fmt": "url"})["text"]          # mask defaults on
        self.assertNotIn(SECRET, masked)
        self.assertNotIn("123456", masked)
        self.assertIn("keep=yes", masked)
        clear = self.panel.ok("export", {"flow_id": fid, "fmt": "url", "mask": False})["text"]
        self.assertIn(SECRET, clear)


if __name__ == "__main__":
    unittest.main(verbosity=2)
