"""W11 crash-safe state, schema migrations, rotating logs, and redacted bug reports."""
import json
import os
import stat
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

ADDONS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "addons")
sys.path.insert(0, ADDONS)
import bug_report
from proxy_common import (COLLECTION_SCHEMA_VERSION, RULES_SCHEMA_VERSION, RotatingTextLog,
                          atomic_write_text, migrate_collection, migrate_rules)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import LiveCase, wait_for


class AtomicWrites(unittest.TestCase):
    def test_atomic_write_is_private_complete_and_leaves_no_temp(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "state.json")
            atomic_write_text(path, "complete")
            self.assertEqual(open(path, encoding="utf-8").read(), "complete")
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(os.listdir(root), ["state.json"])

    def test_failed_replace_keeps_the_old_file_and_cleans_the_temp(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "state.json")
            atomic_write_text(path, "old")
            with mock.patch("proxy_common.os.replace", side_effect=OSError("simulated crash")):
                with self.assertRaises(OSError):
                    atomic_write_text(path, "new")
            self.assertEqual(open(path, encoding="utf-8").read(), "old")
            self.assertEqual(os.listdir(root), ["state.json"])


class Schemas(unittest.TestCase):
    def test_legacy_documents_migrate_without_losing_fields(self):
        rules = migrate_rules({"rules": [{"name": "kept"}]})
        collection = migrate_collection({"name": "journey", "entries": [{"status": 200}]})
        self.assertEqual(rules["schema_version"], RULES_SCHEMA_VERSION)
        self.assertEqual(rules["rules"][0]["name"], "kept")
        self.assertEqual(collection["schema_version"], COLLECTION_SCHEMA_VERSION)
        self.assertEqual(collection["entries"][0]["status"], 200)

    def test_future_schemas_are_refused_instead_of_downgraded(self):
        with self.assertRaisesRegex(ValueError, "newer than"):
            migrate_rules({"schema_version": RULES_SCHEMA_VERSION + 1})
        with self.assertRaisesRegex(ValueError, "newer than"):
            migrate_collection({"schema_version": COLLECTION_SCHEMA_VERSION + 1})


class LogsAndReports(unittest.TestCase):
    def test_log_rotates_and_redacts(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "logs", "rivis.log")
            log = RotatingTextLog(path, max_bytes=90, backups=2)
            for i in range(8):
                log.append("info", "line %d token=top-secret-value padding padding" % i)
            self.assertTrue(os.path.isfile(path))
            self.assertTrue(os.path.isfile(path + ".1"))
            self.assertLessEqual(len([x for x in os.listdir(os.path.dirname(path)) if x.startswith("rivis.log")]), 3)
            all_text = "".join(open(os.path.join(os.path.dirname(path), name), encoding="utf-8").read()
                               for name in os.listdir(os.path.dirname(path)))
            self.assertNotIn("top-secret-value", all_text)
            self.assertIn("[REDACTED]", all_text)

    def test_bug_report_contains_only_redacted_diagnostics(self):
        with tempfile.TemporaryDirectory() as root:
            state = os.path.join(root, "state")
            logs = os.path.join(state, "logs")
            os.makedirs(logs)
            secret = "secret-value-123"
            jwt = "abcdefgh.ijklmnop.qrstuvwx"
            home = os.path.expanduser("~")
            with open(os.path.join(logs, "rivis.log"), "w", encoding="utf-8") as fh:
                fh.write('token=%s Authorization: Bearer %s home=%s\n' % (secret, jwt, home))
            os.makedirs(os.path.join(state, "projects", "default", "sessions"), exist_ok=True)
            with open(os.path.join(state, "web-token"), "w") as fh:
                fh.write("must-never-be-read")
            with open(os.path.join(state, "projects", "default", "sessions", "traffic.flows"), "w") as fh:
                fh.write("must-never-be-read-flow")
            output = os.path.join(root, "report.zip")
            fake_doctor = (0, '{"token":"%s","path":"%s"}' % (secret, home))
            with mock.patch.object(bug_report, "command", side_effect=[fake_doctor, (0, "Mitmproxy: 12.2.3"), (0, "v22")]):
                bug_report.main(["--state-root", state, "--project", "default",
                                 "--rules", os.path.join(state, "rules.json"), "--confdir", os.path.join(root, "conf"),
                                 "--port", "32001", "--web-port", "32002", "--script-dir", os.path.join(state, "scripts"),
                                 "--output", output])
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(set(archive.namelist()), {"manifest.json", "versions.txt", "doctor.txt", "logs.txt", "README.txt"})
                data = b"\n".join(archive.read(name) for name in archive.namelist()).decode("utf-8")
            for forbidden in (secret, jwt, "must-never-be-read", "must-never-be-read-flow", home):
                self.assertNotIn(forbidden, data)
            self.assertIn("[REDACTED]", data)


class LiveLog(LiveCase):
    def test_running_proxy_creates_a_private_product_log(self):
        path = self.inst.path("..", "..", "logs", "rivis.log")
        wait_for(lambda: os.path.isfile(path), 5, 0.1, "Rivis log file")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertIn("Rivis started", open(path, encoding="utf-8").read())


if __name__ == "__main__":
    unittest.main(verbosity=2)
