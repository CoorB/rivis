"""F-03: exporting a saved session with large bodies as HAR must not stall live traffic or the panel.

Before the fix the HAR was built and redacted on the proxy's event loop: two big bodies took a minute or more, and
every proxied call in the meantime hung or timed out."""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import LiveCase


class HarExportDoesNotStall(LiveCase):
    def setUp(self):
        super().setUp()
        for name in [s["name"] for s in self.panel.state()["sessions"]]:
            self.panel.ok("sess_delete", {"name": name})

    def test_big_session_har_keeps_traffic_flowing(self):
        self.assertEqual(self.fetch("/big?mb=30", timeout=120).rc, 0)              # binary, 30 MiB
        self.assertEqual(self.fetch("/bigline?mb=30", timeout=120).rc, 0)          # one text line, 30 MiB
        self.fetch("/json/small", headers={"Authorization": "Bearer sekrit-token-123"})
        self.panel.ok("sess_save", {"name": "bigsess"}, timeout=180)

        lat, errors, stop = [], [], threading.Event()

        def loop():
            while not stop.is_set():
                t = time.time()
                r = self.fetch("/json/small", timeout=30)
                lat.append(time.time() - t)
                if r.rc != 0 or r.status != 200:
                    errors.append((r.rc, r.status))
                time.sleep(0.1)

        th = threading.Thread(target=loop, daemon=True)
        th.start()
        time.sleep(1.0)                      # a baseline before the export starts
        t0 = time.time()
        code, doc, raw = self.panel.post("sess_har", {"name": "bigsess"}, timeout=300)
        took = time.time() - t0
        time.sleep(1.0)
        stop.set()
        th.join(60)

        self.assertFalse(errors, "proxied calls failed during the HAR export: %r" % errors)
        self.assertGreater(len(lat), 5)
        worst = max(lat)
        print("\nHAR export %.2fs; %d small calls, worst %.2fs" % (took, len(lat), worst))
        self.assertLess(worst, 1.0, "a small proxied call took %.2fs while the HAR was exported" % worst)

        self.assertEqual(code, 200, raw[:300])
        entries = doc["har"]["log"]["entries"]
        by_path = {e["request"]["url"].split("?")[0].rsplit("/", 1)[-1]: e for e in entries}
        for big in ("big", "bigline"):
            content = by_path[big]["response"]["content"]
            self.assertEqual(content["text"], "", big)
            self.assertIn("HAR export limit", content.get("comment", ""), big)
            self.assertEqual(content["size"], 30 * 1048576 + (9 if big == "bigline" else 0), big)
        small = by_path["small"]
        self.assertTrue(small["response"]["content"]["text"])                  # normal bodies are kept
        auth = [h["value"] for h in small["request"]["headers"] if h["name"].lower() == "authorization"]
        self.assertTrue(auth and "sekrit-token-123" not in auth[0], auth)    # redaction unchanged
        self.assertNotIn(b"sekrit-token-123", raw)


if __name__ == "__main__":
    import unittest as _u
    _u.main(verbosity=2)
