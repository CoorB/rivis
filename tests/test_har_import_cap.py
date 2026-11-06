"""A HAR bigger than the import cap (10,000 entries) says what it left out; it never drops the tail silently."""
import sys
import unittest
from unittest import mock

import _paths  # noqa: F401
_mitm = mock.MagicMock()
sys.modules.setdefault("mitmproxy", _mitm)
sys.modules.setdefault("mitmproxy.ctx", _mitm.ctx)
sys.modules.setdefault("mitmproxy.http", _mitm.http)
from panel_har import from_har  # noqa: E402


def entry(i):
    return {"request": {"method": "GET", "url": "https://api.example.test/x%d" % i, "headers": [], "queryString": [],
                        "cookies": []},
            "response": {"status": 200, "headers": [], "cookies": [], "content": {"mimeType": "text/plain", "text": "a"}}}


class HarImportCap(unittest.TestCase):
    def test_entries_beyond_the_cap_are_reported_not_dropped_silently(self):
        skipped = []
        out = from_har({"log": {"entries": [entry(i) for i in range(10005)]}}, skipped)
        self.assertEqual(len(out), 10000)
        self.assertTrue(any("5 entries beyond the 10000 limit" in s for s in skipped), skipped)

    def test_a_har_within_the_cap_reports_nothing(self):
        skipped = []
        out = from_har({"log": {"entries": [entry(i) for i in range(3)]}}, skipped)
        self.assertEqual((len(out), skipped), (3, []))


if __name__ == "__main__":
    unittest.main()
