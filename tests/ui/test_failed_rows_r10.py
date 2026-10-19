"""R10-06/07: a call that failed shows as failed in the call list, not as a blank or green status with "…" for ever."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for                 # noqa: E402
from test_traffic_r10 import _RawServer      # noqa: E402
from test_ui import PW_REASON, UiBase        # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class FailedRowsR10Ui(UiBase):
    def cells(self, text):
        return self.page.evaluate("""(text) => {
            const tr = [...document.querySelectorAll('.flow-table tbody tr')].find((r) => r.textContent.includes(text));
            if (!tr) return null;
            const st = tr.querySelector('td.col-status'), tm = tr.querySelector('td.col-time');
            return { failed: st.getAttribute('data-failed'), code: st.getAttribute('data-code'),
                     timeFailed: tm.getAttribute('data-failed'), timeAfter: getComputedStyle(tm, '::after').content,
                     title: tm.getAttribute('title') || '' };
        }""", text)

    def test_r10_refused_and_cut_short_calls_show_as_failed(self):
        cut = _RawServer([b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100000\r\n\r\n" + b"x" * 1000])
        self.addCleanup(cut.close)
        self.inst.fetch("http://127.0.0.1:1/x?r10refused=1", timeout=10)
        self.inst.fetch("http://127.0.0.1:%d/midclose?r10cut=1" % cut.port, timeout=10)
        self.open()
        refused = wait_for(lambda: (lambda c: c if c and c["failed"] else None)(self.cells("r10refused=1")), 15, 0.3,
                           "refused row marked failed")
        self.assertEqual(refused["failed"], "1")
        self.assertEqual(refused["code"], "failed")
        self.assertEqual(refused["timeFailed"], "1")
        self.assertEqual(refused["timeAfter"], '"failed"')
        self.assertIn("Failed:", refused["title"])
        cutrow = wait_for(lambda: (lambda c: c if c and c["failed"] else None)(self.cells("r10cut=1")), 15, 0.3,
                          "cut-short row marked failed")
        self.assertEqual(cutrow["failed"], "cut")
        self.assertEqual(cutrow["code"], "200 ✕")
        self.assertIn("received 1000 bytes", cutrow["title"])
        ok = self.cells("/json/small")
        self.assertIsNone(ok["failed"])
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main()
