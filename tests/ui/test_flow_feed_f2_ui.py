"""F2 in a real browser: with the Tools drawer open the panel no longer downloads the whole call list every poll. After the
first full answer it asks only for what changed (GET /proxy/api/flows_since?epoch&cursor), and it still takes a full answer
now and then (the interval is shortened for the test with localStorage rivis-flow-resync-ms)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class FlowFeedUi(UiBase):
    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def watch(self):
        self.resps = []                         # every call-list download; bodies are read later, from the test thread

        def got(r):
            path = r.url.split("?")[0]
            if path.endswith("/flows") or path.endswith("/proxy/api/flows_since"):
                self.resps.append(r)
        self.page.on("response", got)

    def until(self, cond, seconds, what):
        """Like wait_for, but pumping the browser's events (time.sleep would let Playwright's handlers starve)."""
        for _ in range(int(seconds * 5)):
            if cond():
                return
            self.page.wait_for_timeout(200)
        raise AssertionError("timed out after %s s waiting for %s" % (seconds, what))

    @property
    def lists(self):
        out = []
        for r in self.resps:
            try:
                out.append((r.url, len(r.body())))
            except Exception:                   # noqa: BLE001 - body already gone
                pass
        return out

    def test_open_drawer_polls_download_only_the_delta_with_a_periodic_full_resync(self):
        for i in range(40):                                       # a list big enough that "the whole list" is plainly bigger
            self.fetch("/json/small?f2ui=%d" % i)
        wait_for(lambda: len(self.inst.flows()) >= 40, 15, 0.2, "calls")
        self.page.add_init_script("try { localStorage.setItem('rivis-flow-resync-ms', '4000') } catch (e) {}")
        self.open()
        self.watch()
        self.P("#fab").click()
        self.until(lambda: self.lists, 10, "first list download")
        self.page.wait_for_timeout(1500)
        stock = [u for u, _ in self.lists if u.split("?")[0].endswith("/flows")]
        self.assertEqual(stock, [], "the panel must not download mitmweb's whole /flows list on every poll")
        first_full = max(n for _, n in self.lists)
        self.assertGreater(first_full, 20000, "a 40-call list is expected to be large")
        self.page.wait_for_timeout(1000)
        self.fetch("/json/small?f2ui=new")
        self.until(lambda: len([u for u, _ in self.lists if "epoch=" not in u]) >= 3, 15,
                   "a periodic full resync (rivis-flow-resync-ms) after the first full list")
        deltas = [(u, n) for u, n in self.lists if "epoch=" in u]
        fulls = [n for u, n in self.lists if "epoch=" not in u]
        self.assertTrue(deltas, "the open drawer must keep polling, incrementally")
        self.assertLess(max(n for _, n in deltas), first_full / 5,
                        "a poll between full resyncs carries only what changed: %r vs full %d" % ([n for _, n in deltas], first_full))
        carrying = [r for r in self.resps if "epoch=" in r.url and b"f2ui=new" in r.body()]
        self.assertGreaterEqual(len(carrying), 1, "the new call arrives in a delta")
        self.assertLessEqual(len(carrying), 3, "…and only again when it changes (its response arriving)")
        self.assertGreater(min(fulls), first_full * 0.8)
        self.assertEqual([e for e in self.errors if "400" not in e[1]], [])


if __name__ == "__main__":
    unittest.main()
