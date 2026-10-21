"""0.9.9 soak F4: a URL typed into Compose must arrive exactly as typed, while the panel polls and new calls stream in."""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class ComposeTyping(UiBase):
    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def test_typed_url_is_not_mangled_while_calls_stream_in(self):
        self.open()
        stop = threading.Event()

        def traffic():
            i = 0
            while not stop.is_set():
                i += 1
                try:
                    self.fetch("/echo?stream=%d" % i)
                except Exception:       # noqa: BLE001
                    pass
                time.sleep(0.05)
        t = threading.Thread(target=traffic, daemon=True)
        t.start()
        self.addCleanup(t.join, 5)
        self.addCleanup(stop.set)
        self.P("#fab").click()
        self.P("#drawer nav button[data-t=compose]").click()
        wait_for(lambda: self.P("#cu").count() > 0, 8, 0.1, "compose form")
        for rnd in range(3):
            url = "http://backbase-edge-sit.localhost:50890/api/user-manager/client-api/v2/users/me?compose=%d" % rnd
            self.P("#cu").fill("")
            self.P("#cu").click()
            self.page.keyboard.type(url, delay=90)
            self.assertEqual(self.P("#cu").input_value(), url)
            self.page.wait_for_timeout(2600)               # at least two polls with the drawer open
            self.assertEqual(self.P("#cu").input_value(), url)
