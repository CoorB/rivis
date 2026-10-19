"""Source chooser in a real browser: the Tools header's Source menu lists each device and each app with call counts,
choosing one hides every other app's calls, the strip shows it with an ✕, rows carry the app chip, and This call says
who sent the call. Two local programs (the harness's curl and this test process) stand in for two simulator apps:
the panel path is the same, only proxy_source's process classification differs (covered in tests/test_source.py).
"""
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase, shot   # noqa: E402

CURL = "mac|This Mac|curl"


@unittest.skipIf(PW_REASON, PW_REASON or "")
class SourceChooser(UiBase):
    def raw_get(self, path):
        s = socket.create_connection(("127.0.0.1", self.inst.proxy_port), 10)
        try:
            s.sendall(("GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n"
                       % (self.up.url(path), self.up.http_port)).encode())
            while s.recv(65536):
                pass
        finally:
            s.close()

    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def rows(self):
        return self.page.evaluate("[...document.querySelectorAll('.flow-table tbody tr td.col-path')]"
                                  ".map(td => [td.textContent, td.getAttribute('data-src')])")

    def tearDown(self):
        self.panel.ok("source", {"source": None})
        super().tearDown()

    def test_choose_one_app_then_clear_it_from_the_strip(self):
        self.raw_get("/text?from=python")
        page = self.open()
        wait_for(lambda: any(CURL == k["key"] for k in self.panel.state()["sources"]["list"]), 10, 0.2, "curl source")
        page.locator("#fab").click()
        sel = self.P("#source")
        wait_for(lambda: CURL in sel.evaluate("s => [...s.options].map(o => o.value)"), 10, 0.2, "curl in the Source menu")
        labels = sel.evaluate("s => [...s.options].map(o => o.textContent)")
        self.assertEqual(labels[0], "All sources")
        self.assertTrue(any(t.startswith("All of This Mac (") for t in labels), labels)
        self.assertTrue(any(t.startswith("curl (") for t in labels), labels)
        wait_for(lambda: any(src == "curl" for _, src in self.rows()), 10, 0.2, "app chip on curl's rows")
        self.assertTrue(any("from=python" in t for t, _ in self.rows()))

        sel.select_option(CURL)
        wait_for(lambda: self.panel.state()["source"] == CURL, 8, 0.2, "source chosen")
        wait_for(lambda: self.rows() and not any("from=python" in t for t, _ in self.rows()), 10, 0.2, "python call hidden")
        self.assertTrue(all(src == "curl" for _, src in self.rows()), self.rows())
        strip = self.P("#fstrip")
        wait_for(lambda: "Only curl on This Mac" in strip.text_content(), 8, 0.2, "strip chip")
        shot(page, "source-one-app")

        page.locator(".flow-table tbody tr", has_text="/echo?a=1").first.click()       # This call names the sender
        self.P("button[data-t=call]").click()
        wait_for(lambda: "From curl on This Mac" in self.panel_text(), 8, 0.2, "source line on This call")

        strip.locator("[data-un=source]").click()
        wait_for(lambda: self.panel.state()["source"] is None, 8, 0.2, "source cleared")
        wait_for(lambda: any("from=python" in t for t, _ in self.rows()), 10, 0.2, "python call back")
        self.assertEqual(sel.input_value(), "")
        self.assertEqual(self.errors, [])

    def test_this_call_names_a_mac_tool_once_and_the_empty_list_blames_the_source(self):
        page = self.open()
        wait_for(lambda: any(CURL == k["key"] for k in self.panel.state()["sources"]["list"]), 10, 0.2, "curl source")
        page.locator(".flow-table tbody tr", has_text="/echo?a=1").first.click()
        page.locator("#fab").click()
        self.P("button[data-t=call]").click()
        wait_for(lambda: "From curl on This Mac" in self.panel_text(), 8, 0.2, "source line")
        self.assertNotIn("This Mac · This Mac", self.panel_text())             # R8C-07
        self.P("#source").select_option(CURL)
        wait_for(lambda: self.panel.state()["source"] == CURL, 8, 0.2, "source chosen")
        box = self.P("#sq")
        box.click(); box.fill("no-such-call-xyz")
        page.keyboard.press("Enter")
        wait_for(lambda: "none of those calls match" in self.panel_text(), 10, 0.2, "empty-list explainer")   # R8C-05
        self.assertIn("only curl on This Mac", self.panel_text())
        shot(page, "source-empty-explainer")
        self.assertEqual(self.errors, [])

    def test_a_whole_device_and_the_right_click_menu(self):
        self.raw_get("/text?from=python")
        page = self.open()
        wait_for(lambda: any(CURL == k["key"] for k in self.panel.state()["sources"]["list"]), 10, 0.2, "curl source")
        page.locator("#fab").click()
        sel = self.P("#source")
        wait_for(lambda: "mac|This Mac|" in sel.evaluate("s => [...s.options].map(o => o.value)"), 10, 0.2, "device entry")
        sel.select_option("mac|This Mac|")
        wait_for(lambda: self.panel.state()["source"] == "mac|This Mac|", 8, 0.2, "device chosen")
        wait_for(lambda: any("from=python" in t for t, _ in self.rows()) and any("/echo" in t for t, _ in self.rows()),
                 10, 0.2, "both programs of the device listed")
        self.panel.ok("source", {"source": None})
        wait_for(lambda: sel.input_value() == "", 8, 0.2, "the panel saw the change on its next poll")
        row = page.locator(".flow-table tbody tr", has_text="/echo?a=1").first
        wait_for(lambda: row.locator("td.col-path").get_attribute("data-src") == "curl", 10, 0.2, "chip")
        row.click(button="right")
        item = self.P("#cmenu [data-k=src]")
        item.wait_for(timeout=8000)
        self.assertIn("Show only curl", item.text_content())
        item.click()
        wait_for(lambda: self.panel.state()["source"] == CURL, 8, 0.2, "right-click chose the app")
        self.assertEqual(self.errors, [])

    def test_a_running_device_that_is_not_set_up_is_hinted_in_the_source_menu(self):
        """A just-started emulator that is not set up sent no calls, so the Source menu had nothing for it. It now shows
        a "not set up" line (from the Devices result the panel already has) that opens Tools -> Devices. A device that
        has calls, or one that is ready, gets no hint. No real device: the panel's devices call is answered here."""
        import json as _json
        fake = {"ios": [{"id": "SIM-1", "name": "This Mac", "os": "iOS 18", "ready": False}],
                "android": [{"id": "emulator-5554", "name": "Rivis_Test_Play", "os": "Android 15", "ready": False,
                             "ca_ok": False, "proxy_ok": False, "play": True}], "magisk": False, "job": None}
        self.page.route("**/proxy/api/devices", lambda r: r.fulfill(status=200, content_type="application/json", body=_json.dumps(fake)))
        self.raw_get("/text?from=python")
        page = self.open()
        wait_for(lambda: any(CURL == k["key"] for k in self.panel.state()["sources"]["list"]), 10, 0.2, "curl source")
        page.locator("#fab").click()
        sel = self.P("#source")
        hints = lambda: sel.evaluate("s => [...s.options].filter(o => o.value === '__devices').map(o => o.textContent)")
        self.assertEqual(hints(), [], "no Devices result yet: the menu must not start a device check of its own")
        page.locator("button[data-t=dev]").click()
        wait_for(lambda: "Rivis_Test_Play" in self.panel_text(), 15, 0.2, "fake emulator listed")
        wait_for(lambda: hints(), 10, 0.2, "not-set-up hint in the Source menu")
        self.assertEqual(hints(), ["Rivis_Test_Play — not set up (Tools → Devices)"], "a device with calls is not hinted")
        page.locator("button[data-t=call]").click()
        sel.select_option("__devices")
        wait_for(lambda: "Rivis_Test_Play" in self.panel_text() and "Set up" in self.panel_text(), 10, 0.2, "Devices tab opened")
        self.assertEqual(self.panel.state()["source"] or "", "", "the hint must not change the source filter")
        self.assertEqual(sel.evaluate("s => s.value"), "")
        fake["android"][0].update(ready=True, ca_ok=True, proxy_ok=True)
        wait_for(lambda: hints() == [], 15, 0.2, "hint gone once the emulator is ready")
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main()
