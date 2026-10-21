"""0.9.9 soak F3: a left click on a call row did not select it when a new call arrived during the press. Chromium and WebKit deliver the
click to the nearest common ancestor of the mousedown and mouseup targets: if the list shifts a row under the pointer between the two,
that is the table body and mitmweb's row handler never runs. A person presses for 80-150 ms and calls arrive several times a second."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402

ROWS = ".flow-table tbody tr:has(td.col-path)"


@unittest.skipIf(PW_REASON, PW_REASON or "")
class RowSelectDuringArrivals(UiBase):
    def selected(self):
        h = self.page.evaluate("location.hash").replace("#/", "").split("?")[0].split("/")
        return h[1] if len(h) > 1 and h[0] == "flows" else None

    def first_path(self):
        return self.page.locator(ROWS).first.locator(".col-path").text_content()

    def prepare(self):
        for i in range(30):
            self.fetch("/echo?seed=%02d" % i)
        self.open()
        wait_for(lambda: "sort-desc" in (self.page.locator(".flow-table th.col-timestamp").get_attribute("class") or ""), 10, 0.1, "newest first")
        wait_for(lambda: self.page.locator(ROWS).count() >= 10, 10, 0.1, "the calls listed")
        self.page.wait_for_timeout(500)

    def press_with_arrival(self, row, n, delay_before_up=0):
        """Press on `row`, let call `n` arrive and be drawn above it, then release at the same pixel."""
        box = row.bounding_box()
        x, y = box["x"] + box["width"] * 0.35, box["y"] + box["height"] / 2
        self.page.mouse.move(x, y, steps=4)
        self.page.mouse.down()
        self.fetch("/echo?arrive=%02d" % n)
        wait_for(lambda: "arrive=%02d" % n in self.first_path(), 10, 0.05, "the new call drawn at the top")
        self.page.wait_for_timeout(delay_before_up)
        self.page.mouse.up()

    def test_click_selects_the_row_even_if_a_call_arrives_during_the_press(self):
        self.prepare()
        for n in range(4):
            self.page.keyboard.press("Escape")
            self.page.evaluate("location.hash = '#/flows'")
            wait_for(lambda: self.selected() is None, 5, 0.1, "nothing selected")
            row = self.page.locator(ROWS).nth(3)
            want = row.locator(".col-path").text_content()
            self.press_with_arrival(row, n)
            wait_for(lambda: self.selected() is not None, 3, 0.1, "the pressed call to be selected (call %d arrived mid-press)" % n)
            self.assertIn(want, self.page.locator(ROWS + ".selected").first.locator(".col-path").text_content())
        self.assertEqual(self.errors, [])

    def test_a_drag_across_rows_is_not_a_click(self):
        self.prepare()
        self.page.evaluate("location.hash = '#/flows'")
        row = self.page.locator(ROWS).nth(3)
        box = row.bounding_box()
        self.page.mouse.move(box["x"] + 40, box["y"] + box["height"] / 2, steps=4)
        self.page.mouse.down()
        self.page.mouse.move(box["x"] + 40, box["y"] + box["height"] * 3.5, steps=6)
        self.page.mouse.up()
        self.page.wait_for_timeout(500)
        self.assertIsNone(self.selected())

    def test_plain_click_still_selects_once(self):
        self.prepare()
        self.page.locator(ROWS).nth(2).click()
        wait_for(lambda: self.selected() is not None, 3, 0.1, "selected")


if __name__ == "__main__":
    unittest.main()
