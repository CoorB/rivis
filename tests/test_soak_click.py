"""The soak's click must bring an element that is below the fold into view before pressing, and refuse to press outside the window
(soak F1: the leave-alone chips sat at y=911 in an 837 px window; the "click" went nowhere and the scenario blamed the product)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "soak"))
from driver import SoakFail, Ui  # noqa: E402


class FakeLoc:
    def __init__(self, y, scrolls):
        self.y, self.scrolls = y, scrolls
        self.first = self

    def wait_for(self, **kw):
        pass

    def scroll_into_view_if_needed(self, **kw):
        if self.scrolls:
            self.y = 400

    def bounding_box(self):
        return {"x": 100, "y": self.y, "width": 40, "height": 20}


class FakePage:
    viewport_size = {"width": 1512, "height": 837}

    def wait_for_timeout(self, _ms):
        pass


class ClickUi(Ui):
    def __init__(self):
        import random
        self.rng = random.Random(1)
        self.page_mock = FakePage()

    @property
    def page(self):
        return self.page_mock


class SoakClickTests(unittest.TestCase):
    def test_an_element_below_the_fold_is_scrolled_to_before_the_press(self):
        x, y = ClickUi().centre(FakeLoc(901, scrolls=True))
        self.assertLess(y, 837)

    def test_an_element_that_cannot_be_scrolled_to_is_a_failure_not_a_dead_click(self):
        with self.assertRaises(SoakFail):
            ClickUi().centre(FakeLoc(901, scrolls=False))

    def test_a_node_replaced_while_measuring_is_measured_again(self):
        class Replaced(FakeLoc):
            def __init__(self):
                super().__init__(901, scrolls=True)
                self.calls = 0

            def scroll_into_view_if_needed(self, **kw):
                self.calls += 1
                if self.calls == 1:                    # the panel redrew the tab: the node it had found is gone
                    raise Exception("Locator.scroll_into_view_if_needed: Element is not attached to the DOM")
                super().scroll_into_view_if_needed(**kw)
        loc = Replaced()
        x, y = ClickUi().centre(loc)
        self.assertEqual(loc.calls, 2)
        self.assertLess(y, 837)

    def test_other_errors_while_measuring_are_not_swallowed(self):
        class Broken(FakeLoc):
            def scroll_into_view_if_needed(self, **kw):
                raise Exception("Timeout 8000ms exceeded")
        with self.assertRaises(Exception):
            ClickUi().centre(Broken(901, scrolls=True))


if __name__ == "__main__":
    unittest.main()
