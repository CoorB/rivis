"""The soak's wheel driver must cover long lists and reject a wheel that makes no progress."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "soak"))
from driver import SoakFail, Ui  # noqa: E402


class FakePage:
    def wait_for_timeout(self, _ms):
        pass


class WheelUi(Ui):
    def __init__(self, top, height=200726, stuck=False):
        self.top = top
        self.height = height
        self.stuck = stuck
        self.page_mock = FakePage()
        self.wheels = 0

    @property
    def page(self):
        return self.page_mock

    def list_state(self):
        return {"top": self.top, "height": self.height, "view": 726}

    def wheel(self, dy, steps=1, over_table=True):
        self.wheels += steps
        if not self.stuck:
            self.top = max(0, min(self.height - 726, self.top + dy * steps))


class SoakScrollTests(unittest.TestCase):
    def test_wheels_to_both_ends_of_a_200k_pixel_list(self):
        ui = WheelUi(0)
        ui.go_position("bottom")
        self.assertEqual(ui.top, 200000)
        self.assertGreater(ui.wheels, 120)
        ui.go_position("top")
        self.assertEqual(ui.top, 0)

    def test_wheels_to_middle_of_a_200k_pixel_list(self):
        ui = WheelUi(0)
        ui.go_position("middle")
        self.assertGreaterEqual(ui.top, 70000)
        self.assertLess(ui.top, 130000)

    def test_wheel_pushed_back_is_a_hard_failure(self):
        ui = WheelUi(50000, stuck=True)
        with self.assertRaisesRegex(SoakFail, "pushed back or stopped"):
            ui.go_position("top")


if __name__ == "__main__":
    unittest.main()
