"""Keyboard and screen-reader use of the new main window (/rivis/): shortcuts from a text field, accessible
names when the toolbar collapses, dialog Tab order, and the status bar not chattering as a live region."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402

MOD = "Meta" if sys.platform == "darwin" else "Control"


@unittest.skipIf(PW_REASON, PW_REASON or "")
class A11yKeyboard(UiBase):
    def open_new(self, *paths):
        for p in paths or ("/json/small?a11y=1",):
            self.fetch(p)
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.goto("http://127.0.0.1:%d/rivis/" % self.inst.web_port)
        self.page.locator("#rv-app").wait_for(timeout=15000)
        self.errors[:] = [e for e in self.errors if not (e[0] == "requestfailed" and e[1].endswith("/proxy/api/state"))]
        wait_for(lambda: self.page.evaluate("!!(window.RivisTools && window.RivisApp)"), 10, 0.1, "tools ready")
        return self.page

    def win(self, wid):
        return self.page.locator('.rv-win[data-win="%s"]' % wid)

    def test_compose_and_devices_chords_work_while_filter_has_focus(self):
        """⌥⌘ tool chords type nothing, so they must open from a text field — same as Map Local / Breakpoint."""
        self.open_new()
        self.page.locator("#q").click()
        self.page.locator("#q").fill("still-typing")
        self.page.keyboard.press(MOD + "+Alt+C")
        wait_for(lambda: self.win("compose").is_visible(), 5, 0.1, "Compose from the filter")
        self.assertTrue(self.page.evaluate(
            "() => !!document.activeElement.closest('.rv-win[data-win=\"compose\"]')"), "focus moves into Compose")
        self.page.keyboard.press("Escape")
        wait_for(lambda: not self.win("compose").is_visible(), 5, 0.1, "Compose closed")
        self.page.locator("#q").click()
        self.assertEqual(self.page.locator("#q").input_value(), "still-typing")
        self.page.keyboard.press(MOD + "+Alt+D")
        wait_for(lambda: self.win("devices").is_visible(), 5, 0.1, "Devices from the filter")
        self.assertEqual(self.errors, [])

    def test_help_lists_compose_and_devices_chords(self):
        """? must list Compose and Devices in the KEYS table (the Proxyman blurb already mentions the words)."""
        self.open_new()
        self.page.locator("#tscroll").focus()
        self.page.keyboard.press("?")
        wait_for(lambda: self.page.locator("#dialog").is_visible(), 5, 0.1, "help open")
        key_rows = self.page.evaluate("() => [...document.querySelectorAll('.rv-keys tr')].map((r) => r.innerText)")
        self.assertTrue(any("Compose" in r for r in key_rows), "Compose missing from the shortcuts table")
        self.assertTrue(any("Devices" in r for r in key_rows), "Devices missing from the shortcuts table")
        self.assertEqual(self.errors, [])

    def test_toolbar_tools_keep_an_accessible_name_when_labels_collapse(self):
        """At ≤1100px the visible label is hidden; without aria-label, a screen reader announces only 'button' (or a glyph)."""
        self.open_new()
        self.page.set_viewport_size({"width": 1000, "height": 700})
        wait_for(lambda: self.page.evaluate(
            "() => getComputedStyle(document.querySelector('#tb-tools .rv-tb-l')).display === 'none'"), 5, 0.1, "labels collapsed")
        fixed = self.page.evaluate("""() => {
          const ids = ['tb-record', 'tb-clear', 'tb-follow', 'tb-more'];
          return Object.fromEntries(ids.map((id) => [id, (document.getElementById(id).getAttribute('aria-label') || '').trim()]));
        }""")
        self.assertEqual(fixed["tb-record"], "Record")
        self.assertEqual(fixed["tb-clear"], "Clear")
        self.assertEqual(fixed["tb-follow"], "Follow")
        self.assertEqual(fixed["tb-more"], "More")
        named = self.page.evaluate("""() => {
          const tools = [...document.querySelectorAll('#tb-tools [data-tool]')];
          return tools.map((b) => ({
            id: b.dataset.tool,
            name: (b.getAttribute('aria-label') || '').trim(),
            labelHidden: getComputedStyle(b.querySelector('.rv-tb-l')).display === 'none',
          }));
        }""")
        self.assertTrue(named, "tool buttons present")
        for row in named:
            self.assertTrue(row["labelHidden"], row)
            self.assertTrue(row["name"], "tool %s has no accessible name when collapsed" % row["id"])
        self.page.locator("#tb-record").click()
        wait_for(lambda: self.page.locator("#tb-record").get_attribute("aria-pressed") == "false", 5, 0.1, "paused")
        self.assertEqual(self.page.locator("#tb-record").get_attribute("aria-label"), "Paused")
        self.assertEqual(self.errors, [])

    def test_help_dialog_keeps_tab_inside_and_restores_focus(self):
        self.open_new()
        self.page.locator("#tscroll").focus()
        self.page.keyboard.press("?")
        dlg = self.page.locator("#dialog")
        wait_for(lambda: dlg.is_visible(), 5, 0.1, "help open")
        self.assertTrue(self.page.evaluate("() => document.getElementById('dialog').contains(document.activeElement)"))
        for _ in range(12):
            self.page.keyboard.press("Tab")
            self.assertTrue(self.page.evaluate("() => document.getElementById('dialog').contains(document.activeElement)"),
                            "Tab left the help dialog")
            self.page.keyboard.press("Shift+Tab")
            self.assertTrue(self.page.evaluate("() => document.getElementById('dialog').contains(document.activeElement)"),
                            "Shift+Tab left the help dialog")
        self.page.keyboard.press("Escape")
        wait_for(lambda: not dlg.is_visible(), 5, 0.1, "help closed")
        wait_for(lambda: self.page.evaluate("document.activeElement && document.activeElement.id") == "tscroll", 5, 0.1,
                 "focus back on the list")
        self.assertEqual(self.errors, [])

    def test_column_picker_keeps_tab_inside_and_restores_focus(self):
        """pickColumns shares the dialog trap and must put focus back (it previously did not)."""
        self.open_new()
        self.page.locator("#colpick").focus()
        self.page.locator("#colpick").click()
        dlg = self.page.locator("#dialog")
        wait_for(lambda: dlg.is_visible(), 5, 0.1, "columns open")
        self.page.keyboard.press("Escape")
        wait_for(lambda: not dlg.is_visible(), 5, 0.1, "columns closed")
        wait_for(lambda: self.page.evaluate("document.activeElement && document.activeElement.id") == "colpick", 5, 0.1,
                 "focus back on the column picker")
        self.page.locator("#colpick").click()
        wait_for(lambda: dlg.is_visible(), 5, 0.1, "columns reopened")
        self.assertTrue(self.page.evaluate("() => document.getElementById('dialog').contains(document.activeElement)"))
        for _ in range(20):
            self.page.keyboard.press("Tab")
            self.assertTrue(self.page.evaluate("() => document.getElementById('dialog').contains(document.activeElement)"),
                            "Tab left the columns dialog")
        self.assertEqual(self.errors, [])

    def test_status_bar_is_not_a_polite_live_region(self):
        """role=status implies aria-live=polite; the bar rewrites on every call and would speak the count constantly."""
        self.open_new()
        info = self.page.evaluate("""() => {
          const el = document.getElementById('status');
          return { role: el.getAttribute('role'), live: el.getAttribute('aria-live') };
        }""")
        self.assertNotEqual(info["role"], "status")
        self.assertNotEqual(info["live"], "polite")
        self.assertEqual(self.errors, [])

    def test_escape_closes_front_window_after_filter_blur(self):
        """Help: Esc closes the front window. Typing in the filter may clear first; the next Esc must still close it."""
        self.open_new()
        self.page.keyboard.press(MOD + "+Alt+L")
        wait_for(lambda: self.win("map").is_visible(), 5, 0.1, "Map Local open")
        self.page.locator("#q").click()
        self.page.locator("#q").fill("half-typed")
        self.page.keyboard.press("Escape")
        self.assertEqual(self.page.locator("#q").input_value(), "")
        self.assertTrue(self.win("map").is_visible(), "first Esc only clears the filter")
        self.page.locator("#tscroll").focus()
        self.page.keyboard.press("Escape")
        wait_for(lambda: not self.win("map").is_visible(), 5, 0.1, "second Esc closes the front window")
        self.assertEqual(self.errors, [])
