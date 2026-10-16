"""Every control, clicked. A browser sweep over each Tools tab, the paused sheet, help, settings and the keyboard chords.

Added 2026-10-15: of 246 UI controls only 22 had ever been clicked in a browser test; 169 were tested only through
the API underneath, 55 not at all — and the demo that failed was driven through the UI. Each control is clicked on a
freshly rendered tab with a call selected; the page must raise no JavaScript error, no panel API call may answer 5xx,
and the page must still answer afterwards. Device-setup buttons are listed but never clicked: they would run
`rivis ios/android on` against whatever simulators and emulators are attached to this Mac. Nor are the Web browser
"Open …" buttons (a real browser window; the harness also hides every real browser from the tests).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, TABS, UiBase, shot   # noqa: E402

NEVER_CLICK = ("set up", "setup", "turn off", "install", "remove ca", "reset network",   # device actions (real hardware)
               "open ")                                                                    # Web browser: opens a browser window
import re  # noqa: E402
_PANEL = open(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "addons", "panel.js")).read()
# every data-* hook panel.js wires a click handler to (profile cards, session rows, theme picker …), read from the source
# so a control added later is swept without editing this test
_HOOKS = sorted(set(re.findall(r'querySelectorAll\("(\[data-[a-z-]+\])"\)', _PANEL)) - {"[data-t]"})
CONTROLS = ", ".join(["button", "[role=button]", "a.lnk", "input[type=checkbox]", "select", "summary"] + _HOOKS)


@unittest.skipIf(PW_REASON, PW_REASON or "")
class UiSweep(UiBase):
    def setUp(self):
        super().setUp()
        self.server_errors = []
        self.page.on("dialog", lambda d: d.accept())
        self.page.on("response", lambda r: self.server_errors.append("%s %s" % (r.status, r.url))
                     if "/proxy/api/" in r.url and r.status >= 500 else None)

    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def ready(self):
        self.open()
        for path in ("/json/small?sw=1", "/echo?sw=2", "/text?sw=3"):
            self.fetch(path)
        # one of everything, so each tab also shows its per-item controls (edit, toggle, delete, export, replay)
        fid = self.inst.flow_for("/json/small?sw=1")["id"]
        for op, body in (("add", {"rule": {"name": "sw-status", "match": "/text", "action": "status", "status": 503}}),
                         ("bp_add", {"host": "127.0.0.1", "path": "/never", "request": True}), ("mock", {"flow_id": fid}),
                         ("script_new", {"name": "sw-script", "lang": "py"}), ("sess_save", {"name": "sw-session"}),
                         ("compose_save", {"name": "sw-req", "spec": {"method": "GET", "url": self.up.url("/echo?c=1")}}),
                         ("coll_record", {"name": "sw-coll", "record_match": "/echo"})):
            self.panel.post(op, body)                          # idempotent: the instance is shared by the class
        self.fetch("/echo?coll=1")
        self.panel.post("coll_stop", {})
        row = self.page.locator(".flow-table tbody tr", has_text="sw=1").first
        wait_for(lambda: row.count() > 0, 10, 0.2, "row")
        row.click()
        self.page.wait_for_timeout(300)

    def select_call(self):
        row = self.page.locator(".flow-table tbody tr", has_text="sw=1").first
        if not row.get_attribute("class") or "selected" not in row.get_attribute("class"):
            row.click()
            self.page.wait_for_timeout(200)

    def close_overlays(self):
        # not Escape: Esc also deselects the call; close sheets and editors with their own buttons
        self.page.evaluate("""() => { const sr = document.querySelector('#proxy-panel-host').shadowRoot;
            sr.querySelectorAll('.open').forEach((el) => { if (el.id !== 'drawer') el.classList.remove('open'); }); }""")

    def open_tab(self, name):
        self.close_overlays()
        filt = self.page.locator("#sq")
        if filt.count() and filt.input_value():
            filt.fill("")
        if not self.P("#drawer.open").count():
            self.P("#fab").click()
        self.select_call()
        self.P("button[data-t=%s]" % name).click()
        self.page.wait_for_timeout(350)
        if self.P("#main #sback, #main #back, #main [id$=back]").count():      # an editor left open by the last click
            self.P("#main #sback, #main #back, #main [id$=back]").first.click()
            self.page.wait_for_timeout(250)

    def alive(self):
        return self.page.evaluate("() => !!document.querySelector('#proxy-panel-host') && document.readyState") == "complete"

    def sweep(self, open_fn, scope_sel, label):
        """Click each visible control under scope_sel, re-opening the view before every click."""
        open_fn()
        total = self.P(scope_sel).locator(CONTROLS).count()
        clicked, skipped = [], []
        for i in range(total):
            open_fn()
            controls = self.P(scope_sel).locator(CONTROLS)
            if i >= controls.count():
                break
            c = controls.nth(i)
            try:
                if not c.is_visible() or not c.is_enabled():
                    continue
                text = (c.inner_text(timeout=1000) or c.get_attribute("id") or c.get_attribute("aria-label") or "").strip()[:40]
            except Exception:                                    # noqa: BLE001 - re-rendered under us
                continue
            if any(w in text.lower() for w in NEVER_CLICK) and label == "dev":
                skipped.append(text)
                continue
            before = len(self.errors) + len(self.server_errors)
            try:
                tag = c.evaluate("e => e.tagName.toLowerCase()")
                if tag == "select":
                    opts = c.locator("option")
                    if opts.count() > 1:
                        c.select_option(index=opts.count() - 1, timeout=3000)
                else:
                    c.click(timeout=3000)
                self.page.wait_for_timeout(250)
            except Exception as e:                                # noqa: BLE001 - covered by an overlay etc: record, go on
                self.problems.append("%s: could not click %r (%s)" % (label, text, str(e).splitlines()[0][:80]))
                continue
            new = [e for e in (self.errors + self.server_errors)[before:]
                   if not (e[0] == "console.error" and "status of 4" in e[1])]     # a 4xx is validation answering: fine
            if new:
                self.problems.append("%s: %r -> %s" % (label, text, new))
                shot(self.page, "sweep-%s-%d" % (label, i))
            if not self.alive():
                self.problems.append("%s: page dead after %r" % (label, text))
                break
            clicked.append(text)
        return clicked, skipped

    def test_every_control_in_every_tab(self):
        self.problems = []
        self.ready()
        report = {}
        for name in TABS:
            report[name] = self.sweep(lambda n=name: self.open_tab(n), "#main", name)
        for name, (clicked, skipped) in report.items():
            print("SWEEP %-8s clicked %3d  skipped %d %s" % (name, len(clicked), len(skipped), skipped))
        self.assertEqual(self.problems, [])
        self.assertGreater(sum(len(c) for c, _ in report.values()), 80, "the sweep reached too few controls to mean anything")
        self.assertEqual([e for e in self.errors if e[0] == "pageerror"], [])

    def test_header_help_settings_and_chords(self):
        self.problems = []
        self.ready()
        drawer_tab = lambda: self.page.evaluate(
            "() => { const b = document.querySelector('#proxy-panel-host').shadowRoot.querySelector('nav button.on'); return b && b.dataset.t }")
        expect = {"KeyC": "compose", "KeyL": "map", "KeyB": "bp", "KeyN": "net", "KeyE": "net", "KeyS": "scripts", "KeyD": "cmp", "KeyV": "dev"}
        for key, tab in expect.items():
            self.page.keyboard.press("Escape")
            self.page.locator("body").click(position={"x": 5, "y": 5})
            self.page.keyboard.press("Alt+Shift+" + key[-1])
            self.page.wait_for_timeout(350)
            if drawer_tab() != tab:
                self.problems.append("Alt+Shift+%s opened %r, expected %r" % (key[-1], drawer_tab(), tab))
        self.page.keyboard.press("Escape")
        self.page.locator("body").click(position={"x": 5, "y": 5})
        self.page.keyboard.press("?")
        self.page.wait_for_timeout(400)
        help_open = self.page.evaluate("() => !!document.querySelector('#proxy-panel-host').shadowRoot.querySelector('.open [data-h], #help.open, .help.open')")
        if not help_open:
            self.problems.append("? did not open the help sheet")
        shot(self.page, "sweep-help")
        self.assertEqual(self.problems, [])
        self.assertEqual([e for e in self.errors if e[0] == "pageerror"], [])
        self.assertEqual(self.server_errors, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
