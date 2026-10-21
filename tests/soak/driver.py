"""Human-like input and panel helpers on top of Playwright: real mouse moves (with steps), real wheel, real keystrokes,
randomised 200-2000 ms pauses from a seeded RNG, and the checks every scenario shares."""
import json
import re
import sys
import time

import health

ROOT = "document.querySelector('#proxy-panel-host').shadowRoot"


class SoakFail(AssertionError):
    pass


def check(cond, msg):
    if not cond:
        raise SoakFail(msg)


class Ui:
    def __init__(self, s):
        self.s = s                      # the Soak object: cfg, page, rng, metrics, inst, up
        self.cfg, self.rng, self.m = s.cfg, s.rng, s.metrics
        self.mouse = (756, 420)

    @property
    def page(self):
        return self.s.page

    # -- locators / JS ------------------------------------------------------------------------------------------------
    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def root_js(self, expr, arg=None):
        return self.page.evaluate("(arg) => { const root = %s; %s }" % (ROOT, expr), arg)

    def now_ms(self):
        return self.page.evaluate("Date.now()")

    # -- pacing -------------------------------------------------------------------------------------------------------
    def pause(self, lo=200, hi=2000):
        """A human pause: triangular 200-2000 ms (most near 500-900), scaled for the smoke run."""
        ms = self.rng.triangular(lo, hi, lo + (hi - lo) * 0.2) * self.cfg.pause_scale
        end = time.time() + ms / 1000.0
        while True:
            left = end - time.time()
            if left <= 0:
                break
            self.page.wait_for_timeout(min(left, 0.25) * 1000)
            self.s.tick()

    def wait(self, fn, timeout=8.0, desc="condition", every=0.1):
        end = time.time() + timeout
        last = None
        while time.time() < end:
            try:
                last = fn()
                if last:
                    return last
            except SoakFail:
                raise
            except Exception as exc:            # noqa: BLE001 - polling: remember, retry
                last = exc
            self.page.wait_for_timeout(every * 1000)
        raise SoakFail("timed out after %.0fs waiting for %s (last: %r)" % (timeout, desc, last))

    # -- mouse / keyboard (real input) --------------------------------------------------------------------------------
    def move(self, x, y):
        steps = self.rng.randint(6, 14)
        self.page.mouse.move(x, y, steps=steps)
        self.mouse = (x, y)

    def click_xy(self, x, y, button="left", dwell=None):
        self.move(x, y)
        self.page.mouse.down(button=button)
        self.page.wait_for_timeout(dwell if dwell is not None else self.rng.randint(40, 110))
        self.page.mouse.up(button=button)

    def centre(self, loc, timeout=8000):
        box = None
        for _ in range(5):                      # a re-render can swap the node between "visible" and "measured"
            loc.first.wait_for(state="visible", timeout=timeout)
            box = loc.first.bounding_box()
            if box:
                break
            self.page.wait_for_timeout(200)
        check(box is not None, "element has no box: %s" % loc)
        jx, jy = self.rng.uniform(-0.2, 0.2) * box["width"], self.rng.uniform(-0.2, 0.2) * box["height"]
        return box["x"] + box["width"] / 2 + jx, box["y"] + box["height"] / 2 + jy

    def click(self, loc, button="left"):
        """Move to the element, and press only if it is still under the pointer: toolbar items shift while the page re-lays out."""
        for _ in range(4):
            x, y = self.centre(loc)
            self.move(x, y)
            b = loc.first.bounding_box()
            if b and b["x"] <= x <= b["x"] + b["width"] and b["y"] <= y <= b["y"] + b["height"]:
                break
        self.page.mouse.down(button=button)
        self.page.wait_for_timeout(self.rng.randint(40, 110))
        self.page.mouse.up(button=button)

    def select_all(self):
        self.page.keyboard.press("Meta+a" if sys.platform == "darwin" else "Control+a")

    def type(self, text):
        self.page.keyboard.type(text, delay=self.rng.randint(45, 120))

    def key(self, k):
        self.page.keyboard.press(k)

    def wheel(self, dy, steps=1, over_table=True):
        if over_table:
            b = self.page.locator(".flow-table").bounding_box()
            x, y = b["x"] + b["width"] * 0.4, b["y"] + b["height"] * 0.5
            if abs(self.mouse[0] - x) > 200 or abs(self.mouse[1] - y) > 300:
                self.move(x, y)
        for _ in range(steps):
            self.page.mouse.wheel(0, dy)
            self.page.wait_for_timeout(self.rng.randint(60, 160))

    # -- the call list ------------------------------------------------------------------------------------------------
    def list_state(self):
        return self.page.locator(".flow-table").evaluate("e => ({ top: Math.round(e.scrollTop), height: e.scrollHeight, view: e.clientHeight })")

    def rows(self):
        """Rows that are fully visible in the list viewport, with their centre and path text."""
        return self.page.evaluate("""() => {
          const t = document.querySelector('.flow-table'); if (!t) return [];
          const head = t.querySelector('thead').getBoundingClientRect().bottom, box = t.getBoundingClientRect();
          return [...t.querySelectorAll('tbody tr')].filter(r => r.querySelector('.col-path')).map(r => {
            const b = r.getBoundingClientRect();
            return { text: r.querySelector('.col-path').textContent, x: b.x + b.width * 0.35, y: b.y + b.height / 2, top: b.top, bottom: b.bottom,
                     selected: r.classList.contains('selected') };
          }).filter(r => r.top > head + 2 && r.bottom < box.bottom - 2);
        }""")

    def pick_row(self, contains=None, exclude=None):
        rows = [r for r in self.rows() if (not contains or contains in r["text"]) and (not exclude or exclude not in r["text"])]
        check(rows, "no visible call row%s (rows on screen: %d)" % (" containing %r" % contains if contains else "", len(self.rows())))
        return self.rng.choice(rows)

    def selected_id(self):
        h = self.page.evaluate("location.hash").replace("#/", "").split("?")[0].split("/")
        return h[1] if len(h) > 1 and h[0] == "flows" else None

    def go_position(self, pos):
        """Bring the list to the top (newest, following), the middle, or the end using the real wheel."""
        initial = self.list_state()
        span = max(1, initial["height"] - initial["view"])
        distance = (initial["top"] if pos == "top" else
                    span - initial["top"] if pos == "bottom" else
                    abs(span / 2 - initial["top"]))
        # Each batch is two 700px wheel events (one 380px event near the middle).
        # Allow for rendering and new calls, while scaling with the actual distance.
        deadline = time.monotonic() + 8 + distance / 1400 * 0.6
        stalled = 0
        while time.monotonic() < deadline:
            st = self.list_state()
            span = max(1, st["height"] - st["view"])
            if pos == "top" and st["top"] <= 1:
                break
            if pos == "bottom" and st["height"] - st["top"] - st["view"] <= 2:
                break
            if pos == "middle" and 0.35 * span <= st["top"] <= 0.65 * span:
                break
            if pos == "middle":
                direction = -1 if st["top"] > 0.65 * span else 1
                remaining = abs(span / 2 - st["top"])
                self.wheel(direction * (700 if remaining > 2000 else 380), 2 if remaining > 2000 else 1)
            else:
                self.wheel(-700 if pos == "top" else 700, 2)
            after = self.list_state()
            progress = (st["top"] - after["top"] if pos == "top" else
                        after["top"] - st["top"] if pos == "bottom" else
                        abs(st["top"] - span / 2) - abs(after["top"] - max(1, after["height"] - after["view"]) / 2))
            stalled = stalled + 1 if progress < 8 else 0
            if stalled >= 4:
                raise SoakFail("wheel was pushed back or stopped before reaching %s: before=%s after=%s" % (pos, st, after))
        self.page.wait_for_timeout(250)
        st = self.list_state()
        span = max(1, st["height"] - st["view"])
        if pos == "top":
            check(st["top"] <= 1, "could not wheel the list to the top (scrollTop=%s)" % st["top"])
        elif pos == "bottom":
            check(st["height"] - st["top"] - st["view"] <= 2, "could not wheel the list to the end: %s" % st)
        else:
            check(0.2 * span <= st["top"] <= 0.8 * span, "could not park the list in the middle: %s" % st)

    # -- panel state ----------------------------------------------------------------------------------------------------
    def menu_open(self):
        return self.page.evaluate("() => %s.querySelector('#cmenu').classList.contains('open')" % ROOT)

    def drawer_open(self):
        return self.page.evaluate("() => %s.querySelector('#drawer').classList.contains('open')" % ROOT)

    def active_tab(self):
        return self.page.evaluate("() => { const b = %s.querySelector('#drawer nav button.on'); return b && b.dataset.t; }" % ROOT)

    def sheet_open(self, which="pause"):
        return self.page.evaluate("(id) => %s.querySelector('#' + id).classList.contains('open')" % ROOT, which)

    def lost_bar(self):
        return self.page.evaluate("() => %s.querySelector('#lostbar').classList.contains('open')" % ROOT)

    def main_text(self):
        return self.page.evaluate("() => (%s.querySelector('#main') || {}).textContent || ''" % ROOT)

    def panel_text(self):
        return self.page.evaluate("() => %s.textContent" % ROOT)

    def open_tools(self, tab=None):
        if not self.drawer_open():
            for attempt in (1, 2):
                if self.sheet_open("pause"):            # by design the Tools button opens a held call's sheet first
                    self.s.world.reset()
                    self.key("Escape")
                    self.page.wait_for_timeout(600)
                self.click(self.P("#fab"))
                try:
                    self.wait(self.drawer_open, 6, "Tools drawer open")
                    break
                except SoakFail:
                    if attempt == 2:
                        self.page.screenshot(path="%s/open_tools_fail.png" % self.s.out)
                        raise SoakFail("the Tools button did not open the drawer (paused sheet open: %s)" % self.sheet_open("pause"))
            self.pause(200, 900)
        if tab and self.active_tab() != tab:
            self.click(self.P("#drawer nav button[data-t=%s]" % tab))
            self.wait(lambda: self.active_tab() == tab, 6, "tab %s" % tab)
            self.wait(lambda: self.main_text().strip() != "", 10, "tab %s content" % tab)
            self.pause(200, 900)

    def close_tools(self):
        if self.drawer_open():
            self.click(self.P("#close"))
            self.wait(lambda: not self.drawer_open(), 6, "Tools drawer closed")

    def state(self):
        return self.s.inst.panel.state()

    # -- feedback -------------------------------------------------------------------------------------------------------
    def ensure_toast_log(self):
        try:
            self.page.evaluate(health.TOAST_JS)
        except Exception:                                   # noqa: BLE001 - page mid-navigation
            pass

    def toasts_since(self, t0):
        return [t for t in self.page.evaluate("window.__soak ? window.__soak.toasts : []") if t["t"] >= t0]

    def wait_toast(self, rx, since, timeout=None, allow_err=False, desc=None):
        """First toast at/after `since` (browser ms) matching rx. An error toast fails the check unless allow_err."""
        timeout = timeout or self.cfg.action_deadline
        found = []

        def look():
            for t in self.toasts_since(since):
                if t["err"] and not allow_err:
                    raise SoakFail("error toast instead of success: %r" % t["text"])
                if re.search(rx, t["text"]):
                    found.append(t)
                    return True
        self.wait(look, timeout, desc or "toast /%s/" % rx, 0.12)
        return found[0]["text"]

    def clipboard(self):
        return self.page.evaluate("navigator.clipboard.readText()")

    # -- drain the in-page counters into the metrics ---------------------------------------------------------------------
    def drain(self):
        try:
            d = self.page.evaluate(health.DRAIN_JS)
        except Exception:                                   # noqa: BLE001
            return
        if not d:
            return
        for r in d["api"]:
            self.m.add("panel", ((r["t"] - self.s.t0_ms) / 1000.0, r["url"].split("?")[0], r["ms"], r["status"], r["peak"]))
        for r in d["flows"]:
            self.m.add("flows_dl", ((r["t"] - self.s.t0_ms) / 1000.0, r["ms"], r["bytes"], self.s.drawer_flag))
        for r in d["rej"]:
            self.m.add("errors", ((r["t"] - self.s.t0_ms) / 1000.0, "unhandledrejection", r["text"]))
        for r in d["longtasks"]:
            self.m.add("longtasks", ((r["t"] - self.s.t0_ms) / 1000.0, r["ms"]))
        self.m.add("max_peak", (self.m.now(), d["peak"]))
