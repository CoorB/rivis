"""UI smoke in a real browser (Playwright + Chromium): open the UI, open the panel, click every tab, type into editors
(mitmweb's single-key shortcuts must not fire), no console errors. Screenshots go to tests/.artifacts/.

Skips with a reason when Playwright or its Chromium is missing. To enable on a machine that has neither:
    pip3 install --user playwright && python3 -m playwright install chromium
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import harness
from harness import Background, LiveCase, wait_for

try:
    from playwright.sync_api import sync_playwright
    PW_REASON = None
except ImportError as exc:                       # pragma: no cover - environment dependent
    sync_playwright = None
    PW_REASON = ("Playwright is not importable (%s). Enable with: pip3 install --user playwright && "
                 "python3 -m playwright install chromium" % exc)

TABS = ["call", "compose", "map", "bp", "net", "dev", "coll", "cmp", "sess", "scripts", "rules"]


def shot(page, name):
    os.makedirs(harness.ARTIFACTS, exist_ok=True)
    path = os.path.join(harness.ARTIFACTS, "ui-%s.png" % name)
    page.screenshot(path=path)
    return path


@unittest.skipIf(PW_REASON, PW_REASON or "")
class UiBase(LiveCase):
    """One browser per class + a throw-away Rivis; shared by the UI smoke and the workflow (demo-path) tests."""
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.pw = sync_playwright().start()
        try:
            cls.browser = cls.pw.chromium.launch()
        except Exception as exc:                 # noqa: BLE001 - Chromium not downloaded
            cls.pw.stop()
            raise unittest.SkipTest("Chromium for Playwright is not installed (%s). Enable with: "
                                    "python3 -m playwright install chromium" % str(exc).splitlines()[0])

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls.pw.stop()
        finally:
            super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.errors = []
        self.context = self.browser.new_context(viewport={"width": 1400, "height": 900})
        self.page = self.context.new_page()
        self.page.on("console", lambda m: self.errors.append(("console.error", m.text)) if m.type == "error" else None)
        self.page.on("pageerror", lambda e: self.errors.append(("pageerror", str(e))))
        self.page.on("requestfailed", lambda r: self.errors.append(("requestfailed", r.url)) if "/proxy/" in r.url else None)

    def tearDown(self):
        self.context.close()

    def panel_text(self):
        return self.page.evaluate("document.querySelector('#proxy-panel-host').shadowRoot.textContent")

    def open(self, first_run=False):
        for path in ("/json/small", "/echo?a=1", "/text"):
            self.fetch(path)
        if not first_run:   # the "Coming from Proxyman?" welcome (and its backdrop) shows once per browser; most tests start past it
            self.page.add_init_script("try { localStorage.setItem('rivis-welcome', 'done') } catch (e) {}")
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.wait_for_selector("#fab", timeout=20000)
        return self.page


@unittest.skipIf(PW_REASON, PW_REASON or "")
class ProjectShowToast(UiBase):
    PROJECT = "neo"

    def test_show_active_project_does_not_suggest_starting_it_again(self):
        page = self.open()
        page.locator("#fab").click()
        project = page.locator("#proxy-panel-host").locator("#project")
        panel = page.locator("#proxy-panel-host")
        wait_for(lambda: panel.locator("#main").text_content().strip() != "", 8, 0.2, "Tools content loaded")
        project.select_option("neo")
        toast_el = page.locator("#proxy-panel-host").locator("#toast")
        wait_for(lambda: "Showing only NEO calls" in toast_el.text_content(), 8, 0.2, "NEO-only toast")
        toast = toast_el.text_content()
        self.assertIn("Showing only NEO calls", toast)
        self.assertNotIn("Its rules load when you start", toast)
        self.assertEqual(self.errors, [])


@unittest.skipIf(PW_REASON, PW_REASON or "")
class UiScrollRegression(UiBase):
    PROJECT = "neo"

    def test_selected_project_call_can_wheel_to_and_follow_the_top(self):
        """A selected request pane and arriving calls must not trap the wheel below the newest row."""
        self.wheel_to_top_while_calls_arrive(select=True)

    def test_unselected_project_list_can_wheel_to_and_follow_the_top(self):
        """The same with no call selected and the detail pane closed."""
        self.wheel_to_top_while_calls_arrive(select=False)

    def wheel_to_top_while_calls_arrive(self, select):
        self.panel.ok("view", {"project": "neo", "project_only": True, "show_dns": False})
        for i in range(35):
            self.fetch("/json/small?scroll099=%02d" % i, headers={"Host": "api.neo.sa"})
        page = self.open()
        table = page.locator(".flow-table")
        wait_for(lambda: "sort-desc" in (page.locator(".flow-table th.col-timestamp").get_attribute("class") or ""),
                 10, 0.1, "descending Start time")
        wait_for(lambda: "scroll099=34" in (page.locator(".flow-table tbody tr:has(td.col-path)").first.text_content() or ""),
                 10, 0.1, "newest initial call")
        self.assertTrue(self.panel.state()["project_only"])
        table.evaluate("e => e.scrollTop = 320")
        page.wait_for_timeout(400)
        if select:
            page.locator(".flow-table tbody tr:has(td.col-path)").filter(has_text="scroll099=20").click()
            wait_for(lambda: "/request" in page.evaluate("location.hash"), 10, 0.1, "selected Request pane")
        self.assertGreater(table.evaluate("e => e.scrollTop"), 0)

        # Mirror the emulator's connectivity checks: a call every 1–3 s while the owner wheels upward.
        def arrive():
            for i in range(35, 39):
                self.fetch("/json/small?scroll099=%02d" % i, headers={"Host": "api.neo.sa"})
                time.sleep(1)
        traffic = Background(arrive)
        box = table.bounding_box()
        page.mouse.move(box["x"] + box["width"] / 3, box["y"] + box["height"] / 2)
        for _ in range(8):
            page.mouse.wheel(0, -420)
            page.wait_for_timeout(120)
        traffic.result(15)
        page.wait_for_timeout(400)
        top = table.evaluate("""e => {
          const head = e.querySelector('thead').getBoundingClientRect().bottom;
          const rows = [...e.querySelectorAll('tbody tr')].filter(r => r.querySelector('.col-path'));
          return { scrollTop: e.scrollTop, first: rows[0]?.querySelector('.col-path')?.textContent,
                   gap: rows[0]?.getBoundingClientRect().top - head };
        }""")
        self.assertLessEqual(top["scrollTop"], 1, top)
        self.assertIn("scroll099=38", top["first"], top)
        self.assertLessEqual(abs(top["gap"]), 2, top)
        self.fetch("/json/small?scroll099=39", headers={"Host": "api.neo.sa"})
        wait_for(lambda: "scroll099=39" in (table.locator("tbody tr:has(td.col-path)").first.text_content() or ""),
                 10, 0.1, "following a later new call")
        self.assertLessEqual(table.evaluate("e => e.scrollTop"), 1)
        table.evaluate("e => e.scrollTop = 320")
        page.wait_for_timeout(400)
        visible = """e => { const top = e.querySelector('thead').getBoundingClientRect().bottom;
          for (const tr of e.querySelectorAll('tbody tr')) { const r = tr.getBoundingClientRect();
            if (tr.querySelector('.col-path') && r.bottom > top + 1)
              return [tr.querySelector('.col-path').textContent, Math.round(r.top - top)]; }
        }"""
        middle = table.evaluate(visible)
        for i in range(40, 42):
            self.fetch("/json/small?scroll099=%02d" % i, headers={"Host": "api.neo.sa"})
            page.wait_for_timeout(1000)
            self.assertEqual(table.evaluate(visible), middle, "the middle row moved during live calls")
        self.assertEqual(self.errors, [])


@unittest.skipIf(PW_REASON, PW_REASON or "")
class UiSmoke(UiBase):

    def test_page_loads_with_flows_and_the_panel_button(self):
        page = self.open()
        wait_for(lambda: page.get_by_text("/json/small").count() > 0, 10, 0.2, "flow rows rendered")
        shot(page, "flows")
        self.assertEqual(self.errors, [])

    def test_native_unredacted_export_group_is_hidden(self):
        page = self.open()
        page.locator(".flow-table tbody tr:has(td.col-path)").first.click()
        groups = page.locator("#container > header .menu-group").filter(
            has=page.locator(".menu-legend", has_text="Export"))
        wait_for(lambda: groups.count() > 0, 10, 0.2, "native Export group rendered")
        self.assertTrue(groups.first.evaluate("e => e.hidden && e.getAttribute('aria-hidden') === 'true'"))
        self.assertEqual(self.errors, [])

    def test_native_export_group_is_never_visible_even_for_a_moment(self):
        """Hidden in the same turn mitmweb draws it, not a frame later: a watcher that runs right after each redraw never finds
        the unredacted Export group shown, while selecting calls makes mitmweb redraw the header again and again."""
        page = self.open()
        rows = page.locator(".flow-table tbody tr:has(td.col-path)")
        wait_for(lambda: rows.count() >= 2, 10, 0.2, "calls listed")
        page.evaluate("""() => { window.__shown = 0; new MutationObserver(() => {
            document.querySelectorAll('#container > header .menu-group').forEach((g) => {
              const l = g.querySelector('.menu-legend');
              if (l && l.textContent.trim().toLowerCase() === 'export' && !g.hidden) window.__shown++; });
          }).observe(document.body, { childList: true, subtree: true }); }""")
        for i in range(6):
            rows.nth(i % 2).click()
            page.wait_for_timeout(150)
            page.keyboard.press("Escape")                    # deselect: the flow menu groups go away and come back
            page.wait_for_timeout(150)
        self.assertEqual(page.evaluate("window.__shown"), 0, "the unredacted Export group was shown between redraws")
        self.assertEqual(self.errors, [])

    def test_tunnel_context_decrypt_keeps_explicit_port(self):
        self.reset_state(tls={"mode": "allow", "allow": []})
        self.panel.state()                 # include host-only TCP rows in mitmweb's current view
        self.assertEqual(self.fetch("/echo", tls=True, cacert=self.up.cert).status, 200)
        page = self.open()
        row = page.locator('.flow-table tbody tr[data-tunnel="1"]:has(td)').first
        row.wait_for(timeout=10000)
        row.click(button="right")
        page.locator("#proxy-panel-host #cmenu button[data-k=tlson]").click()
        expected = "127.0.0.1:%d" % self.up.https_port
        wait_for(lambda: self.panel.state()["tls"]["allow"] == [expected], 10, 0.2,
                 "context action added host with port")
        self.assertEqual(self.errors, [])

    def test_plain_host_search_keeps_matching_not_decrypted_tunnel(self):
        self.reset_state(tls={"mode": "allow", "allow": []})
        self.panel.state()
        self.assertEqual(self.fetch("/echo", tls=True, cacert=self.up.cert).status, 200)
        page = self.open()
        tunnel = page.locator('.flow-table tbody tr[data-tunnel="1"]:has(td)')
        tunnel.first.wait_for(timeout=10000)
        page.locator("#proxy-panel-host #sq").fill("127.0.0.1")
        page.wait_for_timeout(1000)  # search debounce and mitmweb's filtered-list refresh
        tunnel.first.wait_for(timeout=10000)
        self.assertEqual(self.errors, [])

    def test_composed_https_has_no_plain_http_edge(self):
        self.open()
        url = self.up.url("/json/small?composed-tls-edge=1", tls=True)
        self.panel.ok("compose_send", {"spec": {"method": "GET", "url": url}})
        row = self.page.locator(".flow-table tbody tr").filter(has=self.page.locator("td.col-path", has_text="composed-tls-edge=1"))
        row.first.wait_for(timeout=10000)
        wait_for(lambda: row.first.locator("td.col-status").text_content().strip() == "200", 10, 0.2,
                 "composed HTTPS response")
        edge = row.first.locator("td.col-tls")
        self.assertEqual(edge.evaluate("e => getComputedStyle(e).backgroundColor"), "rgba(0, 0, 0, 0)",
                         row.first.evaluate("e => e.outerHTML"))
        self.assertEqual(self.errors, [])

    def test_first_run_welcome_shows_once_and_closes_on_escape(self):
        page = self.open(first_run=True)
        welcome = page.locator("#proxy-panel-host #welcome.open")
        welcome.wait_for(timeout=10000)
        page.keyboard.press("Escape")
        wait_for(lambda: welcome.count() == 0, 5, 0.1, "welcome closed on Esc")
        page.reload()
        page.wait_for_selector("#fab", timeout=20000)
        page.wait_for_timeout(500)
        self.assertEqual(welcome.count(), 0, "welcome must not come back after it was closed")
        self.assertEqual(self.errors, [])

    def many_flows(self, n):
        """n plain-HTTP calls in one curl process (fast enough for a few hundred rows)."""
        argv = ["curl", "-sS", "--noproxy", "", "-x", "http://127.0.0.1:%d" % self.inst.proxy_port, "-o", "/dev/null"]
        for i in range(n):
            argv += [self.up.url("/json/small?n=%d" % i)] + (["-o", "/dev/null"] if i < n - 1 else [])
        harness.subprocess.run(argv, timeout=120, check=False)

    def test_rows_are_exactly_mitmwebs_row_height_and_scrolling_to_the_end_does_not_crash(self):
        """mitmweb's virtual list assumes 32px rows; any other height loops setState near the bottom (React #185)."""
        self.many_flows(300)
        page = self.open()
        wait_for(lambda: page.locator(".flow-table tbody tr td.col-path").count() > 20, 15, 0.2, "rows rendered")
        for density in ("comfortable", "compact"):
            page.evaluate("d => d === 'compact' ? document.documentElement.setAttribute('data-density', 'compact')"
                          " : document.documentElement.removeAttribute('data-density')", density)
            heights = page.evaluate("[...document.querySelectorAll('.flow-table tbody tr')]"
                                    ".filter(r => r.querySelector('td')).map(r => r.getBoundingClientRect().height)")
            self.assertTrue(heights and all(abs(h - 32) < 0.01 for h in heights), (density, sorted(set(heights))))
            for _ in range(3):   # bounce between the ends: this is where a wrong row height made the list loop
                page.evaluate("const v = document.querySelector('.flow-table'); v.scrollTop = v.scrollHeight")
                page.wait_for_timeout(300)
                page.evaluate("document.querySelector('.flow-table').scrollTop = 0")
                page.wait_for_timeout(100)
            self.assertEqual(page.locator("text=mitmproxy has crashed").count(), 0)
        self.assertEqual(self.errors, [])

    def test_rows_scrolled_into_view_are_styled_before_they_paint(self):
        """Screen recording, 2026-10-16: rows the virtual list builds while scrolling showed raw (https:// URLs, no badges)
        until the next poll, because the restyle was a 60 ms debounce that kept resetting while rows changed."""
        self.many_flows(300)
        page = self.open()
        wait_for(lambda: page.locator(".flow-table tbody tr td.col-path").count() > 20, 15, 0.2, "rows rendered")
        page.wait_for_timeout(1500)                                   # everything initially on screen is styled
        worst = page.evaluate("""async () => {
            const ft = document.querySelector('.flow-table'), frame = () => new Promise((r) => requestAnimationFrame(() => r()));
            let worst = 0;
            for (let i = 0; i < 12; i++) {
              ft.scrollTop += 640;
              await frame(); await frame();                         // ~33 ms: well inside the old 60 ms debounce
              const raw = [...ft.querySelectorAll('tbody tr')].filter((tr) => {
                const p = tr.querySelector('td.col-path'), s = tr.querySelector('td.col-status');
                return p && (!p.style.getPropertyValue('--hl') || (s && !s.hasAttribute('data-code')));
              }).length;
              worst = Math.max(worst, raw);
            }
            return worst; }""")
        self.assertEqual(worst, 0, "%d rows were on screen unstyled right after a scroll" % worst)
        self.assertEqual(self.errors, [])

    def test_scrolling_past_the_last_row_does_not_crash_the_list(self):
        """mitmweb compares the unclamped scrollTop with the clamped viewportTop it stored, so a scroll position past
        the last rendered row looped setState until React gave up (#185, "mitmproxy has crashed"). A list pane shorter
        than the sticky header is the quickest way to get there; Rivis serves mitmweb's bundle with that fixed."""
        self.many_flows(120)
        page = self.open()
        wait_for(lambda: page.locator(".flow-table tbody tr td.col-path").count() > 10, 15, 0.2, "rows rendered")
        self.assertIn("?rivis=", page.evaluate("document.querySelector('script[type=module]').src"))
        page.add_style_tag(content=".flow-table { height: 12px !important; flex: none !important; }")
        for _ in range(5):
            page.evaluate("const v = document.querySelector('.flow-table'); v.scrollTop = v.scrollHeight")
            page.wait_for_timeout(200)
        self.assertEqual(page.locator("text=mitmproxy has crashed").count(), 0)
        self.assertEqual(self.errors, [])

    def first_visible(self, page):
        return page.evaluate("""() => { const ft = document.querySelector('.flow-table');
            const top = ft.getBoundingClientRect().top + ft.querySelector('thead').getBoundingClientRect().height;
            for (const tr of ft.querySelectorAll('tbody tr')) { const r = tr.getBoundingClientRect();
              if (r.height && r.bottom > top + 1) return tr.querySelector('.col-path').textContent + '|' + Math.round(r.top - top); }
            return null; }""")

    def test_header_stays_pinned_and_rows_stay_put_while_calls_stream_in(self):
        self.many_flows(150)
        page = self.open()
        wait_for(lambda: "sort-desc" in (page.locator(".flow-table th.col-timestamp").get_attribute("class") or ""), 10, 0.1, "newest first")
        wait_for(lambda: "/text" in (self.first_visible(page) or ""), 10, 0.1, "initial flows fully rendered")
        page.evaluate("document.querySelector('.flow-table').scrollTop = 1600")
        page.wait_for_timeout(400)
        gap = page.evaluate("Math.abs(document.querySelector('.flow-table thead').getBoundingClientRect().top - "
                            "document.querySelector('.flow-table').getBoundingClientRect().top)")
        self.assertLess(gap, 1.5, "the column header must sit at the top of the list while scrolled")
        before = self.first_visible(page)
        self.many_flows(12)                                     # 12 newer calls arrive above the visible rows
        page.wait_for_timeout(1200)
        self.assertEqual(self.first_visible(page), before, "rows under the pointer must not move")
        self.many_flows(7)                                      # a second render burst must retain the same original anchor
        page.wait_for_timeout(1200)
        self.assertEqual(self.first_visible(page), before, "the scroll anchor must survive repeated stream updates")
        page.evaluate("document.querySelector('.flow-table').scrollTop = 0")   # at the top: newest calls come into view
        page.wait_for_timeout(300)
        self.fetch("/text?newest=1")
        wait_for(lambda: "newest=1" in (self.first_visible(page) or ""), 10, 0.2, "newest call shown at the top")
        self.assertEqual(self.errors, [])

    def test_the_hover_button_does_not_cover_start_time(self):
        self.page.set_viewport_size({"width": 1920, "height": 1000})            # wide: the button column is shown
        page = self.open()
        row = page.locator(".flow-table tbody tr:has(td.col-path)").first
        row.hover()
        page.wait_for_timeout(200)
        ts = row.locator("td.col-timestamp").bounding_box()
        qa = row.locator("td.col-quickactions").bounding_box()
        self.assertIsNotNone(qa, "at 1920 px the quick-action column is visible")
        self.assertGreaterEqual(qa["x"] + 0.5, ts["x"] + ts["width"])
        clip = row.locator("td.col-timestamp").evaluate("td => td.scrollWidth <= td.clientWidth + 1")
        self.assertTrue(clip, "the start time must fit its column")

    def test_the_no_match_message_stays_over_the_call_list(self):
        page = self.open()
        page.locator(".flow-table tbody tr:has(td.col-path)").first.click()      # opens mitmweb's detail pane
        page.wait_for_timeout(400)
        search = page.locator("#proxy-panel-host").locator("input[type=search], #sq").first
        page.keyboard.press("Meta+f" if sys.platform == "darwin" else "Control+f")
        page.keyboard.type("zz-no-such-call-zz")
        page.keyboard.press("Enter")
        box = page.locator("#proxy-panel-host #emptylist.open")
        box.wait_for(timeout=10000)
        page.wait_for_timeout(1700)                             # one placement tick
        b = box.bounding_box()
        ft = page.locator(".flow-table").bounding_box()
        self.assertLessEqual(b["x"] + b["width"], ft["x"] + ft["width"] + 1, "message must not spill into the detail pane")
        self.assertEqual(self.errors, [])

    def test_view_filter_with_zero_matches_is_not_first_run(self):
        page = self.open()
        self.panel.ok("focus_host", {"host": "no-match.example"})
        box = page.locator("#proxy-panel-host #emptylist.open")
        box.wait_for(timeout=10000)
        # the list can empty a moment before the panel's state names the host limit (R9-03 wording); it settles
        wait_for(lambda: "No matching calls" in box.text_content(), 5, 0.1, "the host-limit wording")
        self.assertNotIn("Nothing captured yet", box.text_content())
        stock = page.locator('.main-view > div[style*="padding: 1em 2em"]')
        if stock.count():
            self.assertFalse(stock.is_visible(), "mitmweb's first-run message must not contradict the filtered-empty message")
        self.assertEqual(self.errors, [])

    def test_the_list_opens_newest_first_and_the_user_can_still_re_sort(self):
        page = self.open()
        th = page.locator(".flow-table th.col-timestamp")
        wait_for(lambda: "sort-desc" in (th.get_attribute("class") or ""), 10, 0.1, "Start time sorted descending")
        first = page.locator(".flow-table tbody tr td.col-path").first.text_content()
        self.assertIn("/text", first)                    # open() fetched /json/small, /echo, then /text
        page.locator(".flow-table th.col-path").click()
        wait_for(lambda: "sort-asc" in (page.locator(".flow-table th.col-path").get_attribute("class") or ""), 5, 0.1,
                 "user re-sorted by path")
        page.wait_for_timeout(500)
        self.assertNotIn("sort", th.get_attribute("class") or "", "the default must not fight the user's own sort")
        self.assertEqual(self.errors, [])

    def test_devices_tab_explains_what_to_do_when_nothing_is_running(self):
        page = self.open()
        page.locator("#fab").click()
        page.locator("button[data-t=dev]").click()
        wait_for(lambda: "iOS Simulators" in self.panel_text(), 15, 0.2, "devices tab rendered")
        text = self.panel_text()
        self.assertIn("No simulator is booted", text)
        self.assertIn("adb was not found", text)                     # hermetic env: no Android SDK
        self.assertIn("rivis setup", text)
        shot(page, "devices")
        self.assertEqual(self.errors, [])

    def test_device_setup_shows_busy_at_once_and_one_consent_text(self):
        """R3-DEV-01: right after Set up the row looked untouched (old text, active button) until the job showed up.
        R3-DEV-02: the consent box gave the Magisk and the Settings-screens explanations at once. No real device:
        the panel's devices/device_setup calls are answered by the test."""
        import json as _json
        fake = {"ios": [], "android": [{"id": "emulator-5590", "name": "Pixel Play", "os": "Android 15", "ready": False,
                                         "ca_ok": False, "proxy_ok": False, "play": True}], "magisk": False, "job": None}
        started = []
        self.page.route("**/proxy/api/devices", lambda r: r.fulfill(status=200, content_type="application/json", body=_json.dumps(fake)))
        self.page.route("**/proxy/api/device_setup", lambda r: (started.append(r.request.post_data),
                        r.fulfill(status=200, content_type="application/json", body='{"id": 1}')))
        page = self.open()
        page.locator("#fab").click()
        page.locator("button[data-t=dev]").click()
        wait_for(lambda: "Pixel Play" in self.panel_text(), 15, 0.2, "fake emulator listed")
        page.locator("#proxy-panel-host [data-dsetup=android][data-id=emulator-5590]").click()
        text = self.panel_text()
        self.assertIn("Settings screens", text)
        self.assertNotIn("Magisk (official", text, "both explanations shown")
        page.locator("#proxy-panel-host #dyes").click()
        wait_for(lambda: started, 5, 0.1, "setup requested")
        page.wait_for_timeout(600)                                   # a devices poll that still reports no job
        row = page.locator("#proxy-panel-host .row", has_text="Pixel Play")
        self.assertIn("Setting up", row.inner_text())
        self.assertEqual(page.locator("#proxy-panel-host [data-dsetup=android][data-id=emulator-5590]").count(), 0,
                         "an active Set up button while the setup is starting invites a second click")
        self.assertEqual(self.errors, [])

    def test_devices_web_browser_row_keeps_the_typed_url_and_opens_the_chosen_browser(self):
        """Web apps: Tools → Devices → Web browser. The tab redraws every few seconds; that must not wipe the URL."""
        import json as _json
        fake = {"ios": [], "android": [], "magisk": False, "job": None,
                "browsers": [{"id": "chrome", "name": "Google Chrome"}, {"id": "edge", "name": "Microsoft Edge"}]}
        opened = []
        self.page.route("**/proxy/api/devices", lambda r: r.fulfill(status=200, content_type="application/json", body=_json.dumps(fake)))
        self.page.route("**/proxy/api/browser_open", lambda r: (opened.append(_json.loads(r.request.post_data)),
                        r.fulfill(status=200, content_type="application/json", body='{"output": "opened"}')))
        page = self.open()
        page.locator("#fab").click()
        page.locator("button[data-t=dev]").click()
        wait_for(lambda: "Web browser" in self.panel_text(), 15, 0.2, "web browser row drawn")
        url = page.locator("#proxy-panel-host #dburl")
        url.click()
        url.type("https://app.example.test")
        page.wait_for_timeout(4800)                                  # through at least one devices poll
        page.keyboard.type("/login")                                 # still typing: focus must not have been lost
        self.assertEqual(url.input_value(), "https://app.example.test/login")
        page.locator("#proxy-panel-host [data-dbrowser=edge]").click()
        wait_for(lambda: opened, 5, 0.1, "browser_open requested")
        self.assertEqual(opened, [{"browser": "edge", "url": "https://app.example.test/login"}])
        self.assertIn("rivis browser", self.panel_text())
        self.assertEqual(self.errors, [])

    def test_alt_shift_e_shows_the_https_section_on_a_small_screen(self):
        # R3-NET-06b: at 1280x800 the chord opened Network at the top, HTTPS decryption below the fold
        self.page.set_viewport_size({"width": 1280, "height": 800})
        self.page.add_init_script("try { localStorage.setItem('rivis-welcome', 'done') } catch (e) {}")   # no first-run card on top
        page = self.open()
        page.locator("body").click(position={"x": 5, "y": 5})
        page.keyboard.press("Alt+Shift+E")
        sec = page.locator("#proxy-panel-host #tlssec")
        wait_for(lambda: sec.count() > 0 and sec.is_visible(), 15, 0.2, "HTTPS section drawn")
        page.wait_for_timeout(3500)                                  # through a few state polls (the Net tab redraws)
        in_view = lambda: (lambda b: b if b and 0 <= b["y"] < 800 - 60 else None)(sec.bounding_box() if sec.count() else None)
        box = wait_for(in_view, 10, 0.2, "HTTPS decryption heading in view after the polls")
        self.assertLess(box["y"], 800 - 60, "HTTPS decryption heading is below the fold: %r" % box)
        self.assertEqual(self.errors, [])

    def test_another_proxy_app_holding_the_mac_proxy_is_named_in_a_banner(self):
        # the iOS Simulator follows the Mac's proxy: when another app holds it, say which one and what to do
        import json as _json
        def patch(route):
            resp = route.fetch()
            doc = resp.json()
            doc["system_proxy"] = {"host": "127.0.0.1", "port": "9090", "owner": "Proxyman", "ours": False, "stale": False}
            route.fulfill(response=resp, body=_json.dumps(doc), headers={**resp.headers, "content-type": "application/json"})
        self.page.route("**/proxy/api/state", patch)
        page = self.open()
        bar = page.locator("#proxy-panel-host #proxybar")
        wait_for(lambda: bar.is_visible(), 10, 0.2, "banner shown")
        text = bar.inner_text()
        self.assertIn("Proxyman", text)
        self.assertIn("Quit Proxyman", text)
        self.assertEqual(self.errors, [])

    def test_an_available_update_shows_a_banner_and_installs_on_click(self):
        import json as _json
        installs = []
        def patch(route):
            resp = route.fetch()
            doc = resp.json()
            doc["update"] = {"configured": True, "installed": True, "signed_in": True, "repo": "CoorB/rivis",
                             "available": {"version": "9.9.9", "notes": "Faster everything.", "url": "x"},
                             "installing": None, "login": None, "error": None}
            route.fulfill(response=resp, body=_json.dumps(doc), headers={**resp.headers, "content-type": "application/json"})
        self.page.route("**/proxy/api/state", patch)
        self.page.route("**/proxy/api/update_install", lambda r: (installs.append(1),
                        r.fulfill(status=200, content_type="application/json", body="{}")))
        page = self.open()
        bar = page.locator("#proxy-panel-host #updatebar")
        wait_for(lambda: bar.is_visible(), 10, 0.2, "update banner")
        self.assertIn("9.9.9 is available", bar.inner_text())
        self.assertEqual(page.locator("#proxy-panel-host #upd-go").inner_text(), "Update to 9.9.9")
        page.locator("#proxy-panel-host #upd-notes").click()             # What's new -> Settings shows the notes
        wait_for(lambda: "Faster everything." in self.panel_text(), 5, 0.2, "notes in Settings")
        page.locator("#proxy-panel-host #hclose").click()
        page.locator("#proxy-panel-host #upd-go").click()
        wait_for(lambda: installs, 5, 0.1, "update_install called")
        self.assertEqual(self.errors, [])

    def test_an_update_needs_no_github_sign_in_for_a_public_release(self):
        import json as _json
        def patch(route):
            resp = route.fetch()
            doc = resp.json()
            doc["update"] = {"configured": True, "installed": True, "signed_in": False, "repo": "CoorB/rivis",
                             "available": {"version": "9.9.9", "notes": "", "url": "x", "private": False},
                             "installing": None, "login": None, "error": None}
            route.fulfill(response=resp, body=_json.dumps(doc), headers={**resp.headers, "content-type": "application/json"})
        self.page.route("**/proxy/api/state", patch)
        page = self.open()
        page.locator("#proxy-panel-host #fab").click()
        page.locator("#proxy-panel-host #gear").click()
        row = page.locator("#proxy-panel-host #set-updates")
        wait_for(lambda: "Update to 9.9.9" in row.inner_text(), 10, 0.2, "update offered without a sign-in")
        self.assertNotIn("Sign in with GitHub", row.inner_text())
        self.assertNotIn("Sign out", row.inner_text())
        self.assertEqual(self.errors, [])

    def test_later_hides_the_banner_for_that_version(self):
        import json as _json
        def patch(route):
            resp = route.fetch()
            doc = resp.json()
            doc["update"] = {"configured": True, "installed": True, "signed_in": True,
                             "available": {"version": "9.9.8", "notes": "", "url": "x"}, "installing": None, "login": None}
            route.fulfill(response=resp, body=_json.dumps(doc), headers={**resp.headers, "content-type": "application/json"})
        self.page.route("**/proxy/api/state", patch)
        page = self.open()
        bar = page.locator("#proxy-panel-host #updatebar")
        wait_for(lambda: bar.is_visible(), 10, 0.2, "update banner")
        page.locator("#proxy-panel-host #upd-later").click()
        page.wait_for_timeout(2500)                                       # through a couple of state polls
        self.assertFalse(bar.is_visible())
        self.assertEqual(self.errors, [])

    def test_sign_in_shows_the_github_code_in_settings(self):
        import json as _json
        def patch(route):
            resp = route.fetch()
            doc = resp.json()
            doc["update"] = {"configured": True, "installed": True, "signed_in": False, "repo": "CoorB/rivis",
                             "available": None, "installing": None,
                             "login": {"status": "waiting", "user_code": "WXYZ-1234", "uri": "https://github.com/login/device"}}
            route.fulfill(response=resp, body=_json.dumps(doc), headers={**resp.headers, "content-type": "application/json"})
        self.page.route("**/proxy/api/state", patch)
        page = self.open()
        page.locator("#proxy-panel-host #fab").click()                    # the gear lives in the Tools drawer
        page.locator("#proxy-panel-host #gear").click()
        wait_for(lambda: "WXYZ-1234" in self.panel_text(), 10, 0.2, "device code shown")
        link = page.locator("#proxy-panel-host #set-updates a")
        self.assertEqual(link.get_attribute("href"), "https://github.com/login/device")
        self.assertEqual(self.errors, [])

    def test_the_empty_list_offers_device_setup(self):
        self.page.add_init_script("try { localStorage.setItem('rivis-welcome', 'done') } catch (e) {}")
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.wait_for_selector("#fab", timeout=20000)
        btn = self.page.locator("#proxy-panel-host [data-act=devices]")
        if btn.count() == 0:                       # the list already has calls from other tests: clear it first
            self.page.evaluate("fetch('./clear', {method: 'POST', credentials: 'same-origin', headers: {'X-XSRFToken': "
                               "(document.cookie.match(/_mitmproxy_xsrf=([^;]+)/) || [])[1] || ''}})")
            wait_for(lambda: btn.count() > 0, 15, 0.3, "empty state with Set up a device")
        btn.click()
        wait_for(lambda: "iOS Simulators" in self.panel_text(), 15, 0.2, "Devices tab opened from the empty list")
        self.assertEqual(self.errors, [])

    def test_open_the_panel_and_click_every_tab(self):
        page = self.open()
        page.locator("#fab").click()
        tabs = page.locator("button[data-t]")
        self.assertEqual([tabs.nth(i).get_attribute("data-t") for i in range(tabs.count())], TABS)
        for name in TABS:
            btn = page.locator("button[data-t=%s]" % name)
            btn.click()
            wait_for(lambda: "on" in (btn.get_attribute("class") or "").split(), 5, 0.1, "tab %s active" % name)
            page.wait_for_timeout(200)
            shot(page, "tab-" + name)
        self.assertEqual(self.errors, [])

    def test_this_call_tab_describes_the_selected_flow(self):
        page = self.open()
        page.get_by_text("/echo?a=1").first.click()
        page.locator("#fab").click()
        page.locator("button[data-t=call]").click()
        wait_for(lambda: "echo" in self.panel_text(), 8, 0.2, "call details")
        shot(page, "this-call")
        self.assertEqual(self.errors, [])

    def test_typing_into_a_panel_editor_does_not_trigger_mitmweb_shortcuts(self):
        self.reset_state(breakpoints=[{"name": "b", "match": r"/echo\?bp", "request": True, "response": False, "enabled": True}])
        page = self.open()
        before = len(self.inst.flows())
        call = Background(self.fetch, "/echo?bp=1", method="POST", data="orig", timeout=40)
        wait_for(lambda: self.panel.state()["paused"], 15, 0.2, "paused call")
        box = page.locator("#pb")
        box.wait_for(timeout=15000)
        box.click()
        box.fill("")
        text = "dar adx e r d a"            # d=delete a=resume r=replay in mitmweb's own key map
        box.press_sequentially(text, delay=15)
        self.assertEqual(box.input_value(), text)
        page.wait_for_timeout(500)
        self.assertEqual(len(self.panel.state()["paused"]), 1, "a shortcut resumed or removed the paused call")
        self.assertGreaterEqual(len(self.inst.flows()), before)
        shot(page, "editor-typing")
        page.locator("text=Continue").last.click()
        r = call.result(30)
        self.assertEqual(r.json()["body"], text)
        self.assertEqual(self.errors, [])

    def test_dark_and_reduced_motion_preferences_do_not_break_the_panel(self):
        page = self.open()
        page.emulate_media(color_scheme="dark", reduced_motion="reduce")
        page.locator("#fab").click()
        for name in ("rules", "net", "scripts"):
            page.locator("button[data-t=%s]" % name).click()
            page.wait_for_timeout(150)
        shot(page, "dark")
        self.assertEqual(self.errors, [])

    def test_rules_added_through_the_api_appear_in_the_rules_tab(self):
        page = self.open()
        page.locator("#fab").click()
        self.panel.ok("add", {"rule": {"name": "ui-rule", "action": "block", "match": "/x"}})
        wait_for(lambda: "Rules2" in self.panel_text().replace(" ", "").replace("\n", ""), 10, 0.3, "tab counter refreshed")
        page.locator("button[data-t=scripts]").click()
        page.locator("button[data-t=rules]").click()
        wait_for(lambda: "ui-rule" in self.panel_text(), 10, 0.3, "rule shown after re-opening the tab")
        self.assertEqual(self.errors, [])

    def test_r7a02_reversed_map_remote_warning_is_visible(self):
        page = self.open()
        self.panel.ok("add", {"rule": {"name": "backwards", "action": "map_remote", "match": "/remote",
                                        "replace": "https://destination.test/echo", "with": "/remote"}})
        page.locator("#fab").click()
        page.locator("button[data-t=rules]").click()
        wait_for(lambda: "may never rewrite a URL" in self.panel_text(), 10, 0.2,
                 "Map Remote warning shown in Rules tab")
        self.assertEqual(self.errors, [])

    def test_open_rules_tab_refreshes_when_a_rule_is_added_elsewhere(self):
        """FOUND-BUGS B15 (fixed): the list of the OPEN tab follows a rule added elsewhere, and focus stays put."""
        page = self.open()
        page.locator("#fab").click()
        page.locator("button[data-t=rules]").click()
        self.panel.ok("add", {"rule": {"name": "elsewhere", "action": "block", "match": "/x"}})
        wait_for(lambda: "elsewhere" in self.panel_text(), 8, 0.3, "open list refreshed")
        self.assertEqual(page.evaluate("document.querySelector('#proxy-panel-host').shadowRoot.activeElement?.dataset?.t"), "rules")

    def test_open_network_tab_tracks_cli_profile_and_packet_loss(self):
        page = self.open()
        page.locator("#fab").click()
        page.locator("button[data-t=net]").click()
        self.panel.ok("profile", {"id": "3g-urban", "match": "cli-set"})
        wait_for(lambda: page.locator('[data-prof="3g-urban"]').get_attribute("class").find("on") >= 0,
                 8, 0.3, "CLI profile shown in open Network tab")
        self.reset_state(throttle="off", throttle_match="lossy", loss=20)
        wait_for(lambda: "Packet loss is active: 20%" in self.panel_text(), 8, 0.3,
                 "CLI packet loss shown in open Network tab")

    def test_network_tab_no_caching_toggle_by_keyboard(self):
        page = self.open()
        page.locator("#fab").click()
        page.locator("button[data-t=net]").click()
        box = page.locator("#proxy-panel-host").locator("#nocache")
        wait_for(lambda: box.count() == 1, 8, 0.2, "No caching switch shown")
        self.assertFalse(box.is_checked())
        self.assertIn("No caching", self.panel_text())
        box.focus()
        page.keyboard.press("Space")
        wait_for(lambda: self.panel.state()["no_cache"] is True, 8, 0.2, "No caching saved on")
        self.assertIs(self.inst.cfg().get("no_cache"), True)
        wait_for(lambda: page.locator("#proxy-panel-host").locator("#nocache").is_checked(), 8, 0.2, "switch shows on")
        page.locator("#proxy-panel-host").locator("#nocache").focus()
        page.keyboard.press("Space")
        wait_for(lambda: self.panel.state()["no_cache"] is False, 8, 0.2, "No caching saved off")
        self.reset_state(no_cache=True)                     # set from the CLI: the open tab follows
        wait_for(lambda: page.locator("#proxy-panel-host").locator("#nocache").is_checked(), 8, 0.3, "CLI change shown")
        self.assertEqual(self.errors, [])

    def test_a_switch_keeps_the_keyboard_after_its_change_redraws_the_tab(self):
        """Full suite 2026-10-23 (the No caching keyboard test flaked): every panel change redraws its tab, which replaced
        the switch under the keyboard, so a second Space did nothing until the user tabbed back to it."""
        page = self.open()
        page.locator("#fab").click()
        page.locator("button[data-t=net]").click()
        box = page.locator("#proxy-panel-host").locator("#nocache")
        wait_for(lambda: box.count() == 1, 8, 0.2, "No caching switch shown")
        box.focus()
        for want in (True, False, True, False):
            page.keyboard.press("Space")
            wait_for(lambda: self.panel.state()["no_cache"] is want, 8, 0.2, "No caching saved %s" % want)
            wait_for(lambda: page.locator("#proxy-panel-host").locator("#nocache").is_checked() is want, 8, 0.2, "switch shows it")
            page.wait_for_timeout(300)
            self.assertEqual(self.page.evaluate("document.querySelector('#proxy-panel-host').shadowRoot.activeElement && "
                                                "document.querySelector('#proxy-panel-host').shadowRoot.activeElement.id"), "nocache")
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
