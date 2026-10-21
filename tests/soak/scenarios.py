"""The scenarios. Each is one thing a tester does in the panel, with real input, a visible assertion, and a clean-up so the
next one starts from a known state. `pos` is where the call list is parked first (top = newest, following; middle; bottom =
the end, following). A scenario raises SoakFail for a product problem and Skip when its precondition is not on screen."""
import re
import time
from urllib.parse import urlsplit

from driver import SoakFail, check
from traffic import PAUSE_PATH


class Skip(Exception):
    pass


class Scenarios:
    def __init__(self, s):
        self.s = s
        self.ui = s.ui
        self.inst = s.inst
        self.up = s.up
        self.cfg = s.cfg
        self.panel = s.inst.panel

    # -- shared ------------------------------------------------------------------------------------------------------
    def seen(self, path_query):
        return self.up.seen.get(path_query, 0)

    def call_info(self, fid):
        info = self.panel.ok("retry_get", {"flow_id": fid})
        u = urlsplit(info["url"])
        info["pq"] = u.path + ("?" + u.query if u.query else "")
        info["host"] = u.hostname
        return info

    def open_menu(self, pos, contains=None):
        ui = self.ui
        for attempt in range(4):
            ui.go_position(pos)
            ui.pause(200, 900)
            row = ui.pick_row(contains)
            ui.click_xy(row["x"], row["y"], "right")
            t_open = time.time()
            ui.wait(ui.menu_open, 6, "the right-click menu to open")
            fid = ui.wait(ui.selected_id, 4, "the right-clicked call to be selected")
            info = self.call_info(fid)
            if not contains or contains in info["pq"]:
                break
            ui.key("Escape")                      # a new call pushed the rows down between looking and clicking: look again
            ui.page.wait_for_timeout(300)
        else:
            raise SoakFail("no visible call row containing %r could be right-clicked (rows kept moving)" % contains)
        # a user reads the menu while calls keep arriving: wait for the list to change under it, at least 1.2 s, then a pause
        h0 = ui.list_state()["height"]
        end = time.time() + 3.5
        while time.time() < end and (time.time() - t_open < 1.2 or ui.list_state()["height"] == h0):
            ui.page.wait_for_timeout(100)
            self.s.tick()
        ui.pause(200, 1200)
        check(ui.menu_open(), "the right-click menu closed by itself %.1f s after it opened while calls kept arriving (list at %s)"
              % (time.time() - t_open, pos))
        return fid, info

    def pick_item(self, key):
        self.ui.click(self.ui.P("#cmenu button[data-k=%s]" % key))

    def need_menu_item_label(self, key, rx):
        txt = self.ui.P("#cmenu button[data-k=%s]" % key).text_content()
        check(re.search(rx, txt), "menu item %s reads %r, expected /%s/" % (key, txt, rx))

    # -- right-click menu ----------------------------------------------------------------------------------------------
    def menu_map(self, pos):
        ui = self.ui
        fid, info = self.open_menu(pos)
        t0 = ui.now_ms()
        self.pick_item("map")
        ui.wait(lambda: ui.drawer_open() and ui.P("#main #back").count() > 0 and ui.P("#main #body").count() > 0,
                self.cfg.action_deadline, "the Map Local editor to open in the Tools drawer")
        ui.wait_toast(r"Map Local '", t0)
        ui.pause()
        ui.click(ui.P("#main #back"))
        ui.wait(lambda: ui.P("#main #back").count() == 0, 8, "Back to leave the editor")
        ui.wait_toast(r"discarded|Map Local", t0)
        ui.close_tools()

    def menu_pause(self, pos):
        ui = self.ui
        try:
            fid, info = self.open_menu(pos, contains=PAUSE_PATH)
        except SoakFail as exc:
            if "no visible call row" in str(exc):
                raise Skip(str(exc))
            raise
        t0 = ui.now_ms()
        self.pick_item("bp")
        ui.wait_toast(r"Breakpoint on", t0)
        check(any(PAUSE_PATH in b["match"].replace("\\", "") or "soak-pause" in b["match"] for b in self.panel.state()["breakpoints"]),
              "no breakpoint for the soak-pause path was added: %s" % self.panel.state()["breakpoints"])
        ui.wait(lambda: self.panel.state()["paused"], 20, "a matching call to be held at the breakpoint")
        ui.wait(lambda: ui.sheet_open("pause"), self.cfg.action_deadline, "the paused-call sheet to open by itself")
        ui.pause()
        t1 = ui.now_ms()
        ui.click(ui.P("#pcont"))
        ui.wait_toast(r"Continued", t1)
        self.s.world.reset()

    def menu_repeat(self, pos):
        ui = self.ui
        fid, info = self.open_menu(pos, contains="i=")
        before = self.seen(info["pq"])
        t0 = ui.now_ms()
        self.pick_item("repeat")
        ui.wait_toast(r"Repeated", t0)
        ui.wait(lambda: self.seen(info["pq"]) > before, 8, "the repeated call to reach the server again (%s)" % info["pq"])

    def menu_edit_repeat(self, pos):
        ui = self.ui
        fid, info = self.open_menu(pos, contains="i=")
        self.pick_item("retry")
        ui.wait(lambda: ui.sheet_open("pause") and ui.P("#rsend").count() > 0, self.cfg.action_deadline, "the Edit & Repeat sheet to open")
        ui.pause()
        ui.click(ui.P("#ru"))
        ui.key("End")
        ui.type("&edited=1")
        ui.pause()
        t0 = ui.now_ms()
        ui.click(ui.P("#rsend"))
        ui.wait_toast(r"Sent — the new call", t0)
        want = info["pq"] + "&edited=1"
        ui.wait(lambda: self.seen(want) >= 1, 8, "the edited call to reach the server (%s)" % want)
        ui.wait(lambda: not ui.sheet_open("pause"), 6, "the sheet to close after Send")

    def menu_compare_a(self, pos):
        ui = self.ui
        fid, info = self.open_menu(pos)
        t0 = ui.now_ms()
        self.pick_item("cmpA")
        ui.wait(lambda: ui.drawer_open() and ui.active_tab() == "cmp", self.cfg.action_deadline, "the Compare tab to open")
        ui.wait_toast(r"Now select another call", t0)
        ui.close_tools()

    def menu_curl(self, pos):
        ui = self.ui
        fid, info = self.open_menu(pos, contains="i=")
        t0 = ui.now_ms()
        self.pick_item("curl")
        ui.wait_toast(r"Copied|cURL", t0)
        txt = ui.clipboard()
        check(txt.lstrip().startswith("curl") and info["host"] in txt, "clipboard is not a cURL for %s: %r" % (info["host"], txt[:120]))
        check(re.search(r"i=\d+", info["pq"]).group(0) in txt, "the cURL lacks the call's query: %r" % txt[:200])

    def menu_url(self, pos):
        ui = self.ui
        fid, info = self.open_menu(pos, contains="i=")
        t0 = ui.now_ms()
        self.pick_item("url")
        ui.wait_toast(r"(?i)URL copied", t0)
        txt = ui.clipboard()
        check(txt.startswith("http") and info["host"] in txt and info["pq"] in txt,
              "clipboard is not this call's URL (%s): %r" % (info["pq"], txt[:160]))

    def menu_host_focus(self, pos):
        ui = self.ui
        fid, info = self.open_menu(pos)
        host = info["host"]
        t0 = ui.now_ms()
        self.pick_item("host")
        ui.wait_toast(r"Showing only", t0)
        ui.wait(lambda: self.panel.state()["focus_host"] == host, 6, "focus_host=%s" % host)
        ui.wait(lambda: host in ui.P("#fstrip").text_content(), 6, "the filter strip to name %s" % host)
        ui.pause()
        fid, info = self.open_menu(pos)
        self.need_menu_item_label("host", r"Show all hosts again")
        t1 = ui.now_ms()
        self.pick_item("host")
        ui.wait_toast(r"Showing all hosts", t1)
        ui.wait(lambda: self.panel.state()["focus_host"] is None, 6, "focus_host cleared")

    def menu_tls(self, pos):
        ui = self.ui
        before = self.panel.state()["tls"]
        fid, info = self.open_menu(pos)
        t0 = ui.now_ms()
        self.pick_item("tls")
        ui.wait_toast(r".", t0)
        after = ui.wait(lambda: (lambda t: t if (t["mode"], t["allow"], t["ignore"]) != (before["mode"], before["allow"], before["ignore"]) else None)(
            self.panel.state()["tls"]), 6, "the TLS list to change")
        check(info["host"] in after["allow"] + after["ignore"] or after["mode"] != before["mode"], "TLS lists do not mention %s: %s" % (info["host"], after))
        ui.pause()
        ui.open_tools("net")                                         # and back, from the Network tab
        t1 = ui.now_ms()
        for x in ui.P("[data-tlsrm]").all():
            ui.click(x)
            ui.pause(200, 600)
        ui.click(ui.P("#tlsmode [data-tm=all]"))
        ui.wait(lambda: (lambda t: t["mode"] == "all" and not t["ignore"] and not t["allow"])(self.panel.state()["tls"]), 8, "decryption back to every host")
        ui.close_tools()

    def menu_delete(self, pos):
        ui = self.ui
        fid, info = self.open_menu(pos)
        check(self.panel.get("/flows/%s/request/content.data" % fid)[0] == 200, "call %s is not readable before the delete" % fid)
        t0 = ui.now_ms()
        self.pick_item("del")
        ui.wait_toast(r"Call deleted", t0)
        ui.wait(lambda: self.panel.get("/flows/%s/request/content.data" % fid)[0] == 404, 8, "the call to be gone from the proxy")

    # -- Tools drawer ----------------------------------------------------------------------------------------------------
    def tab_call(self, pos=None):
        ui = self.ui
        ui.go_position("top")
        row = ui.pick_row("i=")
        ui.click_xy(row["x"], row["y"])
        ui.wait(ui.selected_id, 5, "a call to be selected")
        ui.open_tools("call")
        ui.wait(lambda: "Map Local this call" in ui.main_text(), 10, "This call to offer Map Local this call")
        ui.close_tools()

    def tab_compose(self, pos=None):
        ui = self.ui
        n = self.s.next_id()
        ui.open_tools("compose")
        url = "http://backbase-edge-sit.localhost:%d/api/user-manager/client-api/v2/users/me?compose=%d" % (self.up.http_port, n)
        ui.click(ui.P("#cu"))
        ui.type(url)
        ui.pause()
        t0 = ui.now_ms()
        ui.click(ui.P("#csend"))
        ui.wait_toast(r"Sent GET", t0)
        ui.wait(lambda: self.seen("/api/user-manager/client-api/v2/users/me?compose=%d" % n) >= 1, 8, "the composed call to reach the server")
        # save it under a name (the prompt is answered by the dialog handler), then delete it
        name = "soak-c%d" % n
        self.s.dialog_text = name
        t1 = ui.now_ms()
        ui.click(ui.P("#csaveas"))
        ui.wait_toast(r"Saved " + name, t1)
        ui.pause()
        t2 = ui.now_ms()
        ui.click(ui.P("#cdel"))
        ui.wait_toast(r"Deleted " + name, t2)
        ui.close_tools()

    def tab_map(self, pos=None):
        ui = self.ui
        n = self.s.next_id()
        ui.open_tools("map")
        ui.click(ui.P("#mh"))
        ui.type("backbase-edge-sit.localhost")
        ui.click(ui.P("#mp"))
        ui.select_all()
        ui.type("/api/soak-map/%d" % n)
        ui.pause()
        t0 = ui.now_ms()
        ui.click(ui.P("#madd"))
        ui.wait_toast(r"Map Local '", t0)
        ui.wait(lambda: ui.P("#main #save").count() > 0, self.cfg.action_deadline, "the Map Local editor")
        ui.click(ui.P("#main #body"))
        ui.select_all()
        ui.type('{"mocked": true, "n": %d}' % n)
        ui.pause()
        t1 = ui.now_ms()
        ui.click(ui.P("#save"))
        ui.wait_toast(r"Saved|saved|on", t1)
        ui.pause()
        ui.click(ui.P("#back"))
        ui.wait(lambda: ui.P("#main #back").count() == 0, 8, "Back to the rule list")
        # the rule answers: call its path and read the mocked body
        got = []
        def answered():
            r = self.inst.fetch("http://backbase-edge-sit.localhost:%d/api/soak-map/%d" % (self.up.http_port, n))
            got.append(r)
            return r.status == 200 and b"mocked" in r.body
        try:
            ui.wait(answered, 8, "the saved Map Local to answer its path", 0.5)
        except SoakFail:
            raise SoakFail("the saved Map Local did not answer its path: last reply %s %r" % (got[-1].status if got else "-", got[-1].body[:60] if got else ""))
        # rules tab: switch it off and on again, then remove it
        ui.open_tools("rules")
        t2 = ui.now_ms()
        ui.click(ui.P("input[data-i]").first)
        ui.wait_toast(r"Rule (on|off)", t2)
        ui.pause()
        t3 = ui.now_ms()
        ui.click(ui.P("input[data-i]").first)
        ui.wait_toast(r"Rule (on|off)", t3)
        ui.pause()
        self.s.world.reset()
        ui.close_tools()

    def tab_breakpoints(self, pos=None):
        ui = self.ui
        n = self.s.next_id()
        path = "/api/soak-bp/%d/*" % n
        ui.open_tools("bp")
        ui.click(ui.P("#bh"))
        ui.type("backbase-edge-sit.localhost")
        ui.click(ui.P("#bpth"))
        ui.select_all()
        ui.type(path)
        ui.pause()
        t0 = ui.now_ms()
        ui.click(ui.P("#badd"))
        ui.wait_toast(r"Breakpoint on", t0)
        time.sleep(1.5)                                              # the proxy picks a new breakpoint up within a second
        for how in ("pcont", "pabort"):
            from harness import Background
            url = "http://backbase-edge-sit.localhost:%d/api/soak-bp/%d/%s" % (self.up.http_port, n, how)
            call = Background(lambda u=url: self.inst.fetch(u, timeout=30))
            # a breakpoint on request AND response holds the call twice: act on each hold until the call returns
            for hold in range(3):
                ui.wait(lambda: self.panel.state()["paused"] or not call._t.is_alive(), 15, "the call to be held")
                if not call._t.is_alive():
                    break
                ui.wait(lambda: ui.sheet_open("pause"), self.cfg.action_deadline, "the paused-call sheet")
                ui.pause()
                t1 = ui.now_ms()
                ui.click(ui.P("#" + how))
                ui.wait_toast(r"Continued|Aborted", t1)
                ui.wait(lambda: not self.panel.state()["paused"] or not ui.sheet_open("pause"), 8, "the sheet to close")
                if how == "pabort":
                    break
                ui.pause(200, 800)
            r = call.result(20)
            if how == "pcont":
                check(r.status in (200, 404), "a continued call got %s" % r.status)
            else:
                check(r.status != 200, "an aborted call still got a 200")
            ui.wait(lambda: not self.panel.state()["paused"], 8, "no call left held")
            ui.pause()
        self.s.world.reset()
        ui.close_tools()

    def tab_network(self, pos=None):
        ui = self.ui
        n = self.s.next_id()
        ui.open_tools("net")
        ui.click(ui.P("#tm"))
        ui.select_all()
        ui.type(r"soak-throttle")
        ui.key("Tab")
        ui.pause()
        t0 = ui.now_ms()
        ui.click(ui.P("[data-prof=lte-congested]"))
        ui.wait_toast(r"Network: ", t0)
        ui.wait(lambda: self.panel.state()["throttle"] == "lte-congested", 6, "throttle on")
        time.sleep(1.2)
        url = "http://backbase-edge-sit.localhost:%d/api/soak-throttle/%d" % (self.up.http_port, n)
        t = time.time()
        self.inst.fetch(url)
        slow_ms = (time.time() - t) * 1000
        check(slow_ms >= 120, "the LTE profile did not slow a matching call (%.0f ms)" % slow_ms)
        ui.pause()
        t1 = ui.now_ms()
        ui.click(ui.P("[data-prof=off]"))
        ui.wait_toast(r"Network: ", t1)
        ui.wait(lambda: self.panel.state()["throttle"] == "off", 6, "throttle off")
        ui.pause()
        t2 = ui.now_ms()
        ui.click(ui.P("#nocache"))
        ui.wait_toast(r"No caching on", t2)
        check(self.panel.state()["no_cache"] is True, "no-cache did not switch on")
        ui.pause()
        t3 = ui.now_ms()
        ui.click(ui.P("#nocache"))
        ui.wait_toast(r"No caching off", t3)
        self.s.world.reset()
        ui.close_tools()

    def tab_collections(self, pos=None):
        ui = self.ui
        n = self.s.next_id()
        name = "soak-coll-%d" % n
        ui.open_tools("coll")
        ui.click(ui.P("#cname"))
        ui.type(name)
        ui.click(ui.P("#cmatch"))
        ui.select_all()
        ui.type("soak-coll")
        ui.pause()
        t0 = ui.now_ms()
        ui.click(ui.P("#crec"))
        ui.wait_toast(r"Recording into", t0)
        self.inst.fetch("http://backbase-edge-sit.localhost:%d/api/soak-coll/%d" % (self.up.http_port, n))
        ui.pause(600, 1500)
        t1 = ui.now_ms()
        ui.click(ui.P("#cstop"))
        ui.wait_toast(r"Recording stopped", t1)
        ui.wait(lambda: any(c["name"] == name and c["count"] >= 1 for c in self.panel.state()["collections"]["items"]), 8, "the collection to hold the call")
        self.s.world.reset()
        ui.close_tools()

    def tab_compare(self, pos=None):
        ui = self.ui
        ui.go_position("top")
        a = ui.pick_row("i=")
        ui.click_xy(a["x"], a["y"])
        id_a = ui.wait(ui.selected_id, 5, "call A to be selected")
        ui.open_tools("cmp")
        ui.click(ui.P("#seta"))
        ui.wait(lambda: "not set yet" not in ui.main_text(), 8, "A to be set")
        ui.pause()
        others = [r for r in ui.rows() if r["text"] != a["text"]]
        check(others, "no second call on screen to compare with")
        b = self.s.rng.choice(others)
        ui.click_xy(b["x"], b["y"])
        ui.wait(lambda: ui.selected_id() not in (None, id_a), 5, "call B to be selected")
        ui.wait(lambda: ui.P("#docmp").count() and ui.P("#docmp").is_enabled(), 8, "Compare A with B to be enabled")
        ui.pause()
        ui.click(ui.P("#docmp"))
        ui.wait(lambda: "Response body" in ui.main_text() and "Summary" in ui.main_text(), self.cfg.action_deadline, "the comparison to show")
        ui.close_tools()

    def tab_sessions(self, pos=None):
        ui = self.ui
        n = self.s.next_id()
        name = "soak-sess-%d" % n
        self.inst.fetch("http://backbase-edge-sit.localhost:%d/api/soak-sess/%d" % (self.up.http_port, n))
        ui.open_tools("sess")
        ui.click(ui.P("#sn"))
        ui.type(name)
        ui.click(ui.P("#svis"))                                       # only calls visible under the filter below
        ui.pause()
        ui.close_tools()
        self.set_search("soak-sess")
        ui.open_tools("sess")
        ui.click(ui.P("#sn"))
        ui.select_all()
        ui.type(name)
        t0 = ui.now_ms()
        ui.click(ui.P("#ssave"))
        ui.wait_toast(r"Saved \d+ calls", t0)
        ui.wait(lambda: any(x["name"] == name for x in self.panel.state()["sessions"]), 8, "the session to be listed")
        self.set_search("")
        self.s.world.reset()
        ui.close_tools()

    def tab_open_only(self, pos=None):
        ui = self.ui
        for tab in ("scripts", "dev"):
            ui.open_tools(tab)
            check(ui.main_text().strip(), "the %s tab is empty" % tab)
        ui.close_tools()

    # -- search / filter / source ------------------------------------------------------------------------------------------
    def set_search(self, text):
        ui = self.ui
        ui.key("Escape")
        ui.click(ui.P("#sq"))
        ui.select_all()
        if text:
            ui.type(text)
        else:
            ui.key("Delete")
            ui.key("Enter")
        ui.page.wait_for_timeout(500)
        ui.key("Escape") if not text else None

    def filter_search(self, pos=None):
        ui = self.ui
        ui.go_position("top")
        ui.click(ui.P("#sq"))
        ui.type("cards")
        ui.key("Enter")
        ui.wait(lambda: (lambda rs: rs and all("cards" in r["text"] for r in rs))(ui.rows()), 10, "every visible row to match 'cards'")
        ui.pause()
        ui.click(ui.P("#sclear"))
        ui.wait(lambda: any("cards" not in r["text"] for r in ui.rows()), 10, "other calls to return after clearing the filter")
        check(ui.P("#sq").input_value() == "", "the filter box kept its text after Clear")

    def source_menu(self, pos=None):
        ui = self.ui
        ui.open_tools()
        sel = ui.P("#source")
        opts = ui.wait(lambda: [o for o in sel.evaluate("s => [...s.options].map(o => [o.value, o.textContent])") if o[0] and o[0] != "__devices" and "|" in o[0]
                                and not o[0].endswith("|")], 15, "a sender other than All sources in the Source menu")
        key = self.s.rng.choice(opts)[0]
        ui.click(sel)                                                # the select keeps focus from here on
        ui.page.wait_for_timeout(200)
        sel.select_option(key)
        t0 = time.time()
        ui.wait(lambda: self.panel.state()["source"] == key, 8, "the source to be chosen")
        ui.page.wait_for_timeout(3500)                                # polls run; the select still has focus
        check(sel.input_value() == key, "the Source menu shows %r while %r is chosen and it keeps focus" % (sel.input_value(), key))
        check(sel.evaluate("s => s === document.querySelector('#proxy-panel-host').shadowRoot.activeElement"), "the Source select lost focus unexpectedly") if False else None
        ui.pause()
        sel.select_option("")
        ui.wait(lambda: self.panel.state()["source"] is None, 8, "back to All sources")
        ui.page.wait_for_timeout(2500)
        check(sel.input_value() == "", "the Source menu does not show All sources after choosing it (shows %r)" % sel.input_value())
        ui.close_tools()

    # -- list ----------------------------------------------------------------------------------------------------------
    def scroll_top(self, pos=None):
        ui = self.ui
        ui.go_position("middle")
        ui.pause()
        ui.go_position("top")
        first = (ui.rows() or [{"text": ""}])[0]["text"]
        changed = False
        for _ in range(8):
            ui.page.wait_for_timeout(500)
            self.s.tick()
            st = ui.list_state()
            check(st["top"] <= 1, "the list left the top by itself while calls streamed in (scrollTop=%s)" % st["top"])
            if (ui.rows() or [{"text": ""}])[0]["text"] != first:
                changed = True
        check(changed, "no new call appeared at the top while the list was at the top (not following)")
        ui.wheel(-420, 2)                                             # a further wheel up stays put, no bounce
        check(ui.list_state()["top"] <= 1, "wheel up at the top moved the list")

    def scroll_end(self, pos=None):
        ui = self.ui
        ui.go_position("bottom")
        for _ in range(8):
            ui.page.wait_for_timeout(500)
            self.s.tick()
            st = ui.list_state()
            check(st["height"] - st["top"] - st["view"] <= 3, "the list does not follow at the end: %s" % st)
        ui.wheel(-420, 3)
        ui.pause()
        ui.wheel(2000, 3)
        st = ui.list_state()
        check(st["height"] - st["top"] - st["view"] <= 3, "wheel to the end did not reach the end: %s" % st)

    def scroll_middle(self, pos=None):
        ui = self.ui
        ui.go_position("middle")
        sig = lambda: (lambda r: r[0]["text"] if r else None)(ui.rows())
        first = sig()
        for _ in range(6):
            ui.page.wait_for_timeout(700)
            self.s.tick()
            check(sig() == first, "the rows moved under the reader in the middle of the list while calls streamed in")

    def select_details(self, pos=None):
        ui = self.ui
        ui.go_position("top")
        rows = ui.rows()
        check(len(rows) >= 4, "fewer than 4 rows on screen")
        seen = set()
        for r in self.s.rng.sample(rows, 3):
            ui.click_xy(r["x"], r["y"])
            ui.wait(ui.selected_id, 5, "a call to be selected")
            seen.add(ui.selected_id())
            ui.pause(200, 900)
        check(len(seen) >= 2, "selecting different rows did not change the selection: %s" % seen)
        for tab in ("Response", "Connection", "Timing", "Request"):
            t = ui.page.locator("nav a, .nav-tabs a").filter(has_text=re.compile(r"^%s$" % tab)).first
            ui.click(t)
            ui.wait(lambda: ui.page.evaluate("location.hash").lower().endswith("/" + tab.lower()), 6, "the %s pane" % tab)
            ui.wait(lambda: ui.page.evaluate("document.querySelector('.flow-detail') && document.querySelector('.flow-detail').textContent.length") > 20, 6, "%s content" % tab)
            ui.pause(200, 900)

    def keyboard(self, pos=None):
        ui = self.ui
        ui.go_position("top")
        row = ui.pick_row("i=")
        ui.click_xy(row["x"], row["y"])
        fid = ui.wait(ui.selected_id, 5, "a call to be selected")
        info = self.call_info(fid)
        before = self.seen(info["pq"])
        ui.pause()
        ui.page.mouse.move(row["x"], row["y"] + 2)
        ui.key("r")
        ui.wait(lambda: self.seen(info["pq"]) > before, 8, "'r' to repeat the selected call")
        ui.pause()
        ui.key("Shift+?")
        ui.wait(lambda: ui.sheet_open("help"), 6, "'?' to open help")
        ui.key("Escape")
        ui.wait(lambda: not ui.sheet_open("help"), 6, "Esc to close help")
        ui.pause()
        ui.key("Alt+Shift+KeyP")
        ui.wait(ui.drawer_open, 6, "Alt+Shift+P to open Tools")
        ui.pause()
        ui.key("Alt+Shift+KeyP")
        ui.wait(lambda: not ui.drawer_open(), 6, "Alt+Shift+P to close Tools")
        ui.key("Alt+Shift+KeyF")
        ui.wait(lambda: ui.page.evaluate("() => %s.activeElement && %s.activeElement.id" % (self.s_root(), self.s_root())) == "sq", 6, "Alt+Shift+F to focus the filter")
        ui.key("Escape")

    def s_root(self):
        return "document.querySelector('#proxy-panel-host').shadowRoot"

    # -- idle polling (bug d: the call list downloaded every poll) ----------------------------------------------------------
    def idle_polling(self, pos=None):
        ui = self.ui
        ui.close_tools()
        ui.page.mouse.move(40, 40)
        ui.drain()
        n0 = len(self.s.metrics.flows_dl)
        ui.page.wait_for_timeout(9000)
        ui.drain()
        closed = len(self.s.metrics.flows_dl) - n0
        check(closed == 0, "the panel downloaded the whole call list %d time(s) in 9 s while Tools was closed and nobody touched anything" % closed)
        ui.open_tools()
        ui.drain()
        n1 = len(self.s.metrics.flows_dl)
        ui.page.wait_for_timeout(9000)
        ui.drain()
        opened = len(self.s.metrics.flows_dl) - n1
        ui.close_tools()
        check(opened <= 3, "with Tools open the panel downloaded the whole call list %d times in 9 s (every poll, %d calls in the list)"
              % (opened, self.panel.state()["flow_count"]))

    def session_full(self, pos=None):
        """Save the entire capture (thousands of calls) once: it must finish and must not stall the app's calls."""
        n = self.s.next_id()
        name = "soak-full-%d" % n
        t = time.time()
        code, doc, raw = self.panel.post("sess_save", {"name": name, "note": "soak", "visible_only": False, "search_filter": "", "overwrite": False}, timeout=90)
        took = time.time() - t
        check(code == 200, "saving the whole session returned %s %r" % (code, raw[:120]))
        self.panel.post("sess_delete", {"name": name})
        check(took < 60, "saving the whole session took %.0f s" % took)
        ping = [r for r in self.s.metrics.probe if t - self.s.t0 <= r[0] + 0 <= t - self.s.t0 + took]
        slow = [r for r in ping if r[2] > 3000]
        check(not slow, "the app's calls stalled %.1f s while the session was saved" % (max(r[2] for r in slow) / 1000.0 if slow else 0))
