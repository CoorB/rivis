"""H1 — the Rules tab lists, creates, edits, switches on/off and deletes EVERY rule type, in a real browser.

Each test drives one type through the panel (create → rules.json + effect on a real call; edit → the new value takes
effect; disable → the call is left alone; delete → gone from rules.json). Before this, the Rules tab could only edit
Map Local rules: json_patch, map_remote, set_header, respond, breakpoints, scripts and the network settings had no
form anywhere in the panel (JSON or API only).

Effects are asserted on the wire (a lower bound for timing: the Mac may be loaded).
"""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import harness                          # noqa: E402
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class RulesTabEveryType(UiBase):
    def setUp(self):
        super().setUp()
        self.page.add_init_script(harness.PANEL_AUTO_ANSWER_JS)   # the "Delete …?" questions

    def tearDown(self):
        for p in self.panel.state()["paused"]:
            self.panel.post("paused_abort", {"id": p["id"]})
        super().tearDown()

    # ── helpers ─────────────────────────────────────────────────────────────────────────────────────
    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def rules_tab(self):
        if not self.P("#drawer.open").count():
            self.P("#fab").click()
        self.P("button[data-t=rules]").click()
        self.P("#rtype").wait_for(timeout=10000)

    def new(self, type_, **fields):
        self.rules_tab()
        self.P("#rtype").select_option(type_)
        self.P("#rnew").click()
        self.P("#rsave").wait_for(timeout=10000)
        self.fill(**fields)
        self.P("#rsave").click()
        self.P("#rtype").wait_for(timeout=10000)                # back on the list

    def fill(self, **fields):
        for key, value in fields.items():
            el = self.P("#rf-" + key)
            if isinstance(value, bool):
                el.set_checked(value)
            elif el.evaluate("e => e.tagName") == "SELECT":
                el.select_option(value)
            else:
                el.fill(str(value))

    def row(self, name):
        return self.P(".row").filter(has_text=name).first

    def edit(self, name, button="[data-edit]", **fields):
        self.rules_tab()
        self.row(name).locator(button).click()
        self.P("#rsave").wait_for(timeout=10000)
        self.fill(**fields)
        self.P("#rsave").click()
        self.P("#rtype").wait_for(timeout=10000)

    def toggle(self, name):
        self.rules_tab()
        self.row(name).locator(".sw").click()
        self.page.wait_for_timeout(300)

    def delete(self, name):
        self.rules_tab()
        self.row(name).locator("[data-del]").click()
        wait_for(lambda: self.rule_named(name) is None, 8, 0.2, "rule deleted")

    def rule_named(self, name):
        return next((r for r in self.inst.cfg()["rules"] if r.get("name") == name), None)

    def lifecycle(self, name, type_, create, effect_on, edit, effect_edited, effect_off):
        """create → on the wire; edit → new effect; disable → untouched; delete → gone."""
        self.open()
        self.new(type_, name=name, **create)
        wait_for(lambda: self.rule_named(name), 8, 0.2, "rule in rules.json")
        self.assertEqual(self.rule_named(name)["action"], type_)
        wait_for(effect_on, 10, 0.3, "rule takes effect")
        self.edit(name, **edit)
        wait_for(effect_edited, 10, 0.3, "edited rule takes effect")
        self.toggle(name)
        wait_for(lambda: self.rule_named(name)["enabled"] is False, 8, 0.2, "disabled in rules.json")
        wait_for(effect_off, 10, 0.3, "disabled rule leaves the call alone")
        self.toggle(name)
        wait_for(effect_edited, 10, 0.3, "re-enabled")
        self.delete(name)
        self.assertIsNone(self.rule_named(name))
        wait_for(effect_off, 10, 0.3, "deleted rule leaves the call alone")
        self.assertEqual(self.errors, [])

    # ── one test per type ───────────────────────────────────────────────────────────────────────────
    def test_respond(self):
        body = lambda: self.fetch("/h1/respond").text          # noqa: E731
        self.lifecycle("h1-respond", "respond", dict(match="/h1/respond", status="201", body='{"mocked": 1}'),
                       lambda: self.fetch("/h1/respond").status == 201 and self.fetch("/h1/respond").json() == {"mocked": 1},
                       dict(status="202", body="plain text"),
                       lambda: self.fetch("/h1/respond").status == 202 and body() == "plain text",
                       lambda: self.fetch("/h1/respond").status != 202)

    def test_status(self):
        self.lifecycle("h1-status", "status", dict(match="/status/200$", status="503"),
                       lambda: self.fetch("/status/200").status == 503,
                       dict(status="418"),
                       lambda: self.fetch("/status/200").status == 418,
                       lambda: self.fetch("/status/200").status == 200)

    def test_json_patch(self):
        name = lambda: self.fetch("/json/small").json()["user"]["name"]    # noqa: E731
        self.lifecycle("h1-patch", "json_patch", dict(match="/json/small$", set='{"user.name": "PATCHED"}'),
                       lambda: name() == "PATCHED",
                       dict(set='{"user.name": "EDITED", "flag": true}'),
                       lambda: name() == "EDITED" and self.fetch("/json/small").json()["flag"] is True,
                       lambda: name() == "alice")

    def test_delay(self):
        def took(at_least):
            def check():
                t = time.time()
                self.fetch("/json/small?d=1")
                return time.time() - t >= at_least
            return check
        self.lifecycle("h1-delay", "delay", dict(match="d=1", ms="500"),
                       took(0.45), dict(ms="1400"), took(1.3),
                       lambda: not took(1.3)())                  # an unloaded call is far under 1.3 s

    def test_set_header_request_then_response(self):
        sent = lambda: [v for k, v in self.fetch("/echo").json()["headers"] if k.lower() == "x-h1"]    # noqa: E731
        got = lambda: self.fetch("/echo").header("X-H1-Resp")                                         # noqa: E731
        self.lifecycle("h1-header", "set_header", dict(match="/echo$", side="request", header="X-H1", value="one"),
                       lambda: sent() == ["one"],
                       dict(side="response", header="X-H1-Resp", value="two"),
                       lambda: got() == "two" and sent() == [],
                       lambda: got() is None)

    def test_set_header_remove(self):
        self.open()
        self.new("set_header", name="h1-strip", match="/echo$", side="request", header="X-Strip", value="x")
        self.edit("h1-strip", remove=True)
        self.assertIsNone(self.rule_named("h1-strip")["value"])
        wait_for(lambda: not [1 for k, v in self.fetch("/echo", headers={"X-Strip": "secret"}).json()["headers"]
                              if k.lower() == "x-strip"], 10, 0.3, "header removed")

    def test_map_remote(self):
        path = lambda: self.fetch("/h1/old").json().get("path")                                        # noqa: E731
        self.lifecycle("h1-remote", "map_remote", dict(match="/h1/old$", replace="/h1/old$", **{"with": "/echo"}),
                       lambda: path() == "/echo",
                       dict(**{"with": "/json/small"}),
                       lambda: self.fetch("/h1/old").json().get("flag") is False,
                       lambda: path() != "/echo")

    def test_block(self):
        blocked = lambda: self.fetch("/echo?h1=block", timeout=8).status == 0                         # noqa: E731
        self.lifecycle("h1-block", "block", dict(match="h1=block"),
                       blocked, dict(match="h1=block2"),
                       lambda: self.fetch("/echo?h1=block2", timeout=8).status == 0,
                       lambda: self.fetch("/echo?h1=block2").status == 200)
        self.assertEqual(self.fetch("/echo?h1=block").status, 200)      # the edited match no longer catches it

    def test_map_local(self):
        self.open()
        self.rules_tab()
        self.P("#rtype").select_option("map_local")
        self.P("#rnew").click()                                  # Map Local keeps its own tab: the Rules tab sends you there
        self.P("#madd").wait_for(timeout=10000)
        self.P("#mh").fill("127.0.0.1:%d" % self.up.port if hasattr(self.up, "port") else self.up.url("/").split("//")[1].rstrip("/"))
        self.P("#mp").fill("/h1/local")
        self.P("#madd").click()
        self.P("#body").wait_for(timeout=10000)
        self.P("#body").fill('{"local": 1}')
        self.P("#save").click()
        self.page.wait_for_timeout(600)
        self.P("#back").click()
        rule = next(r for r in self.inst.cfg()["rules"] if r.get("action") == "map_local")
        wait_for(lambda: self.fetch("/h1/local").json() == {"local": 1}, 10, 0.3, "served")
        self.rules_tab()                                           # edit from the Rules tab
        self.row(rule["name"]).locator("[data-edit]").click()
        self.P("#body").wait_for(timeout=10000)
        self.P("#body").fill('{"local": 2}')
        self.P("#save").click()
        self.page.wait_for_timeout(600)
        self.P("#back").click()
        wait_for(lambda: self.fetch("/h1/local").json() == {"local": 2}, 10, 0.3, "edited")
        self.toggle(rule["name"])
        wait_for(lambda: self.fetch("/h1/local").status == 404, 10, 0.3, "disabled")
        self.delete(rule["name"])
        self.assertEqual(self.fetch("/h1/local").status, 404)

    def test_breakpoint(self):
        def held(path):
            box = {}
            t = threading.Thread(target=lambda: box.update(r=self.fetch(path, timeout=20)), daemon=True)
            t.start()
            return t, box

        def pauses(path):
            n = len(self.panel.state()["paused"])
            t, box = held(path)
            ok = wait_for(lambda: len(self.panel.state()["paused"]) > n or "r" in box, 6, 0.2, "paused or done") is not None
            paused = len(self.panel.state()["paused"]) > n
            for p in self.panel.state()["paused"]:
                self.panel.post("paused_abort", {"id": p["id"]})
            t.join(15)
            return paused and ok
        self.open()
        self.new("bp", match="bp-one", method="GET", req=True, resp=False)
        bp = lambda: self.panel.state()["breakpoints"]          # noqa: E731
        wait_for(lambda: any(b["match"] == "bp-one" for b in bp()), 8, 0.2, "breakpoint saved")
        name = next(b["name"] for b in bp() if b["match"] == "bp-one")
        self.page.wait_for_timeout(1200)                         # the proxy picks the filter up within a second
        self.assertTrue(pauses("/echo?bp-one"))
        self.edit(name, "[data-rbedit]", match="bp-two")
        wait_for(lambda: any(b["match"] == "bp-two" for b in bp()), 8, 0.2, "breakpoint edited")
        self.page.wait_for_timeout(1200)
        self.assertTrue(pauses("/echo?bp-two"))
        self.assertFalse(pauses("/echo?bp-one"))
        self.toggle(name)
        wait_for(lambda: bp()[0]["enabled"] is False, 8, 0.2, "disabled")
        self.page.wait_for_timeout(1200)
        self.assertFalse(pauses("/echo?bp-two"))
        self.rules_tab()
        self.row(name).locator("[data-rbdel]").click()
        wait_for(lambda: not bp(), 8, 0.2, "breakpoint deleted")

    def test_script(self):
        tagged = lambda: [v for k, v in self.fetch("/echo").json()["headers"] if k.lower() == "x-qa"]    # noqa: E731
        self.open()
        self.rules_tab()
        self.P("#rtype").select_option("script")
        self.P("#rnew").click()
        self.fill(name="h1script", lang="py", template="header", match="/echo$")
        self.P("#rsave").click()
        wait_for(lambda: self.P("#sematch").count() == 1, 10, 0.2, "the new script opens in its editor")
        self.P("#sesave").click()
        self.P("#rtype").wait_for(timeout=10000)                 # saving goes back to the Rules tab it came from
        wait_for(lambda: tagged() == ["enabled"], 10, 0.3, "script runs")
        self.rules_tab()
        self.row("h1script").locator("[data-rsedit]").click()   # edit: its match
        self.P("#sematch").fill("/nowhere$")
        self.P("#sesave").click()
        self.P("#rtype").wait_for(timeout=10000)
        wait_for(lambda: tagged() == [], 10, 0.3, "edited match no longer runs it")
        self.rules_tab()
        self.row("h1script").locator("[data-rsedit]").click()
        self.P("#sematch").fill("/echo$")
        self.P("#sesave").click()
        self.P("#rtype").wait_for(timeout=10000)
        wait_for(lambda: tagged() == ["enabled"], 10, 0.3, "back on")
        self.row("h1script").locator(".sw").click()
        wait_for(lambda: tagged() == [], 10, 0.3, "disabled")
        self.row("h1script").locator("[data-rsdel]").click()
        wait_for(lambda: not self.panel.state()["scripts"], 8, 0.2, "script deleted")
        self.assertEqual(tagged(), [])

    def test_network_throttle(self):
        took = lambda: (lambda t: (self.fetch("/echo?h1=net"), time.time() - t)[1])(time.time())    # noqa: E731
        self.open()
        self.new("throttle", profile="high-latency-vpn", tmatch="h1=net")
        wait_for(lambda: self.inst.cfg()["throttle"] == "high-latency-vpn", 8, 0.2, "throttle saved")
        self.assertEqual(self.inst.cfg()["throttle_match"], "h1=net")
        wait_for(lambda: took() >= 0.5, 15, 0.2, "throttled (650 ms latency)")
        self.edit_net(profile="3g-urban", tmatch="h1=net2")
        wait_for(lambda: self.inst.cfg()["throttle"] == "3g-urban" and self.inst.cfg()["throttle_match"] == "h1=net2", 8, 0.2, "edited")
        self.rules_tab()
        self.P("#rnetoff").click()                               # delete = off (one throttle per project)
        wait_for(lambda: self.inst.cfg()["throttle"] == "off", 8, 0.2, "off")
        wait_for(lambda: self.P("#rnetedit").count() == 0, 8, 0.2, "the row leaves the Rules tab")

    def edit_net(self, **fields):
        self.rules_tab()
        self.P("#rnetedit").click()
        self.P("#rsave").wait_for(timeout=10000)
        self.fill(**fields)
        self.P("#rsave").click()
        self.P("#rtype").wait_for(timeout=10000)

    def test_no_caching(self):
        revalidate = lambda: self.fetch("/etag", headers={"If-None-Match": '"v1"'}).status          # noqa: E731
        self.open()
        self.assertEqual(revalidate(), 304)
        self.new("nocache")
        wait_for(lambda: self.inst.cfg().get("no_cache") is True, 8, 0.2, "no_cache saved")
        wait_for(lambda: revalidate() == 200, 10, 0.3, "fresh content, never a 304")
        self.rules_tab()
        self.P("#rnocache").locator("xpath=..").click()
        wait_for(lambda: not self.inst.cfg().get("no_cache"), 8, 0.2, "off")
        wait_for(lambda: revalidate() == 304, 10, 0.3, "conditional requests work again")

    def test_form_refuses_what_the_proxy_would_skip(self):
        """The form reports a rule the proxy would silently skip, instead of saving it as if it worked."""
        self.open()
        self.rules_tab()
        self.P("#rtype").select_option("respond")
        self.P("#rnew").click()
        self.fill(name="h1-bad", match="/x", status="100", body="x")
        self.P("#rsave").click()
        wait_for(lambda: "would skip" in (self.P("#rerr").text_content() or ""), 8, 0.2, "error shown")
        self.assertIsNone(self.rule_named("h1-bad"))
        self.fill(status="200", match="(")
        self.P("#rsave").click()
        wait_for(lambda: "regex" in (self.P("#rerr").text_content() or ""), 8, 0.2, "bad regex shown")
        self.assertIsNone(self.rule_named("h1-bad"))

    def test_list_shows_every_type_with_edit_and_delete(self):
        self.reset_state(rules=[self.rule("l-respond", "respond", "/a", status=200, body="x"),
                                self.rule("l-patch", "json_patch", "/b", set={"a": 1}),
                                self.rule("l-hdr", "set_header", "/c", header="X-A", value="1"),
                                self.rule("l-remote", "map_remote", "/d", replace="/d", **{"with": "/e"}),
                                self.rule("l-block", "block", "/f"), self.rule("l-delay", "delay", "/g", ms=5),
                                self.rule("l-status", "status", "/h", status=500)],
                         breakpoints=[{"name": "l-bp", "match": "/bp", "request": True, "response": False, "enabled": True}])
        self.open()
        self.rules_tab()
        for name in ("l-respond", "l-patch", "l-hdr", "l-remote", "l-block", "l-delay", "l-status"):
            self.assertEqual(self.row(name).locator("[data-edit]").count(), 1, name)
        self.assertEqual(self.row("l-bp").locator("[data-rbedit]").count(), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
