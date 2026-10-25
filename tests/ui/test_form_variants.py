"""Paused-call form edits and Map Local variants in the browser."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for  # noqa: E402
from test_ui import PW_REASON, UiBase  # noqa: E402
import test_workflows  # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class FormVariants(UiBase):
    _W = test_workflows.Workflows
    P, row, select, tab, in_background, sheet, breakpoint_from_call = (
        _W.P, _W.row, _W.select, _W.tab, _W.in_background, _W.sheet, _W.breakpoint_from_call)

    def tearDown(self):
        for p in self.panel.state()["paused"]:
            self.panel.post("paused_abort", {"id": p["id"]})
        super().tearDown()

    def test_request_form_keeps_json_types_and_query_headers_in_sync(self):
        body = '{"amount":10,"flag":true,"nested":{"x":1},"nothing":null}'
        self.fetch("/echo?typedjson=1", method="POST", data=body, headers={"Content-Type": "application/json"})
        self.open()
        self.breakpoint_from_call("typedjson=1")
        t, box = self.in_background("/echo?typedjson=1", method="POST", data=body, headers={"Content-Type": "application/json"})
        self.sheet()
        self.P("button[data-psub=form]").click()
        rows = self.P("#pfjson .hrow")
        rows.nth(0).locator("input[aria-label='JSON value']").fill("25")
        rows.nth(1).locator("input[aria-label='JSON value']").fill("false")
        rows.nth(2).locator("input[aria-label='JSON value']").fill('{"x":2}')
        self.P("[data-fadd=pfquery]").click()
        self.P("#pfquery .hrow").last.locator("input").nth(0).fill("extra")
        self.P("#pfquery .hrow").last.locator("input").nth(1).fill("a b")
        self.P("[data-hadd=pfhd]").click()
        self.P("#pfhd .hrow").last.locator("input").nth(0).fill("X-Form")
        self.P("#pfhd .hrow").last.locator("input").nth(1).fill("yes")
        self.P("button[data-psub=body]").click()
        self.assertEqual(json.loads(self.P("#pb").input_value()),
                         {"amount": 25, "flag": False, "nested": {"x": 2}, "nothing": None})
        self.P("button[data-psub=form]").click()
        self.assertEqual(rows.nth(0).locator("select").input_value(), "number")
        self.P("#pcont").click()
        t.join(20)
        got = box["r"].json()
        self.assertEqual(json.loads(got["body"])["nested"], {"x": 2})
        self.assertEqual(got["query"]["extra"], ["a b"])
        self.assertIn(["X-Form", "yes"], got["headers"])

    def test_urlencoded_form_edits(self):
        self.fetch("/echo?encoded=1", method="POST", data="one=1", headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.open()
        self.breakpoint_from_call("encoded=1", phase="request")
        t, box = self.in_background("/echo?encoded=1", method="POST", data="one=1",
                                    headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.sheet()
        self.P("button[data-psub=form]").click()
        self.P("[data-fadd=pffields]").click()
        self.P("#pffields .hrow").last.locator("input").nth(0).fill("two")
        self.P("#pffields .hrow").last.locator("input").nth(1).fill("a b")
        self.P("#pcont").click()
        t.join(20)
        self.assertEqual(box["r"].json()["body"], "one=1&two=a+b")

    def test_response_form_edits(self):
        self.fetch("/json/small?response-edit=1")
        self.open()
        self.breakpoint_from_call("response-edit=1", phase="response")
        t, box = self.in_background("/json/small?response-edit=1")
        self.sheet()
        self.P("button[data-psub=form]").click()
        self.assertEqual(self.P("#pfst").count(), 0, "status is edited once, in the sheet's bar")
        self.P("#pst").fill("202")
        self.P("#pfjson .hrow").first.locator("input[aria-label='JSON value']").fill('{"name":"changed"}')
        self.P("[data-hadd=pfhd]").click()
        self.P("#pfhd .hrow").last.locator("input").nth(0).fill("X-Response-Form")
        self.P("#pfhd .hrow").last.locator("input").nth(1).fill("yes")
        self.P("#pcont").click()
        t.join(20)
        self.assertEqual(box["r"].status, 202)
        self.assertEqual(box["r"].json()["user"], {"name": "changed"})
        self.assertEqual(box["r"].header("x-response-form"), "yes")
        self.assertEqual(self.errors, [])

    def test_form_changes_request_method_and_path(self):
        self.fetch("/json/small?methodpath=1")
        self.open()
        self.breakpoint_from_call("methodpath=1")
        t, box = self.in_background("/json/small?methodpath=1")
        self.sheet()
        self.P("button[data-psub=form]").click()
        methods = self.page.locator("#proxy-panel-host").locator("select[aria-label=Method]:visible, select#pm:visible")
        self.assertEqual(methods.count(), 1, "the Form view shows the method once (the sheet's own selector)")
        self.P("#pm").select_option("POST")
        self.P("#pfpath").fill("/echo")
        self.P("#pcont").click()
        t.join(20)
        got = box["r"].json()
        self.assertEqual((got["method"], got["path"], got["query"]["methodpath"]), ("POST", "/echo", ["1"]))

    def test_empty_json_body_gets_editable_form_fields(self):
        self.fetch("/echo?empty-json=1", method="POST", data="", headers={"Content-Type": "application/json"})
        self.open()
        self.breakpoint_from_call("empty-json=1")
        t, box = self.in_background("/echo?empty-json=1", method="POST", data="",
                                    headers={"Content-Type": "application/json"})
        self.sheet()
        self.P("button[data-psub=form]").click()
        self.P("#pfjadd").click()
        self.P("#pfjson .hrow").last.locator("input[aria-label='JSON key']").fill("ready")
        self.P("#pfjson .hrow").last.locator("input[aria-label='JSON value']").fill("yes")
        self.P("#pcont").click()
        t.join(20)
        self.assertEqual(json.loads(box["r"].json()["body"]), {"ready": "yes"})

    def test_map_local_variant_picker_and_call_menu(self):
        self.fetch("/json/small?ui-variant=1")
        self.open()
        self.select("ui-variant=1")
        self.tab("call")
        self.P("#mock").click()
        self.P("#save").click()
        wait_for(lambda: "Saved" in self.P("#toast").text_content(), 5, 0.2, "mock saved")
        self.P("#vadd").click()
        self.P("#ask-in").fill("empty")
        self.P("#ask-yes").click()
        wait_for(lambda: self.P("#variant").input_value() == "empty", 5, 0.2, "variant added")
        self.P("#body").fill("{}")
        self.P("#save").click()
        wait_for(lambda: not self.P("#dirty").text_content(), 5, 0.2, "variant saved")
        self.P("#variant").select_option("Default")
        wait_for(lambda: self.P("#variant").input_value() == "Default", 5, 0.2, "default selected")
        self.P("#back").click()
        self.row("ui-variant=1").click(button="right")
        self.P("#cmenu button[data-k=mapvariant]").click()
        self.P("#ask-in").fill("from-call")
        self.P("#ask-yes").click()
        wait_for(lambda: self.P("#variant").input_value() == "from-call", 5, 0.2, "call variant saved")
        self.P("#back").click()
        self.tab("rules")
        self.assertIn("from-call", self.P("#main").text_content())
        self.assertEqual(self.errors, [])
