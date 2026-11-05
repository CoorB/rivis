"""Main-window protocol viewers (/rivis/): JWT header/payload with local exp, GraphQL operation/variables/data,
gRPC service/method and field numbers — same facts the classic This call view shows for the same flow — plus a
sidebar chip that filters the list by GraphQL operation name via graphql_filter."""
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402
from upstream import GRPC_BODY, make_jwt  # noqa: E402


@unittest.skipIf(PW_REASON, PW_REASON or "")
class ProtocolViewers(UiBase):
    def open_new(self):
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.goto("http://127.0.0.1:%d/rivis/" % self.inst.web_port)
        self.page.locator("#rv-app").wait_for(timeout=15000)
        self.errors[:] = [e for e in self.errors if not (e[0] == "requestfailed" and e[1].endswith("/proxy/api/state"))]
        wait_for(lambda: self.page.evaluate("!!(window.RivisApp && window.__rivisUI)"), 10, 0.1, "ui ready")
        return self.page

    def row(self, text):
        return self.page.locator(".rv-tr", has_text=text).first

    def wait_row(self, text, timeout=10):
        wait_for(lambda: self.page.locator(".rv-tr", has_text=text).count() > 0, timeout, 0.1, "row %s" % text)

    def shown(self, text):
        return self.page.evaluate(
            "(t) => window.__rivisUI.view.some((id) => { const r = window.__rivisUI.byId.get(id).request; return (r.path || '').includes(t); })",
            text)

    def detail_text(self):
        return self.page.locator("#detail").inner_text()

    def test_bearer_jwt_shows_decoded_header_payload_and_local_exp(self):
        token = make_jwt({"sub": "zed", "iat": 1700000000, "exp": 4102444800})
        self.fetch("/echo?jwt=1", headers={"Authorization": "Bearer " + token})
        self.open_new()
        self.wait_row("jwt=1")
        self.row("jwt=1").click()
        wait_for(lambda: "zed" in self.detail_text() and "Header" in self.detail_text()
                 and "Payload" in self.detail_text(), 10, 0.1, "decoded JWT in detail")
        text = self.detail_text()
        self.assertIn("zed", text)
        self.assertIn("HS256", text)
        self.assertIn("header:authorization", text)
        self.assertIn("exp:", text)
        self.assertRegex(text, r"exp:.*\d{4}-\d{2}-\d{2}")   # local time, not just the epoch
        self.assertIn("signature not verified", text)
        classic = self.panel.ok("viewer", {"flow_id": self.inst.flow_for("/echo")["id"]})
        self.assertEqual(classic["tokens"][0]["payload"]["sub"], "zed")
        self.assertIn(classic["tokens"][0]["times"]["exp"]["local"].split(" ")[0], text)
        self.assertEqual(self.errors, [])

    def test_graphql_shows_operation_variables_data_and_sidebar_chip_filters(self):
        q = json.dumps({"query": "query GetViewer { viewer { id name } }", "variables": {"x": 1}})
        self.fetch("/graphql?gqlv=1", method="POST", data=q, headers={"Content-Type": "application/json"})
        self.fetch("/json/small?gqlv=other")
        self.open_new()
        self.wait_row("gqlv=1")
        self.wait_row("gqlv=other")
        self.row("gqlv=1").click()
        wait_for(lambda: "GetViewer" in self.detail_text() and "Variables" in self.detail_text(), 10, 0.1, "GraphQL op")
        text = self.detail_text()
        self.assertIn("GetViewer", text)
        self.assertIn('"x": 1', text)
        self.assertIn("alice", text)                         # response data.viewer.name
        wait_for(lambda: self.page.locator('#sources [data-gql="GetViewer"]').count() == 1, 15, 0.2, "op chip")
        self.page.locator('#sources [data-gql="GetViewer"]').click()
        wait_for(lambda: self.shown("gqlv=1") and not self.shown("gqlv=other"), 10, 0.1, "filtered to GetViewer")
        self.assertEqual(self.panel.state()["graphql_operation"], "GetViewer")
        self.page.locator('#sources [data-gql="GetViewer"]').click()   # toggle off
        wait_for(lambda: self.shown("gqlv=1") and self.shown("gqlv=other"), 10, 0.1, "filter cleared")
        wait_for(lambda: self.panel.state().get("graphql_operation") in (None, ""), 5, 0.1, "state cleared")
        self.assertEqual(self.errors, [])

    def test_graphql_errors_mark_status_and_show_in_viewer(self):
        q = json.dumps({"query": "query Failing { fail }"})
        self.fetch("/graphql?gqlerr=1", method="POST", data=q, headers={"Content-Type": "application/json"})
        self.open_new()
        self.wait_row("gqlerr=1")
        wait_for(lambda: "200 !" in self.page.locator(".rv-tr", has_text="gqlerr=1").first.inner_text(),
                 15, 0.2, "200 ! GraphQL error status")
        self.row("gqlerr=1").click()
        wait_for(lambda: "boom" in self.detail_text() and "GraphQL errors" in self.detail_text(),
                 10, 0.1, "GraphQL errors in detail")
        wait_for(lambda: self.page.locator('#sources [data-gql="Failing"]').count() == 1, 15, 0.2, "Failing chip")
        self.assertIn("ERR", self.page.locator('#sources [data-gql="Failing"]').inner_text())
        self.assertEqual(self.errors, [])

    def test_grpc_shows_service_method_and_field_numbers(self):
        self.fetch("/grpc/pkg.Greeter/SayHello?grpcv=1", method="POST", data=GRPC_BODY,
                   headers={"Content-Type": "application/grpc"})
        self.open_new()
        self.wait_row("grpcv=1")
        self.row("grpcv=1").click()
        # path alone also contains service/method — wait for the viewer strip, not the URL line
        wait_for(lambda: "gRPC / protobuf" in self.detail_text() and "grpc-status" in self.detail_text(), 10, 0.1, "gRPC viewer")
        text = self.detail_text()
        self.assertIn("pkg.Greeter", text)
        self.assertIn("SayHello", text)
        # field-number view: panel fallback JSON, or mitmproxy's built-in protobuf/gRPC text (same facts)
        self.assertTrue(('"field": 1' in text or '"field":1' in text or re.search(r"\b1:\s*150\b", text)), text)
        self.assertIn("150", text)
        self.assertIn("hi", text)
        classic = self.panel.ok("viewer", {"flow_id": self.inst.flow_for("/grpc/pkg.Greeter/SayHello")["id"]})
        self.assertEqual((classic["grpc"]["service"], classic["grpc"]["method"]), ("pkg.Greeter", "SayHello"))
        self.assertEqual([(f["field"], f["value"]) for f in classic["grpc"]["request"][0]["fields"]], [(1, 150), (2, "hi")])
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
