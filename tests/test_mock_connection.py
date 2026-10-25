"""A mock must not end the app's connection. Map Local from a call copied the server's own `Connection: close`
(the UAT edge sends it on about half its answers), so every mocked answer made the app reconnect before its next
call. Connection headers belong to one hop: a local answer never carries them, whether the mock was made from a
call, by hand, or by an older Rivis that saved them.

  bash tests/run.sh --fast -k test_mock_connection
"""
import os
import subprocess
import unittest

from harness import LiveCase

HOP = ("connection", "keep-alive", "proxy-connection", "te", "trailer", "upgrade")


class MockConnection(LiveCase):
    def two_calls(self, url):
        """The same URL twice through the proxy in one curl, which reuses its connection when it may. Returns the
        connections opened for each call and the response headers of each."""
        argv = ["curl", "-sS", "--noproxy", "", "-x", "http://127.0.0.1:%d" % self.inst.proxy_port,
                "--cacert", self.suite.ca_pem, "--http1.1", "--max-time", "20", "-o", os.devnull,
                "-D", "-", "-w", "\n@@%{num_connects}\n", url, url]
        out = subprocess.run(argv, env=self.suite.env(self.inst.home), capture_output=True, timeout=40).stdout
        connects, headers, block = [], [], []
        for line in out.decode("latin-1").replace("\r\n", "\n").split("\n"):
            if line.startswith("@@"):
                connects.append(int(line[2:]))
                headers.append([h.split(":", 1)[0].strip().lower() for h in block if ":" in h])
                block = []
            elif line.strip():
                block.append(line)
        return connects, headers

    def assert_keeps_the_connection(self, url):
        connects, headers = self.two_calls(url)
        self.assertEqual(len(connects), 2, "two answers")
        for got in headers:
            self.assertEqual([h for h in got if h in HOP], [], "a local answer carries no connection headers")
        self.assertEqual(connects, [1, 0], "the second call reuses the app's connection instead of reconnecting")

    def test_map_local_from_a_call_that_closed_its_connection_keeps_the_apps_connection(self):
        url = self.up.url("/closing", tls=True)
        self.assertEqual(self.inst.fetch(url).status, 200)
        name = self.panel.ok("mock", {"flow_id": self.inst.flow_for("/closing")["id"]})["name"]
        rule = next(r for r in self.inst.cfg()["rules"] if r["name"] == name)
        saved = [k.lower() for k, _v in rule.get("headers") or []]
        self.assertNotIn("connection", saved)
        self.assertNotIn("keep-alive", saved)
        self.inst.write_cfg(self.inst.cfg())       # wait until the engine serves the new mock
        before = len(self.up.hits_for("/closing"))
        self.assert_keeps_the_connection(url)
        self.assertEqual(len(self.up.hits_for("/closing")), before, "answered by the mock, not the server")

    def test_a_mock_saved_with_connection_headers_by_an_older_rivis_is_served_without_them(self):
        mock = self.inst.path("mocks", "old.json")
        os.makedirs(os.path.dirname(mock), exist_ok=True)
        with open(mock, "w") as fh:
            fh.write('{"old": true}\n')
        headers = [["Content-Type", "application/json"], ["connection", "close, X-Hop"], ["Keep-Alive", "timeout=5"],
                   ["X-Hop", "1"], ["X-Kept", "yes"]]
        self.reset_state(rules=[self.rule("old", "map_local", r"/json/small\?old", file=mock, headers=headers)])
        url = self.up.url("/json/small?old", tls=True)
        self.assert_keeps_the_connection(url)
        r = self.inst.fetch(url)
        self.assertEqual(r.header("X-Kept"), "yes", "the mock's own headers stay")
        self.assertIsNone(r.header("X-Hop"), "a header the Connection header names is for that hop only")

    def test_a_hand_written_respond_rule_is_served_without_connection_headers(self):
        self.reset_state(rules=[self.rule("hand", "respond", r"/json/small\?hand", body={"hand": True},
                                          headers=[["Connection", "close"]])])
        self.assert_keeps_the_connection(self.up.url("/json/small?hand", tls=True))


if __name__ == "__main__":
    unittest.main()
