"""Compact command/state contract across bash, PowerShell and the running proxy."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from harness import Background, LiveCase, PWSH, REPO, Suite, wait_for


PHASES = [
    ((), True, True),
    (("--request",), True, False),
    (("--response",), False, True),
    (("--request", "--response"), True, True),
    (("--response", "--request"), True, True),
    (("--method", "post"), True, True),
]
PROFILES = ("3g-urban", "lte-congested", "high-latency-vpn", "packet-loss-8",
            "lte", "3g", "edge", "slow", "manual", "400ms", "250ms/512kbps")
MANUAL = ("latency_ms=120", "jitter_ms=4", "down_kbps=500", "up_kbps=250",
          "loss_pct=3", "response_delay_ms=20")


class Matrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()
        cls.ps = os.path.isfile(PWSH) and os.access(PWSH, os.X_OK)
        if not cls.ps:
            raise AssertionError("pwsh 7 is required for CLI state parity: " + PWSH)
        version = cls.suite.run([PWSH, "-NoProfile", "-NonInteractive", "-Command",
                                 "$PSVersionTable.PSVersion.Major"], timeout=30)
        if version.returncode or version.stdout.strip() != "7":
            raise AssertionError("pwsh 7 is required: " + version.stdout + version.stderr)

    def setUp(self):
        self.home = self.suite.new_home("matrix")
        self.env = self.suite.cli_env(self.home)

    def run_cli(self, surface, project, *args):
        if surface == "bash":
            argv = ["/bin/bash", os.path.join(REPO, "rivis")]
            if project == "neo":
                argv += ["--project", "neo"]
        else:
            argv = [PWSH, "-NoProfile", "-NonInteractive", "-File", os.path.join(REPO, "rivis.ps1")]
        argv += list(args)
        if surface == "ps" and project == "neo":
            argv += ["-Project", "neo"]
        cp = self.suite.run(argv, home=self.home, env=self.env, timeout=120)
        self.assertEqual(cp.returncode, 0, "%s -> %s\n%s\n%s" % (argv, cp.returncode, cp.stdout, cp.stderr))
        return cp.stdout

    def cfg(self, project):
        with open(os.path.join(self.home, ".rivis", "projects", project, "rules.json")) as fh:
            return json.load(fh)

    def surfaces(self):
        return ("bash", "ps") if self.ps else ("bash",)

    def test_breakpoint_phase_matrix(self):
        for project in ("default", "neo"):
            for flags, request, response in PHASES:
                for surface in self.surfaces():
                    with self.subTest(project=project, flags=flags, surface=surface):
                        self.run_cli(surface, project, "breakpoint", "off")
                        args = ["breakpoint", "/matrix", *flags]
                        if surface == "ps":
                            args = ["breakpoint", "/matrix"] + [x.replace("--", "-") for x in flags]
                        out = self.run_cli(surface, project, *args)
                        self.assertIn("ON", out)
                        bp = self.cfg(project)["breakpoints"]
                        self.assertEqual(len(bp), 1)
                        self.assertEqual((bp[0]["request"], bp[0]["response"]), (request, response))
                        self.assertEqual(bp[0].get("method"), "POST" if "post" in flags else None)

    def test_throttle_scope_profiles_and_options(self):
        for project in ("default", "neo"):
            scope = r"neo\.sa" if project == "neo" else ""
            for surface in self.surfaces():
                for profile in PROFILES:
                    with self.subTest(project=project, surface=surface, profile=profile):
                        self.run_cli(surface, project, "throttle", profile)
                        cfg = self.cfg(project)
                        self.assertEqual((cfg["throttle"], cfg["throttle_match"], cfg["loss"]), (profile, scope, 0))
                self.run_cli(surface, project, "throttle", "lte", "match=/only", "loss=7")
                self.assertEqual((self.cfg(project)["throttle_match"], self.cfg(project)["loss"]), ("/only", 7))
                self.run_cli(surface, project, "throttle", "off")
                self.assertEqual((self.cfg(project)["throttle"], self.cfg(project)["throttle_match"], self.cfg(project)["loss"]),
                                 ("off", scope, 0))
                self.run_cli(surface, project, "throttle", "3g-urban")
                self.assertEqual(self.cfg(project)["throttle_match"], scope)
                self.run_cli(surface, project, "throttle", "manual", *MANUAL)
                self.assertEqual(self.cfg(project)["manual"], dict(latency_ms=120, jitter_ms=4, down_kbps=500,
                    up_kbps=250, loss_pct=3, response_delay_ms=20))

    def test_rules_rm_file_ownership(self):
        for project in ("default", "neo"):
            for surface in self.surfaces():
                with self.subTest(project=project, surface=surface):
                    self.run_cli("bash", project, "rules", "list")
                    root = os.path.join(self.home, ".rivis", "projects", project, "mocks")
                    user = os.path.join(self.home, "outside.json")
                    paths = {key: os.path.join(root, key + ".json") for key in ("owned", "file", "body")}
                    paths["user"] = user
                    for key, path in paths.items():
                        if key == "owned": continue
                        with open(path, "w") as fh: fh.write("{}")
                    for name, key in (("owned", "owned"), ("file-owner", "file"),
                                      ("file-reader", "file"), ("body-owner", "body"), ("user", "user")):
                        self.run_cli("bash", project, "rules", "add", name, "match=/" + name,
                                     "action=map_local", "body={}" if key == "owned" else "file=" + paths[key])
                    paths["owned"] = next(r["file"] for r in self.cfg(project)["rules"] if r["name"] == "owned")
                    cfg = self.cfg(project)
                    cfg["rules"].append({"name": "body-reader", "action": "respond", "match": "/reader",
                                         "body_file": paths["body"]})
                    rules = os.path.join(self.home, ".rivis", "projects", project, "rules.json")
                    with open(rules, "w") as fh: json.dump(cfg, fh)
                    for name, remains in (("owned", False), ("file-owner", True), ("body-owner", True),
                                          ("user", True), ("file-reader", True)):
                        self.run_cli(surface, project, "rules", "rm", name)
                        self.assertNotIn(name, [r["name"] for r in self.cfg(project)["rules"]])
                        key = {"file-owner": "file", "file-reader": "file", "body-owner": "body"}.get(name, name)
                        self.assertEqual(os.path.isfile(paths[key]), remains, name)


class LiveBreakpointMatrix(LiveCase):
    def tearDown(self):
        for paused in self.panel.state()["paused"]:
            self.panel.post("paused_abort", {"id": paused["id"]})

    def test_each_phase_combination_arms_before_return(self):
        for flags, request, response in PHASES:
            with self.subTest(flags=flags):
                self.reset_state()
                self.fetch("/json/small")
                project_args = ("--project", self.PROJECT) if self.PROJECT else ()
                cp = self.suite.rivis(*project_args, "breakpoint", "/echo", *flags,
                                      home=self.inst.home, env=self.inst.env)
                self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
                call = Background(self.fetch, "/echo?matrix=" + str(PHASES.index((flags, request, response))),
                                  method="POST" if "post" in flags else "GET",
                                  data="x" if "post" in flags else None)
                expected = [p for p, on in (("request", request), ("response", response)) if on]
                seen = []
                for phase in expected:
                    paused = wait_for(lambda: next((p for p in self.panel.state()["paused"] if p["phase"] == phase), None),
                                      10, 0.1, phase + " pause")
                    seen.append(paused["phase"])
                    self.panel.ok("paused_continue" if phase == "request" and response else "paused_skip", {"id": paused["id"]})
                self.assertEqual(seen, expected)
                self.assertEqual(call.result().status, 200)
                self.assertEqual(self.panel.state()["paused"], [])


class LiveBreakpointNeo(LiveBreakpointMatrix):
    PROJECT = "neo"
