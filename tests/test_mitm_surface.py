"""Upgrade guards: the mitmproxy / Tornado names Rivis reaches into must still exist with the expected shape.

The frozen mitmproxy binary is not importable from system Python, so each check runs a one-shot add-on under
mitmdump or mitmweb (same idiom as tests/fakes/guard_probe.py). When a pin bump moves an internal, these fail
the day of the upgrade instead of a week later when a QA engineer notices missing Source labels or a plain
mitmweb window with no Tools menu.

Also covers panel_mitmweb.patch_mitmweb_js against the live bundle: if mitmweb's minified flow-list code
changes, the scroll-crash fix silently stops applying — that used to be untested.
"""
import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
sys.path.insert(0, os.path.join(harness.REPO, "addons"))
from panel_mitmweb import _VIEWPORT_LOOP, patch_mitmweb_js


FAKES = os.path.join(harness.TESTS, "fakes")


def _run_probe(engine, script, home, out_name):
    """engine: 'mitmdump' or 'mitmweb'. Returns the parsed probe JSON."""
    suite = harness.Suite.get()
    out = os.path.join(home, out_name)
    conf = os.path.join(home, "ca-" + out_name)
    env = dict(os.environ, PROBE_OUT=out, RIVIS_ADDONS=os.path.join(harness.REPO, "addons"))
    script_path = os.path.join(FAKES, script)
    if engine == "mitmdump":
        cmd = [harness.REAL_MITMDUMP, "--listen-host", "127.0.0.1", "-p", "0",
               "--set", "confdir=" + conf, "-q", "-s", script_path]
    else:
        web = harness.free_port()
        proxy = harness.free_port()
        cmd = [harness.REAL_MITMWEB, "--listen-host", "127.0.0.1", "-p", str(proxy),
               "--set", "web_host=127.0.0.1", "--set", "web_port=%d" % web,
               "--set", "web_open_browser=false", "--set", "confdir=" + conf, "-q", "-s", script_path]
    cp = subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
    assert cp.returncode == 0, "probe exited %s\nstdout:\n%s\nstderr:\n%s" % (
        cp.returncode, cp.stdout.decode("utf-8", "replace"), cp.stderr.decode("utf-8", "replace"))
    assert os.path.isfile(out), "probe wrote nothing\nstdout:\n%s\nstderr:\n%s" % (
        cp.stdout.decode("utf-8", "replace"), cp.stderr.decode("utf-8", "replace"))
    with open(out) as fh:
        return json.load(fh)


class MitmproxySurface(unittest.TestCase):
    """Names Rivis imports or monkeypatches inside the frozen mitmproxy package."""

    def test_mitmdump_still_exposes_every_internal_rivis_touches(self):
        suite = harness.Suite.get()
        home = suite.new_home("mitm-surface")
        got = _run_probe("mitmdump", "mitm_surface_probe.py", home, "surface.json")
        self.assertTrue(got.get("ok"), "missing or reshaped:\n  " + "\n  ".join(got.get("errors") or []))
        # a few highest-risk internals called out so a failure message names them without reading the JSON
        for key in ("LocalRedirectorInstance.handle_stream", "Http1Client.read_headers",
                    "_base.format_error", "har.request_to_flow", "webapp.IndexHandler",
                    "viewport.pattern_matches_once", "viewport.patch_changes_source",
                    "index.html.script_src", "tornado.web.RequestHandler"):
            self.assertTrue(got.get(key), "%s missing from this mitmproxy" % key)

    def test_mitmweb_still_exposes_the_app_view_and_web_options(self):
        suite = harness.Suite.get()
        home = suite.new_home("mitm-web-surface")
        got = _run_probe("mitmweb", "mitm_web_surface_probe.py", home, "web-surface.json")
        self.assertTrue(got.get("ok"), "missing or reshaped:\n  " + "\n  ".join(got.get("errors") or []))
        for key in ("master.app", "app.add_handlers", "app.find_handler", "view._store",
                    "option.web_password", "option.view_filter", "option.intercept"):
            self.assertTrue(got.get(key), "%s missing from this mitmweb" % key)


class ViewportPatchShape(unittest.TestCase):
    """panel_mitmweb.patch_mitmweb_js matches by shape. Prove the fail direction without a broken mitmproxy."""

    def test_unmatched_source_is_returned_unchanged(self):
        """Fail-before stand-in: a bundle without the viewport loop must not be rewritten (and must not raise)."""
        bogus = "function unrelated(){return this.state.viewportTop}"
        self.assertEqual(_VIEWPORT_LOOP.findall(bogus), [])
        self.assertEqual(patch_mitmweb_js(bogus), bogus)

    def test_live_bundle_still_matches_the_viewport_loop_exactly_once(self):
        """Same check as the mitmdump probe, but readable when someone only runs this class."""
        suite = harness.Suite.get()
        home = suite.new_home("mitm-viewport")
        got = _run_probe("mitmdump", "mitm_surface_probe.py", home, "viewport.json")
        self.assertTrue(got.get("viewport.pattern_matches_once"), got)
        self.assertTrue(got.get("viewport.patch_changes_source"), got)
