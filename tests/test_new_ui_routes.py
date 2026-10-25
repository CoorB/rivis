"""UI overhaul phase 1: the new main window at /rivis/ (addons/ui). Served by proxy_panel.py next to mitmweb's page,
behind the same login, only its own files, with a strict content security policy; `rivis ui` opens it."""
import http.cookiejar
import os
import sys
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import LiveCase


def opener():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                       urllib.request.ProxyHandler({}))


def get(op, url):
    try:
        with op.open(url, timeout=10) as r:
            return r.status, dict(r.headers), r.read(), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(), url


class NewUiRoutes(LiveCase):
    def base(self):
        return "http://127.0.0.1:%d" % self.inst.web_port

    def test_needs_the_same_login_as_the_classic_view(self):
        for path in ("/rivis/", "/rivis/app.js", "/rivis/app.css"):
            self.assertEqual(get(opener(), self.base() + path)[0], 403, path)

    def test_serves_its_three_files_and_nothing_else(self):
        op = opener()
        self.assertEqual(get(op, self.base() + "/?token=" + self.inst.password)[0], 200)
        status, headers, body, _ = get(op, self.base() + "/rivis/")
        self.assertEqual(status, 200)
        self.assertIn(b'<div id="rv-app"', body)
        csp = headers.get("Content-Security-Policy", "")
        self.assertIn("script-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("unsafe-eval", csp)
        self.assertIn("ws://127.0.0.1:%d" % self.inst.web_port, csp)
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        status, headers, body, _ = get(op, self.base() + "/rivis/app.js")
        self.assertEqual((status, headers.get("Content-Type")), (200, "application/javascript"))
        self.assertIn(b"flows/updateFilter", body)
        self.assertEqual(get(op, self.base() + "/rivis/app.css")[1].get("Content-Type"), "text/css")
        for path in ("/rivis/index.html", "/rivis/../proxy_panel.py", "/rivis/%2e%2e/proxy_panel.py", "/rivis/ui/app.js", "/rivis/app.js.map"):
            self.assertIn(get(op, self.base() + path)[0], (403, 404), path)
        status, _, _, final = get(op, self.base() + "/rivis")
        self.assertEqual((status, final), (200, self.base() + "/rivis/"))

    def test_the_one_time_link_can_land_on_the_new_window(self):
        op = opener()
        with open(os.path.join(self.inst.home, ".rivis", "web-bootstrap-%d" % self.inst.web_port), "w") as fh:
            fh.write("ab" * 16)
        status, _, body, final = get(op, self.base() + "/proxy/bootstrap/" + "ab" * 16 + "?next=rivis")
        self.assertEqual((status, final), (200, self.base() + "/rivis/"))
        self.assertIn(b'<div id="rv-app"', body)
        with open(os.path.join(self.inst.home, ".rivis", "web-bootstrap-%d" % self.inst.web_port), "w") as fh:
            fh.write("cd" * 16)
        status, _, _, final = get(opener(), self.base() + "/proxy/bootstrap/" + "cd" * 16 + "?next=https://evil.example")
        self.assertEqual(final, self.base() + "/", "only the two known places, never an address from the link")

    def test_rivis_ui_new_opens_the_new_window(self):
        before = self.suite.shim_log("open.log")
        cp = self.suite.rivis("ui", "--new", home=self.inst.home, env=self.inst.env)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        opened = self.suite.shim_log("open.log")[len(before):].strip().splitlines()[-1]
        self.assertTrue(opened.endswith("?next=rivis"), opened)
        status, _, body, final = get(opener(), opened)
        self.assertEqual((status, final), (200, self.base() + "/rivis/"))
        self.assertNotEqual(self.suite.rivis("ui", "--old", home=self.inst.home, env=self.inst.env).returncode, 0)

    def test_plain_ui_opens_the_new_window_and_classic_is_explicit(self):
        for flags, suffix, landing in [((), "?next=rivis", "/rivis/"), (("--classic",), "", "/")]:
            before = self.suite.shim_log("open.log")
            cp = self.suite.rivis("ui", *flags, home=self.inst.home, env=self.inst.env)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            opened = self.suite.shim_log("open.log")[len(before):].strip().splitlines()[-1]
            self.assertTrue(opened.endswith(suffix), opened)
            self.assertEqual(get(opener(), opened)[3], self.base() + landing)


if __name__ == "__main__":
    harness.main()
