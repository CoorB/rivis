"""F1 (data loss): File → Open of a HAR replaced the whole live capture without a word. Now Rivis asks first: keep the
captured calls and add the file's (marked imported; the default), replace them (the dialog says how many would be lost),
or cancel. With nothing captured there is nothing to ask."""
import json
import os
import sys
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from harness import wait_for            # noqa: E402
from test_ui import PW_REASON, UiBase   # noqa: E402

ROWS = ".flow-table tbody tr:has(td.col-path)"


@unittest.skipIf(PW_REASON, PW_REASON or "")
class OpenFileAsks(UiBase):
    def P(self, sel):
        return self.page.locator("#proxy-panel-host").locator(sel)

    def har(self, tag):
        """A HAR of what is captured right now, as File → Open would be given."""
        self.panel.ok("sess_save", {"name": tag, "overwrite": True})
        self.addCleanup(lambda: self.panel.ok("sess_delete", {"name": tag}))
        har = self.panel.ok("sess_har", {"name": tag})
        har = har.get("har", har)
        return json.dumps(har).encode(), len(har["log"]["entries"])

    def clear_list(self):
        req = urllib.request.Request(self.panel.base + "/clear", data=b"", method="POST",
                                     headers={"X-XSRFToken": self.panel.xsrf})
        self.assertEqual(self.panel._do(req, 30)[0], 200)

    def choose_file(self, name, data, sent=None):
        """File → Open… with a file. mitmweb's menu occasionally swallows the first selection when it is made the instant
        the menu renders; if nothing happened (no dialog, no upload) select again."""
        for _ in range(4):
            if not self.page.locator("input[type=file]").count():      # the File menu may still be open from before
                self.page.get_by_text("File", exact=True).first.click()
            try:                                                       # a menu closing after Escape still counts once: open it again
                self.page.locator("input[type=file]").first.set_input_files(
                    files=[{"name": name, "mimeType": "application/json", "buffer": data}], timeout=5000)
            except Exception:
                continue
            try:
                wait_for(lambda: self.P("#opendlg.open").count() or (sent or []), 3, 0.1, "the file was taken")
                return
            except AssertionError:
                self.page.keyboard.press("Escape")

    def calls(self):
        return len(self.inst.flows())                                  # not the table's rows: mitmweb only renders a window of them

    def start(self, tag):
        self.clear_list()                                              # a short list: the earlier tests' calls do not pile up
        page = self.open()
        rows = page.locator(ROWS)
        wait_for(lambda: rows.count() >= 3, 10, 0.2, "rows")
        data, n_file = self.har(tag)
        for i in range(3):                                             # calls captured after the file was made: the ones a replace loses
            self.fetch("/json/small?f1extra=%s%d" % (tag, i))
        wait_for(lambda: len(self.inst.flows()) >= n_file + 3, 10, 0.2, "3 more calls")
        before = len(self.inst.flows())
        posts = []
        page.on("request", lambda r: posts.append(r.url) if r.method == "POST" and "/flows/dump" in r.url else None)
        self.choose_file(tag + ".har", data, posts)
        return page, rows, before, n_file, posts

    def test_asks_first_with_the_count_and_keep_is_the_default(self):
        page, rows, before, n_file, posts = self.start("f1ask")
        dlg = self.P("#opendlg.open")
        dlg.wait_for(timeout=10000)
        self.assertIn("%d captured call" % before, dlg.text_content())
        self.assertIn("lose", self.P("#od-replace").text_content())
        self.assertEqual(posts, [], "nothing is sent before the answer")
        self.assertEqual(self.calls(), before)
        focused = page.evaluate("document.querySelector('#proxy-panel-host').shadowRoot.activeElement && "
                                "document.querySelector('#proxy-panel-host').shadowRoot.activeElement.id")
        self.assertEqual(focused, "od-keep", "the safe choice has the focus")

    def test_keep_adds_the_files_calls_and_marks_them_imported(self):
        page, rows, before, n_file, posts = self.start("f1keep")
        self.P("#opendlg.open").wait_for(timeout=10000)
        self.P("#od-keep").click()
        wait_for(lambda: self.calls() == before + n_file, 10, 0.2, "the calls of the file added to the captured ones")
        self.assertEqual(len(posts), 1)
        self.assertIn("mode=keep", posts[0])
        self.assertFalse(self.P("#opendlg.open").count())
        wait_for(lambda: "Added %d" % n_file in self.P("#toast").text_content(), 8, 0.2, "a toast saying what was added")
        imported = [f for f in self.inst.flows() if "imported" in (f.get("comment") or "")]
        self.assertEqual(len(imported), n_file)
        self.assertEqual([e for e in self.errors if "400" not in e[1]], [])

    def test_replace_replaces_only_when_chosen(self):
        page, rows, before, n_file, posts = self.start("f1replace")
        self.P("#opendlg.open").wait_for(timeout=10000)
        self.P("#od-replace").click()
        wait_for(lambda: self.calls() == n_file, 10, 0.2, "only the file's calls left")
        self.assertIn("mode=replace", posts[0])

    def test_cancel_and_escape_open_nothing_and_lose_nothing(self):
        page, rows, before, n_file, posts = self.start("f1cancel")
        self.P("#opendlg.open").wait_for(timeout=10000)
        self.P("#od-cancel").click()
        page.wait_for_timeout(600)
        self.assertFalse(self.P("#opendlg.open").count())
        self.assertEqual((self.calls(), posts), (before, []))
        data, _ = self.har("f1cancel2")
        self.choose_file("again.har", data, posts)
        self.P("#opendlg.open").wait_for(timeout=10000)
        page.keyboard.press("Escape")
        page.wait_for_timeout(600)
        self.assertFalse(self.P("#opendlg.open").count())
        self.assertEqual((self.calls(), posts), (before, []))

    def test_nothing_captured_means_nothing_to_ask(self):
        self.clear_list()
        page = self.open()
        wait_for(lambda: self.calls() >= 3, 10, 0.2, "calls")
        data, n_file = self.har("f1empty")
        self.clear_list()
        wait_for(lambda: self.calls() == 0, 10, 0.2, "list cleared")
        posts = []
        page.on("request", lambda r: posts.append(r.url) if r.method == "POST" and "/flows/dump" in r.url else None)
        self.choose_file("f1empty.har", data, posts)
        wait_for(lambda: self.calls() == n_file, 10, 0.2, "the file loaded without a question")
        self.assertFalse(self.P("#opendlg.open").count())


if __name__ == "__main__":
    unittest.main()
