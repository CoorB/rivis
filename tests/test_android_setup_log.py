"""addons/android_setup_log.py mirrors `rivis android` output into a diagnostic log, and every line of that command
reaches the terminal through it. The one-click CA setup asks for consent with a prompt that ends without a newline and
reads the answer from /dev/tty, so the logger has to pass bytes on as they arrive: holding a partial line back left
`rivis android on` on a Google Play emulator waiting forever on a question that was never printed (0.9.10)."""
import os
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness

SCRIPT = os.environ.get("RIVIS_SETUP_LOG", os.path.join(harness.REPO, "addons", "android_setup_log.py"))


class SetupLog(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="rivis-setuplog-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.log = os.path.join(self.root, "logs", "android-setup.log")

    def run_logger(self):
        return subprocess.Popen([sys.executable, "-I", SCRIPT, self.log],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def test_a_prompt_without_a_newline_reaches_the_terminal(self):
        p = self.run_logger()
        self.addCleanup(p.kill)
        p.stdin.write(b"restarting the emulator\n")
        p.stdin.write(b"Continue? [y/N] ")
        p.stdin.flush()
        got = b""
        deadline = time.time() + 10
        while b"Continue?" not in got and time.time() < deadline:
            ready, _, _ = select.select([p.stdout], [], [], max(0, deadline - time.time()))
            if not ready:
                break
            chunk = os.read(p.stdout.fileno(), 4096)
            if not chunk:
                break
            got += chunk
        self.assertIn(b"Continue? [y/N] ", got,
                      "the consent prompt never reached the terminal, so the setup waits on an unseen question")
        p.stdin.close()
        p.wait(timeout=10)

    def test_a_credential_after_its_scheme_word_is_redacted(self):
        # Redacting only the word after "Authorization:" takes the scheme and leaves the credential itself.
        p = self.run_logger()
        self.addCleanup(p.kill)
        p.communicate(b"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.verysecret\n"
                      b"proxy-authorization: Basic dXNlcjpwYXNz\n", timeout=20)
        with open(self.log, encoding="utf-8") as fh:
            written = fh.read()
        self.assertNotIn("verysecret", written)
        self.assertNotIn("dXNlcjpwYXNz", written)
        self.assertIn("Authorization: [REDACTED]", written)

    def test_whole_lines_still_reach_the_log_and_secrets_stay_out(self):
        p = self.run_logger()
        self.addCleanup(p.kill)
        out, _ = p.communicate(b"proxy set\nAuthorization: abcdef123\nContinue? [y/N] ", timeout=20)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(out, b"proxy set\nAuthorization: abcdef123\nContinue? [y/N] ")
        with open(self.log, encoding="utf-8") as fh:
            written = fh.read()
        self.assertIn("proxy set", written)
        self.assertIn("Authorization: [REDACTED]", written)
        self.assertNotIn("abcdef123", written)
        self.assertIn("Continue? [y/N] ", written)
        self.assertEqual(oct(os.stat(self.log).st_mode & 0o777), oct(0o600))


if __name__ == "__main__":
    unittest.main()
