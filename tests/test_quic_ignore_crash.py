"""Ignored QUIC (HTTP/3) must not flood the log with "mitmproxy has crashed!".

Live iOS Simulator capture hits this when Rivis passes a host through undecrypted
(tls_clienthello ignore_connection): mitmproxy 12.2.3's ClientQuicLayer swap delivers
OpenConnection / UdpStartHook replies into UDPLayer.start, which asserts. Local capture
cannot run in the suite; reverse:quic:// with a real ClientHello and ignore_connection
reaches the same swap.

  /usr/bin/python3 -m pytest tests/test_quic_ignore_crash.py -x -q
"""
import os
import socket
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness

FIXTURE = os.path.join(harness.TESTS, "fixtures", "quic-clienthello.bin")
ADDONS = os.path.join(harness.REPO, "addons")


def _free_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _read_datagrams(path):
    data = open(path, "rb").read()
    out, i = [], 0
    while i + 4 <= len(data):
        n = int.from_bytes(data[i:i + 4], "big")
        i += 4
        out.append(data[i:i + n])
        i += n
    return out


# Upstream answers every datagram with this marker so the client can prove the
# patched ignore→UDPLayer path still relays (not only "no crash" / log line).
RELAY_MARKER = b"RIVIS-QUIC-RELAY-MARKER"


def _run_ignored_quic(extra_scripts, home):
    """reverse:quic + ignore_connection + fixture ClientHello.

    Returns (mitmdump_log_text, client_received_upstream_marker).
    """
    up = _free_udp()
    proxy = _free_udp()
    conf = os.path.join(home, "ca")
    os.makedirs(conf, exist_ok=True)
    ignore = os.path.join(home, "ignore.py")
    ready_addon = os.path.join(home, "ready.py")
    ready_file = os.path.join(home, "ready")
    with open(ignore, "w") as fh:
        fh.write(
            "from mitmproxy import tls\n"
            "def tls_clienthello(data: tls.ClientHelloData) -> None:\n"
            "    data.ignore_connection = True\n"
        )
    with open(ready_addon, "w") as fh:
        fh.write(
            "import os\n"
            "from mitmproxy import ctx\n"
            "READY = os.environ['QUIC_READY_FILE']\n"
            "class Ready:\n"
            "    def running(self):\n"
            "        open(READY, 'w').write('1')\n"
            "addons = [Ready()]\n"
        )

    up_proc = subprocess.Popen(
        [sys.executable, "-c",
         "import socket,time,sys\n"
         "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',int(sys.argv[1])));s.settimeout(0.3)\n"
         "m=sys.argv[2].encode(); end=time.time()+60\n"
         "while time.time()<end:\n"
         "  try:\n"
         "    d,a=s.recvfrom(65535);s.sendto(m,a)\n"
         "  except socket.timeout:\n"
         "    pass\n",
         str(up), RELAY_MARKER.decode()],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    scripts = []
    for s in extra_scripts:
        scripts.extend(["-s", s])
    scripts.extend(["-s", ignore, "-s", ready_addon])
    logpath = os.path.join(home, "mitm.log")
    logfh = open(logpath, "wb")
    env = dict(os.environ, QUIC_READY_FILE=ready_file)
    cmd = [harness.REAL_MITMDUMP, "--listen-host", "127.0.0.1", "-p", str(proxy),
           "--mode", "reverse:quic://127.0.0.1:%d" % up, "--set", "confdir=" + conf] + scripts
    proc = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL,
                            stdout=logfh, stderr=subprocess.STDOUT)
    relayed = False
    try:
        deadline = time.time() + 15
        while time.time() < deadline and not os.path.isfile(ready_file):
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        assert os.path.isfile(ready_file), "mitmdump never became ready; log=%r" % (
            open(logpath, "rb").read()[-1500:].decode("utf-8", "replace"),)

        dgrams = _read_datagrams(FIXTURE)
        assert dgrams, "missing ClientHello fixture %s" % FIXTURE
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.4)
        sock.bind(("127.0.0.1", 0))
        try:
            for d in dgrams:
                sock.sendto(d, ("127.0.0.1", proxy))
            time.sleep(0.05)
            sock.sendto(b"\x00" * 120, ("127.0.0.1", proxy))
            end = time.time() + 2.0
            while time.time() < end:
                try:
                    data, _ = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                if RELAY_MARKER in data:
                    relayed = True
                    break
        finally:
            sock.close()
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(3)
        up_proc.kill()
        try:
            up_proc.wait(3)
        except Exception:
            pass
        logfh.flush()
        logfh.close()
    return open(logpath, "rb").read().decode("utf-8", "replace"), relayed


class QuicIgnoreCrash(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(FIXTURE):
            raise unittest.SkipTest("quic ClientHello fixture missing")
        if not harness.REAL_MITMDUMP:
            raise unittest.SkipTest("mitmdump not on PATH")

    def test_01_without_rivis_fix_mitmproxy_crashes_on_ignored_quic(self):
        """Fail-before: bare mitmdump + ignore_connection hits UDPLayer.start AssertionError."""
        suite = harness.Suite.get()
        home = suite.new_home("quic-crash-bare")
        log, relayed = _run_ignored_quic([], home)
        self.assertIn("mitmproxy has crashed", log,
                      "expected the 12.2.3 QUIC ignore swap crash without Rivis patches;\n--- log ---\n%s" % log[-2000:])
        self.assertIn("UDPLayer.start", log)
        self.assertFalse(relayed,
                         "without the fix, ignored QUIC must not look like a working pass-through")

    def test_02_with_rivis_fix_ignored_quic_does_not_crash(self):
        """proxy_quic stops the crash and still relays upstream datagrams to the client."""
        suite = harness.Suite.get()
        home = suite.new_home("quic-crash-fixed")
        log, relayed = _run_ignored_quic([os.path.join(ADDONS, "proxy_quic.py")], home)
        self.assertNotIn("mitmproxy has crashed", log, log[-2000:])
        self.assertNotIn("Unexpected event type at UDPLayer", log, log[-2000:])
        self.assertIn("passing HTTP/3 to", log, "expected one plain pass-through line;\n%s" % log[-1500:])
        self.assertTrue(relayed,
                        "pass-through must deliver upstream bytes to the client, not only avoid the assert;\n%s"
                        % log[-1500:])


if __name__ == "__main__":
    unittest.main()
