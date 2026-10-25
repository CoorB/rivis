"""Source attribution (addons/proxy_source.py): which device / app sent a call, and the panel's Source filter.

Unit part: path / argv / environment parsing with fakes (no simulator, emulator, adb or lsof is touched).
Live part: a throw-away Rivis; two different local clients (curl and this test process) must come out as two sources,
and choosing one in the panel must hide the other's calls.
"""
import json
import asyncio
import os
import plistlib
import shutil
import socket
import struct
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
import threading
from concurrent.futures import Future
from types import ModuleType
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "addons"))
import harness  # noqa: E402
from harness import LiveCase, wait_for  # noqa: E402
import proxy_source as ps  # noqa: E402

UDID_A = "EE6231F7-3AD9-4321-8509-941E7D2CEA87"
UDID_B = "26205ED2-D7AB-45BC-B201-8E41A9933E54"
GUID = "0A1B2C3D-0000-1111-2222-333344445555"


def procargs(argv, env):
    """A KERN_PROCARGS2 buffer: argc, exec path, NUL padding, argv, env."""
    body = argv[0].encode() + b"\0\0\0" + b"".join(a.encode() + b"\0" for a in argv) + \
        b"".join(("%s=%s" % kv).encode() + b"\0" for kv in env.items())
    return struct.pack("i", len(argv)) + body


class Parsing(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix=harness.run_prefix() + "src-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def sim_app(self, udid, name, display, bundle_id):
        app = os.path.join(self.root, "Library/Developer/CoreSimulator/Devices", udid,
                           "data/Containers/Bundle/Application", GUID, name + ".app")
        os.makedirs(app)
        with open(os.path.join(app, "Info.plist"), "wb") as fh:
            plistlib.dump({"CFBundleDisplayName": display, "CFBundleIdentifier": bundle_id, "CFBundleExecutable": name}, fh)
        return os.path.join(app, name)

    def test_procargs_split_argv_from_environment(self):
        argv, env = ps.parse_procargs(procargs(["/x/qemu-system-aarch64", "-avd", "Pixel_9"], {"SIMULATOR_UDID": UDID_A, "A": "b=c"}))
        self.assertEqual(argv, ["/x/qemu-system-aarch64", "-avd", "Pixel_9"])
        self.assertEqual(env, {"SIMULATOR_UDID": UDID_A, "A": "b=c"})
        self.assertEqual(ps.parse_procargs(b""), ([], {}))

    def test_two_builds_on_two_simulators_are_two_sources(self):
        names = {UDID_A: "iPhone 17", UDID_B: "iPhone 17 Pro"}
        uat = ps.classify(11, self.sim_app(UDID_A, "NEO", "NEO UAT", "com.snb.neo.uat"), [], {}, names)
        sit = ps.classify(12, self.sim_app(UDID_B, "NEO", "NEO SIT", "com.snb.neo.uat"), [], {}, names)
        self.assertEqual((uat["kind"], uat["device"], uat["app"], uat["id"]), ("ios", "iPhone 17", "NEO UAT", "com.snb.neo.uat"))
        self.assertEqual(sit["device"], "iPhone 17 Pro")
        self.assertNotEqual(uat["key"], sit["key"])
        self.assertEqual(uat["key"], "ios|iPhone 17|com.snb.neo.uat")

    def test_two_builds_on_one_simulator_differ_by_bundle_id(self):
        names = {UDID_A: "iPhone 17"}
        a = ps.classify(1, self.sim_app(UDID_A, "NEO", "NEO UAT", "com.snb.neo.uat"), [], {}, names)
        shutil.rmtree(os.path.join(self.root, "Library"))
        b = ps.classify(2, self.sim_app(UDID_A, "NEO", "NEO SIT", "com.snb.neo.sit"), [], {}, names)
        self.assertEqual({a["app"], b["app"]}, {"NEO UAT", "NEO SIT"})
        self.assertNotEqual(a["key"], b["key"])

    def test_simulator_system_processes_name_their_simulator_from_the_environment(self):
        web = ps.classify(5, "/Library/Developer/CoreSimulator/Volumes/iOS_23A/Library/Developer/CoreSimulator/Profiles/"
                             "Runtimes/iOS 26.3.simruntime/Contents/Resources/RuntimeRoot/System/Library/Frameworks/WebKit.framework/"
                             "XPCServices/com.apple.WebKit.Networking.xpc/com.apple.WebKit.Networking",
                          [], {"SIMULATOR_UDID": UDID_A.lower()}, {UDID_A: "iPhone 17"})
        self.assertEqual((web["kind"], web["device"], web["id"]), ("ios", "iPhone 17", "com.apple.WebKit.Networking"))
        self.assertIn("Safari", web["app"])
        geod = ps.classify(6, "/x/RuntimeRoot/usr/libexec/geod", [], {"SIMULATOR_UDID": UDID_A}, {UDID_A: "iPhone 17"})
        self.assertEqual((geod["device"], geod["app"]), ("iPhone 17", "geod"))

    def test_emulators_mac_apps_and_the_rivis_browser(self):
        emu = ps.classify(7, "/sdk/emulator/qemu/darwin-aarch64/qemu-system-aarch64", ["qemu-system-aarch64", "-avd", "Rivis_Test_Play"], {}, {})
        self.assertEqual((emu["kind"], emu["device"], emu["app"]), ("android", "Rivis_Test_Play", ""))
        self.assertEqual(emu["key"], "android|Rivis_Test_Play|")
        shared = ps.classify(8, "/sdk/emulator/netsimd", [], {}, {})
        self.assertEqual((shared["kind"], shared["device"]), ("android", ""))       # Attributor picks the AVD
        curl = ps.classify(9, "/usr/bin/curl", ["curl"], {}, {})
        self.assertEqual((curl["kind"], curl["app"], curl["key"]), ("mac", "curl", "mac|This Mac|curl"))
        helper = "/Applications/Google Chrome.app/Contents/Frameworks/G.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"
        self.assertEqual(ps.enclosing_app(helper), "/Applications/Google Chrome.app")
        self.assertTrue(ps.enclosing_app("/A/Xcode.app/Contents/Py/Python.app/Contents/MacOS/Python").endswith("/Python.app"))
        root = os.path.join(self.root, ".rivis", "browser")
        br = ps.classify(10, helper, [helper, "--type=utility", "--user-data-dir=" + root + "/chrome"], {}, {}, root)
        self.assertEqual((br["kind"], br["device"]), ("browser", "Rivis browser"))

    def test_names_cannot_break_the_key_or_the_filter_line(self):
        s = ps.make_source("ios", "iPhone|17\nx", "Evil|App\r", "com.x|y")
        self.assertEqual(s["key"].count("|"), 2)
        self.assertNotIn("\n", s["key"])
        self.assertEqual(ps.make_source("weird")["kind"], "unknown")

    def test_lsof_answer_skips_our_own_end_of_the_socket(self):
        seen = []

        def runner(argv, timeout=4):
            seen.append(argv)
            return "p4242\ncmitmweb\nf7\np777\nccurl\nf5\n"
        self.assertEqual(ps.lsof_owner("127.0.0.1", 50123, 4242, runner), 777)
        self.assertIn("-iTCP@127.0.0.1:50123", seen[0])
        self.assertIsNone(ps.lsof_owner("::1", 50124, 1, lambda a, timeout=4: seen.append(a) or ""))   # nothing found
        self.assertIn("-iTCP@[::1]:50124", seen[-1])

    def test_one_lsof_snapshot_maps_every_client_port_to_its_program(self):
        # R8C-01/02: one lsof per burst, not one per connection. Both ends of each pair are listed; only the client's
        # end (remote port = the proxy port) names the program; our own pid is skipped.
        out = ("p4242\ncmitmweb\nn127.0.0.1:8089->127.0.0.1:50001\nn127.0.0.1:8089->127.0.0.1:50002\n"
               "p777\nccurl\nn127.0.0.1:50001->127.0.0.1:8089\n"
               "p888\ncPython\nn[::1]:50002->[::1]:8089\nn127.0.0.1:50003->127.0.0.1:9999\n")
        seen = []
        table = ps.lsof_table(8089, 4242, lambda argv, timeout=4: seen.append(argv) or out)
        self.assertEqual(table, {50001: 777, 50002: 888})
        self.assertIn("-iTCP:8089", seen[0])

    @unittest.skipUnless(sys.platform == "darwin", "libproc is macOS")
    def test_in_process_socket_scan_calibrates_and_finds_a_known_client_without_lsof(self):
        scan = ps.SocketScan()
        self.assertIsNotNone(scan.offset, "libproc layout calibration failed")
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        c = socket.create_connection(srv.getsockname(), 2); a, _ = srv.accept()
        try:
            self.assertTrue(scan.holds(os.getpid(), c.getsockname()[1], srv.getsockname()[1]))
            self.assertFalse(scan.holds(os.getpid(), c.getsockname()[1] + 1, srv.getsockname()[1]))
            att = ps.Attributor(lambda argv, timeout=4: self.fail("lsof must not run for a known client"))
            att._seen(os.getpid())
            self.assertEqual(att.loopback_owner("127.0.0.1", c.getsockname()[1], srv.getsockname()[1], time.monotonic()), os.getpid())
        finally:
            a.close(); c.close(); srv.close()

    def test_a_burst_of_connections_shares_one_lsof_run(self):
        calls = []
        gate = threading.Event()

        def runner(argv, timeout=4):
            calls.append(argv)
            gate.wait(2)
            return "".join("p%d\nn127.0.0.1:%d->127.0.0.1:8089\n" % (1000 + i, 40000 + i) for i in range(60))
        att = ps.Attributor(runner)
        since = time.monotonic()
        with ThreadPoolExecutor(8) as pool:
            futs = [pool.submit(att.loopback_owner, "127.0.0.1", 40000 + i, 8089, since) for i in range(60)]
            time.sleep(0.2)
            gate.set()
            pids = [f.result(5) for f in futs]
        self.assertEqual(pids, [1000 + i for i in range(60)])
        self.assertEqual(len(calls), 1, "every connection of the burst should share one lsof run")
        later = time.monotonic()                 # a connection accepted after the snapshot started needs a new one
        self.assertEqual(att.loopback_owner("127.0.0.1", 40001, 8089, later), 1001)
        self.assertEqual(len(calls), 2)

    def test_android_app_only_when_one_app_talks_to_the_proxy(self):
        tcp = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
               "   0: 0F02000A:A1B2 0202000A:4850 01 00000000:00000000 00:00000000 00000000 10123 0 1\n"
               "   1: 0F02000A:A1B3 0202000A:4850 01 00000000:00000000 00:00000000 00000000 10123 0 2\n"
               "   2: 0F02000A:A1B4 0202000A:01BB 01 00000000:00000000 00:00000000 00000000 10200 0 3\n")
        self.assertEqual(ps.guest_uids(tcp, 18512), {"10123"})          # 0x4850 = 18512; the :443 socket is not ours
        self.assertEqual(ps.packages_by_uid("package:com.snb.neo.uat uid:10123\npackage:a uid:1000\npackage:b uid:1000\n"),
                         {"10123": ["com.snb.neo.uat"], "1000": ["a", "b"]})

        def runner(argv, timeout=4):
            if argv[-1] == "args=":
                return "/sdk/emulator/qemu/darwin-aarch64/qemu-system-aarch64 -avd Rivis_Test_Play -no-boot-anim\n/bin/zsh\n"
            if argv[1:] == ["devices"]:
                return "List of devices attached\nemulator-5554\tdevice\n"
            if argv[-3:] == ["emu", "avd", "name"]:
                return "Rivis_Test_Play\nOK\n"
            if "/proc/net/tcp" in argv:
                return tcp
            if argv[-3:] == ["packages", "-U"] or argv[-1] == "-U":
                return "package:com.snb.neo.uat uid:10123\n"
            return ""
        att = ps.Attributor(runner)
        import devices
        orig = devices.adb_path
        devices.adb_path = lambda: "/fake/adb"
        try:
            got = att.android(ps.make_source("android", "", pid=3), 18512)
        finally:
            devices.adb_path = orig
        self.assertEqual((got["device"], got["app"], got["key"]), ("Rivis_Test_Play", "com.snb.neo.uat", "android|Rivis_Test_Play|com.snb.neo.uat"))

    def test_summary_counts_listed_calls_and_maps_connections(self):
        class F:
            def __init__(self, src, conn, kind="http"):
                self.metadata = {"rivis_source": src} if src else {}
                self.client_conn = type("C", (), {"id": conn})()
                self.type = kind
        a, b = ps.make_source("ios", "iPhone 17", "NEO UAT", "com.snb.neo.uat"), ps.make_source("android", "Pixel_9")
        flows = [F(a, "c1"), F(a, "c1"), F(b, "c2"), F(b, "c3", "tcp"), F(None, "c4")]
        out = ps.summarize(flows, lambda f: f.type == "http")
        # R8C-03: the call with no source is offered as Unknown (last), without a per-row chip
        self.assertEqual([(r["key"], r["count"]) for r in out["list"]], [(a["key"], 2), (b["key"], 1), (ps.UNKNOWN["key"], 1)])
        self.assertEqual(out["by_conn"], {"c1": a["key"], "c2": b["key"], "c3": b["key"]})
        only_tcp = ps.summarize([F(b, "c3", "tcp")], lambda f: f.type == "http")
        self.assertEqual(only_tcp["list"], [])           # nothing the list could show: not offered in the menu

    def test_filter_clause_selects_one_app_or_one_device(self):
        self.assertEqual(ps.filter_clause(None), "")
        app = ps.filter_clause("ios|iPhone 17|com.snb.neo.uat")
        dev = ps.filter_clause("ios|iPhone 17|")
        self.assertTrue(app.startswith("~meta '^rivis_source_key: ") and app.endswith("$'"))
        self.assertFalse(dev.endswith("$'"))
        self.assertNotIn("'", ps.filter_clause("mac|This Mac|it's")[7:-1].replace("\\'", ""))


class Lifecycle(unittest.TestCase):
    def test_a_request_is_never_held_and_its_response_waits_at_most_briefly(self):
        # R8C-02: the first REQUEST of every connection waited for lsof (~33 ms each, more in a burst). Now the request
        # goes on at once and only the response waits (overlapping the server's own time), at most WAIT.
        source = ps.ProxySource()
        self.addCleanup(source.done)
        source.WAIT = 0.05
        pending = Future()
        source.conns["c"] = pending
        class Flow:
            metadata = {}
            client_conn = type("Client", (), {"id": "c"})()
        flow = Flow()
        self.assertIsNone(source.requestheaders(flow))           # synchronous: nothing to await, nothing held
        self.assertEqual(source.late["c"], [flow])
        t = time.monotonic()
        asyncio.run(source.responseheaders(flow))
        self.assertLess(time.monotonic() - t, 0.5)
        self.assertEqual(source.late["c"], [flow])               # queued once, labelled when the answer arrives
        pending.set_result(ps.UNKNOWN)

    def test_slow_lookup_timeout_does_not_cancel_attribution(self):
        source = ps.ProxySource()
        self.addCleanup(source.done)
        source.WAIT = 0.01
        pending = Future()
        source.conns["slow"] = pending
        class Flow:
            metadata = {}
            client_conn = type("Client", (), {"id": "slow"})()
        flow = Flow()
        asyncio.run(source.responseheaders(flow))
        self.assertFalse(pending.cancelled())
        self.assertIn(flow, source.late["slow"])
        pending.set_result(ps.make_source("mac", "This Mac", "curl", "curl"))

    def test_local_hook_passes_through_a_changed_stream_signature(self):
        mode_servers = ModuleType("mitmproxy.proxy.mode_servers")
        class LocalRedirectorInstance:
            async def handle_stream(self, *, stream, note):
                return stream, note
        mode_servers.LocalRedirectorInstance = LocalRedirectorInstance
        proxy = ModuleType("mitmproxy.proxy")
        proxy.mode_servers = mode_servers
        mitmproxy = ModuleType("mitmproxy")
        mitmproxy.proxy = proxy
        class Stream:
            def get_extra_info(self, key, default=None):
                return 123 if key == "pid" else default
        with patch.dict(sys.modules, {"mitmproxy": mitmproxy, "mitmproxy.proxy": proxy,
                                      "mitmproxy.proxy.mode_servers": mode_servers}):
            self.assertTrue(ps.install_local_hook())
            stream = Stream()
            self.assertEqual(asyncio.run(LocalRedirectorInstance().handle_stream(stream=stream, note="ok")),
                             (stream, "ok"))

    def test_closed_connection_keeps_pending_flow_until_source_is_known(self):
        source = ps.ProxySource()
        self.addCleanup(source.done)
        class Loop:
            def call_soon_threadsafe(self, fn, *args):
                fn(*args)
        class Flow:
            metadata = {}
        source.loop = Loop()
        flow = Flow()
        pending = Future()
        source.conns["short"] = pending
        source.late["short"] = [flow]
        pending.add_done_callback(lambda _f: source._done("short"))
        source.client_disconnected(type("Client", (), {"id": "short"})())
        pending.set_result(ps.make_source("mac", "This Mac", "curl", "curl"))
        self.assertEqual(flow.metadata.get("rivis_source_key"), "mac|This Mac|curl")
        self.assertNotIn("short", source.conns)

    def test_source_lookup_queue_is_bounded_during_a_connection_burst(self):
        source = ps.ProxySource()
        source.pool.shutdown(wait=False)
        class Pool:
            def __init__(self):
                self.jobs = []
            def submit(self, *_args):
                f = Future()
                self.jobs.append(f)
                return f
            def shutdown(self, **_kwargs):
                pass
        source.pool = Pool()
        n = source.MAX_LOOKUPS + 50
        for i in range(n):
            client = type("Client", (), {"id": str(i), "peername": ("127.0.0.1", 20000+i),
                                          "sockname": ("127.0.0.1", 8089)})()
            source.client_connected(client)
        self.assertLessEqual(len(source.pool.jobs), source.MAX_LOOKUPS)
        self.assertEqual(len(source.conns), n)
        self.assertGreater(sum(f.done() and f.result()["kind"] == "unknown" for f in source.conns.values()), 0)
        for f in source.pool.jobs:
            f.set_result(ps.UNKNOWN)
        for i in range(n):
            source.client_disconnected(type("Client", (), {"id": str(i)})())
        source.done()


class Live(LiveCase):
    """Real mitmweb: two local client programs are two sources; the panel's Source choice filters the list."""

    def raw_get(self, path):
        """A plain proxy request from THIS process (python), so it is a different program from the harness's curl."""
        s = socket.create_connection(("127.0.0.1", self.inst.proxy_port), 10)
        try:
            s.sendall(("GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n"
                       % (self.up.url(path), self.up.http_port)).encode())
            data = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
            return data
        finally:
            s.close()

    def state(self):
        return self.panel.state()

    def keys(self):
        return {r["key"]: r for r in self.state()["sources"]["list"]}

    def test_two_programs_are_two_sources_and_each_can_be_shown_alone(self):
        self.addCleanup(lambda: self.panel.ok("source", {"source": None}))
        self.assertEqual(self.fetch("/json/small?src=curl").status, 200)
        self.assertIn(b"200", self.raw_get("/json/small?src=python").split(b"\r\n", 1)[0])
        curl = "mac|This Mac|curl"
        wait_for(lambda: curl in self.keys() and any(k != curl and k.startswith("mac|This Mac|") for k in self.keys()),
                 10, 0.2, "both sources")
        other = next(k for k in self.keys() if k != curl and k.startswith("mac|This Mac|"))
        self.assertEqual(self.keys()[curl]["app"], "curl")
        conn = {f["request"]["path"]: self.state()["sources"]["by_conn"].get(f["client_conn"]["id"]) for f in self.inst.flows()}
        self.assertEqual(conn.get("/json/small?src=curl"), curl)
        self.assertEqual(conn.get("/json/small?src=python"), other)

        self.panel.ok("source", {"source": curl})
        self.assertEqual(self.state()["source"], curl)
        self.assertIn("rivis_source_key", self.panel.option("view_filter"))
        paths = {f["request"]["path"] for f in self.inst.flows()}
        self.assertIn("/json/small?src=curl", paths)
        self.assertNotIn("/json/small?src=python", paths)

        self.panel.ok("source", {"source": other})
        paths = {f["request"]["path"] for f in self.inst.flows()}
        self.assertEqual(paths & {"/json/small?src=curl", "/json/small?src=python"}, {"/json/small?src=python"})

        self.panel.ok("source", {"source": "mac|This Mac|"})          # the whole device: both programs
        paths = {f["request"]["path"] for f in self.inst.flows()}
        self.assertTrue({"/json/small?src=curl", "/json/small?src=python"} <= paths)

        self.panel.ok("source", {"source": None})
        self.assertIsNone(self.state()["source"])
        self.assertNotIn("rivis_source_key", self.panel.option("view_filter"))

    def test_a_call_that_failed_before_connecting_still_names_the_program(self):
        """QA cycle 5: a curl call refused upstream was listed under "Unknown" while the same curl's answered calls
        read "This Mac - curl". The client exits as soon as it has the error, before a queued lookup can see its
        socket, so the program is read while the connection is being accepted."""
        dead, holder = harness.reserve_dead_port()
        self.addCleanup(holder.close)
        self.assertEqual(self.fetch("/json/small?ok=1").status, 200)
        self.inst.fetch("http://127.0.0.1:%d/refused" % dead)          # curl again, answered by Rivis with an error
        curl = "mac|This Mac|curl"

        def both():
            by_conn = self.state()["sources"]["by_conn"]
            got = {f["request"]["path"]: by_conn.get(f["client_conn"]["id"]) for f in self.inst.flows()}
            return got if got.get("/json/small?ok=1") and got.get("/refused") else None

        got = wait_for(both, 15, 0.2, "both calls labelled")
        self.assertEqual(got["/refused"], curl, got)
        self.assertEqual(got["/json/small?ok=1"], curl, got)
        self.assertEqual([r for r in self.state()["sources"]["list"] if r["kind"] == "unknown"], [])

    def test_a_burst_of_new_connections_keeps_every_source(self):
        # R8C-01: 400 calls, 60 at a time, each on its own connection: only 69 got a source
        with ThreadPoolExecutor(60) as pool:
            list(pool.map(lambda i: self.raw_get("/json/small?burst=%d" % i), range(300)))
        def labelled():
            by_conn = self.state()["sources"]["by_conn"]
            flows = [f for f in self.inst.flows() if "burst=" in f["request"]["path"]]
            got = [by_conn.get(f["client_conn"]["id"]) for f in flows]
            return got if len(flows) == 300 and all(got) else None
        got = wait_for(labelled, 20, 0.3, "every burst call labelled")
        self.assertEqual(len(set(got)), 1, set(got))
        self.assertTrue(got[0].startswith("mac|This Mac|"))

    def test_a_new_connection_is_not_slowed_by_attribution(self):
        # R8C-02: one call per new connection, one after another: +33 ms median each with the add-on
        def direct():
            s = socket.create_connection(("127.0.0.1", self.up.http_port), 10)
            try:
                s.sendall(b"GET /json/small HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                while s.recv(65536):
                    pass
            finally:
                s.close()
        def timed(fn, n=60):
            out = []
            for _ in range(n):
                t = time.perf_counter(); fn(); out.append((time.perf_counter() - t) * 1000)
            return sorted(out)[n // 2]
        for _ in range(5):
            direct(); self.raw_get("/json/small?warm=1")
        added = timed(lambda: self.raw_get("/json/small?serial=1")) - timed(direct)
        self.assertLess(added, 12, "a new connection through the proxy added %.1f ms (median)" % added)

    def test_the_source_composes_with_a_host_limit_and_survives_typing_in_the_filter_box(self):
        self.addCleanup(lambda: (self.panel.ok("source", {"source": None}), self.panel.ok("focus_host", {"host": None})))
        self.fetch("/json/small?compose=1")
        self.panel.ok("source", {"source": "mac|This Mac|curl"})
        self.panel.ok("focus_host", {"host": "127.0.0.1"})
        vf = self.panel.option("view_filter")
        self.assertIn("~d '^127", vf)
        self.assertIn("rivis_source_key", vf)
        self.assertEqual(self.state()["source"], "mac|This Mac|curl")
        self.panel.set_option("view_filter", "~http")            # the user replaced the filter in mitmweb's own box
        self.assertIsNone(self.state()["source"])

    def open_file(self, name, data, query=""):
        """mitmweb's File → Open… upload (multipart field "file"), as the browser sends it."""
        import urllib.request
        boundary = "rivis%s" % os.urandom(6).hex()
        body = (("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
                 "Content-Type: application/octet-stream\r\n\r\n") % (boundary, name)).encode() + data + \
               ("\r\n--%s--\r\n" % boundary).encode()
        req = urllib.request.Request(self.panel.base + "/flows/dump" + query, data=body, method="POST",
                                     headers={"Content-Type": "multipart/form-data; boundary=" + boundary,
                                              "X-XSRFToken": self.panel.xsrf})
        return self.panel._do(req, 30)

    def test_a_rivis_har_opened_with_file_open_keeps_each_source(self):
        # R8C-04: Sessions → HAR carries _rivisSource per entry; File → Open dropped it, so the Source menu was empty
        self.addCleanup(lambda: self.panel.ok("source", {"source": None}))
        self.fetch("/json/small?harsrc=curl")
        self.raw_get("/json/small?harsrc=python")
        wait_for(lambda: sum(1 for k in self.keys() if k.startswith("mac|This Mac|")) >= 2, 10, 0.2, "two sources")
        self.panel.ok("sess_save", {"name": "har-src", "overwrite": True})
        har = self.panel.ok("sess_har", {"name": "har-src"})
        har = har.get("har", har)
        self.assertTrue(all("_rivisSource" in e for e in har["log"]["entries"]))
        code, raw = self.open_file("har-src.har", json.dumps(har).encode())
        self.assertEqual(code, 200, raw[:300])
        def reopened():
            flows = [f for f in self.inst.flows() if "harsrc=" in f["request"]["path"]]
            by_conn = self.state()["sources"]["by_conn"]
            keys = {f["request"]["path"]: by_conn.get(f["client_conn"]["id"]) for f in flows}
            return keys if len(flows) >= 2 and all(keys.values()) else None
        keys = wait_for(reopened, 10, 0.3, "HAR calls reopened with their sources")
        self.assertEqual(keys["/json/small?harsrc=curl"], "mac|This Mac|curl")
        self.assertNotEqual(keys["/json/small?harsrc=python"], "mac|This Mac|curl")
        self.panel.ok("sess_delete", {"name": "har-src"})

    def clear_calls(self):
        import urllib.request
        req = urllib.request.Request(self.panel.base + "/clear", data=b"", method="POST",
                                     headers={"X-XSRFToken": self.panel.xsrf})
        self.assertEqual(self.panel._do(req, 30)[0], 200)
        wait_for(lambda: not self.inst.flows(), 10, 0.2, "list cleared")

    def har_of_two_calls(self, tag):
        self.fetch("/json/small?%s=1" % tag)
        self.fetch("/json/small?%s=2" % tag)
        wait_for(lambda: sum(1 for f in self.inst.flows() if tag + "=" in f["request"]["path"]) >= 2, 10, 0.2, "2 calls")
        self.panel.ok("sess_save", {"name": tag, "overwrite": True})
        self.addCleanup(lambda: self.panel.ok("sess_delete", {"name": tag}))
        har = self.panel.ok("sess_har", {"name": tag})
        har = har.get("har", har)
        return json.dumps(har).encode(), len(har["log"]["entries"])

    def test_file_open_without_a_choice_keeps_the_captured_calls_and_adds_the_file(self):
        # F1 (data loss): File → Open replaced the whole live capture, silently. The safe default keeps it and adds the
        # file's calls, marked as imported, with fresh ids so a dump of this very capture does not collide with itself.
        self.clear_calls()                                             # an earlier test's thousands of calls would hit the retention cap
        data, n_file = self.har_of_two_calls("f1keep")
        for i in range(3):
            self.fetch("/json/small?f1live=%d" % i)
        wait_for(lambda: sum(1 for f in self.inst.flows() if "f1live=" in f["request"]["path"]) >= 3, 10, 0.2, "3 live calls")
        before = self.inst.flows()
        code, raw = self.open_file("two.har", data)
        self.assertEqual(code, 200, raw[:300])
        wait_for(lambda: len(self.inst.flows()) >= len(before) + n_file, 10, 0.2, "the file's calls added")
        after = self.inst.flows()
        self.assertEqual(len(after), len(before) + n_file, "nothing lost, nothing duplicated beyond the file's own calls")
        ids = [f["id"] for f in after]
        self.assertEqual(len(set(ids)), len(ids))
        self.assertTrue({f["id"] for f in before} <= set(ids), "every captured call is still there")
        added = [f for f in after if f["id"] not in {b["id"] for b in before}]
        self.assertTrue(all("imported" in (f.get("comment") or "") for f in added), [f.get("comment") for f in added])
        self.assertEqual(json.loads(raw)["added"], n_file)               # the answer says how many calls were added
        # a native dump of the whole capture, opened again, adds copies instead of overwriting by id
        code, dump = self.panel.get("/flows/dump")
        self.assertEqual(code, 200)
        now = len(self.inst.flows())
        code, raw = self.open_file("calls.mitm", dump)
        self.assertEqual(code, 200, raw[:300])
        wait_for(lambda: len(self.inst.flows()) >= now * 2, 10, 0.2, "the dump's calls added next to the originals")
        flows = self.inst.flows()                                      # (>=: a late call from an earlier test may land too)
        self.assertEqual(len({f["id"] for f in flows}), len(flows))

    def test_file_open_with_replace_replaces_the_list_like_before(self):
        data, n_file = self.har_of_two_calls("f1rep")
        for i in range(3):
            self.fetch("/json/small?f1gone=%d" % i)
        wait_for(lambda: sum(1 for f in self.inst.flows() if "f1gone=" in f["request"]["path"]) >= 3, 10, 0.2, "3 live calls")
        code, raw = self.open_file("two.har", data, "?mode=replace")
        self.assertEqual(code, 200, raw[:300])
        wait_for(lambda: len(self.inst.flows()) == n_file, 10, 0.2, "only the file's calls left")
        self.assertFalse([f for f in self.inst.flows() if "f1gone=" in f["request"]["path"]])

    def test_file_open_into_an_empty_list_just_loads_the_file(self):
        data, n_file = self.har_of_two_calls("f1empty")
        self.clear_calls()
        code, raw = self.open_file("two.har", data)
        self.assertEqual(code, 200, raw[:300])
        wait_for(lambda: len(self.inst.flows()) == n_file, 10, 0.2, "the file's calls")
        self.assertFalse(any("imported" in (f.get("comment") or "") for f in self.inst.flows()), "nothing was kept, so nothing is 'imported'")

    def test_a_file_that_cannot_be_read_keeps_the_calls_and_says_why(self):
        # R9-05: a truncated HAR made mitmweb clear the list, then fail with a bare 500 — every captured call was lost
        for i in range(3):
            self.fetch("/json/small?keepme=%d" % i)
        wait_for(lambda: sum(1 for f in self.inst.flows() if "keepme=" in f["request"]["path"]) >= 3, 10, 0.2, "3 calls")
        before = len(self.inst.flows())
        for name, data, kind in (("broken.har", b'{"log": {"entries": [', "HAR"),
                                 ("junk.bin", b"this is not a flow file at all\n", "flow file")):
            code, raw = self.open_file(name, data)
            self.assertEqual(code, 400, raw[:300])
            text = raw.decode("utf-8", "replace")
            self.assertIn("Could not open " + name, text)
            self.assertIn(kind, text)
            self.assertIn("current calls were kept", text)
            self.assertEqual(len(self.inst.flows()), before, "the list must not be cleared by a file that cannot be read")
        # a native mitmproxy dump still opens (F1: next to the calls already captured)
        code, dump = self.panel.get("/flows/dump")
        self.assertEqual(code, 200)
        code, raw = self.open_file("calls.mitm", dump)
        self.assertEqual(code, 200, raw[:300])
        wait_for(lambda: sum(1 for f in self.inst.flows() if "keepme=" in f["request"]["path"]) >= 3, 10, 0.2,
                 "native dump reopened")

    def test_calls_without_a_source_are_listed_and_selectable_as_unknown(self):
        # R8C-03: a composed call had no source and vanished under any Source choice, with no Unknown entry
        self.addCleanup(lambda: self.panel.ok("source", {"source": None}))
        self.panel.ok("compose_send", {"spec": {"method": "GET", "url": self.up.url("/json/small?composed=1")}})
        wait_for(lambda: any("composed=1" in f["request"]["path"] for f in self.inst.flows()), 10, 0.2, "composed call")
        rows = wait_for(lambda: (lambda r: r if "unknown||" in r else None)(self.keys()), 10, 0.2, "Unknown entry")
        self.assertGreaterEqual(rows["unknown||"]["count"], 1)
        self.panel.ok("source", {"source": "unknown||"})
        paths = {f["request"]["path"] for f in self.inst.flows()}
        self.assertIn("/json/small?composed=1", paths)
        self.fetch("/json/small?src=curl-after-unknown")
        self.assertNotIn("/json/small?src=curl-after-unknown", {f["request"]["path"] for f in self.inst.flows()})

    def test_source_counts_follow_the_show_project_menu(self):
        # R8C-06: under Show → NEO only (no NEO calls here) the Source menu still offered curl (29), Python (135)
        self.addCleanup(lambda: self.panel.ok("view", {"project": "default", "project_only": False, "show_dns": False}))
        self.fetch("/json/small?src=counts")
        wait_for(lambda: "mac|This Mac|curl" in self.keys(), 10, 0.2, "curl source")
        self.panel.ok("view", {"project": "neo", "project_only": True, "show_dns": False})
        self.assertEqual(self.state()["sources"]["list"], [])
        self.panel.ok("view", {"project": "default", "project_only": False, "show_dns": False})
        self.assertIn("mac|This Mac|curl", self.keys())

    def test_status_names_the_chosen_source_in_words(self):
        # R8C-08: `rivis status` printed the internal key "mac|This Mac|curl"
        self.addCleanup(lambda: self.panel.ok("source", {"source": None}))
        self.fetch("/json/small?src=status")
        wait_for(lambda: "mac|This Mac|curl" in self.keys(), 10, 0.2, "curl source")
        self.panel.ok("source", {"source": "mac|This Mac|curl"})
        env = self.suite.env(self.inst.home, extra={"RIVIS_PORT": str(self.inst.proxy_port), "RIVIS_WEB_PORT": str(self.inst.web_port)})
        out = self.suite.rivis("status", home=self.inst.home, env=env).stdout
        self.assertIn("list shows only: curl on This Mac", out)
        self.assertNotIn("mac|This Mac", out)

    def test_bad_selections_are_refused(self):
        for bad in ("no-separators", "a|b\n|c", 7, "x" * 500 + "||"):    # each would become part of a list filter
            self.assertEqual(self.panel.post("source", {"source": bad})[0], 400, repr(bad))
        self.assertIsNone(self.state()["source"])

    def test_a_saved_session_keeps_the_source(self):
        self.fetch("/json/small?saved=1")
        wait_for(lambda: "mac|This Mac|curl" in self.keys(), 10, 0.2, "curl source")
        name = "src-%d" % int(time.time())
        self.panel.ok("sess_save", {"name": name})
        self.addCleanup(lambda: self.panel.ok("sess_delete", {"name": name}))
        har = self.panel.ok("sess_har", {"name": name})["har"]["log"]["entries"]
        tagged = [e.get("_rivisSource") for e in har if "saved=1" in e["request"]["url"]]
        self.assertEqual(tagged and tagged[0]["app"], "curl")
        self.panel.ok("sess_load", {"name": name, "replace": True})
        self.assertIn("mac|This Mac|curl", self.keys())

    def test_visible_session_save_combines_source_and_search_filters(self):
        self.addCleanup(lambda: self.panel.ok("source", {"source": None}))
        self.fetch("/json/small?source-save=keep")
        self.fetch("/json/small?source-save=other-curl")
        self.raw_get("/json/small?source-save=other-program")
        wait_for(lambda: "mac|This Mac|curl" in self.keys(), 10, 0.2, "curl source")
        self.panel.ok("source", {"source": "mac|This Mac|curl"})
        name = "source-visible-%d" % int(time.time())
        self.addCleanup(lambda: self.panel.ok("sess_delete", {"name": name}))
        saved = self.panel.ok("sess_save", {"name": name, "visible_only": True,
                                            "search_filter": "~u 'source-save=keep'"})
        self.assertEqual(saved["count"], 1)
        har = self.panel.ok("sess_har", {"name": name})["har"]["log"]["entries"]
        self.assertEqual(len(har), 1)
        self.assertIn("source-save=keep", har[0]["request"]["url"])


if __name__ == "__main__":
    unittest.main()
