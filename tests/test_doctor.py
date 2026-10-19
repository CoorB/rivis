"""Unit tests for doctor's pure classifiers and state summary (stdlib only, no mitmproxy)."""
import os
import tempfile
import unittest
from unittest import mock

import _paths  # noqa: F401
import doctor
from doctor import (
    Report, _cert_dates, _trusted_panel_listener, check_ca, check_network, check_running,
    classify_network_failure, classify_system_proxy, executable_is_safe, is_loopback,
    parse_lsof_listener, parse_netstat_listener, parse_networksetup_proxy, summarize_state, WARN,
)


class Lsof(unittest.TestCase):
    SAMPLE = (
        "COMMAND   PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
        "mitmweb 80112 macm92    7u  IPv4 0x3f2920d762f904cf      0t0  TCP 127.0.0.1:8083 (LISTEN)\n"
    )

    def test_parses_owner(self):
        rows = parse_lsof_listener(self.SAMPLE)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["command"], "mitmweb")
        self.assertEqual(rows[0]["pid"], "80112")
        self.assertEqual(rows[0]["name"], "127.0.0.1:8083")

    def test_empty(self):
        self.assertEqual(parse_lsof_listener(""), [])
        self.assertEqual(parse_lsof_listener("COMMAND PID USER FD TYPE DEV SIZE NODE NAME"), [])

    def test_proxyman(self):
        out = ("COMMAND  PID USER FD TYPE DEV OFF NODE NAME\n"
               "Proxyman 42 me 10u IPv4 0x1 0t0 TCP *:8080 (LISTEN)\n")
        rows = parse_lsof_listener(out)
        self.assertEqual(rows[0]["command"], "Proxyman")


class AndroidEmulator(unittest.TestCase):
    def check(self, proxy):
        def adb_run(argv, **_):
            cmd = " ".join(argv[1:])
            if cmd == "devices": return 0, "List of devices attached\nemulator-5554\tdevice\n", ""
            if "settings get global http_proxy" in cmd: return 0, proxy, ""
            if "pm list packages com.android.vending" in cmd: return 0, "package:com.android.vending", ""
            if "shell id -u" in cmd: return 0, "2000", ""
            return 0, "", ""
        rep = Report()
        adb = os.path.join(os.path.dirname(__file__), "fakes", "emulator_adb.py")
        with mock.patch("doctor.run", side_effect=adb_run), mock.patch("doctor.port_owner", return_value=[]) as owner:
            doctor.check_android(rep, adb)
        return rep, owner

    def test_dead_emulator_proxy_is_an_error(self):
        # B-02: an emulator with this dead proxy has no network, even if the Mac port is free.
        rep, owner = self.check("10.0.2.2:50141")
        owner.assert_called_once_with(50141)
        self.assertTrue(any(level == "error" and "nothing listens" in title for _, level, title, _, _ in rep.items), rep.items)
        self.assertFalse(any(level == "ok" and "http_proxy" in title for _, level, title, _, _ in rep.items))

    def test_a_recorded_install_is_confirmed_on_a_play_image(self):
        # R5B-02: no root to read the store, but `android on` verified and recorded this CA for this AVD
        with mock.patch("devices.ca_sha256", return_value="AB" * 32), mock.patch("os.path.isfile", return_value=True), \
                mock.patch("devices.avd_name", return_value="Rivis_Test_Play"), \
                mock.patch("devices._android_records", return_value={"Rivis_Test_Play": "AB" * 32}):
            rep = self.check_with_confdir(":0")
        self.assertTrue(any(level == "ok" and "fingerprint matches" in title for _, level, title, _, _ in rep.items), rep.items)
        self.assertFalse(any("no adb root" in title for _, _, title, _, _ in rep.items))

    def check_with_confdir(self, proxy):
        def adb_run(argv, **_):
            cmd = " ".join(argv[1:])
            if cmd == "devices": return 0, "List of devices attached\nemulator-5554\tdevice\n", ""
            if "settings get global http_proxy" in cmd: return 0, proxy, ""
            if "pm list packages com.android.vending" in cmd: return 0, "package:com.android.vending", ""
            if "shell id -u" in cmd: return 0, "2000", ""
            return 0, "", ""
        rep = Report()
        adb = os.path.join(os.path.dirname(__file__), "fakes", "emulator_adb.py")
        with mock.patch("doctor.run", side_effect=adb_run), mock.patch("doctor.port_owner", return_value=[]):
            doctor.check_android(rep, adb, confdir="/nonexistent-confdir")
        return rep

    def test_google_play_advice_names_android_on(self):
        # B-05: the one-restart Play-image CA path replaced the old manual-only guidance.
        rep, _ = self.check(":0")
        advice = " ".join(detail + " " + fix for _, _, title, detail, fix in rep.items if "Google Play image" in title)
        self.assertIn("android on", advice)
        self.assertNotIn("manual Settings step", advice)


class Netstat(unittest.TestCase):
    def test_parses_only_the_requested_windows_listener(self):
        sample = ("  TCP    127.0.0.1:18083    0.0.0.0:0    LISTENING    42\n"
                  "  TCP    [::1]:18083        [::]:0       LISTENING    43\n"
                  "  TCP    127.0.0.1:18080    0.0.0.0:0    LISTENING    44\n")
        self.assertEqual([r["pid"] for r in parse_netstat_listener(sample, 18083)], ["42", "43"])

    def test_windows_port_owner_adds_the_process_name(self):
        netstat = "TCP 127.0.0.1:18083 0.0.0.0:0 LISTENING 42\n"
        tasklist = '"mitmweb.exe","42","Console","1","12,000 K"\n'
        with mock.patch("doctor.WIN", True), mock.patch("doctor.run", side_effect=[(0, netstat, ""), (0, tasklist, "")]):
            self.assertEqual(doctor.port_owner(18083)[0]["command"], "mitmweb.exe")


class NetworksetupParser(unittest.TestCase):
    def test_enabled_proxy(self):
        block = "Enabled: Yes\nServer: 127.0.0.1\nPort: 9090\nAuthenticated Proxy Enabled: 0"
        self.assertEqual(parse_networksetup_proxy(block),
                         {"enabled": True, "server": "127.0.0.1", "port": "9090"})

    def test_disabled(self):
        block = "Enabled: No\nServer:\nPort: 0"
        got = parse_networksetup_proxy(block)
        self.assertFalse(got["enabled"])

    def test_blank(self):
        self.assertEqual(parse_networksetup_proxy(""),
                         {"enabled": False, "server": "", "port": ""})


class SystemProxyClass(unittest.TestCase):
    def test_stale_localhost(self):
        self.assertEqual(classify_system_proxy("127.0.0.1", "9090", False), "local_stale")

    def test_active_localhost(self):
        self.assertEqual(classify_system_proxy("localhost", "9090", True), "local_active")

    def test_corporate(self):
        self.assertEqual(classify_system_proxy("proxy.corp.example", "8080", False), "corporate")

    def test_loopback_helper(self):
        self.assertTrue(is_loopback("127.0.0.1"))
        self.assertTrue(is_loopback("::1"))
        self.assertFalse(is_loopback("10.0.0.1"))


class CertificateParser(unittest.TestCase):
    @staticmethod
    def tlv(tag, value):
        if len(value) < 128:
            length = bytes([len(value)])
        else:
            raw = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
            length = bytes([0x80 | len(raw)]) + raw
        return bytes([tag]) + length + value

    def test_reads_utc_and_generalized_validity_without_private_ssl_api(self):
        validity = self.tlv(0x30, self.tlv(0x17, b"491231235959Z") + self.tlv(0x18, b"20500101000000Z"))
        tbs = self.tlv(0x30, self.tlv(0x02, b"\x01") + self.tlv(0x30, b"") + self.tlv(0x30, b"") + validity)
        der = self.tlv(0x30, tbs)
        with tempfile.NamedTemporaryFile() as fh:
            fh.write(der); fh.flush()
            before, after = _cert_dates(fh.name)
        self.assertEqual(before, 2524607999)  # 2049-12-31 23:59:59 UTC
        self.assertEqual(after, 2524608000)   # 2050-01-01 00:00:00 UTC

    def test_corrupt_certificate_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "mitmproxy-ca-cert.pem")
            with open(path, "wb") as fh:
                fh.write(b"not a certificate")
            with self.assertRaises(ValueError):
                _cert_dates(path)
            rep = Report()
            check_ca(rep, directory)
            self.assertTrue(any(level == "error" and "corrupt" in title
                                for _, level, title, _, _ in rep.items))
            self.assertFalse(any(level == "ok" for _, level, _, _, _ in rep.items))


class ExecutableTrust(unittest.TestCase):
    def test_group_or_world_writable_executable_is_refused(self):
        with tempfile.NamedTemporaryFile() as fh:
            os.chmod(fh.name, 0o755)
            self.assertTrue(executable_is_safe(fh.name)[0])
            os.chmod(fh.name, 0o775)
            safe, reason = executable_is_safe(fh.name)
            self.assertFalse(safe)
            self.assertIn("writable", reason)


class RunningInstanceTrust(unittest.TestCase):
    def test_listener_must_be_loopback_ours_and_use_the_same_rules(self):
        owner = [{"command": "mitmweb", "pid": "42", "name": "127.0.0.1:18083"}]
        command = "501 /opt/mitmweb -s %s --set proxy_rules_file=%s\n" % (
            os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "addons", "proxy_panel.py")),
            os.path.realpath("/tmp/rules.json"))
        with mock.patch("doctor.run", return_value=(0, command, "")), mock.patch("doctor.os.getuid", return_value=501):
            self.assertTrue(_trusted_panel_listener(owner, "/tmp/rules.json")[0])
            self.assertFalse(_trusted_panel_listener(owner, "/tmp/other.json")[0])
            remote = [dict(owner[0], name="*:18083")]
            self.assertFalse(_trusted_panel_listener(remote, "/tmp/rules.json")[0])

    def test_windows_listener_command_line_is_verified_without_unix_ps(self):
        owner = [{"command": "mitmweb.exe", "pid": "42", "name": "127.0.0.1:18083"}]
        rules = os.path.abspath("C:/state/rules.json")
        command = "mitmweb.exe -s %s --set proxy_rules_file=%s" % (
            os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "addons", "proxy_panel.py")), rules)
        with mock.patch("doctor.WIN", True), mock.patch("doctor.run", return_value=(0, command, "")) as run:
            self.assertTrue(_trusted_panel_listener(owner, rules)[0])
            self.assertEqual(run.call_args[0][0][0], "powershell.exe")

    def test_different_project_is_a_warning_and_token_is_not_read(self):
        rep = Report()
        with mock.patch("doctor.port_owner", return_value=[{"command": "mitmweb", "pid": "42", "name": "127.0.0.1:18083"}]), \
             mock.patch("doctor._trusted_panel_listener", return_value=(False, "listener serves a different rules file")), \
             mock.patch("doctor.open", side_effect=AssertionError("must not read token"), create=True):
            check_running(rep, 18083, "/tmp/other.json")
        self.assertTrue(any(level == "warn" and "project" in title for _, level, title, _, _ in rep.items))
        self.assertFalse(any(level == "error" for _, level, _, _, _ in rep.items))

    def test_unreadable_token_is_reported_and_special_characters_are_url_encoded(self):
        class Reply:
            def __init__(self, body=b"x"):
                self.body = body
            def read(self, _n=None):
                return self.body
        class Opener:
            def __init__(self):
                self.urls = []
            def open(self, url, timeout=None):
                self.urls.append(url)
                return Reply(b'{}' if "/proxy/api/state" in url else b"x")
        with tempfile.TemporaryDirectory() as state:
            token_path = os.path.join(state, "web-token-18083")
            with open(token_path, "w") as fh:
                fh.write("a+b&c")
            opener = Opener()
            rep = Report()
            common = [mock.patch("doctor.STATE_ROOT", state), mock.patch("doctor.port_owner", return_value=[{"pid": "42"}]),
                      mock.patch("doctor._trusted_panel_listener", return_value=(True, "pid 42"))]
            with common[0], common[1], common[2], mock.patch("urllib.request.build_opener", return_value=opener):
                check_running(rep, 18083, "/tmp/rules.json")
            self.assertTrue(opener.urls)
            self.assertTrue(all("token=a%2Bb%26c" in u for u in opener.urls))
            rep = Report()
            with common[0], common[1], common[2], mock.patch("doctor.open", side_effect=PermissionError("denied"), create=True):
                check_running(rep, 18083, "/tmp/rules.json")
            self.assertTrue(any(level == "warn" and "unreadable" in title for _, level, title, _, _ in rep.items))


class ProfileNetworkConsent(unittest.TestCase):
    def test_user_profile_hosts_need_explicit_opt_in(self):
        profile = {"doctor_hosts": ["internal.example"]}
        with mock.patch("doctor.project_profile", return_value=profile), \
             mock.patch("doctor.os.path.isfile", return_value=True), \
             mock.patch("doctor._probe_host") as probe:
            rep = Report()
            check_network(rep, "custom", False)
            probe.assert_not_called()
            self.assertTrue(any(level == "skip" for _, level, _, _, _ in rep.items))

            rep = Report()
            check_network(rep, "custom", False, allow_profile_network=True)
            probe.assert_called_once_with("internal.example")


class NetworkFailure(unittest.TestCase):
    def test_dns(self):
        self.assertEqual(classify_network_failure("dns", "gaierror",
                         "[Errno 8] nodename nor servname provided"), "dns_fail")

    def test_tcp_timeout_is_no_route(self):
        self.assertEqual(classify_network_failure("tcp", "timeout", "timed out"), "no_route")

    def test_tcp_refused(self):
        self.assertEqual(classify_network_failure("tcp", "ConnectionRefusedError",
                         "[Errno 61] Connection refused"), "refused")

    def test_tcp_unreachable(self):
        self.assertEqual(classify_network_failure("tcp", "OSError",
                         "[Errno 65] No route to host"), "no_route")

    def test_tls_san_mismatch(self):
        self.assertEqual(classify_network_failure("tls", "SSLCertVerificationError",
                         "Hostname mismatch, certificate is not valid for 'x'"), "cert_san_mismatch")

    def test_tls_untrusted(self):
        self.assertEqual(classify_network_failure("tls", "SSLCertVerificationError",
                         "certificate verify failed: self-signed certificate"), "cert_untrusted")

    def test_tls_reset(self):
        self.assertEqual(classify_network_failure("tls", "ConnectionResetError",
                         "Connection reset by peer"), "tls_reset")

    def test_tls_handshake_refused(self):
        self.assertEqual(classify_network_failure("tls", "SSLError",
                         "[SSL] sslv3 alert handshake failure"), "tls_refused")

    def test_tls_wrong_version(self):
        self.assertEqual(classify_network_failure("tls", "SSLError",
                         "WRONG_VERSION_NUMBER"), "tls_refused")


class PilotExpiredCertificate(unittest.TestCase):
    """Pilot feedback #3: an expired upstream certificate read as "TLS handshake failed — check the host/VPN", and
    doctor ignored that the running proxy was started with --insecure."""

    def test_expired_is_its_own_category(self):
        self.assertEqual(classify_network_failure("tls", "SSLCertVerificationError", "certificate has expired"),
                         "cert_expired")

    def run_network(self, state, category="cert_expired"):
        rep = Report()
        if state is not None:
            rep.running_state = state
        with mock.patch("doctor.project_profile", return_value={"doctor_hosts": ["edge.example"]}), \
             mock.patch("doctor.os.path.isfile", return_value=False), \
             mock.patch("doctor._probe_host", return_value=category), \
             mock.patch("doctor._peer_cert_not_after", return_value=1714608000):    # 2024-05-02
            check_network(rep, "neo", False)
        return [(level, title, detail, fix) for sec, level, title, detail, fix in rep.items if sec == "Network"]

    def test_expired_names_the_date_and_warns_when_verifying(self):
        with mock.patch("doctor.time.localtime", return_value=doctor.time.gmtime(1714608000 + 86400)):
            [(level, title, _detail, fix)] = self.run_network(None)
        self.assertEqual(level, "warn")
        self.assertEqual(title, "edge.example: server certificate expired on 2024-05-02")
        self.assertNotIn("VPN", fix)

    def test_insecure_only_downgrades_decrypted_hosts(self):
        for tls in ({"mode": "allow", "allow": ["other.example"]},
                    {"mode": "ignore", "ignore": ["edge.example"]},
                    {"mode": "allow", "allow": []}):
            [(level, _title, detail, _fix)] = self.run_network({"ssl_insecure": True, "tls": tls})
            self.assertEqual((level, detail), ("warn", ""), tls)
        for tls in ({"mode": "allow", "allow": ["*.example"]},
                    {"mode": "ignore", "ignore": ["other.example"]}):
            [(level, _title, detail, _fix)] = self.run_network({"ssl_insecure": True, "tls": tls})
            self.assertEqual(level, "info", tls)
            self.assertIn("--insecure", detail)

    def test_insecure_running_proxy_makes_certificate_problems_informational(self):
        for category in ("cert_expired", "cert_san_mismatch", "cert_untrusted"):
            [(level, _title, detail, _fix)] = self.run_network({"ssl_insecure": True}, category)
            self.assertEqual(level, "info", category)
            self.assertIn("--insecure", detail)

    def test_insecure_does_not_hide_a_dropped_tunnel(self):
        [(level, _title, _detail, _fix)] = self.run_network({"ssl_insecure": True}, "tls_reset")
        self.assertEqual(level, "error")


class SummarizeState(unittest.TestCase):
    def base(self, **kw):
        state = {"active_project": "neo", "rules": [], "skipped_rules": [],
                 "throttle": "off", "loss": 0, "breakpoints": [],
                 "collections": {}, "tls": {"mode": "all"}, "script_status": {"errors": {}}}
        state.update(kw)
        return state

    def test_clean(self):
        lines, flags = summarize_state(self.base())
        self.assertEqual(flags, [])
        self.assertTrue(any("project neo" in t for _, t, _ in lines))

    def test_skipped_and_script_errors(self):
        lines, flags = summarize_state(self.base(
            skipped_rules=[{"name": "bad"}],
            script_status={"errors": {"qa.js": "boom"}}))
        titles = " ".join(t for _, t, _ in lines)
        self.assertIn("skipped", titles)
        self.assertIn("script error", titles)

    def test_unreadable_rules_file_is_reported(self):
        # R2A-08: doctor said "running" and nothing else while the panel showed rules_error
        lines, _ = summarize_state(self.base(rules_error="Expecting value: line 1 column 1"))
        self.assertTrue(any(lv == WARN and "rules.json is unreadable" in t for lv, t, _ in lines), lines)

    def test_throttle_flagged(self):
        _, flags = summarize_state(self.base(throttle="3g-urban", throttle_match="neo"))
        self.assertTrue(any("throttle active" in f for f in flags))

    def test_block_rule_flagged(self):
        _, flags = summarize_state(self.base(
            rules=[{"name": "kill", "enabled": True, "action": "block"}]))
        self.assertTrue(any("rewrite/replace traffic" in f for f in flags))

    def test_many_rules_warning_is_bounded(self):
        # R4A-03: a long enabled list must leave the rest of doctor readable.
        _, flags = summarize_state(self.base(rules=[{"name": "bulk-%d" % i, "action": "block"} for i in range(1205)]))
        warning = next(f for f in flags if "rewrite/replace traffic" in f)
        self.assertIn("1205 rule(s)", warning)
        self.assertIn("bulk-0", warning)
        self.assertIn("+1200 more (rivis rules list)", warning)
        self.assertNotIn("bulk-1204", warning)
        self.assertLess(len(warning), 200)

    def test_disabled_rule_not_flagged(self):
        _, flags = summarize_state(self.base(
            rules=[{"name": "kill", "enabled": False, "action": "block"}]))
        self.assertEqual(flags, [])

    def test_strict_replay_flagged(self):
        _, flags = summarize_state(self.base(collections={"strict": True}))
        self.assertTrue(any("strict replay" in f for f in flags))

    def test_active_replay_and_bad_rules_are_reported(self):
        # R3A-05/R3A-07: panel state has replay in items, and raw rules may contain junk.
        lines, flags = summarize_state(self.base(rules=[1, {"name": "ok", "action": "block"}],
                                              collections={"items": [{"name": "journey", "replay": True}]}))
        self.assertTrue(any("journey" in f for f in flags))
        self.assertTrue(any("not objects" in title for _, title, _ in lines))

    def test_collection_replay_flagged_from_panel_items(self):
        # R3A-05: doctor receives the panel's items list, not the stored replay names.
        _, flags = summarize_state(self.base(collections={"items": [{"name": "journey", "replay": True}]}))
        self.assertIn("replaying collection(s): journey", flags)

    def test_breakpoint_flagged(self):
        _, flags = summarize_state(self.base(
            breakpoints=[{"name": "bp", "enabled": True, "match": "x"}]))
        self.assertTrue(any("breakpoint" in f for f in flags))


if __name__ == "__main__":
    unittest.main()


class NightQaDoctorFalseAlarms(unittest.TestCase):
    """Night QA 2026-10-16: doctor exited 1 on healthy first runs for reasons that were not true."""

    def test_proxyman_is_matched_on_the_executable_not_any_command_line(self):
        ps = ("/bin/zsh\n/usr/bin/grep\n/Library/PrivilegedHelperTools/com.proxyman.NSProxy.HelperTool\n"
              "/Users/me/Downloads/notes-about-Proxyman/editor\n")
        self.assertEqual(doctor.running_proxy_apps(ps), [])
        self.assertEqual(doctor.running_proxy_apps(ps + "/Applications/Proxyman.app/Contents/MacOS/Proxyman\n"), ["Proxyman"])
        self.assertEqual(doctor.running_proxy_apps("/Applications/FRTMProxy.app/Contents/MacOS/FRTMProxy\n"), ["FRTMProxy"])

    def test_node_is_looked_for_where_the_script_host_looks(self):
        src = open(os.path.join(os.path.dirname(doctor.__file__), "proxy_scripts.py")).read()
        start = src.index("NODE_CANDIDATES = (")
        block = src[start:src.index(")\n", start) + 2]
        scope = {"os": os}
        exec(block, scope)
        self.assertEqual(tuple(scope["NODE_CANDIDATES"]), doctor.NODE_CANDIDATES)
        with mock.patch.object(doctor, "which", return_value=None), \
                mock.patch.object(doctor.os.path, "isfile", side_effect=lambda p: p == "/usr/local/bin/node"), \
                mock.patch.object(doctor.os, "access", return_value=True):
            self.assertEqual(doctor.find_node(), "/usr/local/bin/node")

    def test_an_unreachable_first_address_does_not_hide_a_working_second_one(self):
        import socket
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        self.addCleanup(srv.close)
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()                                      # nothing listens there: refused
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", dead_port)),
                   (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", srv.getsockname()[1]))]
        with mock.patch.object(doctor.socket, "getaddrinfo", return_value=answers), \
                mock.patch.object(doctor.ssl, "create_default_context", side_effect=doctor.ssl.SSLError("stop here")):
            cat = doctor._probe_host("dual.example", 443)
        self.assertNotEqual(cat, doctor.classify_network_failure("tcp", "ConnectionRefusedError", "refused"))


class DoctorTrustsWhatRivisTrusts(unittest.TestCase):
    def test_tls_probe_uses_the_upstream_trust_bundle(self):
        # night QA review: on a network that inspects HTTPS, Rivis trusts the corporate root (upstream-trust.pem) but
        # doctor's probe used Python's default roots and reported a TLS failure while Rivis worked
        import socket
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        self.addCleanup(srv.close)
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", srv.getsockname()[1]))]
        with tempfile.TemporaryDirectory() as root:
            open(os.path.join(root, "upstream-trust.pem"), "w").close()
            ctx = mock.Mock()
            ctx.wrap_socket.side_effect = doctor.ssl.SSLError("stop here")
            with mock.patch.object(doctor, "STATE_ROOT", root), \
                    mock.patch.object(doctor.socket, "getaddrinfo", return_value=answers), \
                    mock.patch.object(doctor.ssl, "create_default_context", return_value=ctx):
                doctor._probe_host("corp.example", 443)
            ctx.load_verify_locations.assert_called_once_with(cafile=os.path.join(root, "upstream-trust.pem"))
