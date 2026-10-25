"""F3: a certificate/hostname-mismatch error says which IP Rivis actually connected to, and when that address comes from
the hosts file, which line of it. Real case: `10.16.209.88 backbase-identity-nfr.neo.sa` in /etc/hosts reached an old
server whose certificate had expired in May 2024, and nothing in the error pointed at the hosts file.

The hosts file path is injectable (RIVIS_HOSTS_FILE); no test reads or edits the real /etc/hosts."""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _paths  # noqa: F401,E402
import doctor  # noqa: E402
import proxy_common  # noqa: E402
from harness import Instance, Suite  # noqa: E402

HOSTS = ("127.0.0.1 localhost\n"
         "# the NFR box\n"
         "10.16.209.88   backbase-identity-nfr.neo.sa   backbase-edge-nfr.neo.sa  # old server\n"
         "10.1.1.1 Other.Example\n"
         "10.2.2.2 other.example\n")


class FakeHosts(unittest.TestCase):
    def setUp(self):
        fh = tempfile.NamedTemporaryFile("w", suffix="-hosts", delete=False)
        fh.write(HOSTS)
        fh.close()
        self.path = fh.name
        self.addCleanup(os.unlink, self.path)
        patcher = mock.patch.dict(os.environ, {"RIVIS_HOSTS_FILE": self.path})
        patcher.start()
        self.addCleanup(patcher.stop)


class HostsLookup(FakeHosts):
    def test_cycle5_standard_localhost_lines_are_kept(self):
        for ip in ("127.0.0.1", "::1"):
            with open(self.path, "w") as fh:
                fh.write(ip + " localhost\n")
            for text in (proxy_common.describe_connection("localhost", ip),
                         proxy_common.upstream_conn_text("Connection refused", "localhost", 443, ip)):
                self.assertIn("loopback", text)
                self.assertNotIn("remove", text)

    def test_finds_the_line_and_ignores_comments(self):
        e = proxy_common.hosts_entry("backbase-identity-nfr.neo.sa")
        self.assertEqual((e["ip"], e["line"], e["path"]), ("10.16.209.88", 3, self.path))
        self.assertEqual(e["text"], "10.16.209.88 backbase-identity-nfr.neo.sa backbase-edge-nfr.neo.sa")
        self.assertEqual(proxy_common.hosts_entry("BACKBASE-EDGE-NFR.NEO.SA")["line"], 3)     # an alias; case-insensitive
        self.assertIsNone(proxy_common.hosts_entry("old"))                                  # the comment is not a name
        self.assertIsNone(proxy_common.hosts_entry("not-listed.example"))

    def test_prefers_the_line_with_the_connected_address(self):
        self.assertEqual(proxy_common.hosts_entry("other.example")["ip"], "10.1.1.1")
        self.assertEqual(proxy_common.hosts_entry("other.example", "10.2.2.2")["ip"], "10.2.2.2")

    def test_a_missing_hosts_file_is_just_no_entry(self):
        with mock.patch.dict(os.environ, {"RIVIS_HOSTS_FILE": self.path + ".nope"}):
            self.assertIsNone(proxy_common.hosts_entry("backbase-identity-nfr.neo.sa"))

    def test_default_path_per_platform(self):
        with mock.patch.dict(os.environ, {"RIVIS_HOSTS_FILE": ""}):
            self.assertEqual(proxy_common.hosts_file_path(), "/etc/hosts" if os.name != "nt" else
                             os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts"))

    def test_describe_says_the_ip_and_the_hosts_line(self):
        text = proxy_common.describe_connection("backbase-identity-nfr.neo.sa", "10.16.209.88")
        self.assertIn("10.16.209.88", text)
        self.assertIn("hosts file", text)
        self.assertIn("%s line 3" % self.path, text)
        self.assertIn("10.16.209.88 backbase-identity-nfr.neo.sa", text)

    def test_describe_when_the_hosts_file_points_elsewhere_or_nowhere(self):
        other = proxy_common.describe_connection("backbase-identity-nfr.neo.sa", "87.101.138.184")
        self.assertIn("87.101.138.184", other)
        self.assertIn("lists 10.16.209.88", other)
        self.assertIn("line 3", other)
        plain = proxy_common.describe_connection("not-listed.example", "87.101.138.184")
        self.assertIn("87.101.138.184", plain)
        self.assertNotIn("hosts file", plain)
        self.assertEqual(proxy_common.describe_connection("x.example", None), "")


class DoctorNames(FakeHosts):
    def probe(self, category, ip):
        def fake(host, port=443):
            doctor.PROBE_IP[host] = ip
            return category
        rep = doctor.Report()
        with mock.patch("doctor.project_profile", return_value={"doctor_hosts": ["backbase-identity-nfr.neo.sa"]}), \
             mock.patch("doctor.os.path.isfile", return_value=False), \
             mock.patch("doctor._probe_host", side_effect=fake), \
             mock.patch("doctor._peer_cert_not_after", return_value=1714608000):    # 2024-05-02
            doctor.check_network(rep, "neo", False)
        [(_s, _level, title, detail, _fix)] = [i for i in rep.items if i[0] == "Network"]
        return title, detail

    def test_expired_certificate_names_the_ip_and_the_hosts_line(self):
        title, detail = self.probe("cert_expired", "10.16.209.88")
        self.assertIn("expired on 2024-05-02", title)
        self.assertIn("10.16.209.88", detail)
        self.assertIn("%s line 3" % self.path, detail)

    def test_hostname_mismatch_names_the_ip(self):
        _title, detail = self.probe("cert_san_mismatch", "87.101.138.184")
        self.assertIn("87.101.138.184", detail)
        self.assertIn("lists 10.16.209.88", detail)

    def test_a_healthy_host_says_nothing_extra(self):
        title, detail = self.probe("ok", "10.16.209.88")
        self.assertEqual(detail, "")


class PanelError(unittest.TestCase):
    """Live: the 502 the app gets (and the Error tab) for an upstream certificate Rivis cannot verify."""

    @classmethod
    def setUpClass(cls):
        cls.suite = Suite.get()
        cls.up = cls.suite.upstream()
        fh = tempfile.NamedTemporaryFile("w", suffix="-hosts", delete=False)
        fh.write("127.0.0.1 localhost\n127.0.0.1 edge.hostsfile.rivis-test\n")
        fh.close()
        cls.hosts = fh.name
        cls.inst = Instance(cls.suite, "hosts-f3", start_args=(), extra_env={
            "RIVIS_HOSTS_FILE": cls.hosts,
            "SHIM_PRE_ADDON": os.path.join(os.path.dirname(os.path.abspath(__file__)), "fakes", "dns_flip.py")}).start()

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()
        os.unlink(cls.hosts)

    def test_502_says_the_connected_ip_and_that_it_came_from_the_hosts_file(self):
        port = self.up.url("/echo", tls=True).rsplit(":", 1)[1].split("/")[0]
        r = self.inst.fetch("https://edge.hostsfile.rivis-test:%s/echo?f3=1" % port)
        self.assertEqual(r.status, 502, r)
        text = r.body.decode("utf-8", "replace")
        self.assertIn("could not verify the HTTPS certificate of edge.hostsfile.rivis-test", text)
        self.assertIn("Connected to 127.0.0.1", text)
        self.assertIn("hosts file", text)
        self.assertIn("%s line 2" % self.hosts, text)
        self.assertIn("127.0.0.1 edge.hostsfile.rivis-test", text)
        flow = self.inst.flow_for("f3=1")
        self.assertIn("Connected to 127.0.0.1", flow["error"]["msg"])         # the Error tab says the same

    def test_502_for_a_name_not_in_the_hosts_file_still_names_the_ip(self):
        r = self.inst.fetch(self.up.url("/echo?f3=2", tls=True))
        self.assertEqual(r.status, 502, r)
        text = r.body.decode("utf-8", "replace")
        self.assertIn("Connected to 127.0.0.1", text)
        self.assertNotIn("hosts file", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
