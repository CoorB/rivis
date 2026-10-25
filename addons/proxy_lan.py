"""proxy_lan — real phones and tablets on the same Wi-Fi (opt-in: `rivis start --lan`).

By default Rivis listens on 127.0.0.1 only. With --lan it also listens on this Mac's own Wi-Fi / Ethernet address(es)
(never 0.0.0.0, never a VPN tunnel), so a phone whose Wi-Fi proxy points there is captured like a simulator.

Nobody else on the network can use this Mac as a proxy: a device must first be allowed on the Mac (panel: Tools →
Devices → Phones and tablets, or `rivis lan allow IP`). Until then every call it makes is refused with a page that
says so, and it is listed as waiting. The setup page, with the certificate and the steps for iOS and Android, opens
from the QR code in the panel (http://<this Mac>:<port>/, no proxy needed yet) or, once the proxy is set, at
http://rivis.setup/.

  <state root>/lan-devices.json   [{"ip", "mac", "name", "added", "last_seen"}]   allowed devices (0600)
  proxy_lan.py FILE list | allow IP [NAME] | rm IP | addresses

Each call from an allowed device is shown with that device's name (proxy_source stamps it, kind "phone").
"""
import html
import ipaddress
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:       # /usr/bin/python3 -I removes the script directory
    sys.path.insert(0, HERE)
from proxy_common import PRODUCT, STATE_ROOT, atomic_json

try:
    from mitmproxy import ctx, http
except ImportError:            # the CLI uses the file helpers with the system Python, without mitmproxy
    ctx = http = None

SETUP_HOST = "rivis.setup"
DEVICES_FILE = os.path.join(STATE_ROOT, "lan-devices.json")
MAX_DEVICES, MAX_PENDING = 50, 20
DEVICE_TTL = 7 * 86400
MAC_CACHE_TTL = 5               # short: a device that just took over an allowed address must not inherit its verdict
NAME_OK = re.compile(r"^[^\x00-\x1f\x7f|<>]{1,40}$")
LAN_IFACE = re.compile(r"^(en|eth|bridge|wlan)\d+$")      # Wi-Fi / Ethernet; never utun (VPN), lo, awdl, llw, anpi


def plain_ip(ip):
    ip = str(ip or "")
    return ip[7:] if ip.startswith("::ffff:") else ip


def is_loopback(ip):
    try:
        return ipaddress.ip_address(plain_ip(ip)).is_loopback
    except ValueError:
        return False


def parse_arp(output):
    """The MAC in `arp -n IP` (macOS prints octets without leading zeros: 0:1c:42:a:5e:6) or `arp -a IP` (Windows:
    00-1c-42-0a-5e-06) output, normalised to 00:1c:42:0a:5e:06; None for "(incomplete)" or no entry."""
    found = re.search(r"\bat\s+([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})\b", output) \
        or re.search(r"\b([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\b", output)
    return ":".join(x.zfill(2) for x in re.split("[:-]", found.group(1).lower())) if found else None


def lookup_mac(ip):
    # Test-only ARP fixture: live tests use this Mac's own Wi-Fi IP, which has no ARP entry.
    fixture = os.environ.get("RIVIS_TEST_ARP_FILE")
    if fixture is not None:
        try:
            with open(fixture) as fh:
                return parse_arp("at " + str(json.load(fh).get(ip) or ""))
        except (OSError, ValueError, AttributeError):
            return None
    argv = ["arp", "-a", ip] if sys.platform == "win32" else ["/usr/sbin/arp", "-n", ip]
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=2)
    except (OSError, subprocess.SubprocessError):
        return None
    return parse_arp(result.stdout) if result.returncode == 0 else None


def lan_addresses(ifconfig=None):
    """This Mac's private IPv4 addresses on Wi-Fi / Ethernet interfaces (macOS `ifconfig` output)."""
    if ifconfig is None:
        try:
            ifconfig = subprocess.run(["/sbin/ifconfig"], capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            return []
    out, iface, active = [], None, {}
    blocks = re.split(r"(?m)^(?=\S)", ifconfig)
    for block in blocks:
        m = re.match(r"^([A-Za-z0-9]+):", block)
        if not m or not LAN_IFACE.match(m.group(1)):
            continue
        if re.search(r"status: inactive", block):
            continue
        for addr in re.findall(r"(?m)^\s+inet (\d+\.\d+\.\d+\.\d+)", block):
            ip = ipaddress.ip_address(addr)
            if ip.is_private and not ip.is_loopback and not ip.is_link_local and addr not in out:
                out.append(addr)
    return out


def guess_name(ua):
    ua = str(ua or "")
    m = re.search(r"\((?:Linux; )?Android [\d.]+; ([^;)]+?)(?: Build/[^;)]*)?[;)]", ua)
    if m and m.group(1).strip() not in ("K", "wv"):
        return clean_name("Android " + m.group(1).strip())
    for word in ("iPhone", "iPad", "Android", "Macintosh", "Windows"):
        if word in ua:
            return {"Macintosh": "Mac", "Windows": "Windows PC"}.get(word, word)
    return "Device"


def clean_name(name):
    name = re.sub(r"[\x00-\x1f\x7f|<>]", "", str(name or "")).strip()[:40]
    return name or "Device"


# ---- the allow-list file (shared by the CLI, the panel and proxy_source) -------------------------------------------
class Devices:
    def __init__(self, path=DEVICES_FILE):
        self.path = path
        self._stamp = None
        self._rows = []

    def rows(self):
        try:
            st = os.stat(self.path)
            stamp = (st.st_mtime_ns, st.st_size)
        except OSError:
            stamp = None
        if stamp != self._stamp:
            self._stamp = stamp
            self._rows = self._read() if stamp else []
        now = time.time()
        keep = [r for r in self._rows if not isinstance(r.get("last_seen"), (int, float))
                or now - r["last_seen"] < DEVICE_TTL]
        if len(keep) != len(self._rows):
            self._write(keep)
            self._rows = keep
        return self._rows

    def _read(self):
        try:
            with open(self.path) as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            return []
        rows = []
        for r in doc.get("devices", []) if isinstance(doc, dict) else []:
            try:
                ip = str(ipaddress.ip_address(plain_ip(r.get("ip"))))
            except (ValueError, AttributeError):
                continue
            rows.append({"ip": ip, "name": clean_name(r.get("name")), "added": r.get("added"),
                         "mac": r.get("mac"), "last_seen": r.get("last_seen", r.get("added"))})
        return rows[:MAX_DEVICES]

    def get(self, ip):
        ip = plain_ip(ip)
        return next((r for r in self.rows() if r["ip"] == ip), None)

    def _write(self, rows):
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        atomic_json(self.path, {"devices": rows})
        self._stamp = None

    def allow(self, ip, name=None):
        ip = str(ipaddress.ip_address(plain_ip(ip)))           # ValueError for anything that is not an address
        if is_loopback(ip):
            raise ValueError("this Mac itself is always allowed")
        rows = [r for r in self.rows() if r["ip"] != ip]
        if len(rows) >= MAX_DEVICES:
            raise ValueError("at most %d devices; remove one first" % MAX_DEVICES)
        old = self.get(ip)
        now = int(time.time())
        row = {"ip": ip, "name": clean_name(name or (old or {}).get("name")), "added": now,
               "last_seen": now, "mac": lookup_mac(ip)}
        self._write(rows + [row])
        return row

    def seen(self, ip):
        row = self.get(ip)
        now = int(time.time())
        if row is None or (row.get("last_seen") or 0) > now - 60:
            return
        rows = [dict(r, last_seen=now) if r["ip"] == ip else r for r in self.rows()]
        self._write(rows)

    def remove(self, ip):
        ip = plain_ip(ip)
        rows = self.rows()
        keep = [r for r in rows if r["ip"] != ip]
        if len(keep) == len(rows):
            return False
        self._write(keep)
        return True


# ---- the setup page ------------------------------------------------------------------------------------------------
PAGE_CSS = ("body{font:16px/1.45 -apple-system,system-ui,sans-serif;margin:0;padding:20px;max-width:640px;color:#1d1d1f;"
            "background:#fff}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:22px 0 6px}.box{border:1px solid #d2d2d7;"
            "border-radius:10px;padding:12px 14px;margin:10px 0}.wait{background:#fff8e1;border-color:#f0c36d}.ok{background:#e9f7ef;"
            "border-color:#7bc496}a.btn{display:inline-block;background:#0a66d8;color:#fff;padding:10px 16px;border-radius:8px;"
            "text-decoration:none;margin:4px 0}code{background:#f2f2f5;padding:1px 5px;border-radius:4px}ol{padding-left:22px}"
            "@media (prefers-color-scheme:dark){body{background:#111;color:#eee}.box{border-color:#444}.wait{background:#3a2f12}"
            ".ok{background:#123222}code{background:#2a2a2e}}")


def setup_page(product, allowed, ip, proxy_addr, port):
    p = html.escape(product)
    you = html.escape(ip)
    if allowed:
        status = '<div class="box ok"><b>This device is allowed.</b> Its calls show in %s as <b>%s</b>.</div>' % (
            p, html.escape(allowed["name"]))
    else:
        status = ('<div class="box wait"><b>Waiting for the Mac.</b> In %s on the Mac: <b>Tools → Devices → Phones and '
                  'tablets</b>, choose <b>Allow</b> next to <code>%s</code>. Until then this device\'s calls are refused. '
                  'This page updates by itself.</div><meta http-equiv="refresh" content="3">' % (p, you))
    proxy = html.escape(proxy_addr or "this Mac's address")
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%(p)s setup</title><style>%(css)s</style></head><body>
<h1>Set up this device for %(p)s</h1><p>Use it with test builds on a test network only. Remove the certificate and the proxy when you are done.</p>
%(status)s
<h2>1. Point the Wi-Fi proxy at this Mac</h2>
<ol><li><b>iPhone / iPad:</b> Settings → Wi-Fi → ⓘ next to the network → Configure Proxy → Manual.</li>
<li><b>Android:</b> Settings → Network &amp; internet → Wi-Fi → the network → ✎ (or Advanced) → Proxy → Manual.</li>
<li>Server <code>%(proxy)s</code>, port <code>%(port)s</code>. No authentication.</li></ol>
<h2>2. Install the %(p)s certificate</h2>
<div class="box"><b>iPhone / iPad</b> (open this page in Safari)<br><a class="btn" href="/rivis-ca.pem">Download the certificate</a>
<ol><li>Allow the download, then Settings → General → VPN &amp; Device Management → <b>%(p)s / mitmproxy</b> → Install.</li>
<li>Settings → General → About → <b>Certificate Trust Settings</b> → turn on full trust for it. Without this step HTTPS fails.</li></ol></div>
<div class="box"><b>Android</b><br><a class="btn" href="/rivis-ca.crt">Download the certificate</a>
<ol><li>Settings → Security → More security → Encryption &amp; credentials → Install a certificate → <b>CA certificate</b> →
Install anyway → choose <code>rivis-ca.crt</code> in Downloads.</li>
<li>Apps trust it only if their build allows user certificates (debug builds with a network security config). On a
physical phone the system store needs root, so release builds cannot be decrypted.</li></ol></div>
<h2>3. When you are done</h2>
<ol><li>Turn the Wi-Fi proxy off (Off / None).</li><li>Remove the certificate: iOS → VPN &amp; Device Management → Remove
Profile; Android → Encryption &amp; credentials → User credentials → remove it.</li></ol>
</body></html>""" % {"p": p, "css": PAGE_CSS, "status": status, "proxy": proxy, "port": html.escape(str(port))}


def refused_page(product, ip, setup_url):
    p, you = html.escape(product), html.escape(ip)
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Not allowed yet</title><style>%s</style></head><body><h1>%s: this device is not allowed yet</h1>
<div class="box wait">On the Mac running %s: <b>Tools → Devices → Phones and tablets</b> → <b>Allow</b> next to <code>%s</code>.
Then open <a href="%s">%s</a> to install the certificate.</div></body></html>"""
            % (PAGE_CSS, p, p, you, html.escape(setup_url), html.escape(setup_url)))


# ---- the add-on ---------------------------------------------------------------------------------------------------
class ProxyLan:
    def __init__(self):
        self.devices = Devices()
        self.pending = {}          # ip → {"ip", "mac", "ua", "name", "first", "last", "count"}
        self._client_macs = {}      # client.id → (ip, mac)
        self._mac_cache = {}        # ip → (time, fixture stamp, mac)

    def load(self, loader):
        loader.add_option("proxy_lan", bool, False,
                          "real devices on the Wi-Fi may use the proxy once allowed (rivis start --lan)")
        loader.add_option("proxy_lan_devices_file", str, "", "allowed devices (default: <state root>/lan-devices.json)")

    def configure(self, updated):
        if "proxy_lan_devices_file" in updated:
            self.devices = Devices(ctx.options.proxy_lan_devices_file or DEVICES_FILE)

    # which addresses the proxy listens on beyond loopback (from `--mode regular@IP:PORT`)
    def listen_addresses(self):
        out = []
        for mode in ctx.options.mode or []:
            m = re.match(r"^(?:regular|upstream:[^@]+)@(\d+\.\d+\.\d+\.\d+):(\d+)$", mode)
            if m and not is_loopback(m.group(1)):
                out.append((m.group(1), int(m.group(2))))
        return out

    async def client_connected(self, client):
        ip = plain_ip(client.peername[0]) if client.peername else ""
        if not ip or is_loopback(ip):
            return
        fixture = os.environ.get("RIVIS_TEST_ARP_FILE")
        try:
            st = os.stat(fixture) if fixture is not None else None
            stamp = (st.st_mtime_ns, st.st_size) if st else None
        except OSError:
            stamp = None
        now = time.monotonic()
        cached = self._mac_cache.get(ip)
        if cached is None or now - cached[0] >= MAC_CACHE_TTL or cached[1] != stamp:
            import asyncio            # arp runs off the event loop: one slow lookup must not stall every other call
            cached = (now, stamp, await asyncio.to_thread(lookup_mac, ip))
            self._mac_cache[ip] = cached
        self._client_macs[client.id] = (ip, cached[2])

    def client_disconnected(self, client):
        self._client_macs.pop(client.id, None)

    def _allowed(self, flow):
        conn = flow.client_conn
        if getattr(getattr(conn, "proxy_mode", None), "type_name", "regular") == "local":
            return True                        # simulator capture on this Mac
        ip = plain_ip(conn.peername[0]) if conn.peername else ""
        if is_loopback(ip):
            return True
        row = self.devices.get(ip)
        mac = self._client_macs.get(conn.id, (ip, None))[1]
        allowed = row is not None and (not row.get("mac") or row["mac"] == mac)
        if allowed:
            self.devices.seen(ip)
        return allowed

    def _note(self, flow):
        ip = plain_ip(flow.client_conn.peername[0]) if flow.client_conn.peername else "?"
        now = time.time()
        row = self.pending.get(ip)
        mac = self._client_macs.get(flow.client_conn.id, (ip, None))[1]
        ua = flow.request.headers.get("user-agent", "")[:300]
        if row is None:
            if len(self.pending) >= MAX_PENDING:
                oldest = min(self.pending.values(), key=lambda r: r["last"])
                del self.pending[oldest["ip"]]
            row = self.pending[ip] = {"ip": ip, "mac": mac, "ua": "", "name": "Device", "first": now, "last": now, "count": 0}
            if ctx is not None:
                ctx.log.warn(f"proxy_lan: {ip} is not allowed to use this proxy; allow it in Tools → Devices "
                             f"({PRODUCT['cli']} lan allow {ip})")
        if ua and (not row["ua"] or row["name"] == "Device"):
            row["ua"], row["name"] = ua, guess_name(ua)
        row["last"] = now
        row["mac"] = mac
        row["count"] += 1
        return ip

    def _proxy_addr(self, flow):
        sock = flow.client_conn.sockname
        if sock and not is_loopback(sock[0]):
            return plain_ip(sock[0]), sock[1]
        lan = self.listen_addresses()
        return lan[0] if lan else ("", sock[1] if sock else "")

    def _is_setup(self, flow):
        host, port = flow.request.pretty_host.lower().rstrip("."), flow.request.port
        if host == SETUP_HOST:
            return True
        sock = flow.client_conn.sockname    # someone opened http://<this Mac>:<port>/ directly (the QR code)
        return bool(sock) and not is_loopback(sock[0]) and host == plain_ip(sock[0]) and port == sock[1]

    def _answer(self, flow, status, body, ctype, kind):
        flow.response = http.Response.make(status, body, {"Content-Type": ctype, "Cache-Control": "no-store",
                                                          "X-Content-Type-Options": "nosniff"})
        flow.metadata["rivis_local_page"] = kind      # proxy_rules and the other add-ons leave such a call alone
        flow.metadata["proxy_local"] = True

    def http_connect(self, flow):
        if self._allowed(flow):
            return
        ip = self._note(flow)
        self._answer(flow, 403, ("%s: this device (%s) is not allowed yet; allow it on the Mac\n" % (PRODUCT["name"], ip)).encode(),
                     "text/plain; charset=utf-8", "refused")

    def requestheaders(self, flow):
        allowed = self._allowed(flow)
        if self._is_setup(flow):
            if not allowed:
                self._note(flow)
            self._setup(flow, allowed)
        elif not allowed:
            ip = self._note(flow)
            addr, port = self._proxy_addr(flow)
            self._answer(flow, 403, refused_page(PRODUCT["name"], ip, "http://%s:%s/" % (addr, port)).encode(),
                         "text/html; charset=utf-8", "refused")

    def _setup(self, flow, allowed):
        path = flow.request.path.split("?")[0]
        ip = plain_ip(flow.client_conn.peername[0]) if flow.client_conn.peername else ""
        if path in ("/rivis-ca.pem", "/rivis-ca.crt"):
            try:
                with open(os.path.join(os.path.expanduser(ctx.options.confdir), "mitmproxy-ca-cert.pem"), "rb") as fh:
                    pem = fh.read()
            except OSError:
                return self._answer(flow, 404, b"certificate not found\n", "text/plain", "setup")
            self._answer(flow, 200, pem, "application/x-x509-ca-cert", "setup")
            flow.response.headers["Content-Disposition"] = 'attachment; filename="%s"' % path[1:]
            return
        if path != "/":
            return self._answer(flow, 404, b"not found\n", "text/plain", "setup")
        addr, port = self._proxy_addr(flow)
        row = self.devices.get(ip) if not is_loopback(ip) else {"name": "this Mac"}
        self._answer(flow, 200, setup_page(PRODUCT["name"], row if allowed else None, ip, addr, port).encode(),
                     "text/html; charset=utf-8", "setup")

    # ---- for the panel -------------------------------------------------------------------------------------------
    def state(self):
        import qr
        lan = self.listen_addresses() if ctx.options.proxy_lan else []
        allowed = {r["ip"]: r for r in self.devices.rows()}
        urls = ["http://%s:%d/" % a for a in lan]
        return {"on": bool(lan), "addresses": ["%s:%d" % a for a in lan], "setup_urls": urls,
                "qr": [qr.svg(u, label="Set up a device: " + u) for u in urls[:3]],
                "devices": self.devices.rows(),
                "pending": sorted((dict(r) for ip, r in self.pending.items()
                                   if ip not in allowed or (allowed[ip].get("mac") and allowed[ip]["mac"] != r["mac"])),
                                  key=lambda r: -r["last"])}

    def allow(self, ip, name=None):
        row = self.pending.pop(plain_ip(ip), None)
        return self.devices.allow(ip, name or (row or {}).get("name"))

    def dismiss(self, ip):
        self.pending.pop(plain_ip(ip), None)


addons = [ProxyLan()]


# ---- CLI ----------------------------------------------------------------------------------------------------------
def main(argv):
    def die(msg):
        print(PRODUCT["cli"] + ": " + msg, file=sys.stderr)
        sys.exit(1)
    if not argv:
        die("usage: lan list | allow IP [NAME] | rm IP")
    path, cmd, args = (argv[0], argv[1] if len(argv) > 1 else "list", argv[2:])
    devices = Devices(path)
    try:
        if cmd == "addresses":
            print("\n".join(lan_addresses()))
        elif cmd == "list" and not args:
            rows = devices.rows()
            for r in rows:
                print("%-16s %s" % (r["ip"], r["name"]))
            if not rows:
                print("no devices allowed (a device that tries the proxy shows in Tools → Devices; or: %s lan allow IP [NAME])" % PRODUCT["cli"])
        elif cmd == "allow" and 1 <= len(args) <= 2:
            row = devices.allow(args[0], args[1] if len(args) > 1 else None)
            print("allowed %s (%s), %s — from its next call, no restart" %
                  (row["ip"], row["name"], row["mac"] or "MAC unknown"))
        elif cmd == "rm" and len(args) == 1:
            if not devices.remove(args[0]):
                die("%s is not in the list" % args[0])
            print("removed %s — its calls are refused from now on" % args[0])
        else:
            die("usage: lan list | allow IP [NAME] | rm IP")
    except (OSError, ValueError) as e:
        die(str(e))


if __name__ == "__main__":
    main(sys.argv[1:])
