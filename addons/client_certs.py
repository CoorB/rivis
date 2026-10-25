"""client_certs — client certificates (mutual TLS) per host, per project. Stdlib only (system Python 3.9).

  client_certs.py STORE list
  client_certs.py STORE add HOST CERT_FILE [--key KEY_FILE] [--password-stdin]
  client_certs.py STORE rm HOST

A server that asks for a client certificate (mTLS) gets the one added for its host. HOST is a host name
(api.example.test), an IP address, or a wildcard for every subdomain (*.example.test). CERT_FILE is a PKCS #12
file (.p12 / .pfx; its password is read from stdin with --password-stdin, never from the command line) or a PEM
file holding the certificate and, unless --key names a separate one, its private key.

Each host's certificate and key are kept unencrypted in STORE/<host>.pem (0600; STORE is 0700), the form mitmproxy
reads. The running proxy picks a change up at the next connection to that host, with no restart.
"""
import calendar
import hashlib
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:       # /usr/bin/python3 -I removes the script directory
    sys.path.insert(0, HERE)
from proxy_common import PRODUCT, atomic_write_bytes

WILDCARD_PREFIX = "_wildcard."          # "*" is not allowed in a Windows file name
RUN_DIR = ".active"                     # what mitmproxy reads; rebuilt from the store when the store changes
LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
MAX_FILE = 256 * 1024
OPENSSL = "/usr/bin/openssl" if os.path.exists("/usr/bin/openssl") else (shutil.which("openssl") or "openssl")


class CertError(ValueError):
    pass


def normalize_host(host):
    """'API.Example.test.' → 'api.example.test'; '*.example.test' stays a wildcard. Ports, schemes, paths: refused."""
    h = str(host or "").strip().lower().rstrip(".")
    try:
        return str(ipaddress.IPv4Address(h))
    except ValueError:
        pass
    wild = h.startswith("*.")
    name = h[2:] if wild else h
    labels = name.split(".")
    if not name or len(name) > 253 or not all(LABEL.fullmatch(x) for x in labels) or (wild and len(labels) < 2):
        raise CertError("host must be a host name such as api.example.test, *.example.test or an IPv4 address "
                        "(no scheme, port or path): %r" % str(host))
    return ("*." if wild else "") + name


def file_name(host):
    host = normalize_host(host)
    return (WILDCARD_PREFIX + host[2:] if host.startswith("*.") else host) + ".pem"


def host_of(name):
    """The host a store file is for, or None for anything that is not a store entry."""
    if not name.endswith(".pem") or name.startswith("."):
        return None
    base = name[:-4]
    host = "*." + base[len(WILDCARD_PREFIX):] if base.startswith(WILDCARD_PREFIX) else base
    try:
        return normalize_host(host)
    except CertError:
        return None


def matching(hosts, server_name):
    """The entry used for server_name: the exact host first, then the longest wildcard that covers it."""
    server_name = str(server_name or "").strip().lower().rstrip(".")
    if not server_name:
        return None
    if server_name in hosts:
        return server_name
    best = None
    for h in hosts:
        if h.startswith("*.") and server_name.endswith(h[1:]) and (best is None or len(h) > len(best)):
            best = h
    return best


# ---- converting what the user has into "certificate chain + unencrypted key" PEM ------------------------------------
def _blocks(text, kinds):
    return [m.group(0) for m in re.finditer(r"-----BEGIN (?:%s)-----\r?\n.*?-----END (?:%s)-----" % (kinds, kinds), text, re.S)]


CERT_KINDS = "CERTIFICATE"
KEY_KINDS = "PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|ENCRYPTED PRIVATE KEY"


def _openssl(args, data=None, password=None):
    """Run the openssl CLI; a password goes through a pipe (fd:N), never through argv or the environment."""
    fds, rfd = (), None
    if password is not None:
        rfd, wfd = os.pipe()
        os.write(wfd, password.encode("utf-8") + b"\n")
        os.close(wfd)
        fds = (rfd,)
        args = [a.replace("@PASS@", "fd:%d" % rfd) for a in args]
    try:
        cp = subprocess.run([OPENSSL] + args, input=data, capture_output=True, timeout=30, pass_fds=fds)
    except OSError as e:
        raise CertError("openssl is needed to read this file (%s)" % e)
    finally:
        if rfd is not None:
            os.close(rfd)
    return cp


def _from_pkcs12(data, password):
    try:        # inside the running proxy: mitmproxy's own Python has the cryptography package
        from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
    except ImportError:
        pkcs12 = None
    if pkcs12 is not None:
        try:
            key, cert, extra = pkcs12.load_key_and_certificates(data, (password or "").encode("utf-8") or None)
        except ValueError:
            raise CertError("could not open the PKCS #12 file: wrong password, or not a .p12/.pfx file")
        if key is None or cert is None:
            raise CertError("the PKCS #12 file needs both a certificate and its private key")
        chain = [cert] + list(extra or [])
        return (b"".join(c.public_bytes(Encoding.PEM) for c in chain)
                + key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())).decode()
    cp = _openssl(["pkcs12", "-nodes", "-passin", "@PASS@"], data=data, password=password or "")
    if cp.returncode != 0 or b"BEGIN" not in cp.stdout:
        raise CertError("could not open the PKCS #12 file: wrong password, or not a .p12/.pfx file")
    return cp.stdout.decode("utf-8", "replace")


def _plain_key(key_pem, password):
    """An ENCRYPTED PRIVATE KEY (or a legacy Proc-Type: ENCRYPTED key) → unencrypted PKCS #8."""
    if "ENCRYPTED" not in key_pem:
        return key_pem
    if not password:
        raise CertError("the private key is encrypted: give its password (--password-stdin)")
    cp = _openssl(["pkey", "-passin", "@PASS@"], data=key_pem.encode(), password=password)
    if cp.returncode != 0:
        raise CertError("could not decrypt the private key: wrong password?")
    return cp.stdout.decode()


def _pubkey(pem, what):
    cp = _openssl(["x509", "-noout", "-pubkey"] if what == "cert" else ["pkey", "-pubout"], data=pem.encode())
    if cp.returncode != 0:
        raise CertError("not a readable %s" % ("certificate" if what == "cert" else "private key"))
    return cp.stdout.strip()


def to_pem(data, password=None, key_data=None):
    """Whatever the user has → 'leaf certificate, chain, unencrypted private key' PEM text. Checks that the key
    belongs to the first certificate."""
    if not data or len(data) > MAX_FILE or (key_data and len(key_data) > MAX_FILE):
        raise CertError("the certificate file is empty or larger than %d KB" % (MAX_FILE // 1024))
    text = data.decode("utf-8", "replace") if b"-----BEGIN" in data else None
    if text is None:
        text = _from_pkcs12(data, password)
    if key_data:
        text += "\n" + key_data.decode("utf-8", "replace")
    certs, keys = _blocks(text, CERT_KINDS), _blocks(text, KEY_KINDS)
    if not certs:
        raise CertError("no certificate found (expected a .p12/.pfx file or a PEM certificate)")
    if len(keys) != 1:
        raise CertError("no private key found: add it to the PEM file or pass it separately (--key)" if not keys
                        else "more than one private key found; keep only the one for this certificate")
    key = _plain_key(keys[0], password)
    if _pubkey(certs[0], "cert") != _pubkey(key, "key"):
        # PKCS #12 exports may list the CA first: put the certificate that matches the key first
        match = [c for c in certs if _pubkey(c, "cert") == _pubkey(key, "key")]
        if not match:
            raise CertError("the private key does not belong to the certificate")
        certs = match[:1] + [c for c in certs if c is not match[0]]
    return "\n".join(c.strip() for c in certs) + "\n" + key.strip() + "\n"


def describe(pem):
    """{subject, issuer, not_after (epoch), expired, sha256} of the first certificate in a PEM text."""
    cert = _blocks(pem, CERT_KINDS)[0]
    cp = _openssl(["x509", "-noout", "-subject", "-issuer", "-enddate", "-fingerprint", "-sha256"], data=cert.encode())
    out = {"subject": "", "issuer": "", "not_after": None, "expired": False, "sha256": ""}
    for line in cp.stdout.decode("utf-8", "replace").splitlines():
        k, _, v = line.partition("=")
        k = k.strip().lower()
        if k == "subject":
            out["subject"] = v.strip()
        elif k == "issuer":
            out["issuer"] = v.strip()
        elif k == "notafter":
            try:
                out["not_after"] = calendar.timegm(time.strptime(" ".join(v.split()), "%b %d %H:%M:%S %Y %Z"))
            except ValueError:
                pass
        elif "fingerprint" in k:
            out["sha256"] = v.strip().replace(":", "").lower()
    if out["not_after"] is not None:
        out["expired"] = out["not_after"] < time.time()
    return out


# ---- the store -------------------------------------------------------------------------------------------------
def _ensure(store):
    os.makedirs(store, mode=0o700, exist_ok=True)
    os.chmod(store, 0o700)


def entries(store):
    out = []
    try:
        names = sorted(os.listdir(store))
    except OSError:
        return out
    for name in names:
        host = host_of(name)
        path = os.path.join(store, name)
        if host is None or os.path.islink(path) or not os.path.isfile(path):
            continue
        try:
            with open(path) as fh:
                info = describe(fh.read())
        except (OSError, IndexError, CertError) as e:
            info = {"error": str(e) or "unreadable"}
        info["host"] = host
        out.append(info)
    return out


def add(store, host, data, password=None, key_data=None):
    host = normalize_host(host)
    pem = to_pem(data, password, key_data)
    _ensure(store)
    atomic_write_bytes(os.path.join(store, file_name(host)), pem.encode(), mode=0o600)
    info = describe(pem)
    info["host"] = host
    return info


def remove(store, host):
    path = os.path.join(store, file_name(host))
    if not os.path.isfile(path):
        return False
    os.unlink(path)
    return True


def fingerprint(store):
    """Changes whenever an entry is added, replaced or removed."""
    h = hashlib.sha256()
    try:
        for name in sorted(os.listdir(store)):
            path = os.path.join(store, name)
            if host_of(name) and os.path.isfile(path) and not os.path.islink(path):
                st = os.stat(path)
                h.update(("%s %d %d\n" % (name, st.st_size, st.st_mtime_ns)).encode())
    except OSError:
        pass
    return h.hexdigest()[:16]


class Active:
    """What the running proxy hands mitmproxy (`client_certs` = a directory of <server name>.pem files).

    mitmproxy keeps a TLS context per certificate PATH for the life of the process, so a replaced certificate under
    the same path would never be used. Each version of the store therefore gets a directory of its own
    (<store>/.active/<fingerprint>); a wildcard entry is copied to <server name>.pem there when a server first needs it."""

    def __init__(self, store):
        self.store = store
        self.version = None
        self.dir = None
        self.hosts = []

    def refresh(self):
        """Rebuild the active directory if the store changed. Returns it, or None when there are no entries."""
        version = fingerprint(self.store)
        if version == self.version:
            return self.dir
        self.version = version
        names = [n for n in sorted(os.listdir(self.store)) if host_of(n) and os.path.isfile(os.path.join(self.store, n))
                 and not os.path.islink(os.path.join(self.store, n))] if os.path.isdir(self.store) else []
        self.hosts = [host_of(n) for n in names]
        base = os.path.join(self.store, RUN_DIR)
        if os.path.isdir(base):
            for old in os.listdir(base):
                if old != version:
                    shutil.rmtree(os.path.join(base, old), ignore_errors=True)
        if not names:
            self.dir = None
            return None
        target = os.path.join(base, version)
        os.makedirs(target, mode=0o700, exist_ok=True)
        os.chmod(base, 0o700)
        for n in names:
            dst = os.path.join(target, n)
            if not os.path.exists(dst):
                shutil.copyfile(os.path.join(self.store, n), dst + ".tmp")
                os.chmod(dst + ".tmp", 0o600)
                os.replace(dst + ".tmp", dst)
        self.dir = target
        return target

    def prepare(self, server_name):
        """Make <server name>.pem exist in the active directory when a wildcard covers it. Returns the entry used."""
        server_name = str(server_name or "").strip().lower().rstrip(".")
        host = matching(self.hosts, server_name)
        if host is None or self.dir is None or not host.startswith("*."):
            return host
        try:
            dst = os.path.join(self.dir, normalize_host(server_name) + ".pem")
        except CertError:
            return None
        if not os.path.exists(dst):
            shutil.copyfile(os.path.join(self.dir, file_name(host)), dst + ".tmp")
            os.chmod(dst + ".tmp", 0o600)
            os.replace(dst + ".tmp", dst)
        return host


# ---- CLI -------------------------------------------------------------------------------------------------------
def die(msg):
    print(PRODUCT["cli"] + ": " + msg, file=sys.stderr)
    sys.exit(1)


def _when(epoch):
    return time.strftime("%Y-%m-%d", time.localtime(epoch)) if epoch else "?"


def main(argv):
    if len(argv) < 2:
        die("usage: tls client-cert list | add HOST FILE [--key KEY_FILE] [--password-stdin] | rm HOST")
    store, cmd, args = argv[0], argv[1], argv[2:]
    try:
        if cmd == "list" and not args:
            rows = entries(store)
            for r in rows:
                if "error" in r:
                    print("%-32s  unreadable: %s" % (r["host"], r["error"]))
                else:
                    print("%-32s  %s  expires %s%s" % (r["host"], r["subject"], _when(r["not_after"]),
                                                       "  (EXPIRED)" if r["expired"] else ""))
            if not rows:
                print("no client certificates (add one: %s tls client-cert add HOST FILE.p12 --password-stdin)" % PRODUCT["cli"])
            return
        if cmd == "add" and len(args) >= 2:
            host, path, rest = args[0], args[1], args[2:]
            key_path, ask_password = None, False
            while rest:
                if rest[0] == "--key" and len(rest) > 1:
                    key_path, rest = rest[1], rest[2:]
                elif rest[0] == "--password-stdin":
                    ask_password, rest = True, rest[1:]
                else:
                    die("tls client-cert add: unknown option %s" % rest[0])
            with open(path, "rb") as fh:
                data = fh.read(MAX_FILE + 1)
            key_data = None
            if key_path:
                with open(key_path, "rb") as fh:
                    key_data = fh.read(MAX_FILE + 1)
            password = sys.stdin.readline().rstrip("\r\n") if ask_password else None
            info = add(store, host, data, password, key_data)
            print("client certificate for %s: %s, expires %s%s" % (info["host"], info["subject"], _when(info["not_after"]),
                                                                     " (ALREADY EXPIRED)" if info["expired"] else ""))
            print("used from the next connection to that host — no restart")
            return
        if cmd == "rm" and len(args) == 1:
            host = normalize_host(args[0])
            if not remove(store, host):
                die("no client certificate for %s" % host)
            print("client certificate for %s removed" % host)
            return
    except (OSError, CertError) as e:
        die(str(e))
    die("usage: tls client-cert list | add HOST FILE [--key KEY_FILE] [--password-stdin] | rm HOST")


if __name__ == "__main__":
    main(sys.argv[1:])
