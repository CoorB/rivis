"""Test-only mitmproxy add-on: DNS for *.rebind.rivis-test answers a public address the first time and 127.0.0.1
afterwards (a DNS-rebinding attacker), and logs every lookup to $SHIM_LOG/dns-flip.log. Loaded by the harness's
mitmweb shim through SHIM_PRE_ADDON; never part of the product."""
import os
import socket

_orig = socket.getaddrinfo
_seen = {}


def _flip(host, port, *args, **kwargs):
    name = host.decode() if isinstance(host, bytes) else (host or "")
    if not name.endswith(".rebind.rivis-test"):
        return _orig(host, port, *args, **kwargs)
    _seen[name] = _seen.get(name, 0) + 1
    ip = "1.1.1.1" if _seen[name] == 1 else "127.0.0.1"
    with open(os.path.join(os.environ.get("SHIM_LOG", "/nonexistent"), "dns-flip.log"), "a") as fh:
        fh.write("%s %d %s\n" % (name, _seen[name], ip))
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, int(port or 0)))]


socket.getaddrinfo = _flip
