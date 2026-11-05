"""Test-only mitmproxy add-on: DNS for *.vpnflip.rivis-test answers a private (VPN) address the first time and a
public TEST-NET address afterwards. Models a FortiClient drop: the name stops resolving inside the tunnel.
Loaded through SHIM_PRE_ADDON; never part of the product."""
import socket

_orig = socket.getaddrinfo
_seen = {}


def _flip(host, port, *args, **kwargs):
    name = host.decode() if isinstance(host, bytes) else (host or "")
    if name.endswith(".vpnflip.rivis-test"):
        _seen[name] = _seen.get(name, 0) + 1
        ip = "10.55.1.1" if _seen[name] == 1 else "1.1.1.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, int(port or 0)))]
    return _orig(host, port, *args, **kwargs)


socket.getaddrinfo = _flip
