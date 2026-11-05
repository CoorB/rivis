"""Test-only: ask ProxyRules whether an HTTPS DNS spoof still pins when the app's host has a trailing FQDN
dot. mitmproxy's interpreter has proxy_rules; system /usr/bin/python3 does not. Writes JSON to $DNS_SPOOF_PIN_OUT."""
import json
import os
import sys
from types import SimpleNamespace

from mitmproxy import ctx

sys.path.insert(0, os.environ["DNS_SPOOF_PIN_ADDONS"])
import proxy_rules  # noqa: E402


async def running():
    rules = proxy_rules.ProxyRules.__new__(proxy_rules.ProxyRules)
    rules.dns_spoof = {"spoof.example.test": "10.0.0.9"}
    rules._https_pins = {}
    flow = SimpleNamespace(
        metadata={},
        comment="",
        request=SimpleNamespace(host="spoof.example.test.", port=8443, scheme="https"),
        client_conn=SimpleNamespace(id="client-1"),
    )
    applied = await rules._apply_dns_spoof(flow)
    data = SimpleNamespace(
        client=SimpleNamespace(id="client-1"),
        server=SimpleNamespace(address=("spoof.example.test.", 8443), sni=None),
    )
    rules.server_connect(data)
    out = {
        "applied": bool(applied),
        "address": list(data.server.address),
        "sni": data.server.sni,
        "pin_keys": [[k[0], k[1], k[2]] for k in rules._https_pins.keys()],
    }
    with open(os.environ["DNS_SPOOF_PIN_OUT"], "w") as fh:
        json.dump(out, fh)
    ctx.master.shutdown()
