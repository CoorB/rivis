"""Test-only mitmdump script: asks the private-address guard's own decision helpers about hand-built flows (mitmproxy's
test helpers are not in the frozen build) and writes the answers as JSON to $GUARD_PROBE_OUT, then exits."""
import json
import os
import sys
from types import SimpleNamespace

from mitmproxy import ctx, http
from mitmproxy.proxy.mode_specs import ProxyMode

sys.path.insert(0, os.environ["GUARD_PROBE_ADDONS"])
import proxy_rules  # noqa: E402


def _flow(mode, headers, tls=True, replay=None):
    return SimpleNamespace(is_replay=replay, request=SimpleNamespace(headers=http.Headers(**headers)),
                           client_conn=SimpleNamespace(proxy_mode=ProxyMode.parse(mode), tls_established=tls))


def running():
    cs = {"sec_fetch_site": "cross-site"}
    out = {
        "regular_cross_site": proxy_rules.ProxyRules._cross_site_page(_flow("regular", cs)),
        "local_cross_site": proxy_rules.ProxyRules._cross_site_page(_flow("local:CoreSimulator", cs)),
        "regular_same_origin": proxy_rules.ProxyRules._cross_site_page(_flow("regular", {"sec_fetch_site": "same-origin"})),
        "replay_cross_site": proxy_rules.ProxyRules._cross_site_page(_flow("regular", cs, replay="request")),
        "local_plain": proxy_rules.ProxyRules._page_reachable(_flow("local:CoreSimulator", {}, tls=False)),
        "regular_plain": proxy_rules.ProxyRules._page_reachable(_flow("regular", {}, tls=False)),
    }
    with open(os.environ["GUARD_PROBE_OUT"], "w") as fh:
        json.dump(out, fh)
    ctx.master.shutdown()
