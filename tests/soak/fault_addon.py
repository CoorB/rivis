"""Test-only mitmproxy add-on for the soak's fault injection. Loaded through the harness's mitmweb shim
(SHIM_PRE_ADDON); inert unless the soak sends a call to the magic path, and never part of the product.

  GET http://<anything>/__soak_fault__?mode=freeze&s=15   the event loop sleeps 15 s: the proxy AND the panel API stop
                                                           answering (what a blocking user script does)
  GET http://<anything>/__soak_fault__?mode=slow&s=20     for 20 s every other call is answered 1.5 s late, the panel
                                                           stays responsive (an overloaded proxy)
"""
import asyncio
import time
from urllib.parse import parse_qs, urlsplit

from mitmproxy import http

PATH = "/__soak_fault__"


class SoakFault:
    def __init__(self):
        self.slow_until = 0.0

    async def request(self, flow: http.HTTPFlow):
        u = urlsplit(flow.request.path)
        if u.path == PATH:
            q = parse_qs(u.query)
            mode, secs = (q.get("mode") or ["freeze"])[0], float((q.get("s") or ["10"])[0])
            if mode == "slow":
                self.slow_until = time.time() + secs
                flow.response = http.Response.make(200, b"slow armed", {"Content-Type": "text/plain"})
            else:
                flow.response = http.Response.make(200, b"freeze over", {"Content-Type": "text/plain"})
                time.sleep(secs)            # deliberately blocking: this is the fault
            return
        if time.time() < self.slow_until:
            await asyncio.sleep(1.5)


addons = [SoakFault()]
