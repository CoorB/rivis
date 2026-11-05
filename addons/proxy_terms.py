"""Second layer of the Terms of Use gate: while the current terms are not accepted, the proxy passes NOTHING.

The CLI asks before it starts the proxy, but some paths start it with nobody at a terminal: the Mac app opened from
Finder, an in-app update's restart, `rivis rollback`. Those start "locked": every call is answered locally with an
explanation (HTTP) or refused (CONNECT, raw TCP/UDP), and the Rivis window shows the terms until the user agrees or
declines. Loaded first, so no rule, mock or script runs before it. The check is two stat() calls per call.
"""
import os

from mitmproxy import http

import terms

MESSAGE = ("Rivis is locked: the Terms of Use have not been accepted on this Mac. Open the Rivis window (or run "
           "`rivis terms` in a terminal), read them and agree; until then Rivis passes no traffic.\n")


class ProxyTerms:
    def __init__(self):
        self._key = None
        self._ok = False

    def _accepted(self):
        key = []
        for path in (terms.terms_path(), terms.record_path()):
            try:
                st = os.stat(path)
                key.append((st.st_mtime_ns, st.st_size, st.st_ino))
            except OSError:
                key.append(None)
        key = tuple(key)
        if key != self._key:
            self._key, self._ok = key, terms.accepted()
        return self._ok

    def _refuse(self, flow):
        flow.response = http.Response.make(403, MESSAGE, {"Content-Type": "text/plain; charset=utf-8",
                                                          "Connection": "close"})
        flow.comment = "blocked: Terms of Use not accepted"
        flow.metadata["rivis_terms_locked"] = True

    def http_connect(self, flow):
        if not self._accepted():
            self._refuse(flow)

    def requestheaders(self, flow):
        if not self._accepted() and flow.response is None:
            self._refuse(flow)

    def request(self, flow):
        if not self._accepted() and flow.response is None:
            self._refuse(flow)

    def tcp_start(self, flow):
        if not self._accepted():
            flow.kill()

    def udp_start(self, flow):
        if not self._accepted():
            flow.kill()


addons = [ProxyTerms()]
