"""Second layer of the Terms of Use gate (and of force update): while the current terms are not accepted, or a signed
release requires a newer version (update_policy.py), the proxy passes NOTHING.

The CLI asks before it starts the proxy, but some paths start it with nobody at a terminal: the Mac app opened from
Finder, an in-app update's restart, `rivis rollback`. Those start "locked": every call is answered locally with an
explanation (HTTP) or refused (CONNECT, raw TCP/UDP), and the Rivis window shows the terms until the user agrees or
declines. Loaded first, so no rule, mock or script runs before it. The check is two stat() calls per call.
"""
import os
import time

from mitmproxy import http

import terms
import update_policy

MESSAGE = ("Rivis is locked: the Terms of Use have not been accepted on this Mac. Open the Rivis window (or run "
           "`rivis terms` in a terminal), read them and agree; until then Rivis passes no traffic.\n")
UPDATE_MESSAGE = "Rivis is locked: an update is required (%s). Until then Rivis passes no traffic.\n"
POLICY_EVERY = 60.0         # the signed policy is re-read (and its signature checked) at most once a minute


class ProxyTerms:
    def __init__(self):
        self._key = None
        self._ok = False
        self._policy_at = 0.0
        self._policy = None          # reason text while an update is required, else None

    def _update_required(self):
        now = time.monotonic()
        try:      # re-read at once when the kept manifest changes (an update check), else once a minute (deadlines)
            st = os.stat(update_policy.MANIFEST)
            key = (st.st_mtime_ns, st.st_size, st.st_ino)
        except OSError:
            key = None
        if key != getattr(self, "_policy_key", None) or now - self._policy_at >= POLICY_EVERY:
            self._policy_key, self._policy_at = key, now
            try:
                st = update_policy.status()
                self._policy = st["reason"] if st["state"] == update_policy.REQUIRED else None
            except Exception:          # noqa: BLE001 - a broken policy file must not take the proxy down
                self._policy = None
        return self._policy

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

    def _locked(self):
        """None when traffic may pass, else the text the app gets."""
        if not self._accepted():
            return MESSAGE
        reason = self._update_required()
        return UPDATE_MESSAGE % reason if reason else None

    def _refuse(self, flow, text):
        flow.response = http.Response.make(403, text, {"Content-Type": "text/plain; charset=utf-8",
                                                       "Connection": "close"})
        flow.comment = "blocked: " + ("Terms of Use not accepted" if text == MESSAGE else "update required")
        flow.metadata["rivis_terms_locked"] = True

    def http_connect(self, flow):
        text = self._locked()
        if text:
            self._refuse(flow, text)

    def requestheaders(self, flow):
        text = self._locked()
        if text and flow.response is None:
            self._refuse(flow, text)

    def request(self, flow):
        text = self._locked()
        if text and flow.response is None:
            self._refuse(flow, text)

    def tcp_start(self, flow):
        if self._locked():
            flow.kill()

    def udp_start(self, flow):
        if self._locked():
            flow.kill()


addons = [ProxyTerms()]
