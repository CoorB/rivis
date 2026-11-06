"""Second layer of the Terms of Use gate (and of IT approval and force update): while the current terms are not
accepted, IT's approval is not confirmed (access.py), or a signed release requires a newer version (update_policy.py),
the proxy passes NOTHING.

The CLI asks before it starts the proxy, but some paths start it with nobody at a terminal: the Mac app opened from
Finder, an in-app update's restart, `rivis rollback`. Those start "locked": every call is answered locally with an
explanation (HTTP) or refused (CONNECT, raw TCP/UDP), and the Rivis window shows the terms until the user agrees or
declines. Loaded first, so no rule, mock or script runs before it. The check is two stat() calls per call.
"""
import os
import time

from mitmproxy import http

import access
import terms
import update_policy

MESSAGE = ("Rivis is locked: the Terms of Use have not been accepted on this Mac. Open the Rivis window (or run "
           "`rivis terms` in a terminal), read them and agree; until then Rivis passes no traffic.\n")
UPDATE_MESSAGE = "Rivis is locked: an update is required (%s). Until then Rivis passes no traffic.\n"
ACCESS_MESSAGE = "Rivis is locked: %s. Until then Rivis passes no traffic.\n"
POLICY_EVERY = 60.0         # the signed policy is re-read (and its signature checked) at most once a minute


class ProxyTerms:
    def __init__(self):
        self._key = None
        self._ok = False
        self._policy_at = 0.0
        self._policy = None          # reason text while an update is required, else None
        self._access_at = 0.0
        self._access_key = ()
        self._access = None          # reason text while IT's approval is not confirmed, else None

    def _not_approved(self):
        """Re-read when the approval record changes, else once a minute (the offline allowance runs out by itself)."""
        now = time.monotonic()
        try:
            st = os.stat(access.record_path())
            key = (st.st_mtime_ns, st.st_size, st.st_ino)
        except OSError:
            key = None
        if key != self._access_key or now - self._access_at >= POLICY_EVERY:
            self._access_key, self._access_at = key, now
            try:
                st = access.status()
                self._access = None if st["allowed"] else st["reason"]
            except Exception as e:     # noqa: BLE001 - fail closed: an unreadable record is not an approval
                self._access = "the IT approval record could not be read (%s)" % e
        return self._access

    def _update_required(self):
        now = time.monotonic()
        try:      # re-read at once when the kept manifest changes (an update check), else once a minute (deadlines)
            st = os.stat(update_policy.MANIFEST)
            key = (st.st_mtime_ns, st.st_size, st.st_ino)
            sg = os.stat(update_policy.SIGNATURE)           # the manifest and its signature are written one after the other
            key += (sg.st_mtime_ns, sg.st_size, sg.st_ino)
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
                key.append((st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_ino))   # ctime: a chmod is a change too
            except OSError:
                key.append(None)
        key = tuple(key)
        if key != self._key:
            try:
                ok = terms.accepted()
            except Exception:          # noqa: BLE001 - fail closed: a record that cannot be read is not an agreement
                ok = False
            self._key, self._ok = key, ok
        return self._ok

    def _locked(self):
        """None when traffic may pass, else (why, the text the app gets)."""
        if not self._accepted():
            return "Terms of Use not accepted", MESSAGE
        reason = self._not_approved()
        if reason:
            return "IT approval not confirmed", ACCESS_MESSAGE % reason
        reason = self._update_required()
        return ("update required", UPDATE_MESSAGE % reason) if reason else None

    def _refuse(self, flow, lock):
        why, text = lock
        flow.response = http.Response.make(403, text, {"Content-Type": "text/plain; charset=utf-8",
                                                       "Connection": "close"})
        flow.comment = "blocked: " + why
        flow.metadata["rivis_terms_locked"] = True

    def http_connect(self, flow):
        lock = self._locked()
        if lock:
            self._refuse(flow, lock)

    def requestheaders(self, flow):
        lock = self._locked()
        if lock and flow.response is None:
            self._refuse(flow, lock)

    def request(self, flow):
        lock = self._locked()
        if lock and flow.response is None:
            self._refuse(flow, lock)

    def tcp_start(self, flow):
        if self._locked():
            flow.kill()

    def udp_start(self, flow):
        if self._locked():
            flow.kill()


addons = [ProxyTerms()]
