"""Rotating, redacted Rivis diagnostics independent of mitmweb's in-memory event log."""
import asyncio
import importlib
import logging
import os
import sys

from mitmproxy import ctx

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import proxy_common
importlib.reload(proxy_common)
from proxy_common import RotatingTextLog, STATE_ROOT, rotate_file


class _LogHandler(logging.Handler):
    """mitmproxy 12 no longer calls an add-on's `log` hook: warnings, errors and tracebacks reach only Python
    logging (and mitmweb.log, which bug-report does not collect). Feed them into the redacted rivis.log instead."""
    rivis_handler = True

    def __init__(self, writer):
        super().__init__(logging.WARNING)
        self.writer = writer

    def emit(self, record):
        try:
            self.writer.append(record.levelname, "%s: %s" % (record.name, self.format(record)))
        except Exception:      # a logging failure must never break a proxied call
            pass


def _detach():
    root = logging.getLogger()
    for h in [h for h in root.handlers if getattr(h, "rivis_handler", False)]:
        root.removeHandler(h)


class ProxyOperability:
    def __init__(self):
        self.writer = None
        self._rotate_task = None

    def load(self, loader):
        loader.add_option("proxy_log_dir", str, os.path.join(STATE_ROOT, "logs"), "directory for rotating Rivis logs")
        loader.add_option("proxy_log_max_bytes", int, 2 * 1024 * 1024, "bytes per Rivis log file before rotation")

    def configure(self, updated):
        if self.writer is None or "proxy_log_dir" in updated or "proxy_log_max_bytes" in updated:
            self.writer = RotatingTextLog(os.path.join(os.path.expanduser(ctx.options.proxy_log_dir), "rivis.log"),
                                          max_bytes=ctx.options.proxy_log_max_bytes, backups=3)
            _detach()                    # a reloaded add-on must not leave the old handler writing a second copy
            logging.getLogger().addHandler(_LogHandler(self.writer))

    def running(self):
        self.writer.append("info", "Rivis started")
        self._check_mitmweb_log()
        try:
            loop = asyncio.get_running_loop()
            self._rotate_task = loop.create_task(self._rotate_loop())
        except RuntimeError:
            pass

    async def _rotate_loop(self):
        while True:
            await asyncio.sleep(15)
            self._check_mitmweb_log()

    def _check_mitmweb_log(self):
        try:
            log_dir = os.path.expanduser(ctx.options.proxy_log_dir)
            mitm_log = os.path.join(log_dir, "mitmweb.log")
            if os.path.isfile(mitm_log) and os.path.getsize(mitm_log) >= ctx.options.proxy_log_max_bytes:
                rotate_file(mitm_log, max_bytes=ctx.options.proxy_log_max_bytes, backups=3, copytruncate=True)
        except Exception:
            pass

    def done(self):
        if self._rotate_task is not None:
            self._rotate_task.cancel()
        self._check_mitmweb_log()
        if self.writer is not None:
            self.writer.append("info", "Rivis stopped")
        _detach()


addons = [ProxyOperability()]
