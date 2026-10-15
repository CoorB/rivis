"""Rotating, redacted Rivis diagnostics independent of mitmweb's in-memory event log."""
import importlib
import os
import sys

from mitmproxy import ctx

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import proxy_common
importlib.reload(proxy_common)
from proxy_common import RotatingTextLog, STATE_ROOT


class ProxyOperability:
    def __init__(self):
        self.writer = None

    def load(self, loader):
        loader.add_option("proxy_log_dir", str, os.path.join(STATE_ROOT, "logs"), "directory for rotating Rivis logs")
        loader.add_option("proxy_log_max_bytes", int, 2 * 1024 * 1024, "bytes per Rivis log file before rotation")

    def configure(self, updated):
        if self.writer is None or "proxy_log_dir" in updated or "proxy_log_max_bytes" in updated:
            self.writer = RotatingTextLog(os.path.join(os.path.expanduser(ctx.options.proxy_log_dir), "rivis.log"),
                                          max_bytes=ctx.options.proxy_log_max_bytes, backups=3)

    def running(self):
        self.writer.append("info", "Rivis started")

    def log(self, entry):
        self.writer.append(getattr(entry, "level", "info"), getattr(entry, "msg", entry))

    def done(self):
        if self.writer is not None:
            self.writer.append("info", "Rivis stopped")


addons = [ProxyOperability()]
