"""Measurements: in-page instrumentation (panel request timings, in-flight count, long tasks, unhandled rejections),
process memory, percentile maths and the per-minute buckets the report is built from."""
import math
import subprocess
import threading
import time

# Installed before the panel loads. Wraps fetch so every panel request (./proxy/api/* and the ./flows list) is timed
# and counted while it is in flight; drained by Ui.drain(). Nothing here changes what the page does.
INIT_JS = r"""
(() => {
  if (window.__soak) return;
  const S = window.__soak = { api: [], flows: [], inflight: 0, maxInflight: 0, rej: [], longtasks: [], toasts: [], errors: [] };
  const origFetch = window.fetch;
  const kind = (url) => /(^|\/)proxy\/api\//.test(url) ? "api" : (/(^|\/)flows(\?|$)/.test(url) ? "flows" : "");
  window.fetch = function (input, init) {
    const url = typeof input === "string" ? input : (input && input.url) || "";
    const method = ((init && init.method) || (input && input.method) || "GET").toUpperCase();
    const k = kind(url);
    if (!k || (k === "flows" && method !== "GET")) return origFetch.apply(this, arguments);
    const t0 = performance.now(), wall = Date.now();
    S.inflight++; if (S.inflight > S.maxInflight) S.maxInflight = S.inflight;
    const done = (status, bytes) => {
      S.inflight--;
      const rec = { t: wall, ms: Math.round(performance.now() - t0), status, bytes, url: url.replace(/^.*proxy\/api\//, ""), peak: S.inflight + 1 };
      (k === "api" ? S.api : S.flows).push(rec);
    };
    const p = origFetch.apply(this, arguments);
    p.then((r) => done(r.status, Number(r.headers.get("content-length") || -1)), () => done(0, 0));
    return p;
  };
  addEventListener("unhandledrejection", (e) => S.rej.push({ t: Date.now(), text: String(e.reason && (e.reason.stack || e.reason)).slice(0, 400) }));
  try { new PerformanceObserver((l) => l.getEntries().forEach((e) => S.longtasks.push({ t: Date.now(), ms: Math.round(e.duration), start: Math.round(Date.now() - (performance.now() - e.startTime)) }))).observe({ entryTypes: ["longtask"] }); } catch (e) { /* not supported */ }
})();
"""

TOAST_JS = r"""
() => {
  const root = document.querySelector('#proxy-panel-host') && document.querySelector('#proxy-panel-host').shadowRoot;
  const el = root && root.querySelector('#toast');
  if (!el) return false;
  if (el.__soakWatched) return true;
  el.__soakWatched = true;
  const note = () => { if (el.style.display !== 'none' && el.textContent) window.__soak.toasts.push({ t: Date.now(), text: el.textContent, err: el.classList.contains('err') }); };
  new MutationObserver(note).observe(el, { childList: true, subtree: true, attributes: true, characterData: true });
  return true;
}
"""

DRAIN_JS = """
() => { const S = window.__soak; if (!S) return null;
  const out = { api: S.api, flows: S.flows, rej: S.rej, longtasks: S.longtasks, peak: S.maxInflight };
  S.api = []; S.flows = []; S.rej = []; S.longtasks = []; S.maxInflight = S.inflight; return out; }
"""


LONGTASK_EVIDENCE_MS = 1000    # a long task this long is reported with its start time, the scenario running then and (when kept) a trace


def pct(values, q):
    if not values:
        return None
    v = sorted(values)
    return v[min(len(v) - 1, max(0, int(math.ceil(q / 100.0 * len(v))) - 1))]


def rss_mb(proc_pid):
    """Resident memory of the Rivis process group (mitmweb + its sidecars), like tests/perf/test_soak.py."""
    out = subprocess.run(["pgrep", "-g", str(proc_pid)], capture_output=True, text=True).stdout.split()
    total = 0
    for pid in sorted({proc_pid} | {int(x) for x in out}):
        raw = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
        total += int(raw or 0)
    return total / 1024.0


class Metrics:
    """Everything is stamped with seconds since the run began (t) and bucketed by minute for the report. Samples taken
    inside a fault window are kept but flagged, so the budgets can leave them out while the report still shows them."""

    def __init__(self, t0):
        self.t0 = t0
        self.lock = threading.Lock()
        self.fault_windows = []          # [start, end] in run seconds (end includes the recovery grace)
        self.panel = []                  # (t, op, ms, status, peak)
        self.flows_dl = []               # (t, ms, bytes, drawer_open)
        self.app = []                    # (t, ms, status, kind)
        self.probe = []                  # (t, direct_ms, proxy_ms)
        self.samples = []                # per-minute dicts: rss, heap, dom, flow_count, calls
        self.errors = []                 # (t, kind, text)
        self.longtasks = []              # (t_end, ms)
        self.longtask_events = []        # {start, end, ms} in run seconds, every long task >= LONGTASK_EVIDENCE_MS (evidence only)
        self.max_peak = []               # (t, peak in-flight panel requests)
        self.ws = []                     # (t, ok, frames)
        self.dropped = 0

    def now(self):
        return time.time() - self.t0

    def in_fault(self, t):
        return any(a <= t <= b for a, b in self.fault_windows)

    def minute(self, t):
        return int(t // 60)

    def add(self, name, row):
        with self.lock:
            getattr(self, name).append(row)

    def bucket(self, rows, idx, quiet=True, tcol=0):
        """Group rows by minute -> list of values at column idx (fault windows excluded unless quiet=False)."""
        out = {}
        for r in list(rows):
            if quiet and self.in_fault(r[tcol]):
                continue
            out.setdefault(self.minute(r[tcol]), []).append(r[idx])
        return out
