"""Soak configuration: every knob is an environment variable so run.sh, CI and the release gate share one interface."""
import os


def _num(name, default, cast=float):
    raw = os.environ.get(name, "")
    try:
        return cast(raw) if raw.strip() else default
    except ValueError:
        raise SystemExit("soak: %s=%r is not a number" % (name, raw))


class Config:
    def __init__(self):
        self.minutes = _num("SOAK_MINUTES", 25.0)
        self.smoke = self.minutes <= 5
        self.seed = _num("SOAK_SEED", 99, int)
        self.rate = _num("SOAK_RATE", 3.5)                       # mean app calls per second (2-5 with the wave below)
        self.prefill = _num("SOAK_PREFILL", 0, int)               # calls sent at full speed before the run starts
        self.workers = _num("SOAK_WORKERS", 14, int)
        # human pacing: every pause is drawn from 200-2000 ms; the smoke run halves it so 3 minutes cover every scenario
        self.pause_scale = _num("SOAK_PAUSE_SCALE", 0.5 if self.smoke else 1.0)
        self.viewport = (1512, 837)
        self.trace = os.environ.get("SOAK_TRACE", "1") != "0"
        self.out = os.environ.get("SOAK_OUT", "")
        # documented timeouts / budgets (README "What the gate asserts")
        self.action_deadline = _num("SOAK_ACTION_DEADLINE", 10.0)  # s: a click must complete or show an error by then
        self.lost_deadline = _num("SOAK_LOST_DEADLINE", 15.0)      # s: "can't reach Rivis" banner while the proxy is frozen
        self.recover_deadline = _num("SOAK_RECOVER_DEADLINE", 20.0)  # s after a fault ends: panel answers again
        self.panel_p95_ms = _num("SOAK_PANEL_P95_MS", 1500.0)
        self.added_p95_ms = _num("SOAK_ADDED_P95_MS", 250.0)
        self.rss_growth_mb = _num("SOAK_RSS_GROWTH_MB", 400.0)
        self.heap_growth_mb = _num("SOAK_HEAP_GROWTH_MB", 150.0)
        self.max_inflight = _num("SOAK_MAX_INFLIGHT", 3, int)
        self.longtask_ms = _num("SOAK_LONGTASK_MS", 4000.0)
        self.flow_cap = _num("SOAK_MAX_FLOWS", 50000, int)         # keep the product's own trim out of the way
        # fault schedule: (fraction of the run, mode, seconds)
        if self.smoke:
            self.faults = [(0.3, "freeze", 20), (0.62, "slow", 10)]
        else:
            self.faults = [(0.2, "freeze", 20), (0.45, "slow", 20), (0.7, "freeze", 30)]
        if os.environ.get("SOAK_FAULTS", "") == "0":
            self.faults = []
