"""Real-use soak gate. See tests/soak/README.md. Run it through tests/soak/run.sh (hermetic snapshot, leftover check,
exit status); this file does the work: Rivis + a NEO-like upstream + streaming traffic + a Playwright-driven panel with
real input + fault injection + health sampling + the report.

Exit status: 0 = every scenario and health budget passed, 1 = at least one failed, 2 = the harness itself broke.
"""
import datetime
import itertools
import json
import os
import random
import subprocess
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
import harness                                  # noqa: E402
from harness import Instance, Suite             # noqa: E402

import health                                   # noqa: E402
from config import Config                       # noqa: E402
from driver import SoakFail, Ui, check          # noqa: E402
from faults import Faults                       # noqa: E402
from neo_upstream import NeoUpstream            # noqa: E402
from report import build_report                 # noqa: E402
from scenarios import Scenarios, Skip           # noqa: E402
from traffic import Traffic                     # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError as exc:                      # pragma: no cover
    sys.exit("soak: Playwright is not importable (%s). pip3 install --user playwright && python3 -m playwright install chromium" % exc)


class World:
    """Server-side clean-up through the panel API (not the UI): whatever a scenario left behind is removed so the next one
    starts clean. Never part of an assertion."""

    def __init__(self, s):
        self.s = s

    def reset(self):
        p = self.s.inst.panel
        try:
            st = p.get_json("/proxy/api/state")
        except Exception:                                   # noqa: BLE001 - a frozen proxy: nothing to clean yet
            return
        try:
            for x in st["paused"]:
                p.post("paused_skip", {"id": x["id"], "edits": {}}, timeout=10)
            for b in st["breakpoints"]:
                p.post("bp_delete", {"name": b["name"]}, timeout=10)
            for r in st["rules"]:
                p.post("delete", {"name": r["name"]}, timeout=10)
            for lst in ("allow", "ignore"):
                for pat in st["tls"][lst]:
                    p.post("tls_update", {"list": lst, "action": "remove", "pattern": pat}, timeout=10)
            if st["tls"]["mode"] != "all":
                p.post("tls_set", {"mode": "all"}, timeout=10)
            if st["throttle"] != "off":
                p.post("profile", {"id": "off", "match": ""}, timeout=10)
            if st["no_cache"]:
                p.post("nocache", {"on": False}, timeout=10)
            if st["focus_host"]:
                p.post("focus_host", {"host": None}, timeout=10)
            if st["source"]:
                p.post("source", {"source": None}, timeout=10)
            if st["collections"]["recording"]:
                p.post("coll_stop", {}, timeout=10)
            for c in st["collections"]["items"]:
                p.post("coll_delete", {"name": c["name"]}, timeout=10)
            for x in st["sessions"]:
                p.post("sess_delete", {"name": x["name"]}, timeout=10)
            for n in st["composer"]["names"]:
                p.post("compose_delete", {"name": n}, timeout=10)
        except Exception:                                   # noqa: BLE001
            pass


class Recorder:
    def __init__(self, s):
        self.s = s
        self.stats = {}                 # name -> {"pass","fail","skip"}
        self.failures = []
        self.nfail = 0
        self.timeline = []              # (start_s, end_s, key) of every scenario run: says what ran when a long task started
        self.slow_runs = []             # runs a long task (>= LONGTASK_EVIDENCE_MS) landed in: {scenario, t, screenshot, trace}
        self.nslow = 0

    def run(self, name, fn, pos=None):
        s = self.s
        key = name + ("@" + pos if pos else "")
        st = self.stats.setdefault(key, {"pass": 0, "fail": 0, "skip": 0})
        t_rel = s.metrics.now()
        if s.cfg.trace:
            try:
                s.ctx.tracing.start_chunk(title=key)
            except Exception:                               # noqa: BLE001
                pass
        err = None
        try:
            fn()
            st["pass"] += 1
        except Skip as exc:
            st["skip"] += 1
            s.skips.append((t_rel, key, str(exc)))
            err = "skip"
        except Exception as exc:                            # noqa: BLE001 - SoakFail, Playwright errors, anything
            st["fail"] += 1
            err = exc
            self.capture(key, t_rel, exc)
        finally:
            self.timeline.append((round(t_rel, 2), round(s.metrics.now(), 2), key))
            slow = self.keep_slow(key, t_rel)
            if s.cfg.trace and not (err and err != "skip"):
                try:
                    s.ctx.tracing.stop_chunk(path=slow["trace_abs"] if slow and slow["trace_abs"] else None)
                except Exception:                           # noqa: BLE001
                    if slow:
                        slow["trace"] = ""
            elif slow:
                slow["trace"] = "(this run also failed: see its failure trace)"
        if err and err != "skip":
            s.normalize(hard=True)
        return err is None

    def keep_slow(self, key, t_rel):
        """A long task >= 1 s that ended inside this run: keep its screenshot and the run's trace (normally dropped when the run
        passed). Evidence only: the 4000 ms budget does not look at it."""
        s = self.s
        try:
            s.ui.drain()
        except Exception:                                   # noqa: BLE001
            return None
        events = [e for e in list(s.metrics.longtask_events) if e["end"] >= t_rel]
        if not events:
            return None
        self.nslow += 1
        stem = "%03d-longtask-%s" % (self.nslow, key.replace("@", "-at-").replace(".", "_"))
        d = os.path.join(s.out, "failures")
        os.makedirs(d, exist_ok=True)
        shot = os.path.join(d, stem + ".png")
        trace = os.path.join(d, stem + "-trace.zip")
        try:
            s.page.screenshot(path=shot, timeout=8000)
        except Exception:                                   # noqa: BLE001
            shot = ""
        rec = {"scenario": key, "t": round(t_rel, 1), "events": events, "screenshot": os.path.relpath(shot, s.out) if shot else "",
               "trace": os.path.relpath(trace, s.out) if s.cfg.trace else "", "trace_abs": trace if s.cfg.trace else ""}
        self.slow_runs.append(rec)
        print("  LONG TASK %-30s t=%5.0fs  %s" % (key, t_rel, ", ".join("%d ms (started %.0fs)" % (e["ms"], e["start"]) for e in events)), flush=True)
        return rec

    def capture(self, key, t_rel, exc):
        s = self.s
        self.nfail += 1
        stem = "%03d-%s" % (self.nfail, key.replace("@", "-at-").replace(".", "_"))
        d = os.path.join(s.out, "failures")
        os.makedirs(d, exist_ok=True)
        shot = os.path.join(d, stem + ".png")
        trace = os.path.join(d, stem + "-trace.zip")
        try:
            s.page.screenshot(path=shot, timeout=8000)
        except Exception:                                   # noqa: BLE001
            shot = ""
        if s.cfg.trace:
            try:
                s.ctx.tracing.stop_chunk(path=trace)
            except Exception:                               # noqa: BLE001
                trace = ""
        else:
            trace = ""
        tb = traceback.format_exception_only(type(exc), exc)
        msg = (str(exc) or tb[-1]).strip().splitlines()[0][:600] if str(exc).strip() else tb[-1].strip()[:600]
        self.failures.append({"scenario": key, "t": round(t_rel, 1), "message": msg, "type": type(exc).__name__,
                              "screenshot": os.path.relpath(shot, s.out) if shot else "", "trace": os.path.relpath(trace, s.out) if trace else "",
                              "lost_bar": self._safe(lambda: s.ui.lost_bar()), "menu_open": self._safe(lambda: s.ui.menu_open()),
                              "toasts": self._safe(lambda: [t["text"][:100] for t in s.ui.toasts_since(s.ui.now_ms() - 15000)][-3:])})
        print("  FAIL %-34s t=%5.0fs  %s" % (key, t_rel, msg[:160]), flush=True)

    @staticmethod
    def _safe(fn):
        try:
            return fn()
        except Exception:                                   # noqa: BLE001
            return None


class Soak:
    def __init__(self, cfg):
        self.cfg = cfg
        self.rng = random.Random(cfg.seed)
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.out = cfg.out or os.path.join(harness.ARTIFACTS, "soak", stamp)
        os.makedirs(self.out, exist_ok=True)
        self.t0 = time.time()
        self.t0_ms = self.t0 * 1000.0
        self.metrics = health.Metrics(self.t0)
        self.skips = []
        self.dialog_text = ""
        self.drawer_flag = False
        self._id = 1000
        self.last_drain = 0.0
        self.next_sample = 0.0
        self.sample_no = 0
        self.faults_done = []
        self.harness_notes = []
        self.pw = self.browser = self.ctx = self.page = self.cdp = None

    def next_id(self):
        self._id += 1
        return self._id

    # -- setup / teardown ---------------------------------------------------------------------------------------------
    def setup(self):
        cfg = self.cfg
        suite = Suite.get()
        self.suite = suite
        self.up = NeoUpstream(suite.root)
        suite.upstreams.append(self.up)
        allow = r"^(127\.0\.0\.1|localhost|[a-z0-9.-]+\.localhost)$"
        self.inst = Instance(suite, "soak", allow_private=False,
                             start_args=["--insecure", "--allow-private-hosts", allow],
                             extra_env={"RIVIS_MAX_FLOWS": str(cfg.flow_cap), "SHIM_PRE_ADDON": os.path.join(HERE, "fault_addon.py")}).start()
        self.world = World(self)
        self.rec = Recorder(self)
        old_tmp = os.environ.get("TMPDIR")                  # the browser's profile dir lands under run.sh's own folder: its leftovers are provable
        if os.environ.get("SOAK_BROWSER_TMP"):
            os.environ["TMPDIR"] = os.environ["SOAK_BROWSER_TMP"]
        try:
            self.pw = sync_playwright().start()
        finally:
            if old_tmp is None:
                os.environ.pop("TMPDIR", None)
            else:
                os.environ["TMPDIR"] = old_tmp
        self.browser = self.pw.chromium.launch(args=["--enable-precise-memory-info"])
        self.ctx = self.browser.new_context(viewport={"width": cfg.viewport[0], "height": cfg.viewport[1]})
        self.ctx.grant_permissions(["clipboard-read", "clipboard-write"], origin="http://127.0.0.1:%d" % self.inst.web_port)
        self.ctx.add_init_script("try { localStorage.setItem('rivis-welcome', 'done') } catch (e) {}")
        self.ctx.add_init_script(health.INIT_JS)
        self.ctx.add_init_script(harness.PANEL_AUTO_ANSWER_JS)      # the panel's own questions, answered yes
        if cfg.trace:
            self.ctx.tracing.start(screenshots=True, snapshots=os.environ.get("SOAK_TRACE_SNAPSHOTS", "0") == "1", sources=False)
        self.page = self.ctx.new_page()
        self.page.on("pageerror", lambda e: self.metrics.add("errors", (self.metrics.now(), "pageerror", str(e)[:400])))
        def on_console(m):
            if m.type != "error":
                return
            # Chrome's own "Failed to load resource: ... status of 4xx" line is a network log, not a script error: kept apart
            kind = "http-status" if m.text.startswith("Failed to load resource") else "console.error"
            self.metrics.add("errors", (self.metrics.now(), kind, "%s @ %s" % (m.text[:300], m.location.get("url", "")[-60:])))
        self.page.on("console", on_console)
        self.page.on("dialog", self._dialog)
        self.cdp = self.ctx.new_cdp_session(self.page)
        self.ui = Ui(self)
        self.sc = Scenarios(self)
        self.faults = Faults(self)
        self.traffic = Traffic(cfg, self.inst, self.up, self.metrics, cfg.seed)
        for i in range(8):                                  # the call list only exists once there is a call
            self.inst.fetch("http://backbase-edge-sit.localhost:%d/api/user-manager/client-api/v2/users/me?i=%d" % (self.up.http_port, i))
        self.open_page()

    def answer_with(self, text):
        """The text the next panel question that asks for one is answered with (Save as…)."""
        self.dialog_text = text
        self.page.evaluate("t => { window.__rivisAnswer = t; }", text)

    def _dialog(self, d):
        try:
            d.accept(self.dialog_text) if d.type == "prompt" else d.accept()
        except Exception:                                   # noqa: BLE001
            pass

    def open_page(self):
        self.page.goto("http://127.0.0.1:%d/?token=%s" % (self.inst.web_port, self.inst.password))
        self.page.wait_for_selector("#fab", timeout=30000)
        self.page.wait_for_selector(".flow-table", timeout=30000)
        self.ui.ensure_toast_log()

    def teardown(self):
        for fn in (lambda: self.traffic.stop(), lambda: self.ctx.tracing.stop() if self.cfg.trace else None, lambda: self.ctx.close(),
                   lambda: self.browser.close(), lambda: self.pw.stop(), lambda: self.inst.stop()):
            try:
                fn()
            except Exception:                               # noqa: BLE001
                pass

    # -- housekeeping -------------------------------------------------------------------------------------------------
    def normalize(self, hard=False):
        ui = self.ui
        try:
            for _ in range(3):
                if ui.menu_open() or ui.sheet_open("pause") or ui.sheet_open("help") or ui.sheet_open("welcome"):
                    ui.key("Escape")
                    self.page.wait_for_timeout(150)
            self.page.evaluate("1")
            if hard and ui.drawer_open():
                ui.close_tools()
        except Exception:                                   # noqa: BLE001
            try:
                self.page.reload()
                self.page.wait_for_selector("#fab", timeout=30000)
                self.ui.ensure_toast_log()
            except Exception as exc:                        # noqa: BLE001
                self.harness_notes.append("page did not come back after a reload: %s" % exc)
        if not self.metrics.in_fault(self.metrics.now()):
            self.world.reset()

    def tick(self):
        now = time.time()
        if now - self.last_drain >= 3.0:
            self.last_drain = now
            self.ui.drain()
            self.ui.ensure_toast_log()
            try:
                self.drawer_flag = self.ui.drawer_open()
            except Exception:                               # noqa: BLE001
                pass
        if now - self.t0 >= self.next_sample:
            self.next_sample = (self.sample_no + 1) * 60.0
            self.sample()

    def sample(self):
        m = self.metrics
        t = m.now()
        rec = {"t": round(t, 1), "minute": self.sample_no, "calls": self.traffic.sent, "fault": m.in_fault(t)}
        try:
            rec["rss_mb"] = round(health.rss_mb(self.inst.proc.pid), 1) if not rec["fault"] else None
        except Exception:                                   # noqa: BLE001
            rec["rss_mb"] = None
        try:
            self.cdp.send("HeapProfiler.collectGarbage")
            rec["heap_mb"] = round(self.page.evaluate("performance.memory ? performance.memory.usedJSHeapSize / 1048576 : -1"), 1)
            rec["dom"] = self.page.evaluate("document.getElementsByTagName('*').length")
        except Exception:                                   # noqa: BLE001
            rec["heap_mb"] = rec["dom"] = None
        try:
            rec["flow_count"] = self.inst.panel.get_json("/proxy/api/state")["flow_count"] if not rec["fault"] else None
        except Exception:                                   # noqa: BLE001
            rec["flow_count"] = None
        m.add("samples", rec)
        self.sample_no += 1
        print("  [%4.1f min] calls=%d flows=%s rss=%sMB heap=%sMB failures=%d" % (t / 60.0, rec["calls"], rec["flow_count"], rec["rss_mb"], rec["heap_mb"],
                                                                              self.rec.nfail), flush=True)

    # -- the loop -----------------------------------------------------------------------------------------------------
    def units(self):
        sc = self.sc
        menu = [("menu.map", sc.menu_map), ("menu.pause", sc.menu_pause), ("menu.repeat", sc.menu_repeat), ("menu.edit_repeat", sc.menu_edit_repeat),
                ("menu.compare_a", sc.menu_compare_a), ("menu.copy_curl", sc.menu_curl), ("menu.copy_url", sc.menu_url),
                ("menu.host_focus", sc.menu_host_focus), ("menu.stop_decrypt", sc.menu_tls), ("menu.delete", sc.menu_delete)]
        tabs = [("tab.call", sc.tab_call), ("tab.compose", sc.tab_compose), ("tab.map_local", sc.tab_map), ("tab.breakpoints", sc.tab_breakpoints),
                ("tab.network", sc.tab_network), ("tab.collections", sc.tab_collections), ("tab.compare", sc.tab_compare),
                ("tab.sessions", sc.tab_sessions), ("tab.scripts_devices", sc.tab_open_only)]
        misc = [("list.scroll_top", sc.scroll_top), ("list.scroll_end", sc.scroll_end), ("list.scroll_middle", sc.scroll_middle),
                ("list.select_details", sc.select_details), ("kbd.shortcuts", sc.keyboard), ("filter.search", sc.filter_search),
                ("source.menu", sc.source_menu), ("idle.polling", sc.idle_polling)]
        return menu, tabs, misc

    def run(self):
        cfg = self.cfg
        self.setup()
        print("soak: out=%s  minutes=%s seed=%s rate=%s/s  rivis web :%d proxy :%d" % (self.out, cfg.minutes, cfg.seed, cfg.rate, self.inst.web_port,
                                                                                    self.inst.proxy_port), flush=True)
        if cfg.prefill:
            self.traffic.prefill(cfg.prefill)
        self.t0 = time.time()
        self.t0_ms = self.t0 * 1000.0
        self.metrics.t0 = self.t0
        self.traffic.start()
        menu, tabs, misc = self.units()
        duration = cfg.minutes * 60.0
        # first pass interleaves the three families so a short run still touches each; later passes are shuffled (seeded)
        order = []
        for a, b, c in itertools.zip_longest(menu, tabs, misc):
            order += [x for x in (a, b, c) if x]
        positions = itertools.cycle(["bottom", "top", "middle"])
        pending = list(cfg.faults)
        full_session_done = cfg.smoke
        n = 0
        try:
            while time.time() - self.t0 < duration:
                el = time.time() - self.t0
                if pending and el >= pending[0][0] * duration:
                    frac, mode, secs = pending.pop(0)
                    print("  fault: %s %ds at %.1f min" % (mode, secs, el / 60), flush=True)
                    self.faults_done.append({"mode": mode, "secs": secs, "at_s": round(el, 1)})
                    try:
                        (self.faults.freeze if mode == "freeze" else self.faults.slow)(secs)
                    except Exception as exc:                # noqa: BLE001 - the fault run itself broke: record, keep soaking
                        self.rec.failures.append({"scenario": "fault.%s.setup" % mode, "t": round(self.metrics.now(), 1), "message": str(exc)[:500],
                                                  "type": type(exc).__name__, "screenshot": "", "trace": "", "lost_bar": None, "menu_open": None, "toasts": []})
                        self.rec.stats.setdefault("fault.%s.setup" % mode, {"pass": 0, "fail": 0, "skip": 0})["fail"] += 1
                        self.normalize(hard=True)
                    continue
                if not full_session_done and el >= 0.55 * duration:
                    full_session_done = True
                    self.rec.run("sess.save_whole_capture", self.sc.session_full)
                    continue
                if n and n % len(order) == 0:
                    self.rng.shuffle(order)
                name, fn = order[n % len(order)]
                n += 1
                self.normalize()
                pos = next(positions) if name.startswith("menu.") else None
                self.rec.run(name, (lambda f=fn, p=pos: f(p)), pos=pos)
                self.tick()
        finally:
            self.traffic.stop()
            self.ui.drain()
            self.sample()
        self.world.reset()

    def finish(self):
        return build_report(self)


def main():
    cfg = Config()
    s = Soak(cfg)
    code = 2
    try:
        s.run()
        code = s.finish()
    except Exception:                                       # noqa: BLE001
        traceback.print_exc()
        s.harness_notes.append("harness crashed: " + traceback.format_exc().strip().splitlines()[-1])
        try:
            code = max(code, build_report(s, crashed=True))
        except Exception:                                   # noqa: BLE001
            traceback.print_exc()
            code = 2
    finally:
        s.teardown()
    return code


if __name__ == "__main__":
    sys.exit(main())
