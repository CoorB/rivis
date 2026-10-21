"""report.md + report.json: scenario counts, every failure (screenshot, trace), health budgets, per-minute tables."""
import collections
import datetime
import json
import os
import re
import subprocess
import time

import health
from health import pct

BARS = "▁▂▃▄▅▆▇█"


def spark(values):
    vals = [v for v in values if v is not None]
    if not vals:
        return ""
    lo, hi = min(vals), max(vals)
    return "".join("·" if v is None else BARS[0 if hi == lo else int((v - lo) / (hi - lo) * 7)] for v in values)


def fmt(v, nd=0):
    return "–" if v is None else ("%.*f" % (nd, v))


def table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def family(key):
    return key.split("@")[0]


def signature(msg):
    return re.sub(r"\d+(\.\d+)?", "N", msg)[:140]


def git(*args):
    try:
        return subprocess.run(["git"] + list(args), capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__))).stdout.strip()
    except Exception:                                       # noqa: BLE001
        return ""


def build_report(s, crashed=False):
    cfg, m, rec = s.cfg, s.metrics, s.rec
    dur = m.now()
    minutes = max(1, int(dur // 60) + 1)
    checks = []                       # (name, ok, detail)

    def add(name, ok, detail):
        checks.append((name, bool(ok), detail))

    # -- per-minute buckets -------------------------------------------------------------------------------------------
    panel_ms = m.bucket(m.panel, 2)
    flows_n, flows_mb = collections.Counter(), collections.defaultdict(float)
    for t, ms, b, drawer in list(m.flows_dl):
        flows_n[m.minute(t)] += 1
        flows_mb[m.minute(t)] += max(b, 0) / 1048576.0
    app_ms = m.bucket([r for r in m.app if r[3] in ("plain", "error")], 1)
    probe_added = {}
    probe_proxy, probe_direct = {}, {}
    for t, d, p in list(m.probe):
        if m.in_fault(t):
            continue
        probe_added.setdefault(m.minute(t), []).append(p - d)
        probe_proxy.setdefault(m.minute(t), []).append(p)
        probe_direct.setdefault(m.minute(t), []).append(d)
    peaks = collections.defaultdict(int)
    for t, p in list(m.max_peak):
        if not m.in_fault(t):
            peaks[m.minute(t)] = max(peaks[m.minute(t)], p)
    lt = collections.defaultdict(int)
    for t, ms in list(m.longtasks):
        if not m.in_fault(t):
            lt[m.minute(t)] = max(lt[m.minute(t)], ms)
    samples = {r["minute"]: r for r in m.samples}
    errs_by_min = collections.Counter(m.minute(t) for t, k, x in list(m.errors) if not m.in_fault(t))
    calls_by_min = collections.Counter(m.minute(r[0]) for r in list(m.app))

    # -- health budgets -----------------------------------------------------------------------------------------------
    quiet_errors = [(t, k, x) for t, k, x in list(m.errors) if not m.in_fault(t) and k != "http-status"]
    http_status = [(t, k, x) for t, k, x in list(m.errors) if not m.in_fault(t) and k == "http-status"]
    fault_errors = len(m.errors) - len(quiet_errors)
    add("no page JS errors (pageerror, console.error, unhandled rejections)", not quiet_errors,
        "%d outside fault windows (%d more during faults, ignored); %d browser 'Failed to load resource' HTTP-status lines noted below" % (len(quiet_errors), fault_errors, len(http_status)) +
        ("".join("\n    - [%s] t=%.0fs %s" % (k, t, x[:200]) for t, k, x in quiet_errors[:6])))
    all_panel = [r[2] for r in m.panel if not m.in_fault(r[0])]
    worst_min = max(((pct(v, 95), k) for k, v in panel_ms.items() if v), default=(None, None))
    add("panel API p95 <= %.0f ms in every minute" % cfg.panel_p95_ms, worst_min[0] is None or worst_min[0] <= cfg.panel_p95_ms,
        "overall p95 %s ms over %d requests; worst minute %s p95 %s ms" % (fmt(pct(all_panel, 95)), len(all_panel), worst_min[1], fmt(worst_min[0])))
    pk = max(peaks.values(), default=0)
    add("concurrent in-flight panel requests <= %d" % cfg.max_inflight, pk <= cfg.max_inflight, "peak %d outside fault windows" % pk)
    all_added = [x for v in probe_added.values() for x in v]
    worst_add = max(((pct(v, 95), k) for k, v in probe_added.items() if v), default=(None, None))
    add("proxy-added latency p95 <= %.0f ms in every minute" % cfg.added_p95_ms, worst_add[0] is None or worst_add[0] <= cfg.added_p95_ms,
        "overall p50 %s / p95 %s ms over %d probes (proxied ping minus direct ping); worst minute %s p95 %s ms"
        % (fmt(pct(all_added, 50), 1), fmt(pct(all_added, 95), 1), len(all_added), worst_add[1], fmt(worst_add[0], 1)))
    ordered = [samples[k] for k in sorted(samples)]
    warm = min(3, max(0, len(ordered) // 3))
    base = next((r for r in ordered[warm:] if r.get("rss_mb")), None)
    last = next((r for r in reversed(ordered) if r.get("rss_mb")), None)
    if base and last and base is not last:
        g = last["rss_mb"] - base["rss_mb"]
        add("mitmweb RSS growth <= %.0f MB after warm-up" % cfg.rss_growth_mb, g <= cfg.rss_growth_mb,
            "%.0f MB at minute %d -> %.0f MB at minute %d (%+.0f MB)" % (base["rss_mb"], base["minute"], last["rss_mb"], last["minute"], g))
    else:
        add("mitmweb RSS growth", False, "fewer than two memory samples (run too short?)")
    hb = next((r for r in ordered[warm:] if r.get("heap_mb") not in (None, -1)), None)
    hl = next((r for r in reversed(ordered) if r.get("heap_mb") not in (None, -1)), None)
    if hb and hl and hb is not hl:
        g = hl["heap_mb"] - hb["heap_mb"]
        add("browser JS heap growth <= %.0f MB after warm-up" % cfg.heap_growth_mb, g <= cfg.heap_growth_mb,
            "%.0f MB at minute %d -> %.0f MB at minute %d (%+.0f MB, after a forced GC)" % (hb["heap_mb"], hb["minute"], hl["heap_mb"], hl["minute"], g))
    else:
        add("browser JS heap growth", False, "fewer than two heap samples")
    ltmax = max(lt.values(), default=0)
    add("no UI freeze longer than %.0f ms (long tasks)" % cfg.longtask_ms, ltmax <= cfg.longtask_ms, "longest long task %d ms outside fault windows" % ltmax)
    quiet_app = [r for r in m.app if not m.in_fault(r[0])]
    failed_app = [r for r in quiet_app if r[2] == 0]
    add("app calls through the proxy succeed (status 0 <= 1%)", not quiet_app or len(failed_app) <= 0.01 * len(quiet_app),
        "%d of %d calls failed outside fault windows; %d queued calls dropped while the proxy was frozen" % (len(failed_app), len(quiet_app), m.dropped))
    total_calls = s.traffic.sent
    last_flows = max((r.get("flow_count") or 0 for r in ordered), default=0)
    if cfg.minutes >= 15:
        add("session grew past 3,000 calls", last_flows > 3000, "%d calls sent, %d in the list at the last sample" % (total_calls, last_flows))
    else:
        add("session size (informational on a short run)", True, "%d calls sent, %d in the list at the last sample (the 3,000-call growth is asserted from 15 minutes)"
            % (total_calls, last_flows))
    ws_ok = [r for r in m.ws if not m.in_fault(r[0])]
    add("websocket through the proxy", not ws_ok or all(r[1] for r in ws_ok) , "%d of %d websocket sessions delivered frames" % (sum(1 for r in ws_ok if r[1]), len(ws_ok)) if ws_ok else "no websocket ran in this run")
    add("no harness errors", not s.harness_notes and not crashed, "; ".join(s.harness_notes) or "none")

    # -- scenario table -----------------------------------------------------------------------------------------------
    fam = collections.OrderedDict()
    for key, st in sorted(rec.stats.items()):
        f = fam.setdefault(family(key), {"pass": 0, "fail": 0, "skip": 0, "pos": collections.OrderedDict()})
        for k in ("pass", "fail", "skip"):
            f[k] += st[k]
        if "@" in key:
            f["pos"][key.split("@")[1]] = st
    scen_rows = []
    for name, f in fam.items():
        pos = " ".join("%s %d/%d" % (p, st["pass"], st["pass"] + st["fail"]) for p, st in f["pos"].items())
        scen_rows.append((name, f["pass"], f["fail"], f["skip"], "FAIL" if f["fail"] else ("ok" if f["pass"] else "skipped"), pos))
    n_fail = sum(f["fail"] for f in fam.values())
    n_pass = sum(f["pass"] for f in fam.values())
    failed_checks = [c for c in checks if not c[1]]
    ok = not n_fail and not failed_checks and not crashed
    verdict = "PASS" if ok else "FAIL"

    # -- failures grouped ---------------------------------------------------------------------------------------------
    groups = collections.OrderedDict()
    for f in rec.failures:
        g = groups.setdefault((family(f["scenario"]), signature(f["message"])), {"first": f, "n": 0, "pos": [], "at": []})
        g["n"] += 1
        g["at"].append(f["t"])
        if "@" in f["scenario"]:
            g["pos"].append(f["scenario"].split("@")[1])

    # -- markdown -----------------------------------------------------------------------------------------------------
    L = []
    L.append("# Rivis real-use soak: %s\n" % verdict)
    L.append("- when: %s   branch `%s` @ `%s`" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), git("rev-parse", "--abbrev-ref", "HEAD"), git("rev-parse", "--short", "HEAD")))
    L.append("- run: %.1f min of %s configured, seed %s, %d calls sent (%.1f/s), viewport %dx%d, pause scale %s" % (dur / 60.0, cfg.minutes, cfg.seed, total_calls,
                                                                                                                total_calls / max(dur, 1), cfg.viewport[0], cfg.viewport[1], cfg.pause_scale))
    L.append("- scenarios: %d passed, %d failed, %d skipped (precondition not on screen); health budgets: %d of %d passed" % (
        n_pass, n_fail, sum(f["skip"] for f in fam.values()), len(checks) - len(failed_checks), len(checks)))
    L.append("- faults injected: " + (", ".join("%s %ds at %.1f min" % (f["mode"], f["secs"], f["at_s"] / 60) for f in s.faults_done) or "none"))
    L.append("")
    L.append("## Health budgets\n")
    L.append(table(["", "budget", "measured"], [("✅" if ok_ else "❌", name, detail.replace("\n", "<br>")) for name, ok_, detail in checks]))
    L.append("\n## Scenarios\n")
    L.append(table(["scenario", "pass", "fail", "skip", "", "by list position (pass/run)"], scen_rows))
    if groups:
        L.append("\n## Failures (%d, in %d distinct groups)\n" % (len(rec.failures), len(groups)))
        for i, ((fam_name, _sig), g) in enumerate(groups.items(), 1):
            f = g["first"]
            L.append("### F%d  %s — %d× %s" % (i, fam_name, g["n"], ("at " + ", ".join(sorted(set(g["pos"])))) if g["pos"] else ""))
            L.append("- message: `%s`" % f["message"].replace("`", "'"))
            L.append("- first at t=%.0fs (%.1f min); also at %s" % (f["t"], f["t"] / 60.0, ", ".join("%.0fs" % t for t in g["at"][1:6]) or "no other time"))
            L.append("- evidence: screenshot `%s`, trace `%s` (open with `python3 -m playwright show-trace`)" % (f["screenshot"] or "none", f["trace"] or "none"))
            L.append("- panel at the time: lost-banner=%s, menu open=%s, last toasts=%s\n" % (f["lost_bar"], f["menu_open"], f["toasts"]))
    else:
        L.append("\n## Failures\n\nnone")

    mins = list(range(minutes))
    L.append("\n## Per minute (fault windows excluded from latency columns)\n")
    L.append("### App calls and the proxy's added latency\n")
    L.append(table(["min", "calls", "flows in list", "app p50 ms", "app p95 ms", "proxied ping p95", "direct ping p95", "added p50", "added p95"],
                   [(k, calls_by_min.get(k, 0), (samples.get(k) or {}).get("flow_count") if samples.get(k) else "–", fmt(pct(app_ms.get(k, []), 50)), fmt(pct(app_ms.get(k, []), 95)),
                     fmt(pct(probe_proxy.get(k, []), 95), 1), fmt(pct(probe_direct.get(k, []), 95), 1), fmt(pct(probe_added.get(k, []), 50), 1),
                     fmt(pct(probe_added.get(k, []), 95), 1)) for k in mins]))
    L.append("\nadded p95 per minute: `%s`" % spark([pct(probe_added.get(k, []), 95) for k in mins]))
    L.append("\n### Panel API (requests from the page to ./proxy/api/*)\n")
    L.append(table(["min", "requests", "p50 ms", "p95 ms", "max ms", "peak in flight", "full call-list downloads", "list MB", "longest long task ms", "JS errors"],
                   [(k, len(panel_ms.get(k, [])), fmt(pct(panel_ms.get(k, []), 50)), fmt(pct(panel_ms.get(k, []), 95)), fmt(max(panel_ms.get(k, []) or [None]) if panel_ms.get(k) else None),
                     peaks.get(k, "–"), flows_n.get(k, 0), "%.1f" % flows_mb.get(k, 0), lt.get(k, "–"), errs_by_min.get(k, 0)) for k in mins]))
    L.append("\npanel p95 per minute: `%s`" % spark([pct(panel_ms.get(k, []), 95) for k in mins]))
    L.append("\n### Memory\n")
    L.append(table(["min", "mitmweb RSS MB", "browser JS heap MB", "DOM nodes (light DOM)", "fault active"],
                   [(k, fmt((samples.get(k) or {}).get("rss_mb"), 0), fmt((samples.get(k) or {}).get("heap_mb"), 0), (samples.get(k) or {}).get("dom", "–"),
                     "yes" if (samples.get(k) or {}).get("fault") else "") for k in mins if k in samples]))
    L.append("\nRSS `%s`   heap `%s`" % (spark([(samples.get(k) or {}).get("rss_mb") for k in mins if k in samples]),
                                         spark([(samples.get(k) or {}).get("heap_mb") for k in mins if k in samples])))
    slow_ops = collections.defaultdict(list)
    for t, op, ms, st, pk_ in list(m.panel):
        if not m.in_fault(t):
            slow_ops[op].append(ms)
    L.append("\n### Panel API by operation (whole run)\n")
    L.append(table(["op", "n", "p50 ms", "p95 ms", "max ms"], [(op, len(v), fmt(pct(v, 50)), fmt(pct(v, 95)), fmt(max(v))) for op, v in
                                                              sorted(slow_ops.items(), key=lambda kv: -len(kv[1]))[:14]]))
    if http_status:
        L.append("\n## Browser network-error lines (HTTP 4xx/5xx the panel received; not counted as script errors)\n")
        L.append(table(["t s", "line"], [(round(t), x[:200]) for t, k, x in http_status[:15]]))
    if s.skips:
        L.append("\n## Skipped scenario runs\n")
        L.append(table(["t s", "scenario", "why"], [(round(t), k, w[:120]) for t, k, w in s.skips[:20]]))
    if s.harness_notes:
        L.append("\n## Harness notes\n")
        L += ["- " + n for n in s.harness_notes]
    L.append("\n## Documented timeouts used\n")
    L.append("- an action must complete or show an error within %.0f s of the click (SOAK_ACTION_DEADLINE)" % cfg.action_deadline)
    L.append("- the 'can't reach' banner must show within %.0f s of the proxy freezing (SOAK_LOST_DEADLINE)" % cfg.lost_deadline)
    L.append("- everything must work again within %.0f s of a fault ending (SOAK_RECOVER_DEADLINE)" % cfg.recover_deadline)
    L.append("\nHermetic leftover check (processes, ports, temp dirs, $HOME, system proxy) runs after this process exits: see run.sh output.")
    md = "\n".join(L) + "\n"
    with open(os.path.join(s.out, "report.md"), "w") as fh:
        fh.write(md)
    doc = {"verdict": verdict, "duration_s": round(dur, 1), "config": {k: v for k, v in vars(cfg).items()}, "calls_sent": total_calls,
           "checks": [{"name": n, "ok": o, "detail": d} for n, o, d in checks], "scenarios": {k: v for k, v in rec.stats.items()},
           "failures": rec.failures, "faults": s.faults_done, "samples": list(m.samples), "skips": s.skips, "harness_notes": s.harness_notes,
           "per_minute": {"panel_p95": {k: pct(v, 95) for k, v in panel_ms.items()}, "added_p95": {k: pct(v, 95) for k, v in probe_added.items()},
                          "flow_downloads": dict(flows_n), "peak_inflight": dict(peaks)}}
    with open(os.path.join(s.out, "report.json"), "w") as fh:
        json.dump(doc, fh, indent=2, default=str)
    print("\n" + "=" * 78)
    print("SOAK %s — %d scenario runs passed, %d failed; %d of %d health budgets passed" % (verdict, n_pass, n_fail, len(checks) - len(failed_checks), len(checks)))
    for n, o, d in checks:
        if not o:
            print("  BUDGET FAILED: %s — %s" % (n, d.splitlines()[0]))
    print("report: %s" % os.path.join(s.out, "report.md"))
    return 0 if ok else 1
