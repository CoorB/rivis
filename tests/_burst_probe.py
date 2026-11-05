"""Burst-width probe for the c/burst lane. Not part of the suite — run by hand:

  /usr/bin/python3 tests/_burst_probe.py

Uses the hermetic harness (fake HOME, random ports). Never touches 8080/8083 or ~/.rivis.
"""
from __future__ import annotations

import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS)

import harness
from harness import Background, Instance, Suite, free_port, wait_for
from test_audit_2026_10_17 import fd_headroom, write_rules_fast

WIDTHS = [int(x) for x in os.environ.get("BURST_WIDTHS", "25,50,100,150,200,400").split(",") if x.strip()]
RUNS_PER = int(os.environ.get("BURST_RUNS", "8"))
MODES = set(os.environ.get("BURST_MODES", "direct,rivis-quiet,rivis-reload,mitmdump-lazy,mitmdump-eager").split(","))
OUT = os.path.join(TESTS, ".artifacts", "burst-probe-%d.json" % os.getpid())


def raise_fds(want=4096):
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = want if hard in (resource.RLIM_INFINITY, -1) else min(want, hard)
    if soft < target:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        except (ValueError, OSError):
            pass
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    return soft, hard


def fire(fetch, url_fn, n, timeout=60):
    calls = [Background(fetch, url_fn(i), timeout=timeout) for i in range(n)]
    return [c.result(timeout + 30) for c in calls]


def summarise(results, up, marker):
    bad = []
    bodies = []
    for i, r in enumerate(results):
        if r.status != 200:
            bad.append({"i": i, "status": r.status, "rc": r.rc, "err": (r.err or "")[:200],
                        "body": (r.body or b"")[:300].decode("utf-8", "replace")})
            bodies.append((r.body or b"")[:120])
    hits = len(up.hits_for(marker)) if hasattr(up, "hits_for") else len([h for h in up.hits if marker in h["path"]])
    conns = dict(up.connection_count)
    return {
        "ok": len(results) - len(bad),
        "bad": len(bad),
        "bad_detail": bad[:8],
        "hits": hits,
        "conns": conns,
        "accepted_minus_hits": conns.get("http", 0) - hits,
        "unique_body_prefixes": sorted({b.decode("utf-8", "replace") if isinstance(b, bytes) else b for b in bodies})[:4],
    }


def churn_rules(inst, stop, match="/echo\\\\?burst"):
    i = 0
    while not stop.is_set():
        i += 1
        write_rules_fast(inst, {"rules": [{"name": "h%d" % (i % 3), "match": match,
                                            "action": "set_header", "header": "X-Gen", "value": str(i)}]})
        time.sleep(0.2)


def start_mitmdump(suite, confdir, port, extras=None):
    os.makedirs(confdir, exist_ok=True)
    # seed CA so mitmdump does not regenerate mid-run
    if not os.path.isfile(os.path.join(confdir, "mitmproxy-ca.pem")):
        for name in os.listdir(suite.ca_dir):
            src = os.path.join(suite.ca_dir, name)
            dst = os.path.join(confdir, name)
            if os.path.isfile(src):
                shutil.copy2(src, dst)
    logpath = os.path.join(harness.ARTIFACTS, "mitmdump-burst-%d.log" % port)
    argv = [harness.REAL_MITMDUMP, "--listen-host", "127.0.0.1", "-p", str(port),
            "--set", "confdir=" + confdir, "--set", "connection_strategy=lazy",
            "--set", "ssl_insecure=true", "--set", "http2=false", "-q"]
    if extras:
        argv += extras
    logfh = open(logpath, "ab")
    proc = subprocess.Popen(argv, stdout=logfh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                            start_new_session=True)
    wait_for(lambda: harness.port_open(port) or proc.poll() is not None, 20, 0.1, "mitmdump listen")
    if proc.poll() is not None:
        raise RuntimeError("mitmdump exited rc=%s; log=%s" % (proc.returncode, logpath))
    return proc, logpath


def stop_pg(proc):
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(8)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(3)


def curl_via(proxy_port, url, cacert, timeout=60):
    tmp = tempfile.mkdtemp()
    hdr, out = os.path.join(tmp, "h"), os.path.join(tmp, "b")
    argv = ["curl", "-sS", "--noproxy", "", "--http1.1", "--max-time", str(timeout),
            "-D", hdr, "-o", out, "-w", "%{http_code}"]
    if proxy_port:
        argv += ["-x", "http://127.0.0.1:%d" % proxy_port, "--cacert", cacert]
    argv.append(url)
    cp = subprocess.run(argv, capture_output=True, timeout=timeout + 15)
    status = 0
    try:
        blocks = open(hdr, "rb").read().decode("latin-1").replace("\r\n", "\n").strip().split("\n\n")
        last = [b for b in blocks if b.startswith("HTTP/")][-1] if blocks and blocks[0] else ""
        if last:
            status = int(last.split("\n")[0].split()[1])
    except (OSError, ValueError, IndexError):
        status = int(cp.stdout.decode() or 0)
    try:
        body = open(out, "rb").read()
    except OSError:
        body = b""
    shutil.rmtree(tmp, ignore_errors=True)
    return harness.Resp(status, [], body, cp.returncode, cp.stderr.decode("utf-8", "replace"))


def run_mode(name, width, runs, fire_fn, up, marker_prefix, reset=True):
    rows = []
    for run in range(runs):
        if reset:
            up.reset_hits()
            up.reset_connections()
        marker = "%s-w%d-r%d" % (marker_prefix, width, run)
        t0 = time.time()
        results = fire_fn(width, marker)
        took = time.time() - t0
        s = summarise(results, up, "/" + marker.split("/")[-1] if False else marker)
        # hits_for uses startswith on path; our urls are /echo?burst=... so filter manually
        hit_n = len([h for h in up.hits if marker in h["path"]])
        s["hits"] = hit_n
        s["accepted_minus_hits"] = s["conns"].get("http", 0) - hit_n
        s["took"] = round(took, 3)
        s["run"] = run
        rows.append(s)
        print("  %s width=%d run=%d ok=%d bad=%d hits=%d conns=%s gap=%d took=%.2fs"
              % (name, width, run, s["ok"], s["bad"], s["hits"], s["conns"], s["accepted_minus_hits"], took),
              flush=True)
        if s["bad"] and s["bad_detail"]:
            d = s["bad_detail"][0]
            print("    sample bad: status=%s rc=%s body=%r err=%r" % (d["status"], d["rc"], d["body"][:160], d["err"][:120]),
                  flush=True)
    fails = sum(1 for r in rows if r["bad"])
    total_bad = sum(r["bad"] for r in rows)
    return {
        "mode": name, "width": width, "runs": runs,
        "fail_runs": fails, "total_bad": total_bad,
        "avg_bad": round(total_bad / float(runs), 3),
        "max_bad": max(r["bad"] for r in rows),
        "avg_gap": round(sum(r["accepted_minus_hits"] for r in rows) / float(runs), 3),
        "rows": rows,
    }


def main():
    raise_fds(8192)
    fd_headroom(4096)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    print("RLIMIT_NOFILE soft=%s hard=%s RUNS_PER=%d" % (soft, hard, RUNS_PER), flush=True)
    os.makedirs(harness.ARTIFACTS, exist_ok=True)
    suite = Suite.get()
    up = suite.upstream()
    report = {"soft_fd": soft, "hard_fd": hard, "runs_per": RUNS_PER, "widths": WIDTHS, "modes": []}

    if "direct" in MODES:
        print("\n=== DIRECT (no proxy) ===", flush=True)
        for w in WIDTHS:
            def fire_direct(width, marker, _up=up, _ca=suite.ca_pem):
                def one(u, timeout=60):
                    return curl_via(None, u, _ca, timeout=timeout)
                def url_fn(i):
                    return _up.url("/echo?%s=%d" % (marker, i))
                return fire(one, url_fn, width)
            report["modes"].append(run_mode("direct", w, RUNS_PER, fire_direct, up, "d"))

    def rivis_fire(inst, up, width, marker):
        # Do not use Instance.fetch: each call rebuilds suite.env() and burns two free_port()
        # numbers into the process-wide set, which exhausts after a few thousand curls.
        port, ca = inst.proxy_port, suite.ca_pem
        def one(u, timeout=60):
            return curl_via(port, u, ca, timeout=timeout)
        def url_fn(i):
            return up.url("/echo?%s=%d" % (marker, i))
        return fire(one, url_fn, width)

    if "rivis-quiet" in MODES:
        print("\n=== RIVIS quiet (no rules churn) ===", flush=True)
        inst = Instance(suite, "burst-quiet", start_args=("--insecure",)).start()
        try:
            for w in WIDTHS:
                report["modes"].append(run_mode("rivis-quiet", w, RUNS_PER,
                                                lambda width, marker, _i=inst: rivis_fire(_i, up, width, marker),
                                                up, "rq"))
        finally:
            inst.stop()

    if "rivis-reload" in MODES:
        print("\n=== RIVIS + rules hot-reload ===", flush=True)
        inst = Instance(suite, "burst-reload", start_args=("--insecure",)).start()
        stop = threading.Event()
        t = threading.Thread(target=churn_rules, args=(inst, stop), daemon=True)
        t.start()
        try:
            for w in WIDTHS:
                report["modes"].append(run_mode("rivis-reload", w, RUNS_PER,
                                                lambda width, marker, _i=inst: rivis_fire(_i, up, width, marker),
                                                up, "rr"))
        finally:
            stop.set()
            t.join(5)
            inst.stop()

    if "mitmdump-lazy" in MODES:
        print("\n=== PLAIN mitmdump (lazy, no add-ons) ===", flush=True)
        port = free_port()
        conf = os.path.join(suite.root, "mitmdump-conf")
        proc, _ = start_mitmdump(suite, conf, port)
        try:
            for w in WIDTHS:
                def fire_md(width, marker, _port=port, _up=up, _ca=suite.ca_pem):
                    def one(u, timeout=60):
                        return curl_via(_port, u, _ca, timeout=timeout)
                    def url_fn(i):
                        return _up.url("/echo?%s=%d" % (marker, i))
                    return fire(one, url_fn, width)
                report["modes"].append(run_mode("mitmdump-lazy", w, RUNS_PER, fire_md, up, "ml"))
        finally:
            stop_pg(proc)

    if "mitmdump-eager" in MODES:
        print("\n=== PLAIN mitmdump (eager, no add-ons) ===", flush=True)
        port = free_port()
        conf = os.path.join(suite.root, "mitmdump-conf-eager")
        os.makedirs(conf, exist_ok=True)
        if not os.path.isfile(os.path.join(conf, "mitmproxy-ca.pem")):
            for name in os.listdir(suite.ca_dir):
                src = os.path.join(suite.ca_dir, name)
                if os.path.isfile(src):
                    shutil.copy2(src, os.path.join(conf, name))
        logpath = os.path.join(harness.ARTIFACTS, "mitmdump-eager-%d.log" % port)
        logfh = open(logpath, "ab")
        proc = subprocess.Popen(
            [harness.REAL_MITMDUMP, "--listen-host", "127.0.0.1", "-p", str(port),
             "--set", "confdir=" + conf, "--set", "connection_strategy=eager",
             "--set", "ssl_insecure=true", "--set", "http2=false", "-q"],
            stdout=logfh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
        wait_for(lambda: harness.port_open(port) or proc.poll() is not None, 20, 0.1, "mitmdump eager")
        if proc.poll() is not None:
            raise RuntimeError("mitmdump eager exited; see %s" % logpath)
        try:
            for w in WIDTHS:
                def fire_md(width, marker, _port=port, _up=up, _ca=suite.ca_pem):
                    def one(u, timeout=60):
                        return curl_via(_port, u, _ca, timeout=timeout)
                    def url_fn(i):
                        return _up.url("/echo?%s=%d" % (marker, i))
                    return fire(one, url_fn, width)
                report["modes"].append(run_mode("mitmdump-eager", w, RUNS_PER, fire_md, up, "me"))
        finally:
            stop_pg(proc)

    with open(OUT, "w") as fh:
        json.dump(report, fh, indent=2)
    print("\nWrote %s" % OUT, flush=True)

    # compact table
    print("\n=== TABLE (fail_runs / total_bad / avg_gap across %d runs) ===" % RUNS_PER, flush=True)
    print("%-16s %6s %10s %10s %8s" % ("mode", "width", "fail_runs", "total_bad", "avg_gap"))
    for m in report["modes"]:
        print("%-16s %6d %10d %10d %8.2f" % (m["mode"], m["width"], m["fail_runs"], m["total_bad"], m["avg_gap"]))


if __name__ == "__main__":
    main()
