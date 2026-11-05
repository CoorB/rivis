"""run.sh helper: prove the run left nothing behind, and print the summary table.

  hermetic.py snapshot OUT.json         record the "before" state
  hermetic.py report RESULTS_DIR SNAP   print the table, compare "after" with SNAP, exit non-zero on any failure/leftover
"""
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

WATCH = [".rivis", ".mitmproxy", ".neo-mitm", ".zshrc", ".zprofile", ".bash_profile", ".bashrc", ".local/rivis", ".local/bin/rivis",
         # installer and doctor also look here; a suite that escaped the fake HOME would leave fingerprints
         ".android/adbkey", ".android/adbkey.pub"]
FORBIDDEN = (8080, 8083, 8090, 8093, 8094, 8095, 9090, 9091)
_RUN = os.environ.get("RIVIS_TEST_RUN", "")
PREFIX = "rivis-t-%s-" % _RUN if re.fullmatch(r"[A-Za-z0-9]{1,32}", _RUN) else "rivis-t-"   # same as harness.run_prefix()


def home():
    # resolve at call time (not import): a subprocess test can set HOME without re-importing this module
    return os.path.expanduser("~")


def tree_digest(path):
    if not os.path.lexists(path):
        return None
    h = hashlib.sha1()
    n = 0
    for base, dirs, files in os.walk(path):
        if base == path and os.path.basename(path) == ".rivis":
            # the user's own Rivis (a `rivis browser` window, an emulator they set up) writes in these while a run
            # is going: android-ramdisk holds the emulator's console log, appended for as long as it stays on the
            # setup boot, which made every run on that machine report an unclean $HOME
            for live in ("logs", "browser", "android-ramdisk"):
                if live in dirs:
                    dirs.remove(live)
        dirs.sort()
        for name in sorted(files + dirs):
            p = os.path.join(base, name)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            h.update(("%s|%d|%d|%o\n" % (os.path.relpath(p, path), st.st_size, st.st_mtime_ns, st.st_mode)).encode())
            n += 1
    try:
        st = os.lstat(path)
        h.update(("%d|%d" % (st.st_size, st.st_mtime_ns)).encode())
    except OSError:
        pass
    return "%s:%d" % (h.hexdigest(), n)


def listeners():
    out = subprocess.run(["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn"], capture_output=True, text=True).stdout
    rows, pid, cmd = [], None, None
    for line in out.splitlines():
        if line[0] == "p":
            pid = int(line[1:])
        elif line[0] == "c":
            cmd = line[1:]
        elif line[0] == "n":
            rows.append((pid, cmd, line[1:]))
    return rows


def forbidden_listeners():
    # (cmd, name) only — not pid: the user's Rivis or Proxyman may restart mid-run with a new pid; that is not a suite leak
    return sorted((c, n) for _, c, n in listeners() if any(n.endswith(":%d" % p) for p in FORBIDDEN))


def suite_pids():
    """PIDs whose argv still carries this run's temp prefix (rivis-t-<run>-)."""
    out = subprocess.run(["ps", "-axww", "-o", "pid=,args="], capture_output=True, text=True).stdout
    pids = set()
    for line in out.splitlines():
        line = line.strip()
        if PREFIX not in line or "hermetic.py" in line:
            continue
        parts = line.split(None, 1)
        try:
            pids.add(int(parts[0]))
        except (ValueError, IndexError):
            continue
    return pids


def suite_on_forbidden():
    """A suite process listening on a protected port — even when the before/after (cmd,name) set looks unchanged
    because it replaced the user's Rivis/Proxyman on the same address."""
    mine = suite_pids()
    if not mine:
        return []
    return sorted((c, n) for pid, c, n in listeners()
                  if pid in mine and any(n.endswith(":%d" % p) for p in FORBIDDEN))


def leftover_processes():
    out = subprocess.run(["ps", "-axww", "-o", "pid=,args="], capture_output=True, text=True).stdout
    return [l.strip()[:160] for l in out.splitlines() if PREFIX in l and "hermetic.py" not in l]


def tmp_leftovers():
    return sorted(glob.glob(os.path.join(tempfile.gettempdir(), PREFIX + "*")))


def scutil():
    return subprocess.run(["scutil", "--proxy"], capture_output=True, text=True).stdout


def snap():
    h = home()
    return {"watch": {w: tree_digest(os.path.join(h, w)) for w in WATCH}, "forbidden": forbidden_listeners(),
            "scutil": scutil(), "tmp": tmp_leftovers(), "top": sorted(os.listdir(h))}


def main():
    cmd = sys.argv[1]
    if cmd == "snapshot":
        json.dump(snap(), open(sys.argv[2], "w"))
        return 0
    results_dir, snap_path = sys.argv[2], sys.argv[3]
    before, after = json.load(open(snap_path)), json.loads(json.dumps(snap()))     # same types on both sides
    rows, totals, bad = [], {}, False
    for path in sorted(glob.glob(os.path.join(results_dir, "*.json"))):
        name = os.path.basename(path)[:-5]
        r = json.load(open(path))
        rows.append((name, r))
        for k in ("passed", "failed", "skipped", "xfailed", "unexpected_success", "error"):
            totals[k] = totals.get(k, 0) + r[k]
        totals["seconds"] = max(totals.get("seconds", 0), r["seconds"])
        if r["failed"] or r["error"] or r["unexpected_success"] or r["exitstatus"] not in (0, 5):
            bad = True
    print()
    print("%-26s %6s %6s %7s %7s %6s %6s %7s" % ("module", "pass", "fail", "xfail", "skip", "xpass", "error", "secs"))
    print("-" * 78)
    for name, r in rows:
        print("%-26s %6d %6d %7d %7d %6d %6d %7.1f" % (name, r["passed"], r["failed"], r["xfailed"], r["skipped"], r["unexpected_success"], r["error"], r["seconds"]))
    print("-" * 78)
    print("%-26s %6d %6d %7d %7d %6d %6d %7.1f  (wall clock ≈ slowest module)" % ("TOTAL", totals.get("passed", 0), totals.get("failed", 0), totals.get("xfailed", 0),
          totals.get("skipped", 0), totals.get("unexpected_success", 0), totals.get("error", 0), totals.get("seconds", 0)))
    for name, r in rows:
        for nodeid, msg in r["failures"]:
            print("FAIL  %s\n      %s" % (nodeid, msg))
    skips = {}
    for _, r in rows:
        for reason, ids in r["skips"].items():
            skips.setdefault(reason, []).extend(ids)
    if skips:
        print("\nSKIPPED (with reasons)")
        for reason, ids in sorted(skips.items()):
            print("  %3d  %s" % (len(ids), reason))
    xf = [i for _, r in rows for i in r["xfails"]]
    if xf:
        print("\nEXPECTED FAILURES = known product bugs, see tests/FOUND-BUGS.md (%d)" % len(xf))
        for i in xf:
            print("  " + i)
    problems = []
    # a path added to WATCH after an older snapshot was written must not KeyError the report
    for w, d in before["watch"].items():
        if after["watch"].get(w) != d:
            problems.append("$HOME/%s changed during the run" % w)
    for w in after["watch"]:
        if w not in before["watch"] and after["watch"][w] is not None:
            problems.append("$HOME/%s appeared during the run" % w)
    if before["forbidden"] != after["forbidden"]:
        problems.append("listeners on protected ports changed: %s -> %s" % (before["forbidden"], after["forbidden"]))
    held = suite_on_forbidden()
    if held:
        problems.append("this run is listening on a protected port: %s" % held[:5])
    if before["scutil"] != after["scutil"]:
        problems.append("system proxy configuration changed")
    new_tmp = [t for t in after["tmp"] if t not in before["tmp"]]
    if new_tmp:
        problems.append("temp dirs left behind: %s" % new_tmp[:5])
    left = leftover_processes()
    if left:
        problems.append("processes left behind: %s" % left[:5])
    gained = sorted(set(after["top"]) - set(before["top"]))
    if gained:
        print("\nnote: new entries appeared in $HOME during the run (other apps?): %s" % gained[:8])
    print("\nHERMETIC CHECK: %s" % ("clean — no leftover processes/ports/temp dirs; $HOME, protected ports and system proxy unchanged" if not problems
                                  else "FAILED"))
    for p in problems:
        print("  - " + p)
    if problems:
        bad = True
    print("RESULT: %s" % ("FAIL" if bad else "PASS"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
