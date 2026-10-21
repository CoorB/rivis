"""run.sh helper: prove the soak left nothing behind (reuses tests/hermetic.py).

  hermetic_check.py snapshot OUT.json
  hermetic_check.py report BEFORE.json OUTDIR     appends "Hermetic check" to OUTDIR/report.md; exit 1 on any leftover / change
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import hermetic                      # noqa: E402


def chromium_pids():
    out = subprocess.run(["ps", "-axww", "-o", "pid=,args="], capture_output=True, text=True).stdout
    tag = os.environ.get("SOAK_BROWSER_TMP") or "playwright_chromiumdev_profile"      # run.sh's own folder: another session's browser is not ours
    return sorted(int(l.split(None, 1)[0]) for l in out.splitlines() if tag in l and "hermetic_check" not in l)


def snap():
    d = hermetic.snap()
    d["chromium"] = chromium_pids()
    return d


def main():
    if sys.argv[1] == "snapshot":
        json.dump(snap(), open(sys.argv[2], "w"))
        return 0
    before = json.load(open(sys.argv[2]))
    out = sys.argv[3]
    after = json.loads(json.dumps(snap()))
    problems = []
    for w, dg in before["watch"].items():
        if after["watch"][w] != dg:
            problems.append("$HOME/%s changed during the run" % w)
    if before["forbidden"] != after["forbidden"]:
        problems.append("listeners on protected ports changed: %s -> %s" % (before["forbidden"], after["forbidden"]))
    if before["scutil"] != after["scutil"]:
        problems.append("system proxy configuration changed")
    new_tmp = [t for t in after["tmp"] if t not in before["tmp"]]
    if new_tmp:
        problems.append("temp dirs left behind: %s" % new_tmp[:5])
    left = hermetic.leftover_processes()
    if left:
        problems.append("processes left behind: %s" % left[:5])
    stray = [p for p in after["chromium"] if p not in before["chromium"]]
    if stray:
        problems.append("Chromium processes left behind: %s" % stray[:5])
    line = ("clean: no leftover Rivis/upstream/Chromium process, no listener on protected ports, no temp dir; $HOME, protected ports and the system proxy unchanged"
            if not problems else "FAILED")
    print("HERMETIC CHECK: " + line)
    for p in problems:
        print("  - " + p)
    path = os.path.join(out, "report.md")
    if os.path.exists(path):
        text = open(path).read()
        if problems:
            text = text.replace("# Rivis real-use soak: PASS", "# Rivis real-use soak: FAIL", 1)
        text += "\n## Hermetic check\n\n%s\n%s" % (line, "".join("- %s\n" % p for p in problems))
        open(path, "w").write(text)
    jpath = os.path.join(out, "report.json")
    if os.path.exists(jpath):
        doc = json.load(open(jpath))
        doc["hermetic"] = {"ok": not problems, "problems": problems}
        if problems:
            doc["verdict"] = "FAIL"
        json.dump(doc, open(jpath, "w"), indent=2)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
