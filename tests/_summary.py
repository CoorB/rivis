"""pytest plugin used by run.sh: per-module outcome counts + skip reasons + failures, written as JSON (--json-out)."""
import json
import time


def pytest_addoption(parser):
    parser.addoption("--json-out", action="store", default=None)


def pytest_configure(config):
    config._rivis = {"passed": 0, "failed": 0, "skipped": 0, "xfailed": 0, "unexpected_success": 0, "error": 0,
                     "failures": [], "skips": {}, "xfails": [], "t0": time.time()}


def _record(config, report):
    r = config._rivis
    wasxfail = hasattr(report, "wasxfail")
    text = str(report.longrepr) if report.longrepr is not None else ""
    if report.when == "call":
        if report.passed and not wasxfail:
            r["passed"] += 1
        elif report.skipped and wasxfail:
            r["xfailed"] += 1
            r["xfails"].append(report.nodeid)
        elif report.failed and "Unexpected success" in text:
            r["unexpected_success"] += 1
            r["failures"].append([report.nodeid, "UNEXPECTED SUCCESS — a known bug looks fixed: remove its expectedFailure marker"])
        elif report.passed and wasxfail:
            r["unexpected_success"] += 1
            r["failures"].append([report.nodeid, "UNEXPECTED SUCCESS — a known bug looks fixed"])
        elif report.failed:
            r["failed"] += 1
            r["failures"].append([report.nodeid, text.strip().splitlines()[-1][:300] if text.strip() else ""])
        elif report.skipped:
            r["skipped"] += 1
            reason = report.longrepr[2] if isinstance(report.longrepr, tuple) else text
            reason = reason.replace("Skipped: ", "")[:200]
            r["skips"].setdefault(reason, []).append(report.nodeid)
    elif report.when in ("setup", "teardown"):
        if report.failed:
            r["error"] += 1
            r["failures"].append([report.nodeid + " (%s)" % report.when, text.strip().splitlines()[-1][:300] if text.strip() else ""])
        elif report.skipped and report.when == "setup":
            r["skipped"] += 1
            reason = report.longrepr[2] if isinstance(report.longrepr, tuple) else text
            r["skips"].setdefault(reason.replace("Skipped: ", "")[:200], []).append(report.nodeid)


def pytest_runtest_logreport(report):
    _record(_CONFIG[0], report)


_CONFIG = [None]


def pytest_sessionstart(session):
    _CONFIG[0] = session.config


def pytest_sessionfinish(session, exitstatus):
    path = session.config.getoption("--json-out")
    if path:
        r = dict(session.config._rivis)
        r["seconds"] = round(time.time() - r.pop("t0"), 1)
        r["exitstatus"] = int(exitstatus)
        with open(path, "w") as fh:
            json.dump(r, fh, indent=1)
