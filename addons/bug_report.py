#!/usr/bin/env python3
"""Create a redacted Rivis support bundle without traffic, credentials, or UI tokens."""
import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from proxy_common import commit_temp_file, redact_diagnostic
import proxy_redact

MAX_LOG_BYTES = 256 * 1024
QUOTED_SECRET = re.compile(
    r'(?i)(["\'](?:authorization|access_token|refresh_token|token|password|secret|api[_-]?key)["\']\s*:\s*["\'])(.*?)(["\'])')
QUERY_SECRET = re.compile(r'(?i)([?&](?:access_token|refresh_token|token|password|secret|api[_-]?key)=)([^&\s]+)')
BEARER = re.compile(r'(?i)(bearer\s+)([^\s,;]+)')


def device_names():
    """Names of this Mac's simulators and AVDs: they can be internal app or team code names (R6A-03), and a support
    bundle needs only that a device exists, not what it is called."""
    names = set()
    try:
        out = subprocess.run(["xcrun", "simctl", "list", "-j", "devices"], capture_output=True, text=True,
                             timeout=10, check=False).stdout
        for devs in (json.loads(out or "{}").get("devices") or {}).values():
            names.update(d.get("name") for d in devs if isinstance(d, dict) and d.get("name"))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    try:
        names.update(n[:-4] for n in os.listdir(os.path.expanduser("~/.android/avd")) if n.endswith(".ini"))
    except OSError:
        pass
    return sorted((n for n in names if len(n) >= 3), key=len, reverse=True)    # longest first: no partial overlaps


def redact(text, home, devices=()):
    text = redact_diagnostic(text)
    # R6A-02: the HAR redactor's field names (otp, pin, cvv, session, csrf …) for log lines, tracebacks and doctor JSON
    text = proxy_redact._loose(text)       # text-level pass: keeps doctor.txt and the logs laid out as they were
    for i, name in enumerate(devices, 1):
        text = text.replace(name, "<device %d>" % i)
    text = QUOTED_SECRET.sub(r"\1[REDACTED]\3", text)
    text = QUERY_SECRET.sub(r"\1[REDACTED]", text)
    text = BEARER.sub(r"\1[REDACTED]", text)
    if home:
        text = text.replace(os.path.realpath(home), "~").replace(home, "~")
    return text


def command(args, timeout=20):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return result.returncode, (result.stdout + result.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "%s: %s" % (type(exc).__name__, exc)


def last_logs(log_dir):
    chunks = []
    for name in ("rivis.log.3", "rivis.log.2", "rivis.log.1", "rivis.log"):
        path = os.path.join(log_dir, name)
        try:
            with open(path, "rb") as fh:
                data = fh.read()[-MAX_LOG_BYTES:]
        except OSError:
            continue
        chunks.append("===== %s =====\n%s" % (name, data.decode("utf-8", "replace")))
    return "\n".join(chunks)[-MAX_LOG_BYTES:]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--rules", required=True)
    parser.add_argument("--confdir", required=True)
    parser.add_argument("--port", required=True)
    parser.add_argument("--web-port", required=True)
    parser.add_argument("--script-dir", required=True)
    parser.add_argument("--adb", default="")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    home = os.path.expanduser("~")

    doctor_cmd = [sys.executable, "-I", os.path.join(HERE, "doctor.py"), "--project", args.project,
                  "--rules", args.rules, "--confdir", args.confdir, "--port", str(args.port),
                  "--web-port", str(args.web_port), "--script-dir", args.script_dir, "--json", "--no-net"]
    if args.adb:
        doctor_cmd += ["--adb", args.adb]
    doctor_rc, doctor_output = command(doctor_cmd, timeout=30)
    mitm_rc, mitm_version = command(["mitmweb", "--version"])
    node_rc, node_version = command(["node", "--version"])
    with open(os.path.join(ROOT, "product.json"), encoding="utf-8") as fh:
        product = json.load(fh)
    product_version = "unknown"
    # R6A-01: an installed tree keeps VERSION at its root; a source checkout keeps it in install/
    for path in (os.path.join(ROOT, "VERSION"), os.path.join(ROOT, "install", "VERSION")):
        try:
            with open(path, encoding="utf-8") as fh:
                product_version = fh.read().strip() or "unknown"
            break
        except OSError:
            continue

    manifest = {
        "bundle_schema_version": 1,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "product": product.get("name"),
        "product_version": product_version,
        "project": args.project,
        "doctor_exit": doctor_rc,
        "contents": ["manifest.json", "versions.txt", "doctor.txt", "logs.txt", "README.txt"],
        "excluded": ["captured flows", "web-token", "web-bootstrap", "composer variables", "request/response bodies",
                     "simulator and emulator names"],
    }
    versions = "\n".join((
        "%s %s" % (product.get("name"), product_version),
        "Python " + platform.python_version(),
        "OS " + platform.platform(),
        "mitmweb (exit %d): %s" % (mitm_rc, mitm_version),
        "Node (exit %d): %s" % (node_rc, node_version),
    )) + "\n"
    contents = {
        "manifest.json": json.dumps(manifest, indent=2) + "\n",
        "versions.txt": versions,
        "doctor.txt": doctor_output + "\n",
        "logs.txt": last_logs(os.path.join(args.state_root, "logs")) + "\n",
        "README.txt": "Redacted Rivis diagnostics. This bundle intentionally contains no captured flows or tokens.\n",
    }

    output_dir = os.path.join(args.state_root, "bug-reports")
    os.makedirs(output_dir, mode=0o700, exist_ok=True)
    output = os.path.abspath(os.path.expanduser(args.output)) if args.output else os.path.join(
        output_dir, "rivis-bug-report-%s.zip" % time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    if os.path.dirname(output) != os.path.abspath(output_dir) and not args.output:
        raise SystemExit("invalid bug report output path")
    names = device_names()
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(output), prefix=".bug-report-", suffix=".zip")
    os.close(fd)
    try:
        with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, value in contents.items():
                archive.writestr(name, redact(value, home, names))
        with open(tmp, "rb") as fh:
            os.fsync(fh.fileno())
        commit_temp_file(tmp, output)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print(output)
    # R6A-04: say what is inside before it is shared, not only in a file inside the zip
    print("  contains: %s (redacted)" % ", ".join(manifest["contents"]), file=sys.stderr)
    print("  left out: %s" % ", ".join(manifest["excluded"]), file=sys.stderr)
    print("  check it before you share it: unzip -l / open the .txt files", file=sys.stderr)


if __name__ == "__main__":
    main()
