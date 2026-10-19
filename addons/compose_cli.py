"""compose_cli — list / replay saved Compose requests through the running proxy. Stdlib only.

  compose_cli.py list --dir COMPOSER_DIR
  compose_cli.py send NAME --dir COMPOSER_DIR --port WEB_PORT --token-file FILE [--project ID] [--var k=v ...] [--no-wait]

`send` talks to the same panel API as the browser (127.0.0.1 only; mitmweb token + XSRF), so the call
shows up in the proxy's list and passes through rules and scripts like any other.
"""
import http.cookiejar
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from proxy_common import PRODUCT
from proxy_compose import ComposerStore


def die(msg):
    print(PRODUCT["cli"] + ": " + msg, file=sys.stderr)
    sys.exit(1)


def option(args, flag, default=None, multi=False):
    values = []
    i = 0
    while i < len(args):
        if args[i] == flag and i + 1 < len(args):
            values.append(args[i + 1])
            del args[i:i + 2]
            continue
        i += 1
    if multi:
        return values
    return values[-1] if values else default


def do_list(directory):
    store = ComposerStore(directory)
    names = store.list()
    if not names:
        print("(no saved requests in %s)" % directory)
    for name in names:
        try:
            spec = store.load(name)
            print("  %-24s %-7s %s" % (name, spec.get("method", "GET"), spec.get("url", "")))
        except (OSError, ValueError):
            print("  %-24s (unreadable)" % name)
    try:
        variables = store.variables()
        if variables:
            print("variables: " + ", ".join(sorted(variables)))
    except (OSError, ValueError) as e:
        print("variables: unreadable (%s)" % e)


def do_send(name, directory, port, token_file, overrides, wait, project=None):
    try:
        ComposerStore(directory).load(name)       # fail early (and offline) on a bad name
    except FileNotFoundError:
        die("no saved request '%s' (%s compose list)" % (name, PRODUCT["cli"]))
    except (OSError, ValueError) as e:
        die("cannot read saved request '%s': %s" % (name, e))
    try:
        with open(token_file) as fh:
            token = fh.read().strip()
    except OSError:
        die("no token file %s — is the proxy running? (%s start)" % (token_file, PRODUCT["cli"]))
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),
                                         urllib.request.ProxyHandler({}))      # never via a system proxy
    base = "http://127.0.0.1:%s" % port
    try:
        opener.open(base + "/?token=" + token, timeout=10).read()
    except (urllib.error.URLError, OSError) as e:
        die("cannot reach the proxy UI on 127.0.0.1:%s (%s) — is it running?" % (port, e))
    xsrf = next((c.value for c in jar if c.name == "_mitmproxy_xsrf"), "")
    if not xsrf:   # mitmweb 12 does not always issue it; tornado only needs the cookie and the header to agree
        xsrf = secrets.token_hex(16)
        jar.set_cookie(http.cookiejar.Cookie(0, "_mitmproxy_xsrf", xsrf, None, False, "127.0.0.1", True, False, "/",
                                             True, False, None, False, None, None, {}))

    if project:     # the running proxy loads saved requests from ITS project's composer/ directory
        try:
            running = json.load(opener.open(base + "/proxy/api/state", timeout=10)).get("active_project")
        except (urllib.error.URLError, OSError, ValueError) as e:
            die("cannot read the proxy state (%s)" % e)
        if running != project:
            die("the running proxy serves project '%s', not '%s' — restart it with --project %s (or use --project %s)"
                % (running, project, project, running))

    def post(op, body, fatal=True):
        request = urllib.request.Request(base + "/proxy/api/" + op, data=json.dumps(body).encode(), method="POST",
                                         headers={"Content-Type": "application/json", "X-XSRFToken": xsrf})
        try:
            return json.load(opener.open(request, timeout=30))
        except urllib.error.HTTPError as e:
            try:
                detail = json.load(e).get("error")
            except ValueError:
                detail = None
            if not fatal:
                return {}
            die("%s failed: %s" % (op, detail or "HTTP %d" % e.code))

    sent = post("compose_send", {"name": name, "vars": overrides})
    print("sent %s %s" % (sent.get("method"), sent.get("url")))
    if not wait:
        return
    for _ in range(40):
        time.sleep(0.5)
        try:   # R2A-03: mitmweb 12.2.3 refuses GET /flows/<id> (405), so ask the panel; a real error is shown, not retried
            got = post("flow_result", {"id": sent["id"]}, fatal=False)
        except (urllib.error.URLError, OSError, ValueError):
            continue
        if got.get("error"):
            die("call failed: %s" % got["error"])
        if got.get("status"):
            print("→ %s" % got["status"])
            return
    print("no response yet — check the proxy list")


def main(argv):
    if not argv:
        die(__doc__)
    cmd, args = argv[0], list(argv[1:])
    directory = option(args, "--dir")
    if not directory:
        die("--dir is required")
    if cmd == "list":
        do_list(directory)
    elif cmd == "send":
        port = option(args, "--port", "8083")
        token_file = option(args, "--token-file", os.path.join(os.path.expanduser(PRODUCT["state_dir"]), "web-token"))
        overrides = {}
        for item in option(args, "--var", multi=True):
            key, sep, value = item.partition("=")
            if not sep:
                die("--var expects name=value")
            overrides[key] = value
        project = option(args, "--project")
        wait = "--no-wait" not in args
        args = [a for a in args if a != "--no-wait"]
        if len(args) != 1:
            die("usage: compose send NAME [--var name=value]")
        do_send(args[0], directory, port, token_file, overrides, wait, project)
    else:
        die(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
