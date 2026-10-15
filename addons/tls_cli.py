"""tls_cli — edit the TLS decryption list of a project rules file. Stdlib only (system Python 3.9).

  tls_cli.py FILE list
  tls_cli.py FILE mode [all|allow|ignore]
  tls_cli.py FILE allow add|rm PATTERN
  tls_cli.py FILE ignore add|rm PATTERN

Patterns are host names with Proxyman-style wildcards (*.example.test). The running proxy picks the
change up within a second; it applies to NEW connections, no restart needed.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:       # /usr/bin/python3 -I removes the script directory
    sys.path.insert(0, HERE)
from proxy_common import PRODUCT, atomic_json, migrate_rules, tls_config, tls_host_regex, tls_update

NOTE = "applies to new connections within a second — no restart; open connections keep their earlier decision"


def die(msg):
    print(PRODUCT["cli"] + ": " + msg, file=sys.stderr)
    sys.exit(1)


def show(cfg):
    tls = tls_config(cfg)
    print("tls mode: %s" % tls["mode"])
    for which in ("allow", "ignore"):
        used = tls["mode"] == which
        print("%s%s:" % (which, "  (active)" if used else "  (used when mode is %s)" % which))
        for pattern in tls[which]:
            print("  %-32s %s" % (pattern, tls_host_regex(pattern)))
        if not tls[which]:
            print("  (none)")
    if tls["mode"] == "all":
        print("all hosts are decrypted; hosts that are not decrypted show as host-only tunnel rows in the other modes")


def main(argv):
    if len(argv) < 2:
        die(__doc__)
    path, args = argv[0], argv[1:]
    try:
        with open(path) as fh:
            cfg = migrate_rules(json.load(fh))
        cmd = args[0]
        if cmd == "list":
            show(cfg)
            return
        if cmd == "mode":
            if len(args) == 1:
                print("tls mode: %s" % tls_config(cfg)["mode"])
                return
            tls_update(cfg, mode=args[1])
            message = "tls mode: %s" % args[1].lower()
        elif cmd in ("allow", "ignore") and len(args) == 3 and args[1] in ("add", "rm"):
            pairs = [(cmd, args[2])]
            tls_update(cfg, add=pairs if args[1] == "add" else (), remove=pairs if args[1] == "rm" else ())
            message = "%s %s: %s" % (cmd, "added" if args[1] == "add" else "removed", args[2].lower())
        else:
            die("usage: tls list | tls mode [all|allow|ignore] | tls allow|ignore add|rm HOST[:PORT]")
    except (OSError, ValueError) as e:
        die(str(e))
    atomic_json(path, cfg)
    print(message)
    tls = tls_config(cfg)
    if tls["mode"] != "all" and not tls[tls["mode"]]:
        print("note: mode is %s but the %s list is empty" % (tls["mode"],
              tls["mode"]) + (" — nothing would be decrypted" if tls["mode"] == "allow" else ""))
    print(NOTE)


if __name__ == "__main__":
    main(sys.argv[1:])
