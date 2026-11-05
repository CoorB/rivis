"""Test-only mitmweb script: check web-UI surfaces Rivis registers routes on and drives from the panel.
Writes JSON to $PROBE_OUT, then exits. Never part of the product.

mitmdump has no Tornado app and no web_* / view_filter / intercept options — those live only on mitmweb.
"""
import json
import os

from mitmproxy import ctx


def _need(report, name, fn):
    try:
        ok = bool(fn())
        report[name] = ok
        if not ok:
            report["ok"] = False
            report["errors"].append(name)
    except Exception as exc:  # noqa: BLE001
        report[name] = False
        report[name + ".error"] = "%s: %s" % (type(exc).__name__, exc)
        report["ok"] = False
        report["errors"].append(name)


def running():
    report = {"ok": True, "errors": [], "engine": "mitmweb"}
    app = getattr(ctx.master, "app", None)
    _need(report, "master.app", lambda: app is not None)
    _need(report, "app.add_handlers", lambda: callable(getattr(app, "add_handlers", None)))
    _need(report, "app.find_handler", lambda: callable(getattr(app, "find_handler", None)))
    _need(report, "app.get_handler_delegate", lambda: callable(getattr(app, "get_handler_delegate", None)))
    _need(report, "app.settings", lambda: isinstance(getattr(app, "settings", None), dict))

    view = ctx.master.view
    _need(report, "master.view", lambda: view is not None)
    _need(report, "view.update", lambda: callable(getattr(view, "update", None)))
    _need(report, "view.add", lambda: callable(getattr(view, "add", None)))
    _need(report, "view.remove", lambda: callable(getattr(view, "remove", None)))
    _need(report, "view.get_by_id", lambda: callable(getattr(view, "get_by_id", None)))
    _need(report, "view._store", lambda: hasattr(view, "_store"))
    _need(report, "view.focus", lambda: hasattr(view, "focus"))

    _need(report, "master.commands.call", lambda: callable(getattr(ctx.master.commands, "call", None)))
    _need(report, "master.addons.get", lambda: callable(getattr(ctx.master.addons, "get", None)))

    for opt in ("web_password", "web_port", "web_host", "web_open_browser", "view_filter",
                "intercept", "intercept_active", "web_columns"):
        _need(report, "option." + opt, lambda o=opt: hasattr(ctx.options, o))

    with open(os.environ["PROBE_OUT"], "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
    ctx.master.shutdown()
