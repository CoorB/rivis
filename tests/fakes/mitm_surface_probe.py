"""Test-only mitmdump script: check that every mitmproxy / Tornado name Rivis reaches into still exists
with the shape the add-ons expect. Writes JSON to $PROBE_OUT, then exits. Never part of the product.

Run under the frozen mitmproxy binary (system Python cannot import these packages). A mitmproxy upgrade
that renames an internal turns a silent runtime skip into a loud test failure the day of the pin bump.
"""
import importlib
import json
import os
import re
import sys

from mitmproxy import ctx

INDEX_SCRIPT = re.compile(r'src="\./static/index-[\w-]+\.js"')


def _need(report, name, fn):
    try:
        ok = bool(fn())
        report[name] = ok
        if not ok:
            report["ok"] = False
            report["errors"].append(name)
    except Exception as exc:  # noqa: BLE001 — surface must be reported, never take the probe down mid-loop
        report[name] = False
        report[name + ".error"] = "%s: %s" % (type(exc).__name__, exc)
        report["ok"] = False
        report["errors"].append(name)


def running():
    report = {"ok": True, "errors": [], "engine": "mitmdump"}

    from mitmproxy.tools.web import app as webapp
    for name in ("IndexHandler", "RequestHandler", "FlowContentView", "FlowContent",
                 "DumpFlows", "APIError", "flow_to_json"):
        _need(report, "webapp." + name, lambda n=name: hasattr(webapp, n))

    static = os.path.join(os.path.dirname(webapp.__file__), "static")
    js = sorted(f for f in os.listdir(static) if f.startswith("index-") and f.endswith(".js"))
    _need(report, "static.index_js", lambda: len(js) == 1)
    report["static.index_js.name"] = js[0] if js else None

    idx = os.path.join(os.path.dirname(webapp.__file__), "index.html")
    html = open(idx, encoding="utf-8").read() if os.path.isfile(idx) else ""
    _need(report, "index.html.head", lambda: "</head>" in html)
    _need(report, "index.html.body", lambda: "</body>" in html)
    _need(report, "index.html.script_src", lambda: bool(INDEX_SCRIPT.search(html)))

    sys.path.insert(0, os.environ["RIVIS_ADDONS"])
    from panel_mitmweb import _VIEWPORT_LOOP, patch_mitmweb_js  # noqa: E402
    source = open(os.path.join(static, js[0]), encoding="utf-8").read() if js else ""
    _need(report, "viewport.pattern_matches_once", lambda: len(_VIEWPORT_LOOP.findall(source)) == 1)
    patched = patch_mitmweb_js(source)
    _need(report, "viewport.patch_changes_source", lambda: patched != source)

    from mitmproxy.proxy import mode_servers
    _need(report, "LocalRedirectorInstance", lambda: hasattr(mode_servers, "LocalRedirectorInstance"))
    _need(report, "LocalRedirectorInstance.handle_stream",
          lambda: callable(getattr(mode_servers.LocalRedirectorInstance, "handle_stream", None)))

    from mitmproxy.proxy.layers.http import _base, _http1
    _need(report, "Http1Client.read_headers",
          lambda: callable(getattr(_http1.Http1Client, "read_headers", None)))
    _need(report, "_base.format_error", lambda: callable(getattr(_base, "format_error", None)))
    for name in ("_http1", "_http2", "_http3"):
        mod = importlib.import_module("mitmproxy.proxy.layers.http." + name)
        _need(report, "format_error." + name, lambda m=mod: hasattr(m, "format_error"))

    from mitmproxy.proxy import commands, events
    _need(report, "events.DataReceived", lambda: hasattr(events, "DataReceived"))
    _need(report, "commands.Log", lambda: hasattr(commands, "Log"))

    from mitmproxy.io import har
    _need(report, "har.request_to_flow", lambda: callable(getattr(har, "request_to_flow", None)))

    from mitmproxy.addons.savehar import SaveHar
    _need(report, "SaveHar.make_har", lambda: callable(getattr(SaveHar(), "make_har", None)))

    from mitmproxy.addons import export as mexport
    for fmt in ("raw_request", "raw_response", "raw"):
        _need(report, "export." + fmt, lambda f=fmt: callable(getattr(mexport, f, None)))

    from mitmproxy import contentviews
    _need(report, "contentviews.add", lambda: callable(contentviews.add))

    from mitmproxy.addonmanager import traverse
    _need(report, "addonmanager.traverse", lambda: callable(traverse))

    from mitmproxy import connection, exceptions, flowfilter, http, io
    from mitmproxy.net.http import status_codes
    _need(report, "http.HTTPFlow", lambda: hasattr(http, "HTTPFlow"))
    _need(report, "http.Response.make", lambda: callable(http.Response.make))
    _need(report, "http.Headers", lambda: hasattr(http, "Headers"))
    _need(report, "connection.Client", lambda: hasattr(connection, "Client"))
    _need(report, "connection.Server", lambda: hasattr(connection, "Server"))
    _need(report, "flowfilter.parse", lambda: callable(flowfilter.parse))
    _need(report, "flowfilter.match", lambda: callable(flowfilter.match))
    _need(report, "exceptions.OptionsError", lambda: hasattr(exceptions, "OptionsError"))
    _need(report, "exceptions.FlowReadException", lambda: hasattr(exceptions, "FlowReadException"))
    _need(report, "io.FlowReader", lambda: hasattr(io, "FlowReader"))
    _need(report, "status_codes.RESPONSES", lambda: isinstance(status_codes.RESPONSES, dict))

    for opt in ("confdir", "connection_strategy", "http2", "stream_large_bodies", "ssl_insecure",
                "ssl_verify_upstream_trusted_ca", "allow_hosts", "ignore_hosts", "show_ignored_hosts",
                "client_certs", "mode", "listen_port"):
        _need(report, "option." + opt, lambda o=opt: hasattr(ctx.options, o))

    import tornado.web
    _need(report, "tornado.web.RequestHandler", lambda: hasattr(tornado.web, "RequestHandler"))
    _need(report, "tornado.web.HTTPError", lambda: hasattr(tornado.web, "HTTPError"))
    _need(report, "tornado.web.ErrorHandler", lambda: hasattr(tornado.web, "ErrorHandler"))

    with open(os.environ["PROBE_OUT"], "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
    ctx.master.shutdown()
