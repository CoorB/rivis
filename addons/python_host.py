"""Isolated, persistent Python script host. One process per enabled script."""
import asyncio
import contextlib
import io
import json
import re
import sys
import traceback


def send(value):
    sys.__stdout__.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.__stdout__.flush()


def main():
    namespace = {}
    name = ""
    for line in sys.stdin:
        logs = []
        try:
            call = json.loads(line)
            if call["op"] == "load":
                name = call["name"]
                namespace = {"__file__": call["path"], "__name__": "proxy_user_" + re.sub(r"\W", "_", name)}

                def log(*parts): namespace["_logs"].append(" ".join(map(str, parts)))
                async def sleep(ms): await asyncio.sleep(float(ms) / 1000)
                def mock(status=200, body="", headers=None):
                    return {"__proxy_mock__": True, "statusCode": status, "body": body, "headers": headers or {}}
                namespace.update(log=log, sleep=sleep, mock=mock, _logs=logs)
                with open(call["path"], encoding="utf-8") as fh:
                    code = fh.read()
                with contextlib.redirect_stdout(io.StringIO()):
                    exec(compile(code, call["path"], "exec"), namespace)
                send({"ok": True, "logs": logs})
                continue
            hook = call["hook"]
            namespace["_logs"] = logs
            shared = call.get("shared_state")
            if not isinstance(shared, dict):
                shared = {}
            # Same dict under both names so a Proxyman paste (sharedState) and Python style (shared_state) share one bag.
            def clear_shared_state():
                shared.clear()
            namespace["shared_state"] = shared
            namespace["sharedState"] = shared
            namespace["clear_shared_state"] = clear_shared_state
            namespace["clearSharedState"] = clear_shared_state
            camel = {"on_request": "onRequest", "on_response": "onResponse", "on_websocket": "onWebsocket"}
            fn = namespace.get(hook) or namespace.get(camel.get(hook, ""))
            if fn is None:
                send({"ok": True, "invoked": False, "logs": logs, "shared_state": shared})
                continue
            context, request, response = call["context"], call["request"], call["response"]
            if hook == "on_websocket":
                args = (context, call["url"], call.get("message"))
            elif response is None:
                args = (context, call["url"], request)
            else:
                args = (context, call["url"], request, response)
            with contextlib.redirect_stdout(io.StringIO()):
                result = fn(*args)
                if asyncio.iscoroutine(result): result = asyncio.run(result)
            # Prefer the live namespace binding: a script that rebinds shared_state = {...} still round-trips.
            out_shared = namespace.get("shared_state")
            if out_shared is None:
                out_shared = namespace.get("sharedState")
            if not isinstance(out_shared, dict):
                raise TypeError("shared state must be a dictionary")
            send({"ok": True, "invoked": True, "result": result, "context": context,
                  "shared_state": out_shared, "logs": logs})
        except BaseException as exc:
            send({"ok": False, "error": "%s: %s" % (type(exc).__name__, exc),
                  "traceback": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__, limit=8)), "logs": logs})


if __name__ == "__main__":
    main()
