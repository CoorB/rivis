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
            fn = namespace.get(hook) or namespace.get("onRequest" if hook == "on_request" else "onResponse")
            if fn is None:
                send({"ok": True, "invoked": False, "logs": logs})
                continue
            context, request, response = call["context"], call["request"], call["response"]
            args = (context, call["url"], request) if response is None else (context, call["url"], request, response)
            with contextlib.redirect_stdout(io.StringIO()):
                result = fn(*args)
                if asyncio.iscoroutine(result): result = asyncio.run(result)
            send({"ok": True, "invoked": True, "result": result, "context": context, "logs": logs})
        except BaseException as exc:
            send({"ok": False, "error": "%s: %s" % (type(exc).__name__, exc),
                  "traceback": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__, limit=8)), "logs": logs})


if __name__ == "__main__":
    main()
