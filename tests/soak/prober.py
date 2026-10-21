"""Independent latency probe process: Playwright tracing cannot pause its Python thread."""
import http.client
import json
import sys
import time


def run(upstream_port, proxy_port, t0):
    direct = http.client.HTTPConnection("127.0.0.1", upstream_port, timeout=30)
    via = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=30)
    url = "http://127.0.0.1:%d/neo/ping" % upstream_port
    while True:
        time.sleep(1)                           # 60 a minute: a minute cut short by a fault window still has enough samples for a real p95
        try:
            t = time.time() - t0
            a = time.perf_counter()
            direct.request("GET", "/neo/ping")
            direct.getresponse().read()
            b = time.perf_counter()
            via.request("GET", url)
            via.getresponse().read()
            c = time.perf_counter()
            print(json.dumps([t, (b - a) * 1000, (c - b) * 1000]), flush=True)
        except Exception:                       # a dropped connection is retried with new sockets
            direct.close()
            via.close()
            direct = http.client.HTTPConnection("127.0.0.1", upstream_port, timeout=30)
            via = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=30)


if __name__ == "__main__":
    run(int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]))
