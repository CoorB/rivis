"""The soak's 'Pause on this call' scenario (soak F1, 25 min run: menu.pause timed out after 20 s, 'last: []').

A breakpoint made from a call is for that call's own scheme, host, port and path, so the random traffic mix reaches it only
now and then (about one run in four got nothing in 20 s). The tester would trigger the call again in the app; the scenario now
does the same, and the call it sends must be one the breakpoint actually matches."""
import ast
import os
import re
import sys
import threading
import unittest
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "soak"))
import traffic  # noqa: E402
from scenarios import Scenarios  # noqa: E402


def flow_regex(f):
    """ProxyPanel.flow_regex taken from the source (proxy_panel imports mitmproxy, which this Python lacks)."""
    src = open(os.path.join(HERE, "..", "addons", "proxy_panel.py")).read()
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "flow_regex")
    fn.decorator_list = []
    ns = {"re": re}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "proxy_panel.py", "exec"), ns)
    return ns["flow_regex"](f)


def flow_of(url):
    m = re.match(r"(https?)://([^:/]+):(\d+)(/[^?]*)", url)
    scheme, host, port, path = m.groups()
    return SimpleNamespace(request=SimpleNamespace(scheme=scheme, pretty_host=host, port=int(port), path=path))


class FakeTraffic(traffic.Traffic):
    def __init__(self):
        self.n, self.lock, self.sent_calls = 5400, threading.Lock(), []
        self.done = threading.Event()

    def execute(self, conns, call):
        self.sent_calls.append(call)
        self.done.set()


def url_of(call, http_port=64437, https_port=64438):
    return "%s://%s:%d%s" % ("https" if call["tls"] else "http", call["host"], https_port if call["tls"] else http_port, call["path"])


class AppCallsAgainTests(unittest.TestCase):
    def test_the_call_is_one_the_breakpoint_made_from_the_selected_call_matches(self):
        for url in ("http://backbase-identity-sit.localhost:64437%s?i=5408" % traffic.PAUSE_PATH,
                    "https://lifestyle-api-sit.localhost:64438%s?i=77" % traffic.PAUSE_PATH):
            rx = re.compile(flow_regex(flow_of(url)))
            t = FakeTraffic()
            call = t.app_calls_again(url)
            self.assertTrue(t.done.wait(5))
            self.assertTrue(rx.search(url_of(call)), (url, url_of(call)))
            self.assertNotEqual(call["i"], 5408)

    def test_the_random_mix_alone_often_misses_the_breakpoint(self):
        """The reason for the fix, measured: the share of paused-path calls that a breakpoint on one of them would not catch."""
        import random
        t = FakeTraffic()
        t.rng = random.Random(7)
        rx = re.compile(flow_regex(flow_of("http://backbase-identity-sit.localhost:64437%s?i=1" % traffic.PAUSE_PATH)))
        pause = [c for c in (t.make_call() for _ in range(4000)) if c["path"].startswith(traffic.PAUSE_PATH)]
        missed = sum(1 for c in pause if not rx.search(url_of(c)))
        self.assertGreater(missed / len(pause), 0.7)


class FakeUi:
    def __init__(self, panel):
        self.panel = panel

    def now_ms(self):
        return 0

    def wait(self, fn, timeout, what):
        if not fn():
            from driver import SoakFail
            raise SoakFail("timed out after %ds waiting for %s" % (timeout, what))
        return True

    def wait_toast(self, *a):
        pass

    def pause(self, *a):
        pass

    def click(self, *a):
        pass

    def P(self, *a):
        return None

    def sheet_open(self, which="pause"):
        return True


class PausePanel:
    """Holds a call only when one for the breakpoint's endpoint arrives, as the proxy does."""
    def __init__(self, url):
        self.url, self.held, self.sent = url, [], []

    def state(self):
        return {"breakpoints": [{"match": "/api/soak-pause/client-api/v1/ping"}], "paused": list(self.held)}


class MenuPauseScenarioTests(unittest.TestCase):
    def run_scenario(self, app_sends_call):
        url = "http://backbase-identity-sit.localhost:64437%s?i=5408" % traffic.PAUSE_PATH
        panel = PausePanel(url)

        class Traf:
            def app_calls_again(self, u):
                if app_sends_call:
                    panel.held.append(u)

        sc = Scenarios.__new__(Scenarios)
        sc.ui, sc.panel, sc.cfg = FakeUi(panel), panel, SimpleNamespace(action_deadline=10)
        sc.s = SimpleNamespace(traffic=Traf(), world=SimpleNamespace(reset=lambda: None))
        sc.open_menu = lambda pos, contains=None: ("fid", {"url": url, "pq": url.split("64437")[1]})
        sc.pick_item = lambda key: None
        sc.menu_pause("top")

    def test_the_app_makes_the_call_again_so_the_breakpoint_holds_it(self):
        self.run_scenario(app_sends_call=True)

    def test_when_the_app_never_sends_it_the_scenario_fails_not_passes(self):
        from driver import SoakFail
        with self.assertRaisesRegex(SoakFail, "held at the breakpoint"):
            self.run_scenario(app_sends_call=False)


if __name__ == "__main__":
    unittest.main()
