"""Fault injection: the proxy stops answering (freeze) or answers late (slow) for 10-30 s while a person keeps clicking.
The panel must never go silent: every action either completes, or shows an error within SOAK_ACTION_DEADLINE; a "can't
reach" banner must appear within SOAK_LOST_DEADLINE; and everything works again within SOAK_RECOVER_DEADLINE afterwards.
The fault itself is a test-only add-on (fault_addon.py, loaded through the harness shim) driven by one call to a magic path."""
import time

from driver import SoakFail, check
from harness import Background


class Faults:
    def __init__(self, s):
        self.s = s
        self.ui = s.ui
        self.inst = s.inst
        self.up = s.up
        self.cfg = s.cfg
        self.panel = s.inst.panel

    def arm(self, mode, secs):
        url = "http://127.0.0.1:%d/__soak_fault__?mode=%s&s=%d" % (self.up.http_port, mode, secs)
        now = self.s.metrics.now()
        self.s.metrics.fault_windows.append([now - 1, now + secs + (22 if mode == "freeze" else 12)])
        return Background(lambda: self.inst.fetch(url, timeout=secs + 40))

    def frozen(self, timeout=1.5):
        try:
            return self.panel.get("/proxy/api/state", timeout=timeout)[0] != 200
        except Exception:                                   # noqa: BLE001 - a timeout IS the answer
            return True

    def feedback(self, label, t0_ms, t0, deadline=None):
        """Visible feedback to a click made at t0: any toast (the action's own or an error) within the deadline."""
        deadline = deadline or self.cfg.action_deadline
        ui = self.ui
        end = time.time() + deadline
        while time.time() < end:
            ts = ui.toasts_since(t0_ms)
            if ts:
                return ts[0]
            ui.page.wait_for_timeout(150)
            self.s.tick()
        raise SoakFail("silent failure: %s gave no toast and no error for %.0f s while the proxy was not answering"
                       % (label, time.time() - t0))

    def freeze(self, secs):
        s, ui, rec, cfg = self.s, self.ui, self.s.rec, self.cfg
        ui.open_tools("net")
        ui.go_position("top")
        bg = self.arm("freeze", secs)
        t_start = time.time()
        try:
            rec.run("fault.freeze.harness_froze", lambda: check(self._wait_frozen(), "the fault add-on did not stop the proxy answering (harness problem)"))
            # 1) a click in the Tools drawer
            def toggle():
                t0, t0m = time.time(), ui.now_ms()
                ui.click(ui.P("#nocache"))
                self.feedback("switching No caching", t0m, t0)
            rec.run("fault.freeze.action_feedback_tools", toggle)
            ui.pause(200, 600)

            # 2) right-click a call: the menu opens, or an error shows
            def menu():
                row = ui.pick_row()
                t0, t0m = time.time(), ui.now_ms()
                ui.click_xy(row["x"], row["y"], "right")
                end = time.time() + cfg.action_deadline
                while time.time() < end:
                    if ui.menu_open() or ui.toasts_since(t0m):
                        return
                    ui.page.wait_for_timeout(150)
                    s.tick()
                raise SoakFail("silent failure: right-clicking a call opened no menu and showed no error for %.0f s while the proxy was not answering"
                               % (time.time() - t0))
            rec.run("fault.freeze.action_feedback_menu", menu)
            ui.key("Escape")

            # 3) the global banner
            def banner():
                end = t_start + cfg.lost_deadline
                while True:
                    if ui.lost_bar():
                        return
                    if time.time() >= end:
                        break
                    ui.page.wait_for_timeout(200)
                    s.tick()
                raise SoakFail("no 'can't reach' banner within %.0f s of the proxy freezing" % cfg.lost_deadline)
            rec.run("fault.freeze.banner", banner)
        finally:
            left = secs + 3 - (time.time() - t_start)
            while left > 0:
                ui.page.wait_for_timeout(300)
                s.tick()
                left = secs + 3 - (time.time() - t_start)
            try:
                bg.result(secs + 40)
            except Exception:                               # noqa: BLE001
                pass
        # recovery
        t_end = time.time()
        rec.run("fault.freeze.recovers_api", lambda: ui.wait(lambda: not self.frozen(3.0), cfg.recover_deadline, "the panel API to answer again"))
        rec.run("fault.freeze.recovers_banner", lambda: ui.wait(lambda: not ui.lost_bar(), cfg.recover_deadline, "the banner to clear after recovery"))
        s.world.reset()
        ui.page.wait_for_timeout(1500)
        ui.close_tools()

        def again():
            ui.open_tools("net")
            t0m = ui.now_ms()
            ui.click(ui.P("#nocache"))
            ui.wait_toast(r"No caching on", t0m)
            s.world.reset()
            ui.close_tools()
        rec.run("fault.freeze.action_after_recovery", again)

        def app_back():
            end = time.time() + cfg.recover_deadline
            while time.time() < end:
                recent = [r for r in s.metrics.probe if r[0] > s.metrics.now() - 8]
                if recent and max(r[2] for r in recent) < 800:
                    return
                ui.page.wait_for_timeout(500)
                s.tick()
            raise SoakFail("app calls through the proxy were still slow %.0f s after the freeze ended" % cfg.recover_deadline)
        rec.run("fault.freeze.app_calls_recover", app_back)

    def _wait_frozen(self):
        end = time.time() + 8
        while time.time() < end:
            if self.frozen(1.0):
                return True
            time.sleep(0.3)
        return False

    def slow(self, secs):
        s, ui, rec, cfg = self.s, self.ui, self.s.rec, self.cfg
        ui.open_tools("net")
        bg = self.arm("slow", secs)
        bg.result(15)
        t_start = time.time()
        time.sleep(1.0)

        def effect():
            ui.wait(lambda: any(r[2] > 1300 for r in s.metrics.probe if r[0] > s.metrics.now() - 6), 12, "the app's calls to get slower")
        rec.run("fault.slow.app_calls_are_slow", effect)

        def panel_ok():
            t0m = ui.now_ms()
            t0 = time.time()
            ui.click(ui.P("#nocache"))
            ui.wait_toast(r"No caching on", t0m, timeout=5)
            check(time.time() - t0 < 5, "the panel answered a click slowly while only the app's calls were slow")
            s.world.reset()
        rec.run("fault.slow.panel_stays_responsive", panel_ok)
        left = secs + 2 - (time.time() - t_start)
        while left > 0:
            ui.page.wait_for_timeout(300)
            s.tick()
            left = secs + 2 - (time.time() - t_start)

        def back():
            end = time.time() + cfg.recover_deadline
            while time.time() < end:
                recent = [r for r in s.metrics.probe if r[0] > s.metrics.now() - 8]
                if recent and max(r[2] for r in recent) < 800:
                    return
                ui.page.wait_for_timeout(500)
                s.tick()
            raise SoakFail("calls through the proxy were still late %.0f s after the slow period ended" % cfg.recover_deadline)
        rec.run("fault.slow.app_calls_recover", back)
        ui.close_tools()
