# Real-use soak gate

Every earlier test round ran in clean conditions: a few calls, a still list, an instantly answering proxy, scripted
instant clicks, sessions of seconds. The bugs pilot users hit on day one lived in the gaps: the call list that could not
be wheeled to the top while calls streamed in, the right-click menu that closed itself when the list auto-scrolled, panel
actions that failed silently when the proxy stopped answering, the whole call list downloaded every 1.2 s, the Source menu
stuck on "All sources". This gate runs Rivis the way a tester uses it, for a long time, and fails on any of those.

## Run it

```
tests/soak/run.sh --smoke          # 3 minutes: proves the harness, covers about two thirds of the scenarios
tests/soak/run.sh                  # the full gate: SOAK_MINUTES (default 25)
tests/soak/run.sh --minutes 10
SOAK_SEED=7 SOAK_RATE=5 SOAK_PREFILL=3000 tests/soak/run.sh --smoke     # a bigger list from the start
```

Needs what `tests/run.sh --ui` needs: `/usr/bin/python3` with Playwright and its Chromium
(`pip3 install --user playwright && python3 -m playwright install chromium`), `mitmweb`, `curl`. A launched run takes
the configured minutes plus about 40 s of start-up and shutdown. Launch it detached (`neojob tests/soak/run.sh`) and read
the report afterwards.

Exit status: `0` PASS; `1` a scenario or budget failed, or something was left behind; `2` the harness itself could not run.

Output: `tests/.artifacts/soak/<timestamp>/report.md` and `report.json`, plus `failures/NNN-<scenario>.png` (screenshot at the
moment of failure) and `failures/NNN-<scenario>-trace.zip` (Playwright trace of the failing scenario, which ends at the
failure; open with `python3 -m playwright show-trace <zip>`).

## What runs

- **Rivis** started through the real `rivis start` CLI in a throw-away HOME with a private CA, random ports, `RIVIS_MAX_FLOWS`
  raised so the product's own trimming stays out of the way. Same hermetic harness as the rest of the suite
  (`tests/harness.py`): it never touches 8080/8083/8090/8093/9090/9091, `~/.rivis`, `~/.mitmproxy`, the system proxy,
  simulators or emulators. The check afterwards (`hermetic_check.py`, built on `tests/hermetic.py`) proves no process, port or
  temp dir is left and `$HOME`, the protected ports and the system proxy are unchanged. It also checks for stray Chromium.
- **A NEO-like upstream** (`neo_upstream.py`, extends `tests/upstream.py`): Backbase-style JSON for accounts, cards,
  transactions (20 to 2,500 rows), payment orders, users/me; loyalty and SADAD endpoints that take 1 to 3 s; an inbox that
  answers 400/401/403/404/429/500/502/503; a 1 to 3 MB statement PDF; and a websocket (`/neo/ws`, four frames). HTTP and
  HTTPS. Hosts are `backbase-edge-sit.localhost`, `backbase-identity-sit.localhost`, `lifestyle-api-sit.localhost`: they
  resolve to 127.0.0.1, so a Repeat never leaves the machine, yet the list shows three realistic hosts.
- **Traffic** (`traffic.py`): from minute 0 to the end, 2 to 5 calls/s (a slow sine wave around SOAK_RATE) with a burst of 12-35
  calls every 25 to 70 s, over pooled keep-alive connections from 14 worker threads (a slow call never delays the rest),
  20% over HTTPS (decrypted), 5% through the curl binary so the Source menu has a second sender. Seeded. A latency probe sends
  the same ping directly to the upstream and through the proxy every 3 s: the difference is the proxy's added latency.
  A websocket session runs every 40 s.
- **A browser** (Playwright Chromium, 1512x837) driving the panel with **real input only**: mouse moves with 6-14 steps,
  `mouse.down/up` clicks with a short dwell, `mouse.wheel`, `keyboard.type` with per-key delays, human pauses of 200-2000 ms
  (triangular, most near 500-900 ms) from a seeded RNG. The smoke run halves the pauses (`SOAK_PAUSE_SCALE`).
- **A fault add-on** (`fault_addon.py`), test-only, loaded through the harness's `SHIM_PRE_ADDON`, so the product has no
  hook and nothing to leave inert. It acts only on a call to `/__soak_fault__`: `freeze` sleeps in the proxy's event loop (the
  panel API stops answering too, which is what a blocking user script does), `slow` delays every call by 1.5 s while the panel
  stays responsive.

## Scenarios (what is asserted)

Menu scenarios run with the list parked at the **top** (newest, following), the **middle**, and the **end** (following), rotating.
Before choosing an item the scenario waits at least 1.2 s and until a new call has arrived, like a person reading the menu.

| scenario | asserts |
|---|---|
| `menu.map` | menu still open after calls arrived; Map Local editor opens in the drawer; Back discards the draft |
| `menu.pause` | breakpoint added (toast, state), a matching call is held, the paused sheet opens by itself, Continue releases it |
| `menu.repeat` / `menu.edit_repeat` | the repeated / edited call reaches the upstream again (exact path and query counted there) |
| `menu.compare_a` | Compare tab opens, toast tells to pick the other call |
| `menu.copy_curl` / `menu.copy_url` | clipboard holds a cURL / URL for that call |
| `menu.host_focus` | "Show only this host" sets the filter, strip names it; the menu then offers "Show all hosts again" and it clears |
| `menu.stop_decrypt` | TLS list changes; then restored from the Network tab |
| `menu.delete` | the call is gone from the proxy |
| `tab.call` `compose` `map_local` `breakpoints` `network` `collections` `compare` `sessions` `scripts_devices` | each tab opened with its main action used once: Compose send/save/delete; Map Local add, edit, save, it answers, rules toggle off/on, Back; breakpoint add, Continue and Abort on held calls; throttle on (a matching call is slower) and off, No caching on/off; collection record/stop; session save; scripts/devices open |
| `list.scroll_top` | wheel to the very top while streaming; it stays at the top and follows the newest call |
| `list.scroll_end` | wheel to the end; it stays at the end as calls arrive |
| `list.scroll_middle` | rows do not move under the reader while calls arrive |
| `list.select_details` | selection changes; Request, Response, Connection, Timing panes each show |
| `kbd.shortcuts` | `r` repeats the selected call, `?` opens help, Alt+Shift+P toggles Tools, Alt+Shift+F focuses the filter |
| `filter.search` | typing a filter hides non-matching calls; Clear brings them back |
| `source.menu` | choose a sender, keep the select focused for 3.5 s while polls run, it still shows the choice; back to All sources shows All sources |
| `idle.polling` | with Tools closed and idle the panel downloads the call list 0 times in 9 s; with Tools open at most 3 times in 9 s |
| `sess.save_whole_capture` (once, full run) | saving the entire session (thousands of calls) finishes and the app's calls do not stall |
| `fault.freeze.*` | proxy frozen 15 s and 30 s (12 s in the smoke): **each click gets visible feedback (a toast) within SOAK_ACTION_DEADLINE, and the right-click menu opens or errors**; the "can't reach" banner appears within SOAK_LOST_DEADLINE; the panel API, banner, a click, and the app's calls all recover within SOAK_RECOVER_DEADLINE |
| `fault.slow.*` | calls 1.5 s late for 20 s (10 s in the smoke): the panel stays responsive; the app's calls are back to normal afterwards |

## Health budgets (checked over the whole run; fault windows and 22 s after them are excluded)

| budget | default | variable |
|---|---|---|
| no page JS errors: `pageerror`, `console.error`, unhandled rejections | 0 | |
| panel API p95, every minute | 1500 ms | `SOAK_PANEL_P95_MS` |
| in-flight panel requests (`./proxy/api/*` plus the `./flows` list) | at most 3 | `SOAK_MAX_INFLIGHT` |
| proxy-added latency p95, every minute (proxied ping minus direct ping) | 250 ms | `SOAK_ADDED_P95_MS` |
| mitmweb process-group RSS growth after minute 3 | 400 MB | `SOAK_RSS_GROWTH_MB` |
| browser JS heap growth after minute 3, after a forced GC | 150 MB | `SOAK_HEAP_GROWTH_MB` |
| longest UI freeze (long task) | 4000 ms | `SOAK_LONGTASK_MS` |
| app calls that fail outright | at most 1% | |
| websocket sessions that deliver frames | all | |
| session grows past 3,000 calls (runs of 15 minutes or more) | yes | |
| nothing left behind (processes, ports, temp dirs, Chromium, `$HOME`, system proxy) | clean | |

Documented timeouts: an action must complete or show an error within **10 s** of the click (`SOAK_ACTION_DEADLINE`); the
"can't reach" banner within **15 s** of the proxy freezing (`SOAK_LOST_DEADLINE`); recovery within **20 s** of a fault ending
(`SOAK_RECOVER_DEADLINE`).

The report also carries per-minute tables (calls, list size, app and added latency, panel latency per minute and per operation,
call-list downloads and bytes, peak in-flight, longest freeze, JS errors, RSS, heap, DOM nodes) with a sparkline under each.

## Reading a failure

Failures are grouped by scenario and message, with the first occurrence's screenshot and trace, the positions it happened in
and whether the panel's "can't reach" banner or menu was showing. A scenario that cannot find what it needs on screen (for
example no call to the soak-pause path in view) is **skipped**, counted, and listed, never passed silently. Skips above a few
per run mean the harness, not the product, needs attention.

Not every bug the gate reports is a product bug: a failure that reproduces in `tests/ui` with the same steps is. Everything
random is seeded (`SOAK_SEED`), so a failing run can be repeated with the same pauses, call mix and burst times (timing of the
proxy itself is of course not repeatable).

## Release gate

Opt in from `qa-overnight/A2b-run.sh` with `RIVIS_SOAK=1` (see the lines in `qa-overnight/R-SOAK-RESULT.md`): the step runs
`tests/soak/run.sh` (25 minutes) after the full suite and fails the gate on a non-zero exit.
