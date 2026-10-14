# Product bugs found while building the suite

Fixed entries retain their original repro for regression history and are marked with the fixing commit. Open entries
still have an `expectedFailure` test, so an unexpected success fails the suite until its marker and ledger entry are updated.


All repros assume a running Rivis: `rivis start --no-ios --no-open`, then log in at `rivis ui` and use the panel's
cookie + XSRF pair. In the suite this is `harness.Panel`. `P` below means "POST /proxy/api/<op> with the session".

## B1 — FIXED in 222d3d0 — panel returns an HTML 500 for wrongly shaped input (should be a JSON 400)
- **Where:** `addons/proxy_panel.py` `Api.post` catches `PanelError, KeyError, TypeError, ValueError, OSError, re.error`,
  but `act()` calls `a.get(...)` / `.strip()` on whatever JSON arrived.
- **Repro:**
  - `P add` with body `[]`, `null`, `123`, `"x"` or `true` → `AttributeError` → HTTP 500 `<html>…500: Internal Server Error`.
  - `P sess_save {"name": ["x"]}` (also `5`, `{}`, `true`) → 500. Same for `coll_record`, `coll_import`, `maplocal_add`,
    `script_new` (`name`) and `bp_add` (`host`).
- **Expected:** `400 {"error": "..."}` (brief §8, STANDARDS §1 "no silent failure").
- **Severity:** low (authenticated local user only) but every 500 is a swallowed error with no message.
- **Tests:** `test_panel.py::MalformedInput` (2 × expectedFailure).

## B2 — Host header is not validated (DNS rebinding)
- **Repro:** with a valid session cookie, `GET /proxy/api/state` with `Host: evil.example` → `200`.
- **Expected:** 403/421 for any Host that is not `127.0.0.1[:port]` / `localhost[:port]` (STANDARDS §2).
- **Test:** `test_panel.py::Auth::test_dns_rebinding_host_header_is_refused` (expectedFailure).

## B3 — FIXED in 222d3d0 — rules created from a captured call never match calls on a non-default port
- **Where:** `proxy_panel.py` `flow_regex()` = `re.escape(pretty_host + path) + r"(\?|$)"`. The URL the rules engine tests is
  `http://host:PORT/path`, so `host/path` never matches when a port is present.
- **Repro:** capture `http://127.0.0.1:5173/api/x`, then `P quick {"flow_id": <id>, "kind": "block"}` → the new rule's
  `match` is `127\.0\.0\.1/api/x(\?|$)` and the next identical call is NOT blocked. Same for `mock` (Map Local from a call),
  `quick` status/delay and `bp_add` with `flow_id`. (Works on 443/80 URLs, which is why NEO traffic hides it; local dev
  servers, `localhost:3000`, simulators and the like are affected.)
- **Expected:** the generated regex allows `(:\d+)?` after the host, like `wildcard_regex` already does.
- **Test:** `test_panel.py::Ops::test_rules_built_from_a_call_match_that_call_on_a_non_default_port` (expectedFailure);
  the other panel tests re-point the rule at the path so the rest of each op is still covered.

## B4 — FIXED in 222d3d0 — a failed `script_new` leaves an orphan empty script file that blocks the name
- **Where:** `proxy_panel.py` `script_new`: `open(path, "x")` runs before `script_template()` can raise.
- **Repro:** `P script_new {"name": "orph", "lang": "py", "template": "nope"}` → 400, but `scripts/orph.py` (empty) now exists,
  and `P script_new {"name": "orph", "lang": "py"}` fails with `[Errno 17] File exists`.
- **Test:** `test_panel.py::Ops::test_failed_script_new_leaves_no_orphan_file` (expectedFailure).

## B5 — panel ops follow symlinks inside the project's state dir (read outside the project)
- **Where:** `script_get` (`_script_path` does not resolve), `coll_entries` / `coll_export` / `sess_*` (plain `open`).
  Only the mock-file ops use `realpath` confinement.
- **Repro:** `ln -s /etc/hosts ~/.rivis/projects/default/collections/evil.json`; `P coll_entries {"name":"evil"}` reads it
  through the symlink (for `scripts/evil.py` + a rules.json entry: `P script_get {"file":"evil.py"}` returns `/etc/hosts`).
  A shared project archive that preserves symlinks is enough to plant one.
- **Expected:** one confinement helper (STANDARDS §2) that refuses anything whose realpath leaves the project dir.
- **Tests:** `test_panel.py::Confinement::test_symlinked_{script,collection}_is_not_read_through_the_panel` (expectedFailure).

## B6 — a rule can serve any file the user can read (`map_local.file`, `respond.body_file`)
- **Repro:** rules.json `{"name":"m","action":"map_local","match":"/echo","file":"/etc/hosts"}` → the proxy answers with
  `/etc/hosts`. A shared rules.json therefore reads outside its project with no visible opt-in (STANDARDS §2:
  "never read files outside its project without an explicit, visible user opt-in").
  The panel refuses to *create* such a rule (`add` rejects `file`/`body_file`) and to *open* it (`mockfile_get`), but the
  engine serves it.
- **Tests:** `test_panel.py::Confinement::test_{map_local_rule,respond_body_file}_…outside_the_project_is_not_served`
  (expectedFailure). Note: the CLI `rivis rules add --file` and the NEO migration deliberately use arbitrary paths today —
  the fix is probably a per-rule opt-in flag, so decide the policy before "fixing" the test.

## B7 — FIXED in 7d2b67e — `mock()` in a Python/JavaScript script fails whenever it carries headers (incl. the shipped `mock` template)
- **Where:** `addons/proxy_scripts.py` `_run`: builds `headers = [(name, value) …]` of `str` tuples and calls
  `http.Response.make(status, body, headers)`; mitmproxy 12.2.3 requires bytes there →
  `TypeError: Header fields must be bytes.` (an empty header list works, which is why `mock(200, "x")` does).
- **Repro:** `rivis scripts add mock demo --lang py --template mock --match /api` (or `mock(200, {"a": 1})`: a dict body adds
  `Content-Type` automatically) → every matching call goes upstream unchanged; log line
  `proxy_scripts: demo on_request: TypeError: Header fields must be bytes.; flow unchanged`.
- **Expected:** a local response with the given status/body/headers. Fix: pass a dict (or encode to bytes).
- **Tests:** `test_scripts.py::PythonScripts::test_mock_with_json_body_and_headers`,
  `JavaScriptScripts::test_mock_json_with_headers` (expectedFailure). Plain-text, header-less mocks are covered and pass.

## B8 — FIXED in 7d2b67e — a script's error disappears from the panel state almost immediately
- **Where:** `proxy_scripts.py` `_run`: on every hook call that does not raise, `self.last_errors.pop(item["file"])`.
  A script that only defines `on_request` raises in the request hook, then the response hook of the same flow finds no
  function (`return None`), takes the success path and erases the error. The panel's *Scripts* tab therefore (almost)
  never shows request-hook errors; only the log does.
- **Repro:** `def on_request(context, url, request): raise ValueError("boom")`, match `/echo`; call `/echo` once; poll
  `GET /proxy/api/state` → `script_status.errors` stays `{}` (log shows `boom on_request: ValueError: boom`).
  A script with only an `on_response` hook keeps its error, which is what the passing tests use.
- **Expected:** error shown until the next *successful run of that same hook* (or the file is edited).
- **Test:** `test_scripts.py::PythonScripts::test_request_hook_error_stays_in_state` (expectedFailure).

## B9 — FIXED in c60c71b — `make-release.sh` is a deny-list: `.git/`, `.env`, key files and `tests/` artifacts ship in the tarball
- **Where:** `install/mirror/make-release.sh` excludes a fixed list of names (rules.json, web-token, *.har, *.snapshot …) and
  tars everything else under `next/`.
- **Repro:** in a checkout that has a `.git/` dir (which `next/` does), a stray `.env` / `id_rsa` / `server.pem`, or
  `tests/.artifacts/*.log` (those logs contain the test run's web-UI tokens), run `install/mirror/make-release.sh out/` and
  `tar -tzf out/*.tar.gz` → all of them are inside, plus the whole git history. The planted denied names are correctly excluded.
- **Expected (STANDARDS §2 supply chain):** an allow-list (or `git archive`) so only tracked product files ship; at minimum
  exclude `.git`, `tests/`, `.env*`, `*.pem`, `*.key`, `id_*`.
- **Test:** `test_installer.py::Release::test_release_has_no_vcs_history_env_files_keys_or_test_artifacts` (expectedFailure).
  The deny-list itself and the "no private keys / developer paths in shipped files" scans pass.

## B10 — FIXED in c60c71b — installer cosmetics (low)
- `install.sh` self-check prints `redirector    enabled]` (`awk '{print $NF}'` on `[activated enabled]`).
  Test: `Cosmetics::test_self_check_redirector_state_has_no_stray_bracket` (skipped when the extension is not installed).
- install appends a blank line before the managed rc block; uninstall removes the block but not that blank line, so
  install/uninstall cycles grow the user's rc file. Test: `Cosmetics::test_install_then_uninstall_restores_the_rc_file_byte_for_byte`.

## B11 — FIXED in F-03 — the web-UI password is on mitmweb's command line (visible in `ps`)
- **Where:** `rivis` `cmd_start`: `--set "web_password=$token"`.
- **Repro:** `rivis start …` in one terminal; in another, as any local user: `ps -ww -o args= -p $(pgrep -x mitmweb)` →
  `… --set web_password=<the token> …`. The token is the only thing standing between a local user/process and the
  panel (rules, scripts that run code, mock files, captured traffic). STANDARDS §2: "Secrets never in argv".
- **Expected:** pass it through a file/env mitmweb supports (e.g. `--set web_password=@file` is not available; use
  `MITMPROXY_WEB_PASSWORD`/a generated options file with 0600), or hash it (mitmweb accepts an argon2 hash).
- **Test:** `test_security.py::Argv::test_web_password_is_not_visible_in_the_process_list` (expectedFailure).

## B12 — FIXED in 13ca519 — legacy `~/.neo-mitm` migration rewrites mock paths into a temp dir that is then renamed away
- **Where:** `rivis` `migrate_legacy`: it copies into `projects/.neo.tmp.XXXXXX/`, rewrites each `file` / `body_file` that
  lived under `~/.neo-mitm/mocks` to `<tmp>/mocks/…`, and only afterwards renames the tmp dir to `projects/neo`.
- **Repro:** create `~/.neo-mitm/{rules.json,mocks/m.json}` with a `map_local` rule whose `file` is `~/.neo-mitm/mocks/m.json`;
  run `rivis projects list`; `rivis --project neo rules show <name>` → `file` is `~/.rivis/projects/.neo.tmp.AbC123/mocks/m.json`,
  which does not exist → every migrated map_local / respond-body_file rule silently 404s/falls through.
- **Expected:** rewrite to `~/.rivis/projects/neo/mocks/…` (the final location) — or rename first, then rewrite.
- **Test:** `test_cli.py::Migration::test_map_local_and_body_file_paths_point_at_files_that_exist` (expectedFailure).

## B14 — FIXED in 9ae2fbc — `throttle` accepts out-of-range and non-finite numbers (CLI + PowerShell; the panel validates them)
- **Where:** `addons/rules_cli.py` `throttle` (`float(v)` with no range check) and the same logic in `rivis.ps1`. The panel's
  `profile` op enforces `0 ≤ loss_pct ≤ 100`, `0 ≤ latency ≤ 120000 ms` and finiteness.
- **Repro:** `rivis throttle lte loss=nan` → exit 0, `rules.json` now contains `"loss": NaN`; `rivis throttle manual down_kbps=inf`
  → `"down_kbps": Infinity`. Python can read these back, but `/proxy/api/state` serialises them as `NaN`/`Infinity`, which
  the browser's `JSON.parse` rejects, so the panel's state refresh breaks until the file is fixed by hand.
  `loss=150`, `loss=-1`, `latency_ms=-5`, `loss_pct=500` are also stored unchallenged.
- **Expected:** exit non-zero with `loss must be 0–100` (same limits as the panel).
- **Tests:** `test_cli.py::Throttle::test_out_of_range_and_non_finite_numbers_are_refused`,
  `test_powershell.py::Commands::test_throttle_rejects_out_of_range_and_non_finite_numbers` (expectedFailure).

## B15 — the panel's open tab does not refresh when state changes elsewhere (low)
- **Repro:** open the panel on the *Rules* tab; run `rivis rules add …` (or call `add` from another browser tab). The tab badge
  updates (`Rules 2`) but the list keeps showing 1 rule until you switch tabs and come back (screenshot:
  `tests/.artifacts/ui-dbg.png` when the test is run with a failing wait). Same for CLI edits to throttle/breakpoints etc.
- **Expected:** the visible tab re-renders when the polled state changed (and no input has focus), so CLI and UI never disagree on screen.
- **Test:** `tests/ui/test_ui.py::UiSmoke::test_open_rules_tab_refreshes_when_a_rule_is_added_elsewhere` (expectedFailure).

## B16 — FIXED in 222d3d0 — the panel's `/proxy/api/state` returns HTTP 500 while `rules.json` is broken
Found by a QA run (01:04). The proxy keeps applying the previous rules and mitmweb stays up, but the
panel state endpoint 500s, so the drawer breaks until the file is fixed. Repro:
`test_rules_engine.py::HotReload::test_broken_rules_json_keeps_previous_rules_and_never_kills_mitmweb` (write any of
the listed broken payloads to rules.json, wait 2 s, GET /proxy/api/state). Expected: 200 with the last good state plus
a visible "rules.json has an error: <reason>" banner.
