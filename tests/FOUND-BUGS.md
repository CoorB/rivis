# Product bugs found while building the suite

Nothing here was fixed (the brief says: do not touch the product). Each entry has a standalone repro and the
related test is marked `expectedFailure` (or asserts the correct behaviour and is listed as such), so the suite
flips to "unexpected success" — a failing run — the moment the bug is fixed, which is the cue to delete the marker.


All repros assume a running Rivis: `rivis start --no-ios --no-open`, then log in at `rivis ui` and use the panel's
cookie + XSRF pair. In the suite this is `harness.Panel`. `P` below means "POST /proxy/api/<op> with the session".

## B1 — panel returns an HTML 500 for wrongly shaped input (should be a JSON 400)
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

## B3 — rules created from a captured call never match calls on a non-default port
- **Where:** `proxy_panel.py` `flow_regex()` = `re.escape(pretty_host + path) + r"(\?|$)"`. The URL the rules engine tests is
  `http://host:PORT/path`, so `host/path` never matches when a port is present.
- **Repro:** capture `http://127.0.0.1:5173/api/x`, then `P quick {"flow_id": <id>, "kind": "block"}` → the new rule's
  `match` is `127\.0\.0\.1/api/x(\?|$)` and the next identical call is NOT blocked. Same for `mock` (Map Local from a call),
  `quick` status/delay and `bp_add` with `flow_id`. (Works on 443/80 URLs, which is why NEO traffic hides it; local dev
  servers, `localhost:3000`, simulators and the like are affected.)
- **Expected:** the generated regex allows `(:\d+)?` after the host, like `wildcard_regex` already does.
- **Test:** `test_panel.py::Ops::test_rules_built_from_a_call_match_that_call_on_a_non_default_port` (expectedFailure);
  the other panel tests re-point the rule at the path so the rest of each op is still covered.

## B4 — a failed `script_new` leaves an orphan empty script file that blocks the name
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
