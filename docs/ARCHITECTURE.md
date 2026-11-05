# Rivis architecture (for people changing it)

This is the map a new engineer needs before opening `rivis` or `addons/`. User-facing how-to stays in the [README](../README.md) and [REFERENCE.md](REFERENCE.md). How to run from source and how to test is in [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## Process model: what `rivis start` actually runs

Trace starts at `cmd_start()` in `rivis`.

1. Resolve project, ports (`RIVIS_PORT` / `RIVIS_WEB_PORT`, default 8080 / 8083), rules path and confdir (`~/.mitmproxy` by default).
2. Ensure the mitmproxy CA exists (`ensure_ca`) and the project rules file exists (`ensure_rules`).
3. If `our_listeners` already sees this Rivis on the chosen ports, print "already running" and **return 0** — no new process, no new token. Otherwise take a `start-guard-$WEB_PORT` directory lock and refuse foreign owners of `$PORT` / `$WEB_PORT`. (So a second `start` on 8080/8083 while QA's proxy is up looks successful but never runs your checkout; use `RIVIS_PORT` / `RIVIS_WEB_PORT`.)
4. Write a one-run UI password to `$STATE_ROOT/web-token` (or `web-token-$WEB_PORT`) and a one-time bootstrap nonce to `web-bootstrap` / `web-bootstrap-$WEB_PORT` (mode 600).
5. Build a `mitmweb` argv: listen on `127.0.0.1`, web UI on `127.0.0.1:$WEB_PORT`, load the add-ons below, pass options (`proxy_rules_file`, `proxy_auth_token_file`, …).
6. Optionally clear stale loopback system-proxy leftovers (`cmd_net_reset --auto`), then either:
   - foreground: `exec mitmweb …` (this Terminal *is* the proxy), or
   - `--background`: `nohup` a child that re-enters `start` without `--background`, log to `$STATE_ROOT/logs/mitmweb.log`.
7. Open the browser on `/proxy/bootstrap/<nonce>?next=rivis` so the UI lands signed in (mitmweb's own auto-open would hit 403).

**mitmweb** is mitmproxy's bundled web UI + proxy in one process. Rivis does not fork a separate API server: everything after start is that one process plus CLI helpers that talk to it over loopback HTTP.

Add-ons loaded with `-s` (order in `cmd_start` argv; `proxy_scripts` is after `proxy_rules`):

| `-s` path | Role |
|---|---|
| `addons/proxy_auth.py` | Read the UI password from the private token file into mitmweb options (secret never in argv/`ps`) |
| `addons/proxy_lan.py` | Opt-in `--lan` listener + allow-list for real phones |
| `addons/proxy_rules.py` | Hot-reloaded rules / breakpoints / throttle / nocache / TLS host lists |
| `addons/proxy_scripts.py` | Per-project Python/JS scripts |
| `addons/proxy_collections.py` | Record / replay collections |
| `addons/proxy_source.py` | Attribute each call to a device + app (Source menu) |
| `addons/proxy_panel.py` | Inject panel + serve `/proxy/api/*` and `/rivis/` |
| `addons/proxy_retention.py` | Cap in-memory flow count |
| `addons/proxy_operability.py` | Rotating redacted diagnostic log |

Other Python under `addons/` is imported by those add-ons or invoked by the CLI with `/usr/bin/python3 -I` (see the module map).

**Browser panel.** `proxy_panel.py` registers Tornado routes on the running mitmweb app. When mitmweb serves its index HTML, the add-on rewrites the response: inject `./proxy/boot.js` into `<head>` and `./proxy/panel.js` before `</body>`. There is no `addons/boot.js` on disk — `/proxy/boot.js` is generated and served from `panel_mitmweb.py` (pre-paint theme + mitmweb scroll patch). `panel.js` and `theme.css` are real files under `addons/`. The new main window is a separate page at `/rivis/` (files under `addons/ui/`). Both UIs call `/proxy/api/<op>` with mitmweb's XSRF cookie scheme.

**How the CLI talks to a running instance afterwards.** Commands that need live state (`status`, `compose send`, `mock`, parts of `scripts`, `warn_running_project`) use `ui_curl`: read the token from `$TOKEN_FILE`, hit `http://127.0.0.1:$WEB_PORT…` with `?token=…` (token never placed in argv). Rule edits go to the rules JSON on disk; the rules add-on reloads on the next request. Device setup (`ios` / `android`) talks to simctl/adb directly, not through mitmweb.

```
  Terminal: rivis start [--background]
            │
            ▼
     mitmweb (one process)
       listen 127.0.0.1:$PORT          ◄── Android emulator via 10.0.2.2:$PORT
       local:CoreSimulator (macOS)     ◄── iOS Simulator (no system proxy)
       web   127.0.0.1:$WEB_PORT
            │
            ├── -s proxy_auth, proxy_lan, proxy_rules, proxy_scripts,
            │      proxy_collections, proxy_source, proxy_panel,
            │      proxy_retention, proxy_operability
            │
            ├── HTML rewrite → panel.js / boot.js / theme.css
            ├── /rivis/        → addons/ui/*
            └── /proxy/api/*   → panel + CLI (ui_curl)

  Later: rivis ui | status | rules … | compose send …
            │
            ├── disk: ~/.rivis/…, rules.json, mocks, scripts
            └── loopback HTTP with web-token (ui_curl)
```

---

## State directory

`product.json` sets `"state_dir": "~/.rivis"`. The CLI expands `~` against `$HOME` into `STATE_ROOT`. The mitmproxy confdir (CA and keys) is separate: default `$HOME/.mitmproxy` (`RIVIS_CONFDIR`).

Created with `umask 077` and `chmod 700` on the sensitive trees (`secure_dirs` in `rivis`; `Protect-StateRoot` / owner-only ACL on Windows). Private files (tokens, bootstrap, upstream setting, last-start) are written mode 600 via `atomic_private_text`. Treat the whole tree as workstation-secret: captured traffic, mocks, sessions, UI tokens and client certs live here.

| Path | Purpose |
|---|---|
| `current-project` | Last `projects use` selection |
| `projects/<id>/` | Per-project state |
| `projects/<id>/rules.json` | Hot-reloaded rules (default `RIVIS_RULES`) |
| `projects/<id>/mocks/` | Map Local response files |
| `projects/<id>/collections/` | Recorded journeys |
| `projects/<id>/sessions/` | Saved sessions |
| `projects/<id>/scripts/` | Script source next to rules metadata |
| `projects/<id>/composer/` | Saved Compose requests (created on first compose save) |
| `projects/<id>/client-certs/` | Per-host mTLS material (created on first `tls client-cert add`) |
| `profiles/<id>/` | User-created project profiles (`projects new`) |
| `web-token` / `web-token-$WEB_PORT` | mitmweb UI password for this run (**secret**) |
| `web-bootstrap` / `web-bootstrap-$WEB_PORT` | One-time login nonce (**secret**, consumed on use) |
| `last-start` / `last-start-$WEB_PORT` | Args so update/restart can relaunch the same way |
| `upstream-$WEB_PORT` | Saved `--upstream` setting |
| `start-guard-$WEB_PORT` | Directory lock while start is binding ports |
| `ui-session.key` | Optional remembered UI session (`RIVIS_REMEMBER_UI=1`) (**secret**) |
| `logs/` | Background mitmweb log and operability logs |
| `ca-history` | SHA-256 + Android subject-hash of every CA ever pushed to a device (so `off` can remove old ones) |
| `android-ca`, `android-proxy`, `android-system-ca` | Which AVDs Rivis set up / marked |
| `android-ramdisk/` | Temporary Magisk-patched ramdisk work for Play images |
| `lan-devices.json` | Allowed phone/tablet IPs when `--lan` |
| `browser/` | Isolated Chromium profiles for `rivis browser` |
| `app/` | Built native Mac window (`Rivis.app`) |
| `updates/` | Detached update install log / staging |
| `upstream-trust.pem` | Exported Mac trust store when `--verify-upstream` |
| `proxy-owner-history` | Observed dead loopback proxy owners for `net-reset` |

Outside `STATE_ROOT` but equally sensitive: `$CONFDIR` (`mitmproxy-ca.pem`, `mitmproxy-ca-cert.pem`, …). Losing or replacing the CA without re-running device setup breaks every simulator/emulator that still trusts the old one.

---

## Module map (`addons/`)

### Capture / traffic (loaded into mitmweb, or imported by those add-ons)

| File | Responsibility |
|---|---|
| `proxy_rules.py` | Match/apply rules from the project's JSON; breakpoints, map local/remote, throttle, nocache, TLS mode lists |
| `proxy_scripts.py` | Run enabled per-project scripts (Python hosts + Node for JS); protocol viewers |
| `proxy_collections.py` | Record matching calls into a collection; replay as mocks |
| `proxy_source.py` | Stamp each flow with device/app source metadata |
| `proxy_retention.py` | Drop oldest safe flows when over `proxy_max_flows` |
| `proxy_lan.py` | Extra listen on Wi-Fi/Ethernet; refuse non-allowed clients; CLI allow-list helper |
| `proxy_operability.py` | Independent rotating, redacted diagnostic log |
| `proxy_common.py` | Shared constants, atomic writes, project/profile helpers, path confinement |
| `proxy_rule_validation.py` | Same per-rule checks for proxy load and CLI |
| `proxy_redact.py` | Mask secrets in HAR / exports / snippets |
| `proxy_compose.py` | Compose request storage helpers |
| `proxy_codegen.py` | "Copy as …" snippet generation |
| `proxy_auth.py` | Load web password from token file into mitmweb |
| `system_trust.py` | Export this Mac's trust store (+ extras) for upstream verify |
| `python_host.py` | Persistent isolated process per enabled Python script |
| `js_host.mjs` | Persistent Node host for JS scripts |

### Rules & mocking (CLI entry points; stdlib `/usr/bin/python3`)

| File | Responsibility |
|---|---|
| `rules_cli.py` | `rivis rules` / `breakpoint` / `mock` / `mocks` / `throttle` / `nocache` |
| `scripts_cli.py` | `rivis scripts` |
| `compose_cli.py` | `rivis compose list\|send` via panel API |
| `tls_cli.py` | `rivis tls` allow/ignore mode lists |
| `client_certs.py` | `rivis tls client-cert` store under the project |
| `curl_import.py` | Parse a pasted cURL into a Compose request |
| `proxyman_import.py` | Import Proxyman Map Local trees into a project |

### Device setup

| File | Responsibility |
|---|---|
| `devices.py` | Devices tab status + kicks off `rivis ios/android on` as background jobs |
| `android_picker.py` | Pick DocumentsUI controls by resource-id during Play-image CA install |
| `android_settings_timeout.py` | Bound a Settings child process group during setup |
| `android_setup_log.py` | Timestamped mirror of Android setup stdout |
| `android_magisk.sh` | One-click CA on Google Play AVDs (Magisk ramdisk patch, no lasting root shell) |
| `android/rivis_inject.sh` | On-emulator: add Rivis overlay into Magisk-patched ramdisk |
| `android/rivis_ca.rc` / `rivis_ca.sh` | One-shot boot service that installs the CA into the user store |
| `android/rivis_system_ca.sh` | Temporary system-store CA for apps that ignore the user store |
| `android/magisk.pins` | Pinned Magisk version + SHA-256s |
| `qr.py` | QR encoder for the phone setup URL |

### UI

| File | Responsibility |
|---|---|
| `proxy_panel.py` | Tornado routes, HTML inject, `/proxy/api/*`, `/rivis/`, bootstrap login |
| `panel_mitmweb.py` | `/proxy/boot.js` body + mitmweb index/bundle patch helpers (imported by `proxy_panel`) |
| `panel_view.py` | Response text view, body clipping, `/proxy/api/flows_since` feed helpers |
| `panel_har.py` | HAR import/export helpers for the panel (redacted) |
| `panel.js` | Classic drawer injected into mitmweb (shadow DOM) |
| `theme.css` | Design tokens + mitmweb skin |
| `tree-worker.js` | Worker that JSON-parses large trees off the UI thread |
| `ui/index.html`, `app.js`, `app.css` | New main window |
| `ui/tools.js` | Floating tool windows shell |
| `ui/tool-bp.js` | Breakpoint tool |
| `ui/tool-map.js` | Map Local tool |
| `ui/tool-rules.js` | Map Remote / rewrite / block rules |
| `ui/tool-scripts.js` | Scripting tool |
| `ui/tool-net.js` | Network, TLS, client certs, LAN |
| `ui/tool-compose.js` | Edit & Repeat / compose |
| `ui/tool-more.js` | Devices, collections, sessions, compare |
| `macapp/RivisApp.swift`, `build.sh`, `Info.plist` | Native Mac window that opens the same UI |

### Packaging / updates

| File | Responsibility |
|---|---|
| `updater.py` | Check / download signed GitHub releases (signature + SHA-256) |
| `update_install.sh` | Detached install of a verified zip, then restart from `last-start` |
| `release-signers` | Public half of the release-signing key (empty ⇒ updates never install) |

### Diagnostics

| File | Responsibility |
|---|---|
| `doctor.py` | `rivis doctor` — read-only health check (+ optional `--fix-safe`) |
| `bug_report.py` | Redacted support zip (no flows, tokens or keys) |

---

## The two CLIs

| | `rivis` | `rivis.ps1` |
|---|---|---|
| Shell | bash 3.2 (Apple `/bin/bash`) | PowerShell (5.1 / 7) |
| Primary OS | macOS | Windows |
| iOS Simulator | Yes (`local:CoreSimulator`, Redirector) | No (nothing to capture) |
| Android emulator | Yes | Yes |
| Native `app` window | Yes | Tells you to use `ui` |
| `browser --current` | Yes (front tab) | Not on Windows (`-Current` is Mac-only) |

Same product: same `product.json`, same add-ons, same state layout names, same security conditions (loopback by default, never the OS system proxy). A user-visible behaviour change in one CLI usually needs the matching change in the other. Parity is guarded by `tests/test_cli_matrix.py` (shared command/state contract against a live proxy) and `tests/test_powershell.py` (parse checks + commands that run under portable `pwsh` on a fake HOME).

---

## Boundaries that must not be crossed

Read `SECURITY.md` and the security block at the top of `rivis` / `rivis.ps1`. In short:

- **Bind 127.0.0.1 only** for the proxy and always for the web UI. `--lan` additionally binds this machine's own Wi-Fi/Ethernet address(es) — never `0.0.0.0`, never a VPN tunnel — and refuses every client until it is allow-listed.
- **Never change the OS system proxy.** iOS capture uses mitmproxy local-capture scoped to Simulator processes; Android uses the emulator's own proxy setting (`10.0.2.2:port`).
- **Simulators and emulators by default.** Physical devices need `--lan` plus an explicit allow.
- **No third-party Python dependencies** beyond mitmproxy and the standard library. Add-ons and CLI helpers that run under `/usr/bin/python3` must stay on 3.9-compatible stdlib code.
- **State and CA are owner-only.** Do not relax `chmod 700` / mode 600 on tokens, or share `~/.rivis` / `~/.mitmproxy`.
- **mitmproxy itself is pinned and unmodified** (12.2.3 via `install/mirror.conf`). Rivis is add-ons + CLI around it, not a fork.
