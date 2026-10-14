# Rivis — a project-aware mitmproxy toolkit

The product name and command are defined once in [`product.json`](product.json) (Rivis / `rivis`).
`rename.sh NEWNAME` changes them everywhere.

`Rivis` wraps mitmproxy with simulator/emulator certificate handling, interception rules, traffic
profiles, breakpoints, Map Local, collections, comparisons, and saved sessions. The browser panel is injected
into mitmweb; the installed mitmproxy is never modified.

## Security boundaries

- Proxy and web UI bind to `127.0.0.1` only. Android emulators reach host loopback at `10.0.2.2`; physical
  devices are intentionally rejected.
- The tool never enables a macOS or Windows system proxy. `net-reset` only clears a stale loopback proxy whose
  listener has disappeared.
- Certificates are installed only on simulators/emulators and removed by `ios off` or `android off`.
- Collections, sessions, mocks, and HAR files stay on the workstation. There is no upload or Git sync.
- The panel may write only inside the active project's state directory.

## Install and first run

Install the approved mitmproxy build, then link the command without copying it:

```bash
mkdir -p ~/bin
ln -sf "$PWD/rivis" ~/bin/rivis
rivis projects list
rivis start
```

On macOS, enable the Mitmproxy Redirector network extension when prompted. Quit tools that own the system
proxy before iOS Simulator testing; otherwise simulator traffic goes to that other proxy.

Windows uses `rivis.ps1`. The iOS Simulator is macOS-only.

## Projects

Project profiles hold client-specific labels, host filters, collection/throttle defaults, device identifiers,
and example rules. Shipped profiles are read-only under `projects/`; user profiles live under
`~/.rivis/profiles/`. A user profile with the same ID overrides a shipped profile.

```bash
rivis projects list
rivis projects show neo
rivis projects use neo
rivis projects new bank-a --label "Bank A" --hosts 'api\.bank-a\.test'
rivis --project bank-a status
rivis rules list --project bank-a
```

Resolution order is `--project ID`, `$<PREFIX>_PROJECT`, `current-project`, then `default`. Every command accepts
`--project`. Project state is isolated under:

```text
~/.rivis/
├── current-project
├── web-token
├── profiles/<id>/{project.json,rules.example.json}
└── projects/<id>/
    ├── rules.json
    ├── mocks/
    ├── scripts/
    ├── collections/
    └── sessions/
```

On first use, the project's example rules are copied to its state directory. A first run also copies legacy
`~/.neo-mitm/` state into the NEO project when needed; it never moves or deletes the original.

### Adding a project

Use `projects new` for a workstation-local profile, then edit its `project.json` or `rules.example.json`.
To ship a profile, add `projects/<id>/project.json` and `rules.example.json`, following `projects/_template/`.
The profile's `hosts` regex drives the “<label> only” panel view, `record_match` seeds collections, and
`throttle_match` seeds traffic profiles. Keep client-specific operational notes in that profile's README.

## Daily commands

```bash
rivis start [--project-only] [--insecure] [--all] [--no-ios] [--no-open]
rivis stop | ui | status | cert
rivis ios on|off [--udid UDID]
rivis android on|off [-s emulator-5554] [--auto-ui]
rivis rules list | on NAME | off NAME | show NAME | rm NAME | edit
rivis rules add NAME match=REGEX action=ACTION [key=value ...]
rivis scripts list | new NAME --lang py|js [--match REGEX] | on NAME | off NAME | edit NAME | rm NAME
rivis throttle off|3g-urban|lte-congested|high-latency-vpn|packet-loss-8|manual|lte|3g|edge|slow|<ms>ms[/<kbps>kbps]
              [match=REGEX] [loss=PCT] [latency_ms=N jitter_ms=N down_kbps=N up_kbps=N loss_pct=N response_delay_ms=N]
rivis tls list | mode all|allow|ignore | allow add|rm PATTERN | ignore add|rm PATTERN
rivis compose list | send NAME [--var name=value] [--no-wait]
rivis breakpoint REGEX [--request|--response] [--method M] | off [NAME]
rivis mock NAME URL-REGEX
rivis net-reset [--dry-run]
```

`rivis.ps1` takes the same commands. Options that are `key=value` in bash work the same way in PowerShell
(`.\rivis.ps1 throttle lte-congested match=neo\.sa loss=5`); `-Match` / `-Loss` still work, and `--var` / `--no-wait`
become `-Var name=value` / `-NoWait`.

`--dev` remains an alias of `--insecure`; `--neo-only` remains an alias of `--project-only`. The legacy
`neo-mitm` and `neo-mitm.ps1` wrappers select project `neo` unless an explicit project is supplied.

Environment variables are named from `product.json`: `<PREFIX>_PORT`, `_WEB_PORT`, `_RULES`, `_WEB_PASSWORD`,
`_CONFDIR`, and `_PROJECT`. Legacy `NEO_MITM_*` variables remain fallback aliases.

## Panel

Open the mitmweb UI and click the **Tools** button at the right end of the toolbar. Tabs provide This call, Compose, Map Local,
Breakpoints, Network, Collections, Compare, Sessions, Scripts, and Rules. The header shows `Rivis · <project label>` and has
a project selector. That selector changes only the host view; restart with `--project ID` to load a different
rules file.

Saved data is owner-only. Rules hot-reload within about one second. A malformed file leaves the previous good
configuration active, and a bad individual rule is skipped and shown in the panel.

### Top bar, filter and right-click

- **Always-visible filter** (top bar, after the tabs; `⌘F` / `Ctrl+F` focuses it, `Esc` clears). Plain words filter
  by URL — `postman-echo`, `/v2/cards`, `get?user=42` all work literally, several words must all match. Anything
  with a `~` (`~m POST`, `~c 500`, `~q`, `~u /api & ~c 404`) is passed through as a mitmproxy filter. A filter is
  checked with the server's own parser before it is applied (an invalid one would drop mitmweb's connection), so
  half-typed `~` filters show a red outline and the list keeps the last good result. It drives mitmweb's own filter:
  the Search box on mitmweb's *Calls* tab is hidden while the bar is active, and `?s=…` in the address still works.
- **Why did my call vanish?** A strip under the toolbar lists everything that hides calls — an active filter, "Only
  <project> calls", "Only <host>", a GraphQL operation — each with an ✕ to undo it. If *everything* is hidden, the
  list explains why and offers one button to clear it.
- **Clear all calls**: the trash button next to the filter (asks first; saved sessions, rules and scripts stay).
- **Right-click a call** for Map Local, Breakpoint, Repeat, Edit & Repeat, Compare as A, Copy as cURL / URL, Show
  only this host, decrypt / stop decrypting the host, and Delete.
- **One-row toolbar:** mitmweb's 95 px ribbon is a single 42 px row; below ~900 px (e.g. with the Tools drawer open)
  it shows icons only, with the names in tooltips. mitmweb's *Flow List* / *Flow* tabs read **Calls** / **Selected call**.
- **First run:** an empty list explains the next step (`rivis ios on` / `rivis android on`, with `--project` when a
  project is active).

### Themes

Rivis ships a skin (`addons/theme.css`) for the mitmweb UI and the panel: a shared set of design tokens,
method/status pills in the call list, tag chips for mocked/rule/script/composed calls, a "not decrypted"
marker for TLS tunnels, and a cleaner details pane and chrome. It is served at `/proxy/theme.css` and injected
by a tiny same-origin boot script in `<head>` (the page CSP forbids inline scripts).

- **Light / dark** follow the OS by default; the brand bar (top-right) has a theme toggle, remembered per
  browser.
- **Compact rows** and the **skin on/off** switch live in the panel's **Settings** (the gear / `?` → Settings).
- **List tags:** MOCK / RULE / SCRIPT / COMPOSED / NOT DECRYPTED show as a one-letter glyph in the first column (the word
  appears when the list is wide); a GraphQL response with `errors` shows `200 !`. Plain `http://` calls get an amber edge.
- **Project switch:** the **Show** menu in the drawer header picks *All traffic* or *<project> only* (list view; rules still load via `--project`).
- **Kill switch:** add `?theme=off` to the URL (or turn the skin off in Settings) to fall back to stock mitmweb;
  `?theme=on` restores it. Both are remembered in `localStorage`, so stock mode persists until you turn it back on.
- Press **`?`** for the keyboard-shortcut sheet. First-time users get a dismissible **"Coming from Proxyman?"**
  card, always reachable again from the Help (`?`) button.

The skin never replaces mitmweb's own React-managed DOM — it only adds attributes/classes to existing nodes — so
a mitmproxy upgrade can at worst drop styling, never break the UI. The selectors it relies on are listed in one
commented "mitmweb DOM contract" block at the top of `addons/theme.css`; re-check it after a mitmproxy upgrade.

### Coming from Proxyman

Most of the tools you know carry over under the same generic names (Map Local, Breakpoints, Network Conditions,
Compose, Diff, Copy as cURL, SSL proxying, Scripting, Sessions). See
[`docs/COMING-FROM-PROXYMAN.md`](docs/COMING-FROM-PROXYMAN.md) for the full task-by-task mapping, the shortcut
list, and the three biggest differences. The same table is in the UI under Help (`?`) → **Coming from Proxyman?**

### Compose

The **Compose** tab builds a request from scratch (or from the selected call: **Compose from this call**).
It has a method box (common verbs or any custom one), the URL, a Params table that stays in sync with the URL
(untick a row to keep it without sending it), a Headers table, and a body editor: none, JSON (validate and
pretty-print), form-urlencoded (table) or raw text. **Send** creates the call server-side exactly like
Edit & Retry, so it appears in the list, passes through rules, scripts and breakpoints, and is marked
`proxy_composed` with the comment `composed`.

- **Saved requests** live in `~/.rivis/projects/<id>/composer/<name>.json` (owner-only): save, load, rename,
  delete. Names use the same safe-name rule as sessions (letters, digits, `.`, `_`, `-`, max 64; `vars` is reserved).
- **Variables**: `{{name}}` is substituted in the URL, params, headers and body from
  `composer/vars.json`, which the Variables sub-tab edits (for example `{{edge}}`, `{{token}}`). An undefined
  variable is an error, never an empty string.
- **Use latest token for this host** (Headers sub-tab) takes the newest `Authorization: Bearer` JWT seen for the
  URL's host, stores it as `{{token}}` and adds `Authorization: Bearer {{token}}`.
- **CLI**: `rivis compose list` and `rivis compose send NAME [--var name=value]` replay a saved request
  headlessly through the running proxy using the same token and XSRF scheme as the panel (127.0.0.1 only).

### Copy as

On This call and in Compose, **Copy as** generates a ready-to-run snippet: cURL, HTTPie, wget, Python
`requests`, JavaScript `fetch`, Node `axios`, Swift `URLSession`, Kotlin `OkHttp`, Java `HttpClient`,
Go `net/http`, PowerShell `Invoke-RestMethod`, or a Postman v2.1 collection. JSON bodies become native
literals where the language has one (Python, fetch, axios); binary bodies become base64 with a comment;
HTTP/2 pseudo-headers, hop-by-hop headers and `Content-Length` are dropped; repeated headers are merged.

**Mask secrets** is on by default: `Authorization` and `Cookie` values become `<redacted>`. Untick it only when
the snippet will not leave your machine; the note under the menu says so. Snippets get pasted into tickets and
chats, and tokens must not be.

### HTTPS decryption (TLS list)

Network → **HTTPS decryption** (or `rivis tls ...`) chooses which hosts are decrypted, like Proxyman's
SSL Proxying list. In the UI the three modes read *Every host*, *Only listed hosts* and *All except listed*;
the lists are *Hosts to decrypt* and *Hosts to leave alone*. It is stored per project in `rules.json`:

```json
"tls": {"mode": "all", "allow": ["*.example.test"], "ignore": []}
```

- `all` (default): decrypt everything. `allow`: decrypt only hosts in the allow list. `ignore`: decrypt
  everything except the ignore list. The other list is kept but not applied.
- Patterns are host names with wildcards (`*.example.test`, `api.example.test`, `?` = one character) and an
  optional port (`api.example.test:8443`); they become anchored, case-insensitive regexes for mitmproxy's
  `allow_hosts` / `ignore_hosts`. `*.example.test` does not match `example.test` itself; add both if you need both.
  The NEO project ships `*.neo.sa` and `*.alahli.com` in its allow list but stays in mode `all`.
- **No restart.** mitmproxy reads these options for every new connection (it also applies in local-capture mode,
  which is where the iOS Simulator is captured), and Rivis re-applies the file within a second. Connections that
  are already open keep their earlier decision: reopen the app or its screen. `rivis status` shows the mode.
- Ignored hosts are **not intercepted at all**: rules, Map Local, breakpoints, scripts and throttling do not
  apply to them. In regular (Android emulator) mode mitmproxy ignores only TLS traffic, so plain HTTP to such a host
  is still captured; in local-capture mode (iOS Simulator) everything to that host is tunnelled, plain HTTP included.
  An empty `allow` list therefore decrypts nothing (Rivis passes mitmproxy a never-matching pattern, because mitmproxy
  itself ignores nothing when both lists are empty).
- A host that is not decrypted still appears as a host-only **tunnel** row marked "🔒 not decrypted" (Rivis
  turns on mitmproxy's `show_ignored_hosts` and lets the list show those rows when the mode is not `all`; mitmproxy
  warns that this keeps the tunnels' bytes in memory, which adds up over a long session). IP-only
  connections carry no host name, so in `allow` mode they are tunnelled, not decrypted.
- On This call: **Decrypt this host** / **Don't decrypt this host**. In mode `all`, "Don't decrypt" switches to
  `ignore` with that host so everything else stays decrypted; "Decrypt" in mode `all` is a no-op.

### Protocol viewers

The read-only **This call** view detects JWTs in bearer, Cookie and response Set-Cookie headers, URL query values,
and JSON/form string values (including JSON bodies without a content type), decodes the
header and payload without claiming signature verification, and renders `exp`, `iat`, and `nbf` in local time.
It also keeps a session token list keyed by `sub` + `iat`. GraphQL GET and POST/batch calls show operation details,
variables, and split response data/errors; GraphQL errors receive an `ERR` list marker even with HTTP 200, and the
operation mini-list filters the flow list. gRPC/protobuf calls show service/method, trailers, and schema-less field
numbers. For these messages the panel requests mitmweb 12.2.3's own `gRPC/Protocol Buffer` / `Protocol Buffer`
content endpoint, with a small schema-less fallback if the native view cannot decode the body. No custom content
view is registered, so the add-on does not depend on an unstable content-view registration signature. Viewers inspect the current flow store, so they
also work after opening a saved session.

### Scripts

Script source lives only in `~/.rivis/projects/<id>/scripts/*.py|*.js`. Matching and enablement metadata uses a
`scripts` array in that project's `rules.json`:

```json
{"name":"qa-header","file":"qa-header.js","lang":"js","enabled":true,"match":"/api/","method":"GET"}
```

Rules execute first, followed by enabled scripts in filename order. Python and JavaScript are trusted user code and
run with the user's rights. JavaScript runs in one lazily started Node sidecar; its `node:vm` contexts omit exposed
`require`, `process`, network, and filesystem helpers to prevent accidents, but **this is not a security boundary**.
Only run scripts you trust. Node may be overridden with `<PREFIX>_NODE`.
The Scripts tab can create, edit, toggle, or delete scripts and reports each script's last error. Templates are:
request header, JSON response field, local mock, endpoint latency, and token-refresh logging. Source and metadata
hot-reload within about one second.

Scripts use Proxyman-compatible `onRequest(context, url, request)` / `onResponse(context, url, request,
response)` hooks (snake_case is also accepted in Python). Request objects include method, URL parts, queries,
headers, and body; responses include `statusCode`, headers, and body. JSON bodies are parsed, text stays text,
and binary bodies are base64 with `body_is_base64: true`. Returning nothing leaves the message unchanged.
Both languages receive `log`, `sleep`, and request-side `mock` helpers. A changed flow is tagged
`script:<name>`; locally answered calls are marked so collections skip them.
Synchronous Python hooks and Python top-level reload code run in worker threads with a two-second wait, keeping the
capture loop responsive. Python cannot safely kill a running thread: after a timeout its result is ignored and the
flow stays unchanged, but blocking user code in that abandoned worker may continue in the background.

## Rules

Supported actions are `respond`, `map_local`, `status`, `json_patch`, `delay`, `set_header`, `map_remote`, and
`block`. CLI-added rules append in file order; quick panel errors are inserted first so they can override an
older local response. Breakpoints pause requests/responses in mitmweb for editing and continuation.

Unit tests (stdlib only, no mitmproxy needed): `/usr/bin/python3 -I -m unittest discover -s tests`.

Traffic profiles include 3G Urban, congested LTE, high-latency VPN, packet loss, manual values, and legacy
profiles. Collection replay keys calls by method, host, path, canonical query, then request-body hash; repeated
calls replay in recorded order and stick on the last result.

## Rename the placeholder

```bash
./rename.sh "Chosen Name"
```

The script updates `product.json`, derives a lowercase CLI name and uppercase environment prefix, renames the
two product CLI files, and prints the links to recreate. Add-ons, panel identity, paths, messages, environment
variables, and wrappers read `product.json`, so nothing else needs editing.

## Troubleshooting

| Symptom | Action |
|---|---|
| UI says 403 | Close the stale tab and run `rivis ui` to reopen with the current token. |
| iOS shows DNS but no API calls | Quit another tool that owns the system proxy. |
| Emulator has no network | Run `rivis android off`, or start the proxy on the configured port. |
| Client rejects the CA | Install it with `ios on`/`android on` and use a build that trusts the workstation CA. |
| Upstream certificate cannot validate | Confirm the project policy, then start with `--insecure`. |
| A port is occupied | Stop the previous mitmweb instance or choose another `<PREFIX>_PORT`/`_WEB_PORT`. |

The panel relies on mitmweb internals and must be retested after mitmproxy upgrades. Never use
`simctl keychain reset`; `ios off` removes only this workstation's mitmproxy CA row.
