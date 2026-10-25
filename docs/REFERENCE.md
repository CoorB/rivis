# Rivis — technical reference

The full command, panel and configuration reference. New here? Start with the [README](../README.md).

`Rivis` wraps mitmproxy with simulator/emulator certificate handling, interception rules, traffic
profiles, breakpoints, Map Local, collections, comparisons, and saved sessions. The browser panel is injected
into mitmweb; the installed mitmproxy is never modified.

## Security boundaries

- Proxy and web UI bind to `127.0.0.1` only. Android emulators reach host loopback at `10.0.2.2`; physical
  devices are intentionally rejected.
- The tool never enables a macOS or Windows system proxy. On macOS, `net-reset` clears a dead loopback setting only
  when Rivis previously observed Rivis or Proxyman listening there and that process has exited; an unknown setting is left alone. On Windows it
  reports unanswered proxy settings for manual inspection.
- Certificates are installed only on simulators/emulators and removed by `ios off` or `android off`.
- Collections, sessions, mocks, and HAR files stay on the workstation. There is no upload or Git sync.
- The panel may write only inside the active project's state directory.

## Install and first run

Use the installer zip from the release (see the [README](../README.md#install)). Developers working from a source
checkout: see [From a source checkout (developers)](#from-a-source-checkout-developers) at the end.

On macOS, enable the Mitmproxy Redirector network extension when prompted. Quit tools that own the system
proxy before iOS Simulator testing; otherwise simulator traffic goes to that other proxy.

Windows uses `rivis.ps1`. The iOS Simulator is macOS-only.

### Upgrading, checking it works, going back

Run the newer installer's `install.sh` while Rivis is running or stopped. A running Rivis is stopped, upgraded and
started again with the same project, ports and options, then **health-checked**: the installer prints
`health check :8080/:8083 ok`, or `health check FAILED` with what is wrong and the command to go back.

```bash
rivis health                 # proxy answers, panel answers, running version = installed version (exit 0 = yes)
rivis rollback --list        # versions installed on this Mac (each install keeps its own folder)
rivis rollback               # back to the version before the current one, restarted with the same options
rivis rollback 0.9.7         # or to a named version — also how you undo a rollback
```

Versions before 0.9.7 have no `rollback` command: after going back to one of them, come forward again with
`~/.local/rivis/tool-0.9.7/rivis rollback 0.9.7` (rollback prints this line for you), or re-run the newer installer.
`rollback` only switches between versions already installed on this Mac; it never deletes one. Rules, Map Local
files, sessions and collections are shared by all versions and are not changed.

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

`projects use` selects the project but does not filter the call list; to hide other apps' calls, set **Show** in the
Tools header to the project (for example *NEO only*).
For a proxy started without `--project`, run `rivis restart` after `projects use ID` to load that project's rules.
A proxy started with `--project ID` keeps that explicit project on restart; stop and start it with another ID to change it.

Resolution order is `--project ID`, `$<PREFIX>_PROJECT`, `current-project`, then `default`. Every command accepts
`--project`. Project state is isolated under:

```text
~/.rivis/
├── current-project
├── web-token                         # default web port login
├── web-token-<web-port>              # other web ports keep separate logins
├── profiles/<id>/{project.json,rules.example.json}
└── projects/<id>/
    ├── rules.json
    ├── mocks/
    ├── scripts/
    ├── collections/
    └── sessions/
```

`status` reports the project running on the selected proxy and web ports. If your current selection differs, it
also shows the selected project separately.

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
rivis stop | restart | ui | status | cert # status exits 0 when running, 3 when not (for scripts and CI)
rivis browser [URL | --current] [--browser chrome|edge|chromium|brave] [--fresh] [--list]   # web apps, see below
rivis ios on|off [--udid UDID | --all]     # --all: every booted simulator
rivis android on|off [-s emulator-5554 | --all] [--manual] [--yes] [--strict] [--proxy-only]   # Play images: one restart, like Proxyman (--strict: back to normal at once, 2–4 min)
rivis setup                                          # every booted simulator + running emulator
rivis rules list | on NAME | off NAME | show NAME | rm NAME | edit
rivis rules test URL [METHOD]                        # what each rule would do to this call; sends nothing
rivis health | rollback [VERSION|--list]             # after an upgrade: is it working? / go back a version
rivis rules add NAME match=REGEX action=ACTION [key=value ...]
rivis rules variant NAME add|use|rm VARIANT [file=PATH]
rivis scripts list | new NAME --lang py|js [--match REGEX] | on NAME | off NAME | edit NAME | rm NAME
rivis throttle off|3g-urban|lte-congested|high-latency-vpn|packet-loss-8|manual|lte|3g|edge|slow|<ms>ms[/<kbps>kbps]
              [match=REGEX] [loss=PCT] [latency_ms=N jitter_ms=N down_kbps=N up_kbps=N loss_pct=N response_delay_ms=N]
rivis nocache on|off|status                          # No Caching: always fresh content, never an empty 304
rivis tls list | mode all|allow|ignore | allow add|rm PATTERN | ignore add|rm PATTERN
rivis compose list | send NAME [--var name=value] [--no-wait]
rivis compose --from-curl FILE|-                     # parse a copied cURL command into Compose JSON; sends nothing
rivis breakpoint [REGEX [--request|--response] [--method M] | off [NAME]]   # no arguments: list; paused calls: Continue in the UI
rivis mock NAME URL-REGEX
rivis mocks import-proxyman [PATH] [--dry-run]
rivis net-reset [--dry-run]
rivis update [check|install|login|logout|status]     # signed updates when configured; otherwise install the new release zip
```

For `throttle`, `loss=` applies only to that command; a later profile uses its own packet loss.
Each throttle command resets the scope to the selected project's `throttle_match` (all calls for `default`); pass `match=REGEX` to override it. `throttle off` also restores that project scope.
`throttle` and `rules list` show the active manual latency, jitter, bandwidth, loss and response delay values.
The Compose tab can import a copied cURL command with **Paste cURL…**. `rivis compose --from-curl -`
reads standard input; `rivis.ps1 compose -FromCurl FILE|-` provides the same JSON on Windows.
The response contains `spec` (method, URL, headers and body) and `ignored` (unsupported flags).
Saved list filters are per project in `filters.json`; Alt+1 through Alt+9 toggle the first nine when a text field is not focused.
`rules add`, `rules on` and `rules edit` check enabled rules against the proxy's load validation. `rules list`
marks rules that the proxy skips as `SKIPPED` and prints the reason. Editing a rules file saves only after that
validation succeeds. `breakpoint off NAME` reports an unknown name and shows the available names.
An invalid `mock` URL pattern exits with a single validation error.

For one Map Local endpoint, `rules variant NAME add success` copies the current response into a new saved
file and makes it active. `add error file=/path/to/response.json` uses an existing file instead. Use
`rules variant NAME use success` to switch the response served on the next matching call, or
`rules variant NAME rm error` to remove a variant (its file is kept). The PowerShell command has the
same syntax: `rivis.ps1 rules variant NAME add|use|rm VARIANT [file=PATH]`. The Map Local editor also
adds, renames, deletes, and selects variants. Right-clicking an already mocked call can save its response
as a new variant. A rule without variants keeps its existing behavior. Folder rules do not use variants.

The paused-call sheet has a **Form** view beside Body and Headers. On requests it edits the method, path,
query parameters, headers, and JSON or URL encoded body fields. On responses it edits status, headers, and
JSON or URL encoded body fields. JSON fields keep their selected value type when switching views; Body remains
available for raw text and other formats. Continue sends the current form edits through the breakpoint.

### Map Local folders and Proxyman import

A folder rule reads the matching file on every request. The `match` regex selects full URLs; `base` is the URL
prefix removed before looking inside `file`. A request for `/v1/cards?view=full` under the rule below tries
`cards`, `cards.json`, `cards/index.json`, then the last path segment `cards`. Missing files go to the real server.
Paths and symlinks cannot escape the folder. A file beginning with an HTTP status line supplies its saved status,
headers and body; connection and transfer headers are removed.

```json
{"name":"cards-folder","enabled":true,"action":"map_local","match":"^https://api.example.com/v1/.*$","base":"https://api.example.com/v1/","file":"/path/to/project/mocks/cards"}
```

`rivis rules add cards-folder match='^https://api.example.com/v1/.*$' action=map_local base='https://api.example.com/v1/' file=/path/to/project/mocks/cards`
adds the same rule. A folder outside the project needs `rivis rules allow-file PATH` on that machine. The Rules
tab can add, switch, and delete folder rules.

`rivis mocks import-proxyman` reads Proxyman's `MapLocalFiles-RuleTree` from its default application data folder.
Pass a RuleTree file or its containing folder to import a team copy; relative mock paths resolve beside that file.
It copies mock files and folders into the active project's `mocks/`, preserves methods and enabled state, and
renames clashing rules with `-2`, `-3`, and so on. `--dry-run` reports the planned imports without writing.
The Rules tab offers **Import from Proxyman…** for the default local RuleTree. Proxyman's published export
instructions do not specify a file schema; this importer accepts exports that use the same RuleTree JSON shape.

For Map Remote, `match` selects calls, `replace` is the URL regex to replace, and `with` is the replacement URL.
For example, to send a call from one local server to another:

```bash
rivis rules add move-echo match='/echo' action=map_remote replace='^http://127\.0\.0\.1:50525/echo$' with='http://127.0.0.1:50526/echo'
```

The `replace` pattern must match the full URL, not just the path shown in the call list. `rules add`, `rules list`
and the Rules tab warn when a simple `match` example would leave the URL unchanged.

For `json_patch`, `set` defines fields to modify in the JSON response body using dot and index notation.
The CLI accepts `set='path=value'`, multiple `set='path=value'` flags, comma-separated `path=val` pairs,
dot-prefixed `set.path=value`, or a JSON object `set='{"path": value}'`:

```bash
rivis rules add patch-user match='/user$' action=json_patch set='user.name=PATCHED' set='user.age=25'
```

`android on` turns the emulator's proxy on only once the CA is verified on it; otherwise it prints the steps and
exits with status 2 (not done), so no emulator is left with a proxy it cannot use. After installing the CA by
hand where Rivis cannot read the emulator's Settings, `--proxy-only` turns the proxy on anyway. `android off`
removes only CAs whose SHA-256 this workstation recorded, never another workstation's "mitmproxy" CA.

### Web apps (`rivis browser`)

`rivis browser https://app.example.com` (or **Tools → Devices → Web browser**) opens a separate Chrome, Edge,
Chromium or Brave window with its own profile in `~/.rivis/browser/<browser>` (logins stay between runs; `--fresh`
uses a temporary profile). That window uses the proxy on `127.0.0.1` and trusts only this workstation's Rivis
certificate, pinned by its public key (`--ignore-certificate-errors-spki-list`), so nothing is added to the keychain
and the macOS system proxy is not changed. Your normal browser and its profiles are not touched. Firefox is not
supported yet.

- `--current` opens the page of your browser's front tab (Chrome, Edge, Brave, Chromium or Safari). It only reads
  the tab's address. The first time, macOS asks whether your terminal may control that browser (System Settings →
  Privacy & Security → Automation). You need to log in again in the Rivis window; the profile keeps the login.
  Calls your normal tab already made are not captured.
- Web apps on `localhost`: Rivis blocks private addresses by default, so the browser opens them directly (not
  captured). To capture them, start Rivis with `--allow-private-hosts '^(localhost|127\.0\.0\.1)$'`;
  `rivis browser` then sends them through Rivis too.

Server certificates are checked against what this Mac trusts: Apple's root store plus any root your IT, MDM or you
marked as trusted in Keychain Access (as Safari and Proxyman do), so networks that inspect HTTPS keep working.
`RIVIS_EXTRA_TRUST=/path/root.pem` (several joined with `:`) adds a root the keychain lacks;
`RIVIS_SYSTEM_TRUST=0` uses mitmproxy's own list only; `--insecure` turns the check off.
When an upstream certificate fails the check (incomplete chain, expired, self-signed, wrong host), the app gets a
502 from Rivis whose body names the reason and the fixes, and the call shows as **failed** in the list. A server that
leaves out its intermediate certificate works in browsers and phones (they fetch the missing intermediate themselves)
but not through Rivis: pass that host through undecrypted with `rivis tls ignore add HOST` + `rivis tls mode ignore`,
or start with `--insecure` for a dev server.

Large bodies: a body over 64 MB (`RIVIS_STREAM_LARGE_BODIES`, a mitmproxy size such as `256m`) is streamed straight
to the app and **not kept**: it cannot be viewed, edited by a response rule, mocked from or breakpointed, and the call
is tagged *large body streamed, not kept*. This keeps one big download from holding gigabytes of memory. Smaller
bodies are kept as before; the body view renders only the start of a body over 4 MB (Download / Open raw give all of
it), so opening a large response never stalls other traffic.

Interim responses: an HTTP/1 `103 Early Hints` (or any other 1xx except `101`) from the server is dropped and the real
response that follows is passed on.

Calls that fail (connection refused, TLS failure, body cut short) show **failed** in the status and time columns
(a cut-short response shows its status with ✕); hover for the reason, or open the Error tab.

Servers on private addresses (VPN, internal DNS): app HTTPS calls, simulator capture and Repeat/Compose reach them on
any project. Plain-HTTP proxy requests to a private address are refused (403), because a web page could aim the proxy
port at one (DNS rebinding). With `--insecure`, web pages' own requests to private addresses are blocked too unless
the host is in the project or matches `--allow-private-hosts`. For a local test server, add its domain to the project's
`hosts`, or start Rivis with `--allow-private-hosts 'REGEX'`.

`rivis.ps1` supports the same cross-platform commands, including `stop`, `breakpoint`, `mock`, and `setup`.
Windows has no iOS Simulator, so `setup` says so and configures every running Android emulator (`android on -All`).
Options that are `key=value` in bash work the same way in PowerShell (`.\rivis.ps1 throttle lte-congested
match=neo\.sa loss=5`); GNU-style options use their PowerShell spellings, such as `-Request`, `-Response`,
`-Method`, `-Var name=value`, and `-NoWait`.

`--dev` remains an alias of `--insecure`; `--neo-only` remains an alias of `--project-only`. The legacy
`neo-mitm` and `neo-mitm.ps1` wrappers select project `neo` unless an explicit project is supplied.

`breakpoint` can save a rule while the proxy is stopped. A running proxy hot-reloads it within about one second;
wait for that reload before sending the call that should pause.

Environment variables are named from `product.json`: `<PREFIX>_PORT`, `_WEB_PORT`, `_RULES`, `_WEB_PASSWORD`,
`_CONFDIR`, and `_PROJECT`. Legacy `NEO_MITM_*` variables remain fallback aliases.
`<PREFIX>_MAX_FLOWS` (default 5000, 1 to 1000000) caps how many calls are kept: the oldest are dropped past it, and the footer shows how many were trimmed. Sessions and HARs saved afterwards contain only the survivors.
Trimming happens in batches to a low-water mark, so the list can contain fewer than 5000 calls just after trimming.

For simultaneous projects, start each with a different `<PREFIX>_PORT` and `<PREFIX>_WEB_PORT`. Use the same
`<PREFIX>_WEB_PORT` for `ui`, `status`, `stop`, or `restart`; web login and saved start settings belong to that port.
After an upgrade, the installer restarts running instances whose saved start settings identify their ports and flags.
If it cannot restart one, it names the instance and tells you to run `rivis restart`; `start` and `status` warn when
the running version differs from the installed version. Uninstall stops every instance using this installation
before removing add-ons. It retains `~/.rivis` and `~/.mitmproxy` and prints separate removal commands for each.

## Panel

Open the mitmweb UI and click the **Tools** button at the right end of the toolbar. Tabs provide This call, Compose, Map Local,
Breakpoints, Network, Devices, Collections, Compare, Sessions, Scripts, and Rules. The header shows `Rivis / <project label>` (for example `Rivis / NEO`, or `Rivis / All`) and has
a project selector. That selector changes only the host view; restart with `--project ID` to load a different
rules file.

Devices and Network are pages inside the **Tools** drawer on the right, not tabs along the top.
`rivis rules rm NAME` also deletes the mock file owned by that Map Local rule. Files shared with other rules or created separately are kept.
The panel script editor checks syntax on Save. For a CLI-edited JavaScript file, send a matching call before
checking `rivis scripts list` or `rivis doctor` for a syntax error.

Saved data is owner-only. Rules hot-reload within about one second. A malformed file leaves the previous good
configuration active, and a bad individual rule is skipped and shown in the panel.

### Top bar, filter and right-click

- **Always-visible filter** (top bar, after the tabs; `⌘F` / `Ctrl+F` focuses it, `Esc` clears). Plain words filter
  by URL — `postman-echo`, `/v2/cards`, `get?user=42` all work literally, several words must all match. Anything
  with a `~` (`~m POST`, `~c 500`, `~q`, `~u /api & ~c 404`) is passed through as a mitmproxy filter. A filter is
  checked with the server's own parser before it is applied (an invalid one would drop mitmweb's connection), so
  half-typed `~` filters show a red outline and the list keeps the last good result. It drives mitmweb's own filter:
  the Search box on mitmweb's *Calls* tab is hidden while the bar is active, and `?s=…` in the address still works.
  When the header has too little room for a readable box (a ~900 px window with the drawer open) the bar moves to
  its own row under the toolbar, in the filter strip.
- **Why did my call vanish?** A strip under the toolbar lists everything that hides calls — an active filter, "Only
  <project> calls", "Only <host>", a GraphQL operation — each with an ✕ to undo it. If *everything* is hidden, the
  list explains why and offers one button to clear it.
- **Source: one device or one app** (Proxyman's per-app view). The **Source** menu in the Tools header (next to
  **Show**) lists every device that sent calls — each iOS Simulator by name, each Android emulator by AVD, *This Mac*
  (curl, tools), the `rivis browser` window — and each app on it, with the number of calls the list can show. Choosing
  a device or an app limits the list to it; it combines with the filter box, **Show** and *Only <host>*, and shows in
  the strip with an ✕. A wide list shows each call's app as a chip at the right of the URL; **This call** says
  *From <app> on <device>* with its bundle ID; right-click → **Show only <app>**. `rivis status` lists the sources too.
  How a call is attributed (`addons/proxy_source.py`, once per connection, off the event loop):
  - iOS Simulator (local capture): the redirector knows the sending process; Rivis reads that app's `Info.plist`
    (display name, bundle ID) and the simulator's name. Two builds installed on one simulator have different bundle IDs,
    so they are separate entries; the same build on two simulators is listed under each simulator. Safari's and web
    views' pages are fetched by the simulator's WebKit networking process and show as *Web content (Safari / web
    views)*; system services (`geod`, `trustd`, …) show under their own names.
  - Android emulator, `rivis browser`, Mac tools (proxy port): the process on the other end of the connection. A
    program that already talked to Rivis is recognised in-process (microseconds); a new program's first connection
    needs one `lsof` run, shared by every connection that opened at the same time. A request is never held for this:
    only the first response on a new connection may wait, at most half a second and usually not at all (the lookup
    runs while the server answers). Emulators: the AVD name (with emulator 36+ all emulators share one network process, `netsimd`; with
    several running, the one whose guest has a connection to Rivis at that moment is chosen, else *Android
    emulator*). The app inside the emulator is named (package) only when exactly one app is talking to Rivis at that
    moment; otherwise the row shows the AVD.
  - Sessions keep each call's source; a session's HAR export carries it as `_rivisSource` on each entry, and opening
    that HAR with **File → Open** brings the sources back. Repeats and edited copies keep the original call's source.
    Calls with no source — made in Compose, opened from a HAR made elsewhere, or not attributable (an unknown process,
    Windows) — are listed under **Unknown**, which can be chosen like any source. When more than 512 new connections
    await a lookup at once, the excess calls are marked *Unknown* so a lookup can never build an unlimited queue.
  - The counts in the Source menu are the calls the list can show: under **Show → <project> only** only that
    project's calls are counted. A mitmproxy upgrade
    that changes its local-capture internals also turns simulator attribution into *Unknown* (capture keeps working);
    re-test after an upgrade.
- **Clear all calls**: the trash button next to the filter (asks first; saved sessions, rules and scripts stay).
- **Save session** keeps the call types shown by the list (HTTP calls, plus tunnel rows when TLS mode shows them,
  and other network rows when **Show network calls** is on).
  The **Only calls visible with the current filter** checkbox also narrows the save to the current filter.
- **Sessions → HAR** exports a saved session with secrets redacted. It is built in the background, so live calls
  and the panel keep working while it runs. A single request or response body over 4 MiB is left out of the HAR
  (`text` empty, `size` kept, and a `comment` saying so); the saved session still holds it.
- **Right-click a call** for Map Local, Breakpoint, Repeat, Edit & Repeat, Compare as A, Copy as cURL / URL, Show
  only this host, decrypt / stop decrypting the host, and Delete.
- **Compare two calls**: right-click the first → **Compare: set as A**, select the second, open **Compare**
  (`⌥⇧D`), then click **Compare A with B**. The result lists both URLs and highlights header and body differences.
- **Map Local to your own file anywhere** (e.g. `~/Desktop/mock.json`): `rivis rules add NAME match=REGEX action=map_local
  file=PATH` trusts that file on this machine; for a hand-edited rule run `rivis rules allow-file PATH`
  (`disallow-file`, `trusted-files` to review). Files from shared or imported rules are only read inside the project,
  and keys (`~/.mitmproxy`, `~/.ssh`, `*.pem`, …) and Rivis's own login files are never served.
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
- **List tags:** MOCK / RULE / SCRIPT / COMPOSED show as a one-letter glyph (M, R, S, C) and NOT DECRYPTED as `⇄` in the
  first column (the word appears when the list is wide); a GraphQL response with `errors` shows `200 !`. Plain `http://` calls get an amber edge.
- **Project switch:** the **Show** menu in the drawer header picks *All traffic* or *<project> only* (list view; rules still load via `--project`).
- **Kill switch:** add `?theme=off` to the URL (or turn the skin off in Settings) to fall back to stock mitmweb;
  `?theme=on` restores it. Both are remembered in `localStorage`, so stock mode persists until you turn it back on.
- **Response and request bodies:** valid UTF-8 text with little or no ASCII (Arabic, Hebrew, emoji) shows as text
  (view *Text*) instead of a hex dump, and right-to-left lines run right to left. A body view longer than 256 KB
  (a 5 MB one-line script, a 20 MB JSON) shows its first 256 KB with "showing first … of … MB" and **Download** /
  **Open raw** links for the whole body; the full body is still what is captured, mapped and exported.
- **Keyboard:** the chords, Edit & Repeat, a paused call's sheet and the Map Local editor take focus; `Tab` stays
  inside them and `Esc` closes them like their own Cancel / Back / close button, then focus goes back where it was.
- Press **`?`** for the keyboard-shortcut sheet. First-time users get a dismissible **"Coming from Proxyman?"**
  card, always reachable again from the Help (`?`) button.

The skin never replaces mitmweb's own React-managed DOM — it only adds attributes/classes to existing nodes — so
a mitmproxy upgrade can at worst drop styling, never break the UI. The selectors it relies on are listed in one
commented "mitmweb DOM contract" block at the top of `addons/theme.css`; re-check it after a mitmproxy upgrade.

### Coming from Proxyman

Most of the tools you know carry over under the same generic names (Map Local, Breakpoints, Network Conditions,
Compose, Diff, Copy as cURL, SSL proxying, Scripting, Sessions). See
[`docs/COMING-FROM-PROXYMAN.md`](COMING-FROM-PROXYMAN.md) for the full task-by-task mapping, the shortcut
list, and the three biggest differences. The same table is in the UI under Help (`?`) → **Coming from Proxyman?**

### Compose

The **Compose** tab builds a request from scratch (or from the selected call: **Compose from this call**).
It has a method box (common verbs or any custom one), the URL, a Params table that stays in sync with the URL
(untick a row to keep it without sending it), a Headers table, and a body editor: none, JSON (validate and
pretty-print), form-urlencoded (table) or raw text. **Send** creates the call server-side exactly like
Edit & Repeat, so it appears in the list, passes through rules, scripts and breakpoints, and is marked
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

**Mask secrets** is on by default: `Authorization`, cookies, API keys, session and CSRF tokens, and fields such as
password, PIN, OTP or token (plus anything shaped like a JWT) become `<redacted>`. Untick it only when
the snippet will not leave your machine; the note under the menu says so. Snippets get pasted into tickets and
chats, and tokens must not be.

### Network: No caching

Tools → **Network → Caching → No caching** (or `rivis nocache on|off|status`, `.\rivis.ps1 nocache …`) is
Proxyman's *No Caching* tool, a per-project switch stored as `"no_cache": true` in the project's `rules.json`
and hot-reloaded like the throttle. Off by default. While it is on, every decrypted call:

- request: `If-None-Match`, `If-Modified-Since`, `If-Match`, `If-Unmodified-Since` and `If-Range` are removed and
  `Cache-Control: no-cache` + `Pragma: no-cache` are added, so the server cannot answer an empty `304`;
- response: `Cache-Control: no-store, no-cache, must-revalidate`, `Pragma: no-cache` and `Expires: 0` are set and
  `ETag` / `Last-Modified` are removed, so the app does not keep or revalidate it.

Affected calls carry `no-cache` in their comment. Calls answered locally (Map Local, `respond` rules) are left
exactly as the mock defines them. `rivis status` prints `No caching: on` while it is on.

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
  which is where the iOS Simulator is captured), and Rivis re-applies the file on its next poll; allow a few seconds. Connections that
  are already open keep their earlier decision: reopen the app or its screen. `rivis status` shows the mode.
- Ignored hosts are **not intercepted at all**: rules, Map Local, breakpoints, scripts and throttling do not
  apply to them. In regular (Android emulator) mode mitmproxy ignores only TLS traffic, so plain HTTP to such a host
  is still captured; in local-capture mode (iOS Simulator) everything to that host is tunnelled, plain HTTP included.
  An empty `allow` list therefore decrypts nothing (Rivis passes mitmproxy a never-matching pattern, because mitmproxy
  itself ignores nothing when both lists are empty).
- **Servers requiring a client certificate (mTLS):** Rivis does not configure or forward client certificates while
  decrypting HTTPS. If the app already has a certificate for the server, let it negotiate directly through a tunnel:
  `rivis tls ignore add api.example.test`, then `rivis tls mode ignore`. Start a new connection (reopen the app or
  screen). The client still needs its certificate; this setting cannot create one. The call's contents cannot be
  inspected or changed while that host is ignored. If you use the `allow` mode instead, leave the host out of the
  allow list.
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
Python scripts run in separate, persistent host processes, one per enabled script. A hook or top-level load that
exceeds two seconds is killed; the call continues unchanged and the host starts again on its next call. The Scripts
tab and log name the script and show the timeout.

## Rules

Supported actions are `respond`, `map_local`, `status`, `json_patch`, `delay`, `set_header`, `map_remote`, and
`block`. CLI-added rules append in file order; quick panel errors are inserted first so they can override an
older local response. The panel's **Rules** tab lists, creates, edits, switches on/off and deletes every one of them, plus
breakpoints, scripts and the network throttle / No caching (**New** → pick a type; a rule's name and type stay fixed when
you edit it, and a Map Local rule opens its own editor). Breakpoints pause requests/responses in mitmweb for editing and continuation.
`text/event-stream` responses stream events to the client as they arrive. Their calls appear in the panel without a
body; response rules and response breakpoints cannot edit streamed events.
Other HTTP responses are buffered before Rivis forwards their headers and body. A slow download can therefore deliver
its first byte to the app only after the entire response arrives at Rivis; app timeouts and progress indicators may
behave differently than they do without capture. This also applies when no response rule or breakpoint is enabled.

### Is my rule working? (hit counts and Test)

While Rivis runs, every ON rule counts the calls it changed and when it last did. The **Rules** tab and
`rivis rules list` show it under each rule:

- `matched 12 calls · last 3s ago` — the rule is working.
- `matched 4 calls but changed nothing — …` — the rule's pattern matches, but it had no effect (for example a Map
  Remote whose `replace` does not occur in the URL, or Edit JSON on a response that is not JSON). The reason is given.
- `ON, but none of the 15 calls since it was switched on matched it` — shown after 10 calls: check the pattern
  and the method.

Counts start again when a rule is edited (not when it is only switched off and on) and when Rivis restarts.

To find out why a rule does or does not change a call, select the call and click **Test against the selected
call** in the Rules tab, or run `rivis rules test URL [METHOD]`. Each rule gets one line: what it would do, or why it
does not fire (pattern does not match, other method, an earlier Map Local already answers the call, a blocking
rule, a Map Remote that would change nothing). Nothing is sent.

Traffic profiles include 3G Urban, congested LTE, high-latency VPN, packet loss, manual values, and legacy
profiles. Collection replay keys calls by method, host, path, canonical query, then request-body hash; repeated
calls replay in recorded order and stick on the last result.

## Troubleshooting with `rivis doctor`

When something does not work and you do not know why, run:

```bash
rivis doctor            # grouped, coloured, human-readable
rivis doctor --no-net   # skip host reachability (finishes in under a few seconds)
rivis doctor --json     # machine-readable, for scripts/CI
rivis doctor --fix-safe # offer only safe, reversible fixes (asks y/N; add --yes to accept all)
```

It is **read-only** by default and checks, in order:

1. **mitmproxy** is the pinned version and where it lives; **Node.js** for JS scripts.
2. The **CA** exists, its private key is `0600`, its age and fingerprint.
3. macOS **local-capture extension** is activated + enabled (needed for the iOS Simulator).
4. The **proxy / web ports** are free or owned by Rivis — otherwise it names the process
   (Proxyman, FRTMProxy, an older instance) and how to stop it.
5. The **system proxy**: an unanswered localhost setting (ownership must be checked before clearing), a local tool
   routing simulator traffic, or a corporate proxy (left untouched).
6. **Proxyman / FRTMProxy** running.
7. **iOS Simulators** booted and whether each trusts the Rivis CA → `rivis ios on` if not.
8. **Android emulators**: running, `http_proxy`, CA in the user store, Play vs Google APIs image.
9. The **running instance**: project, rule counts, skipped (broken) rules, script errors, throttle,
   TLS mode and — flagged loudly — anything that silently changes traffic (an active throttle,
   block/rewrite rules, armed breakpoints, and active or strict collection replay). A forgotten rule is a common "my app is
   broken".
10. **Network reachability** for the project's `doctor_hosts` (DNS, TCP 443, TLS), distinguishing a
    DNS failure, no route (VPN down), a reset tunnel, and a certificate SAN mismatch. Skip with `--no-net`.
11. **Disk**: state-dir size, the largest collections/sessions, and a low-free-space warning.
12. The system **Python 3.9** the CLI helpers depend on.

Exit code is `0` when everything passes, `1` with warnings, `2` with errors — so CI can gate on it.
`rivis doctor` never sets a system proxy, never binds a port, never touches the CA, devices, the VPN,
or a corporate proxy, and masks any token it reads. On Windows, `rivis.ps1 doctor` runs the same
checks when Python is installed, and a reduced native subset (ports, WinINET/WinHTTP proxy, adb,
mitmproxy version) otherwise.

## Troubleshooting

| Symptom | Action |
|---|---|
| UI says 403 | Close the stale tab and run `rivis ui` to reopen with the current token. |
| iOS shows DNS but no API calls | Quit another tool that owns the system proxy. |
| Emulator has no network | Run `rivis android off`, or start the proxy on the configured port. |
| Client rejects the CA | Install it with `ios on`/`android on` and use a build that trusts the workstation CA. |
| Upstream certificate cannot validate | Read the 502 body: it names the reason. Incomplete chain, expired, self-signed or wrong-host server: `rivis tls ignore add HOST` + `rivis tls mode ignore` (not captured), or `--insecure` for a dev server. Otherwise your network inspects HTTPS with a root this Mac does not trust: install IT's root in Keychain Access, or `RIVIS_EXTRA_TRUST=/path/root.pem rivis start`. Only if the server's own certificate is invalid (e.g. a dev environment) and the project policy allows it, start with `--insecure`. |
| 403 *Private upstream destinations are blocked* | The server is on a private address and the call is plain HTTP or from a web page: add its domain to the project's `hosts`, or start with `--allow-private-hosts 'REGEX'`. |
| A port is occupied | Stop the previous mitmweb instance or choose another `<PREFIX>_PORT`/`_WEB_PORT`. |

The panel relies on mitmweb internals and must be retested after mitmproxy upgrades. Never use
`simctl keychain reset`; `ios off` removes only this workstation's mitmproxy CA row.

## From a source checkout (developers)

This section is for people working on Rivis itself. The installed copy has no `tests/` or `install/` directory, and
testers do not need anything here.

Install the approved mitmproxy build, then link the command without copying it:

```bash
mkdir -p ~/bin
ln -sf "$PWD/rivis" ~/bin/rivis
rivis projects list
rivis start
```

### Running the test suite

```bash
tests/run.sh            # everything (CLI, PowerShell, rules, profiles, breakpoints, collections, panel, scripts, viewers,
                        # TLS, installer, security, perf budgets, browser UI)
tests/run.sh --fast     # same without the browser UI and the perf budgets
tests/run.sh --ui       # only the browser UI smoke
tests/run.sh -k tls     # select by name; --jobs N sets parallelism (default 4)
```

The suite is hermetic: every module gets a fake `HOME`, a private CA, a shim directory first on `PATH`, random ports
and a local upstream test server; it never touches `~/.rivis`, `~/.mitmproxy`, the system proxy or devices. It needs only
`/usr/bin/python3` with `pytest`, `mitmweb`, `node` and `curl`. The run ends with a table of pass/fail/xfail/skip
counts plus a check that nothing was left behind. Known product bugs live in `tests/FOUND-BUGS.md`; their tests are
marked `expectedFailure`, so fixing a bug turns its test into an "unexpected success" failure (delete the marker then).
The browser tests need Playwright: `pip3 install --user playwright && python3 -m playwright install chromium`.
