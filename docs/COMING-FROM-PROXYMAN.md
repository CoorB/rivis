# Coming from Proxyman

Rivis is a mitmproxy-based toolkit, not a Proxyman clone — but most of the day-to-day tasks map over
directly, under the same generic industry names (Map Local, Breakpoint, Network Conditions, Compose, Diff,
Copy as cURL, SSL proxying, Scripting). This page is the honest translation guide.

The same table is built into the UI: click the Help (`?`) button in the brand bar, top-right → **Coming from
Proxyman?**. Each row there has an **Open →** link that takes you straight to the place in the panel.

## The three biggest differences

1. **It runs in a browser tab**, not a native window. The call list, the details pane and the menus are
   mitmweb; the Rivis tools live in a drawer on the right (the **Tools** button at the right end of the toolbar) and in
   per-call actions, including a right-click menu on every call. Nothing to install in the menu bar.
2. **It captures the simulator per-process, with no system proxy.** Rivis does not flip your Mac's system
   proxy, so it never sweeps up traffic from your browser, Slack, or anything else on the machine — only the
   app you pointed at it. (That is also why you will not see the dozens of background tunnels Proxyman shows.)
3. **There is a project switcher.** A project is a saved profile — a label, a host filter, and its own rules,
   collections and sessions. Switch the *view* with the **Show** menu in the drawer header (*All traffic* or *<project> only*); load a different project's *rules* by
   restarting with `--project <id>`.

## Task-by-task mapping

| In Proxyman you did | In Rivis |
|---|---|
| **Certificate → Install on iOS Simulator / Android Emulator** | **Tools → Devices**: each booted simulator and running emulator with a **Set up** button (Google Play emulators ask once to restart). Terminal: `rivis setup`. |
| **Map Local** (answer a call from a saved response) | On the call: **This call → Map Local this call…**; or the **Map Local** tab to add one by host and path. Edits body, status and headers; one mock per endpoint. |
| **Breakpoint** | **This call → Breakpoint** (Request / Response). A matching call pauses and a sheet opens by itself with Continue / Skip / Abort. Manage all breakpoints in the **Breakpoints** tab. |
| **Network Conditions** (throttle) | **Network** tab → traffic profiles (3G, LTE, high-latency VPN, packet loss, or a manual profile with your own latency / bandwidth / loss). Can be limited to URLs containing some text (e.g. your API host). |
| **Compose a new request** | **Compose** tab, or **Compose from this call**. Method, URL, params, headers and a JSON / form / raw body; **Send** runs it through rules, scripts and breakpoints just like a real call. |
| **Repeat / Edit & Repeat** | Repeat as-is: `⌘↵` (Ctrl+Enter) or mitmweb's `r`. Edit first: **This call → Edit & Retry…** — change method, URL, headers and body, then send a copy; the original stays in the list. |
| **Diff two requests** | **Compare** tab: pick **Compare: set as A** on one call, then select another. Shows a field-level diff. |
| **Export HAR** | **Sessions** or **Collections** → **HAR**. Sessions also save and reopen the whole capture with a note. |
| **Filter by host / app** | The filter box at the top is always visible (`⌘F` / `Ctrl+F`, `Esc` clears): type a host or part of a URL. `~` filters (`~m POST`, `~c 500`, `~q`) work too. Or right-click a call → **Show only this host**. A strip under the toolbar shows what is hiding calls, with an ✕ to undo each. |
| **Clear the session** | The trash button next to the filter box (asks first). |
| **Right-click a call** | Map Local, Breakpoint, Repeat, Edit & Repeat, Compare, Copy as cURL, Show only this host, Delete. |
| **SSL Proxying list** | **Network → HTTPS decryption**: every host, only the hosts you list, or everything except the hosts you list. Per-host quick toggles are on each call (**This call → HTTPS**, or right-click). |
| **Scripting** | **Scripts** tab — JavaScript or Python, enabled per project, run in filename order after rules. (Trusted user code: it runs with your rights; the Node VM drops network/`require` to prevent accidents but is not a security boundary.) |
| **Save a session** | **Sessions** tab → save, add a note, reopen later, or export HAR. |
| **Copy as cURL** | **This call → Copy cURL**, or **Copy as…** for many languages. Secrets (Authorization, cookies) are masked by default — untick **Mask secrets** to include them. |

## Keyboard shortcuts

Proxyman's shortcuts are `⌘`-based; in a browser tab most `⌘` combinations are already claimed by the browser,
so Rivis uses `⌥⇧` (Alt+Shift) chords for its own actions. Single-key mitmweb shortcuts work when the call
list is focused (and are ignored while you type in a field).

**Rivis**

| Keys | Action |
|---|---|
| `⌥⇧P` | Open / close the tools drawer |
| `⌥⇧C` | Compose a new request |
| `⌥⇧L` | Map Local |
| `⌥⇧B` | Breakpoints |
| `⌥⇧N` | Network conditions |
| `⌥⇧E` | HTTPS decryption list (SSL proxying) |
| `⌥⇧S` | Scripts |
| `⌥⇧D` | Compare (diff) two calls |
| `⌥⇧V` | Devices: set up simulators / emulators |
| `⌘F` / `Ctrl+F` | Filter the list (`Esc` clears) |
| `⌥⇧F` | Filter the list (same) |
| `⌘↵` | Repeat the selected call |
| `⌥⇧↵` | Edit & Repeat the selected call |
| `?` | Shortcut sheet |

**Built into mitmweb** (call list focused)

| Keys | Action |
|---|---|
| `↑` `↓` or `k` `j` | Previous / next call |
| `r` | Replay the selected call |
| `d` | Delete the selected call |
| `D` | Duplicate the selected call |
| `Esc` | Deselect |

(On Windows / Linux, read `⌘` as `Ctrl` and `⌥` as `Alt`.)

## Themes and the kill switch

The skin follows your OS light/dark setting; toggle it from the brand bar. **Compact rows** and a **skin
on/off** switch are in the panel's **Settings**. To fall back to stock mitmweb, add `?theme=off` to the URL
(`?theme=on` restores it) — the choice is remembered per browser. See the README's **Themes** section for
details.
