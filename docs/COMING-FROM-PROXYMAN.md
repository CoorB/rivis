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

For slow downloads, Rivis buffers ordinary HTTP responses before forwarding them to the app. The app may receive the
first byte only when the download is complete, even with no rules enabled. Server-sent events (`text/event-stream`)
stream as they arrive; see the [Rules section](REFERENCE.md#rules) for the editing limitation.

## Task-by-task mapping

| In Proxyman you did | In Rivis |
|---|---|
| **Certificate → Install on iOS Simulator / Android Emulator** | **Tools → Devices**: each booted simulator and running emulator with a **Set up** button (Google Play emulators ask once to restart). Terminal: `rivis setup`. |
| **Map Local** (answer a call from a saved response) | On the call: **This call → Map Local this call…**; or the **Map Local** tab to add one by host and path. Edits body, status and headers; one mock per endpoint. |
| **Breakpoint** | **This call → Breakpoint** (Request / Response). A matching call pauses and a sheet opens by itself with Continue / Skip / Abort. Manage all breakpoints in the **Breakpoints** tab. |
| **Network Conditions** (throttle) | **Tools → Network** tab → traffic profiles (3G, LTE, high-latency VPN, packet loss, or a manual profile with your own latency / bandwidth / loss). Can be limited to URLs matching a pattern (a regex, e.g. `neo\.sa` for your API host). |
| **No Caching** | **Tools → Network** tab → **No caching** switch, or `rivis nocache on\|off\|status`. Strips `If-None-Match` / `If-Modified-Since` (and the other conditional headers) from requests and marks responses `no-store` without `ETag` / `Last-Modified`, so the app always fetches fresh content. Per project; Map Local answers are not touched. |
| **Compose a new request** | **Compose** tab, or **Compose from this call**. Method, URL, params, headers and a JSON / form / raw body; **Send** runs it through rules, scripts and breakpoints just like a real call. |
| **Repeat / Edit & Repeat** | Repeat as-is: `⌘↵` (Ctrl+Enter) or mitmweb's `r`. Edit first: **This call → Edit & Repeat…** — change method, URL, headers and body, then send a copy; the original stays in the list. |
| **Diff two requests** | Pick **Compare: set as A** on one call, select another, open **Compare**, then click **Compare A with B**. The result lists both URLs and highlights header and body differences. |
| **Export HAR** | **Sessions** or **Collections** → **HAR**. Sessions also save and reopen the whole capture with a note. |
| **Filter by host / app** | The filter box at the top is always visible (`⌘F` / `Ctrl+F`, `Esc` clears): type a host or part of a URL. `~` filters (`~m POST`, `~c 500`, `~q`) work too. Or right-click a call → **Show only this host**. A strip under the toolbar shows what is hiding calls, with an ✕ to undo each. |
| **Filter by device / app** (one simulator app, one emulator) | **Source** menu in the Tools header, next to **Show**: *All sources*, each device (*All of iPhone 17*), and each app on it with its call count. Two builds of one app (e.g. *NEO UAT* and *NEO SIT*) are separate entries. Each call shows its app as a chip in the list and under **This call**; right-click → **Show only &lt;app&gt;**. The choice shows in the strip under the toolbar with an ✕. |
| **Is my rule hitting?** | Each rule in the **Rules** tab shows how many calls it changed and when; an ON rule that matches nothing is flagged. Select a call → **Test against the selected call** explains each rule. Terminal: `rivis rules test URL [METHOD]`. |
| **Clear the session** | The trash button next to the filter box (asks first). |
| **Right-click a call** | Map Local, Breakpoint, Repeat, Edit & Repeat, Compare, Copy as cURL, Show only this host, Delete. |
| **SSL Proxying list** | **Network → HTTPS decryption**: every host, only the hosts you list, or everything except the hosts you list. Per-host quick toggles are on each call (**This call → HTTPS**, or right-click). |
| **Client certificates (mTLS)** | Rivis cannot present a client certificate to the server while decrypting. If your app already has one, leave that host undecrypted: `rivis tls ignore add HOST`, then `rivis tls mode ignore`. The app connects through a tunnel; its calls cannot be inspected or rewritten. |
| **Scripting** | **Scripts** tab — JavaScript or Python, enabled per project, run in filename order after rules. (Trusted user code: it runs with your rights; the Node VM drops network/`require` to prevent accidents but is not a security boundary.) |
| **Save a session** | **Sessions** tab → save, add a note, reopen later, or export HAR. |
| **Copy as cURL** | **This call → Copy cURL**, or **Copy as…** for many languages. Secrets (Authorization, cookies) are masked by default — untick **Mask secrets** to include them. |

## Keyboard shortcuts

Proxyman's shortcuts are `⌘`-based; in a browser tab most `⌘` combinations are already claimed by the browser,
so Rivis uses `⌥⇧` (Alt+Shift) chords for its own actions. Single-key mitmweb shortcuts work when the call
list is focused, and never while focus is anywhere in the Rivis panel (a field, a button, a sheet).

Everything Rivis opens takes the keyboard: the chords move focus into the drawer (Compose lands in its URL field),
Edit & Repeat, a paused call's sheet (also when it opens by itself) and the Map Local editor focus their first
field. `Tab` / `⇧Tab` stay inside what is open, and `Esc` closes it the way its own button does — Cancel on Edit &
Repeat, Back on an editor, hide on a paused call's sheet (the call stays paused; the Tools button reopens it), close
on the drawer. Focus then goes back to where it was.

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
| `Esc` | Close the open sheet, editor or drawer (focus goes back where it was) |

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
(`?theme=on` restores it) — the choice is remembered per browser. See the [**Themes** section of the
reference](REFERENCE.md#themes) for details.
