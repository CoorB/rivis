# Coming from Proxyman

Rivis is a mitmproxy-based toolkit, not a Proxyman clone — but most of the day-to-day tasks map over
directly, under the same generic industry names (Map Local, Breakpoint, Network Conditions, Compose, Diff,
Copy as cURL, SSL proxying, Scripting). This page is the honest translation guide.

In the classic view (`rivis ui --classic`), the same table is under Help (`?`) → **Coming from Proxyman?**; each row
has an **Open →** link into the drawer. The main window's Help (`?`) lists its own shortcuts and a short Proxyman
note; use this page for the full mapping.

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
| **Certificate → Install on iOS / Android physical device** | `rivis start --lan`, then **Tools → Devices → Phones and tablets**: scan the QR code on the phone for the setup page and certificate, set its Wi-Fi proxy to the address shown, and **Allow** it. Unlike Proxyman, a device that has not been allowed is refused. |
| **Install the certificate in the Android emulator's system store** | **Tools → Devices → Add to system store** on the emulator's row, or `rivis android on --system`. For apps that trust only system certificates (most release builds). Does not bypass pinning. |
| **Map Local** (answer a call from a saved response) | On the call: **Map Local** (toolbar, right-click, or classic **This call → Map Local this call…**). Edits body, status and headers; switch saved variants for the same endpoint, or use a folder of files. |
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
| **Client certificates (mTLS)** | **Tools → Network → Client certificates**: a host plus a `.p12` (with its password) or PEM certificate and key, like Proxyman's Certificate → Custom Certificates → Client Certificates. CLI: `rivis tls client-cert add HOST FILE.p12 --password-stdin`. Wildcards (`*.example.test`) work. |
| **Scripting** | **Scripts** tab — JavaScript or Python, enabled per project, run in filename order after rules. (Trusted user code: it runs with your rights; the Node VM drops network/`require` to prevent accidents but is not a security boundary.) |
| **Save a session** | **Sessions** tab → save, add a note, reopen later, or export HAR. |
| **Copy as cURL** | **This call → Copy cURL**, or **Copy as…** for many languages. Secrets (Authorization, cookies) are masked by default — untick **Mask secrets** to include them. |
| **JWT / GraphQL / Protobuf viewers** | Select the call. The main window shows a protocol strip above the request/response panes; classic **This call** shows the same facts (decoded JWT with local `exp`, GraphQL operation/variables/data/errors, gRPC service/method and field numbers). GraphQL operations also appear in the main window sidebar (or classic's operation chips) to filter the list. |

## Keyboard shortcuts

The **main window** (default) uses Proxyman-style `⌥⌘` (Alt+Cmd) tool chords. The **classic view**
(`rivis ui --classic`) uses `⌥⇧` (Alt+Shift) instead, because mitmweb already claims many `⌘` combinations.
Single-key mitmweb shortcuts work when the call list is focused in classic view, and never while focus is in the
Rivis panel (a field, a button, a sheet).

Everything Rivis opens takes the keyboard: tools, Edit & Repeat, a paused call's sheet and the Map Local editor
focus their first field. `Tab` / `⇧Tab` stay inside what is open, and `Esc` closes it the way its own button does.
Focus then goes back to where it was.

**Main window** (default)

| Keys | Action |
|---|---|
| `⌥⌘F` | Filter the list |
| `⌘F` | Search in the request or response body |
| `⌘K` | Find or pin a domain in the sidebar |
| `⇧⌘L` | Follow the newest call |
| `⇧⌘⌫` | Clear the list (asks first) |
| `⌥⌘L` / `⌥⌘R` / `⌥⌘B` | Map Local / Map Remote / Breakpoint |
| `⌥⌘N` / `⌥⌘A` / `⌥⌘X` | No Caching / TLS hosts to decrypt / Block List |
| `⌥⌘C` / `⌥⌘D` | Compose / Devices |
| `⌥1` … `⌥9` | Saved filters |
| `↑` `↓` | Move through the list |
| `⌫` | Delete the selected call |
| `?` | Shortcut sheet |
| `Esc` | Close the front window |

**Classic view** (`rivis ui --classic`)

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

**Built into mitmweb** (classic call list focused)

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
