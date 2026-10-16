# Rivis

A free, in-house replacement for **Proxyman**, for mobile QA teams.
See, pause, change and mock the calls your iOS Simulator or Android emulator makes, from a browser tab.

Built on [mitmproxy](https://mitmproxy.org) (unchanged). Runs only on your Mac, only for simulators and emulators.

---

## What you can do

| You want to… | In Rivis |
|---|---|
| See every call the app makes | The call list, with a filter box and a view of just your app's hosts |
| Pause a call and edit it before it continues | **Breakpoint** on a call: change the request or the response, then *Continue* |
| Serve your own response instead of the server's | **Map Local this call**, then edit the mock |
| Force an error, a delay or a dropped call | One click on a call: status `503`, delay, block |
| Test on a slow or flaky network | **Network** tab: 3G, congested LTE, VPN latency, packet loss |
| Send a call again, or edit and resend it | **Repeat** (`⌘↵`) / **Edit & Repeat** (`⌥⇧↵`), or build one in **Compose** |
| Compare two calls | Right-click → **Compare** |
| Keep or share evidence | Save a **session**, or export a **HAR** (secrets are masked) |
| Set up a simulator or emulator | **Tools → Devices → Set up**, one click per device |
| Test a web app | **Tools → Devices → Web browser**, or `rivis browser https://your.app`: a separate Chrome/Edge window with its own profile, pointed at Rivis. Your normal browser is not touched |

Coming from Proxyman? The full side-by-side is in [docs/COMING-FROM-PROXYMAN.md](docs/COMING-FROM-PROXYMAN.md),
and inside Rivis: press `?`.

---

## How it fits

```
  iOS Simulator / Android emulator  ──►  Rivis on your Mac (127.0.0.1)  ──►  your app's servers
                                              │
                                              └── browser tab: call list + Tools panel
```

Your Mac's system proxy is never changed, and nothing is reachable from outside your Mac.

---

## Install

Mac with Apple Silicon. No admin password, nothing else to download.

1. Quit Proxyman, Charles or any other proxy app (while it runs it takes the simulator's traffic). If it leaves your
   Mac's proxy setting behind, Rivis clears it for you.
2. Download the zip from the [latest release](https://github.com/CoorB/rivis/releases) into **Downloads**.
3. Paste this into Terminal (the release page has the same line for its version):
   ```bash
   cd ~/Downloads && { [ -d rivis-installer-0.9.3 ] || unzip -q rivis-installer-0.9.3.zip; } && ./rivis-installer-0.9.3/install.sh
   ```
   It works whether or not Safari already unzipped the file. For iOS, approve *Mitmproxy Redirector* when
   System Settings opens; the installer continues by itself as soon as you do (or press Enter to skip).
4. Open a new Terminal window, then:
   ```bash
   rivis start --background
   ```
   Rivis opens in your browser. Go to **Tools → Devices** and click **Set up** for your simulator or emulator.

---

## Everyday commands

```bash
rivis start --background   # start (keeps running after you close Terminal)
rivis ui                   # reopen the browser tab
rivis browser URL          # web apps: open a separate Chrome/Edge window that goes through Rivis
rivis browser --current    # the same, for the page open in your browser's front tab
rivis status               # is it running?
rivis stop                 # stop
rivis --version            # which version you have
```

Everything else is in the browser panel. The full command list is in [docs/REFERENCE.md](docs/REFERENCE.md).

---

## Ground rules

- Simulators and emulators only. Physical phones are not supported.
- Keep the Rivis certificate (`~/.mitmproxy`), saved sessions and HAR files on your own Mac. Don't share them.
- Done with a device? `rivis ios off` / `rivis android off` removes the certificate and proxy from it.

---

## Something not working?

1. Run `rivis doctor`. It checks everything and tells you what to fix.
2. Still stuck? Run `rivis bug-report` and attach the zip it creates (it contains no calls, tokens or keys),
   together with the output of `rivis --version`.

---

## Repository layout

```
rivis              # the command (macOS)        rivis.ps1   # the command (Windows, not in the pilot yet)
addons/            # what runs inside mitmproxy, plus the browser panel
projects/          # one profile per app: its hosts and example rules
install/           # installer, offline bundle builder
docs/              # reference, Proxyman comparison, SBOM
tests/             # automated test suite (bash tests/run.sh --fast)
```

---

## License & ownership

Proprietary — © Coorb. Owner: Vaibhav Santhaliya (`vaibhav.santhaliya@coorb.io`).
