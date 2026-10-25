# Rivis

A free, in-house replacement for **Proxyman**, for mobile QA teams.
See, pause, change and mock the calls your iOS Simulator or Android emulator makes, from a browser tab.

Built on [mitmproxy](https://mitmproxy.org) (unchanged). Runs only on your Mac, only for simulators and emulators.

---

## What you can do

| You want to… | In Rivis |
|---|---|
| See every call the app makes | The call list, with a filter box and a view of just your app's hosts |
| See only one simulator, one emulator or one app | **Source** menu in the Tools header: each device, and each app on it (e.g. *NEO UAT* and *NEO SIT* side by side on one simulator), with its call count |
| Pause a call and edit it before it continues | **Breakpoint** on a call: change the request or the response, then *Continue* |
| Serve your own response instead of the server's | **Map Local this call**, then edit the mock |
| Force an error, a delay or a dropped call | One click on a call: status `503`, delay, block |
| Test on a slow or flaky network | **Network** tab: 3G, congested LTE, VPN latency, packet loss |
| Always get fresh content (never a cached copy or an empty 304) | **Network** tab → **No caching**, or `rivis nocache on` |
| Send a call again, or edit and resend it | **Repeat** (`⌘↵`) / **Edit & Repeat** (`⌥⇧↵`), or build one in **Compose** |
| Compare two calls | Right-click the first → **Compare: set as A**, select the second, then in **Compare** click **Compare A with B** |
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

Mac, Apple silicon or Intel. No admin password, nothing else to download. Apple's Command Line Tools must be installed
(they are if you have Xcode; otherwise the installer tells you to run `xcode-select --install` once).

1. Quit Proxyman, Charles or any other proxy app (while it runs it takes the simulator's traffic). If it leaves your
   Mac's proxy setting behind, Rivis clears it for you.
2. Download the zip from the [latest release](https://github.com/CoorB/rivis/releases) into **Downloads**.
3. Paste this into Terminal (the release page has the same line for its version):
   ```bash
   cd ~/Downloads && { [ -d rivis-installer-0.9.9 ] || unzip -q rivis-installer-0.9.9.zip; } && ./rivis-installer-0.9.9/install.sh
   ```
   For scripted installs, pass `--yes --skip-local-capture` to `install.sh`.
   It works whether or not Safari already unzipped the file. For iOS, approve *Mitmproxy Redirector* when
   System Settings opens; the installer continues by itself as soon as you do (or press Enter to skip).
4. At the end, press Enter to start Rivis; it opens in your browser. Go to **Tools → Devices** and click **Set up**
   for your simulator or emulator. (Later, from a new Terminal window: `rivis start --background`.)

To upgrade, download the new release zip from the latest release page and run its `install.sh`.
`rivis update` remains available for signed in-app updates when that feature is configured; otherwise it points to the release zip.
Installing an update restarts a running instance on the new version when its saved start settings are available. A foreground instance continues in the background after an installer or detached update, and the restart message says so. `rivis restart` in a terminal keeps foreground mode. If
the installer reports an instance still running on an older version, use the shown ports with `rivis restart` before
using the updated features. `rivis status` also reports a running version that differs from the installed version.

**Devices** and **Network** are inside the **Tools** drawer; they are not top tabs.

### Uninstall

1. **First**, while the `rivis` command is still there, remove Rivis from every simulator and emulator you set up:
   `rivis ios off --all` and `rivis android off --all`. After uninstalling, the command is gone and you have to remove
   the certificate on each device by hand.
2. Run the installer from the unzipped release folder with `--uninstall`:
   `~/Downloads/rivis-installer-<version>/install.sh --uninstall`. It stops Rivis and keeps your saved projects
   (`~/.rivis`) and the certificate (`~/.mitmproxy`); it prints the commands to delete those too.

---

## Everyday commands

```bash
rivis start --background   # start (keeps running after you close Terminal)
rivis start --upstream http://proxy.company:3128  # forward calls through an HTTP proxy; saved for later starts
rivis start --upstream direct  # return to a direct connection
rivis ui                   # reopen the browser tab
rivis ui --new             # preview: the new main window, laid out like Proxyman
rivis browser URL          # web apps: open a separate Chrome/Edge window that goes through Rivis
rivis browser --current    # the same, for the page open in your browser's front tab
rivis status               # is it running?
rivis stop                 # stop
rivis restart              # restart with saved options; load a new `projects use` selection unless start used --project
rivis --version            # which version you have
```

Everything else is in the browser panel. The full command list is in [docs/REFERENCE.md](docs/REFERENCE.md).
`rivis status` and `rivis doctor` show the saved upstream setting. On Windows, use
`.\rivis.ps1 start -Upstream http://proxy.company:3128` (or `-Upstream direct`).

To run two projects at once, give each instance its own `RIVIS_PORT` and `RIVIS_WEB_PORT`. Use the matching
`RIVIS_WEB_PORT` with `rivis ui` to reopen each panel; each web port keeps its own login. Uninstall stops every
instance using this installation before removing its add-ons, and leaves saved projects and the CA in place.

---

## Ground rules

- Simulators and emulators by default. A real phone or tablet on your Wi-Fi works only when you start with
  `rivis start --lan` and allow that device in Tools → Devices; every other device on the network is refused.
- Keep the Rivis certificate (`~/.mitmproxy`), saved sessions and HAR files on your own Mac. Don't share them.
- Done with a device? `rivis ios off` / `rivis android off` removes the certificate and proxy from it.

---

## Something not working?

1. Run `rivis doctor`. It checks everything and tells you what to fix.
2. A call answers **403 Private upstream destinations are blocked**: that server is on a private (VPN) address and the
   call is plain HTTP or comes from a web page. Add the app's domain to your project (`rivis projects use <app>`), or
   start with `--allow-private-hosts 'REGEX'`. Apps' HTTPS calls are never blocked.
3. HTTPS calls fail with **502 … could not verify the HTTPS certificate**: the 502 body says why. If the server sends
   an incomplete chain, an expired, self-signed or wrong-host certificate (often a dev server; browsers fetch a missing
   intermediate themselves, Rivis does not), run `rivis tls ignore add HOST` and `rivis tls mode ignore` to pass that
   host through undecrypted, or start with `--insecure`. If it fails for every site on your company network, Rivis
   trusts what your Mac trusts: install IT's root certificate in Keychain Access (or start with
   `RIVIS_EXTRA_TRUST=/path/root.pem`).
4. A server requires a **client certificate** (mTLS): give Rivis that certificate for the host, in the panel
   (Tools → Network → Client certificates) or with `rivis tls client-cert add HOST FILE.p12 --password-stdin`.
   Rivis then sends it to the server, and the calls stay readable. Or leave the host undecrypted
   (`rivis tls ignore add HOST`, `rivis tls mode ignore`), so the app presents its own certificate through a tunnel.
5. It broke right after an upgrade: `rivis health` says what is wrong, and `rivis rollback` takes you back to the
   version you had before, with the same options.
6. Still stuck? Run `rivis bug-report` and attach the zip it creates (it contains no calls, tokens or keys),
   together with the output of `rivis --version`.

---

## From a source checkout (developers)

Only for people working on Rivis itself: the installed copy contains just what is needed to run it (no `install/` or
`tests/`), and testers can skip this section. A source checkout looks like this; developer setup and the test suite
are in [docs/REFERENCE.md](docs/REFERENCE.md#from-a-source-checkout-developers).

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
