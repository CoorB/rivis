## Install

You need access from IT first (they publish the files on the internal mirror). Nothing here needs admin rights,
changes your system proxy, or listens outside your own computer.

### Mac
1. Download the installer folder from the internal mirror and open Terminal in it.
2. Run `./install.sh` (add `--dry-run` first to see what it will do without changing anything).
3. For iOS Simulator capture, macOS asks you to approve "Mitmproxy Redirector" once. The installer opens the
   right System Settings page and waits. Under Extensions, click By Category, then the ⓘ next to Network Extensions: switch it on,
   confirm with Touch ID or your password, and the installer carries on by itself. Skip it and everything else
   still works; only iOS capture needs it. To approve later, run `./install.sh` again.
4. The installer offers to start Rivis and open its UI. Then **Tools → Devices**: one click per simulator or
   emulator (Google Play emulators ask once to restart). Later: `rivis start --background` (or `rivis setup` from a terminal).

Remove with `./install.sh --uninstall`. Your saved data and certificate are kept; the command tells you how to delete them.

### Windows
1. Download the installer folder from the internal mirror and open PowerShell in it.
2. Run `.\install.ps1` (add `-DryRun` first to preview).
3. Open a new PowerShell window, then: `rivis start`, `rivis android on`.

Windows has no iOS Simulator, so iOS capture is Mac-only. Android emulator capture needs the Android SDK
(`adb`). Remove with `.\install.ps1 -Uninstall`.

If the installer says a checksum doesn't match, stop and tell IT. It never uses a file it cannot verify.
