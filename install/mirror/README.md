# What IT must publish on the internal mirror

Policy (HANDOVER §1): install only from the internal mirror, pinned version, auto-update off. The installers
(`install.sh`, `install.ps1`) take the mirror from `--from-mirror URL` / `-FromMirror URL`, or from `MIRROR_BASE_URL`
in `install/mirror.conf`. **Every file is verified against a pinned SHA-256 before use; a mismatch is refused.**

Note: `downloads.mitmproxy.org` is blocked by the corporate web filter (Sophos category block, seen 2026-10-14), so
IT has to fetch the official files from an unfiltered host and publish them unmodified.

## 1. mitmproxy 12.2.3 (official files, byte-for-byte, do not repack)

Layout: `<MIRROR_BASE_URL>/mitmproxy/12.2.3/<file>`

| Platform | File | SHA-256 | Official URL |
|---|---|---|---|
| macOS Apple silicon | `mitmproxy-12.2.3-macos-arm64.tar.gz` | `0a09ee3b82569e8985aff8186e4792618b8e5d0c766098db093d09a87d4b013a` | https://downloads.mitmproxy.org/12.2.3/mitmproxy-12.2.3-macos-arm64.tar.gz |
| macOS Intel | `mitmproxy-12.2.3-macos-x86_64.tar.gz` | `7998187f5a0d399ab796af4523d3ad830ebe690726a41bc3e1df47a8e477a641` | https://downloads.mitmproxy.org/12.2.3/mitmproxy-12.2.3-macos-x86_64.tar.gz |
| Windows x64 (portable zip) | `mitmproxy-12.2.3-windows-x86_64.zip` | **IT to compute** (`Get-FileHash -Algorithm SHA256`) | https://downloads.mitmproxy.org/12.2.3/mitmproxy-12.2.3-windows-x86_64.zip |

Where the macOS hashes come from: Homebrew's cask API for `mitmproxy` 12.2.3 (`formulae.brew.sh/api/cask/mitmproxy.json`,
checked 2026-10-14). The tarball contains `mitmproxy.app/Contents/MacOS/{mitmdump,mitmproxy,mitmweb}` and the signed
"Mitmproxy Redirector" (team S8XHQB96PW) inside the app, so **no separate redirector download is needed**.

**Unconfirmed:** the Windows zip name and hash. mitmproxy's build script produces a standalone-binaries zip for Windows,
but no published checksum for it was reachable. Only the installer is independently confirmed (winget manifest):
`mitmproxy-12.2.3-windows-x86_64-installer.exe`, SHA-256 `844D0D40C4B9D7E68A8FCDB66354255C4480EA43C4CEB783D7E41C7A98FA8CE9`.
It is not used by `install.ps1` (an installer typically needs admin; the zip is user-scope). If IT publishes the zip, put its
hash into `MITMPROXY_SHA256_WINDOWS_X86_64` in `mirror.conf`; until then `install.ps1` refuses to install from a download.

## 2. The tool (versioned tarball)

Layout: `<MIRROR_BASE_URL>/<cli>/<cli>-<version>.tar.gz`  (cli name from `product.json`; version from `install/VERSION`)

```bash
install/mirror/make-release.sh ./dist     # builds dist/<cli>-<version>.tar.gz and prints its SHA-256
```
Put the printed hash into `TOOL_SHA256` in `mirror.conf`. The tarball excludes `install/`, snapshots, diffs,
`.DS_Store` and any state (rules.json, tokens, sessions, collections).

## 3. The installer bundle (so users need nothing else)

Publish alongside: `install.sh`, `install.ps1`, `VERSION`, `mirror.conf`, `product.json` (with `MIRROR_BASE_URL` and all hashes filled in).
They must stay in one directory; the tool tarball does not contain them. Distribute as a folder or zip.

## 3b. Or: one offline bundle (no mirror needed)

```bash
install/mirror/make-bundle.sh mitmproxy-12.2.3-macos-arm64.tar.gz mitmproxy-12.2.3-macos-x86_64.tar.gz --out ./dist
```
Builds `dist/<cli>-installer-<version>.zip`: the installer files plus the tool archive and the given official mitmproxy
archives (each must match its pin, or nothing is built). The installer uses archives sitting next to it before any
mirror and verifies them exactly like a download. Share the zip through any internal channel (Teams, SharePoint, a
file share). Users unzip it and run `./install.sh`. A mirror, when configured, must be `https://`.

## 4. Optional: internal Homebrew tap

`<cli>.rb.template` is a formula template for an internal tap. Placeholders only. Fill them in and host the tap
on IT's own Git, never a public tap. Note a brew install would not run the Redirector approval; users still
run `<cli> start` once and approve it (see the README).

## Upgrading

An upgrade is a reviewed change: new files + new hashes in `mirror.conf` + new `MITMPROXY_VERSION`. Nothing auto-updates.
