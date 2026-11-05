# Rivis software bill of materials

Snapshot: 2026-10-26. Scope: repository on branch `c/upgrade` and the pinned runtime artifacts
configured in `install/mirror.conf`. Transitive inventory taken from the inspected macOS arm64
mitmproxy 12.2.3 app bundle (`mitmproxy.app/Contents/Resources`), not from an unrelated pip
environment.

## Shipped direct dependencies

| Component | Version | Purpose | Source / integrity |
|---|---:|---|---|
| mitmproxy / mitmweb / mitmdump | 12.2.3 | Proxy engine and local web UI | Pinned in `install/mirror.conf`; official macOS arm64 and x86_64 archives have reviewed SHA-256 values there. The Windows archive must not be published until its currently-empty SHA-256 pin is filled. Team ID for reuse of an already-installed copy: `S8XHQB96PW` (`MITMPROXY_TEAM_ID`). |
| Python standard library | System Python 3.9+ for CLI helpers; bundled Python in the mitmproxy binary | JSON/state helpers, doctor, bug-report, tests | Rivis runtime helpers import only the standard library. The inspected macOS mitmproxy 12.2.3 binary reports bundled Python 3.14.4 (`mitmweb --version`). |
| OpenSSL | Bundled with the mitmproxy artifact (reported 3.5.5) | TLS implementation | Shipped as `libssl.3.dylib` / `libcrypto.3.dylib` inside the macOS app Resources. |
| Magisk | 30.7 (optional) | One-time CA install on Google Play Android emulators, which refuse `adb root` (same approach as Proxyman 6.14) | Official upstream release APK and `scripts/host_patch.sh` at commit e8a5877, GPLv3, pinned by SHA-256 in `addons/android/magisk.pins` and verified at install and before each use. Never linked into Rivis; runs only on the emulator, on a temporary ramdisk copy, after explicit consent. Rivis adds a one-shot boot service that copies the CA and grants root to nothing else. |
| Node.js | Optional, version not pinned | Runs user-authored JavaScript interception scripts | No npm packages are installed or shipped. If Node is absent, Python scripts and all non-script proxy features continue to work. |

## Bundled with mitmproxy 12.2.3 (transitive, macOS archive)

These ship inside the pinned mitmproxy binary; Rivis does not install them separately. Versions below
are from `*-dist-info` directories (or package trees) present in the inspected macOS arm64 Resources
tree on 2026-10-26. Re-check on every pin bump.

| Component | Version (dist-info / reported) | Why it matters to Rivis |
|---|---|---|
| Tornado | (vendored under `Resources/tornado`; no dist-info in this build) | mitmweb's HTTP server. `proxy_panel` subclasses its handlers, calls `app.add_handlers` / `find_handler`, and raises `tornado.web.HTTPError`. |
| cryptography | 46.0.4 | Upstream TLS and the Rivis CA. |
| argon2_cffi | 25.1.0 | mitmweb password hashing. |
| attrs | 25.4.0 | mitmproxy internals. |
| click | 8.3.1 | mitmproxy CLI. |
| Flask / Werkzeug / itsdangerous / MarkupSafe | 3.1.2 / 3.1.5 / 2.2.0 / 3.0.3 | Present in the archive; mitmweb itself is Tornado-based. Listed because they ship. |
| h2 | 4.3.0 | HTTP/2 (off by default in Rivis: `--set http2=false`). |
| service_identity | 24.2.0 | TLS identity checks. |
| certifi | (cacert.pem tree; no dist-info) | mitmproxy's default upstream trust list when `--verify-upstream` / system trust is not used. |
| aioquic / pylsqpack | (package trees; no dist-info) | HTTP/3 support inside mitmproxy. |
| bcrypt / zstandard / brotli / charset_normalizer / publicsuffix2 / wcwidth / setuptools | (package trees) | Transitive runtime of the frozen app. |
| mitmproxy_rs / mitmproxy_macos | bundled with 12.2.3 | Local-capture redirector (`org.mitmproxy.macos-redirector`) used by `--mode local:CoreSimulator`. |

Exact OpenSSL and Python versions for a given install: run `mitmweb --version` from the pinned binary
on PATH (the installer places it there).

## Python and npm inventories

- Production Python packages installed by this repository: **none**. There is no `requirements.txt`, lock file,
  `pyproject.toml`, or `pip install` step. The official mitmproxy executable is distributed as one pinned binary
  artifact and contains its own transitive Python environment.
- Production npm packages installed by this repository: **none**. The panel is checked-in browser JavaScript and
  the optional Node host uses built-in Node modules only. There is no `package.json` or npm install step.
- Test-only dependency: `pytest`, supplied by the controlled test runner rather than installed by Rivis.

## Regeneration and review

On every runtime upgrade, update the mitmproxy pin and archive hashes in `install/mirror.conf`, capture
`mitmweb --version`, rerun `bash tests/run.sh`, run the upgrade-surface guards
(`/usr/bin/python3 -m pytest tests/test_mitm_surface.py -x -q`), and replace this snapshot. Obtain the
complete transitive component inventory from the exact official mitmproxy archive used by the internal
mirror (macOS: `mitmproxy.app/Contents/Resources`); do not infer transitive versions from an unrelated pip
environment. Fill `MITMPROXY_SHA256_WINDOWS_X86_64` before publishing a Windows build.
