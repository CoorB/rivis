# Rivis software bill of materials

Snapshot: 2026-10-15. Scope: repository commit `75aa15a` and the pinned runtime artifacts configured in
`install/mirror.conf`.

## Shipped direct dependencies

| Component | Version | Purpose | Source / integrity |
|---|---:|---|---|
| mitmproxy / mitmweb | 12.2.3 | Proxy engine and local web UI | Pinned in `install/mirror.conf`; official macOS arm64 and x86_64 archives have reviewed SHA-256 values there. The Windows archive must not be published until its currently-empty SHA-256 pin is filled. |
| Python standard library | System Python 3.9+ for CLI helpers; bundled Python in the mitmproxy binary | JSON/state helpers, doctor, bug-report, tests | Rivis runtime helpers import only the standard library. The inspected macOS mitmproxy 12.2.3 binary reports bundled Python 3.14.4. |
| OpenSSL | Bundled with the mitmproxy artifact | TLS implementation | The inspected macOS mitmproxy 12.2.3 binary reports OpenSSL 3.5.5. |
| Magisk | 30.7 (optional) | One-time CA install on Google Play Android emulators, which refuse `adb root` (same approach as Proxyman 6.14) | Official upstream release APK and `scripts/host_patch.sh` at commit e8a5877, GPLv3, pinned by SHA-256 in `addons/android/magisk.pins` and verified at install and before each use. Never linked into Rivis; runs only on the emulator, on a temporary ramdisk copy, after explicit consent. Rivis adds a one-shot boot service that copies the CA and grants root to nothing else. |
| Node.js | Optional, version not pinned | Runs user-authored JavaScript interception scripts | No npm packages are installed or shipped. If Node is absent, Python scripts and all non-script proxy features continue to work. |

## Python and npm inventories

- Production Python packages installed by this repository: **none**. There is no `requirements.txt`, lock file,
  `pyproject.toml`, or `pip install` step. The official mitmproxy executable is distributed as one pinned binary
  artifact and contains its own transitive Python environment.
- Production npm packages installed by this repository: **none**. The panel is checked-in browser JavaScript and
  the optional Node host uses built-in Node modules only. There is no `package.json` or npm install step.
- Test-only dependency: `pytest`, supplied by the controlled test runner rather than installed by Rivis.

## Regeneration and review

On every runtime upgrade, update the mitmproxy pin and archive hashes, capture `mitmweb --version`, rerun
`bash tests/run.sh`, and replace this snapshot. Obtain the complete transitive component inventory from the exact
official mitmproxy archive used by the internal mirror; do not infer transitive versions from an unrelated pip
environment.
