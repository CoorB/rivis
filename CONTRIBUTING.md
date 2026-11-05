# Contributing to Rivis

For how the pieces fit together, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) first. This file is the day-to-day: checkout, tests, safety rules, style.

---

## Working checkout

You need the pinned mitmproxy **12.2.3** on your PATH (`mitmweb` / `mitmdump`). The installer and `install/mirror.conf` are authoritative; a Homebrew cask of that version is fine for development when its signature verifies.

From the repository root:

```bash
mkdir -p ~/bin
ln -sf "$PWD/rivis" ~/bin/rivis
rivis projects list
rivis start
```

On Windows, run `.\rivis.ps1` from the checkout (or link it the same way). The installed product zip has no `tests/` or `install/`; a source checkout does.

Do not point your everyday QA work at this checkout's default ports while someone else's live Rivis is on 8080/8083 — use `RIVIS_PORT` / `RIVIS_WEB_PORT`, or stop the live instance first.

---

## Running the tests

Authoritative flags: `bash tests/run.sh --help`.

```bash
bash tests/run.sh            # everything (~9+ min): CLI, PowerShell, rules, panel, TLS, installer, security, perf, browser UI
bash tests/run.sh --fast     # same without the browser UI and the perf budgets/soak
bash tests/run.sh --ui       # only tests/ui (needs Playwright + Chromium)
bash tests/run.sh --jobs N   # parallel modules (default 4); each gets its own fake HOME, CA, temp dir, random ports
bash tests/run.sh -k PATTERN # pytest -k selection
```

One module while you iterate (from the repo root):

```bash
/usr/bin/python3 -m pytest tests/test_<name>.py -x -q
/usr/bin/python3 -m pytest tests/test_<name>.py -k <pattern> -x -q
```

Needs `/usr/bin/python3` with `pytest`, `mitmweb` on PATH, `node` (JS scripts) and `curl`. Browser UI tests: `pip3 install --user playwright && python3 -m playwright install chromium`.

**Hermetic check at the end.** `tests/run.sh` snapshots the machine before the suite (`tests/hermetic.py`), runs the modules, then compares. It fails the run if any Rivis test process, port or temp dir was left behind, or if `$HOME`, the protected ports or the system proxy changed. Exit status is also non-zero on an "unexpected success" (a known bug in `tests/FOUND-BUGS.md` whose `expectedFailure` you fixed — remove the marker).

---

## The testing rule

Every behaviour change ships with a test that **fails without the fix and passes with it**. A fix with no such test is not done.

Prove both directions without throwing away your work:

1. Copy the changed file(s) aside (`cp path/to/file /tmp/file.with-fix`).
2. Put the pre-fix version back into the tree (from another copy, or from `git show HEAD:path > path` — never `git checkout --` on a file you still need, and never `git stash` in this repo's shared worktrees).
3. Run the new test; it must fail for the right reason.
4. Restore your fixed copy; the same test must pass.

Do not add skips or `expectedFailure` to hide a regression. Do not weaken an existing assertion to make a run green — if an old test fails, you found a second bug or broke something; report it.

Tests live under `tests/` and use `tests/harness.py` (`Suite`, `free_port()`, fake HOME, PATH shims). Copy the idiom of a neighbouring `test_*.py`; do not invent a new style.

---

## Safety rules (and why)

1. **Tests must never use ports 8080 / 8083 (or the other ports in `FORBIDDEN_PORTS` in `tests/harness.py`) or the real `~/.rivis`.** The harness assigns random ports and a fake `HOME`, and raises if you force a live port. Reason: a test's `rivis stop` once killed the maintainer's live proxy mid-session (comment in `harness.py`, 2026-10-16).

2. **Live / device tests clean up exactly what they started.** If you boot a proxy, stop that instance; if you mark an AVD, unmark it. Leftovers fail the hermetic check and can strand the next run.

3. **The suite is hermetic by design:** random ports, fake HOME, private CA copied into that HOME, shim directory first on PATH (so `adb` / `networksetup` / browsers are fakes). Subprocess environments are built from scratch — they never inherit your real `~/.rivis`, `~/.mitmproxy`, system proxy, VPN or devices.

4. **Do not run `rivis start` / `rivis stop` against the maintainer's live 8080/8083 or touch `~/.rivis` while debugging product code.** Use the harness, or an explicit alternate `RIVIS_PORT` / `RIVIS_WEB_PORT` and a temporary `HOME`.

---

## Environment constraints

| Constraint | What breaks if you ignore it |
|---|---|
| Bash CLI must run under **bash 3.2** (Apple `/bin/bash`) | Associative arrays, `${var,,}`, `mapfile`, `nameref`, `declare -g`, bash-4 `$'\n'` tricks: syntax errors on every Mac that has not installed a newer bash |
| Anything invoked as **`/usr/bin/python3`** is **Python 3.9** | `match`, `X \| Y` unions, `dict1 \| dict2` merge: `SyntaxError` the moment the CLI calls that file. Grep the filename in `rivis` before assuming mitmproxy's newer interpreter is the only one |
| **No new third-party dependencies** beyond mitmproxy and the stdlib | Installers and air-gapped QA machines have no pip world; a new import fails for every user who is not you |

Add-ons loaded by mitmweb run under mitmproxy's interpreter, but many of the same modules are also started by the CLI with `/usr/bin/python3 -I`. Check both call sites.

A user-visible change in `rivis` usually needs the same change in `rivis.ps1`. If you only change one, say so in the review.

---

## Code style

Match the file you are in. Comments explain **why**, not what the next line does, and stay short. Example from `rivis` (start-guard):

```bash
# A second start must not replace the first process's UI token while mitmweb is still binding its ports.
```

User-facing messages are plain sentences for a QA engineer under time pressure — not error codes or stack traces. Two real ones:

```text
no running emulator (adb devices). Physical devices need a separate approval.
```

```text
mitmweb not found (brew install --cask mitmproxy)
```

---

## Traps in this codebase

Things that have already cost someone a day. The test suite guards each one, but knowing why saves you
the detour.

**`grep -q` at the end of a pipeline.** Both shell entry points run under `set -o pipefail` (`rivis:93`,
`addons/android_magisk.sh:20`). `grep -q` exits the moment it matches. If the writer is still pushing
output it dies of SIGPIPE, and `pipefail` then reports the pipeline as **141** — so a match reads as
"no match". With a short producer the writer finishes first and everything works, which is what makes
this so slow to find: it only bites on a long `ps` listing or a `uiautomator` dump, and only sometimes.

It deleted a browser profile that someone was working in, deleted the UI token of a second running
instance, and told the Android setup an emulator had exited while it still held its port.

Use the `contains` helper, or capture the output and test the value:

```bash
contains "--user-data-dir=$d" "$running" && continue      # literal substring, no pipe, no subprocess
[ -n "$(printf '%s\n' "$x" | grep -E 'text="(User|USER)"')" ]   # a regex: drop -q so grep reads it all
```

`tests/test_cli.py::SigpipeProneChecks` fails if the shape comes back, and names the file and line.
The same reasoning applies to anything else that stops reading early — `head`, `grep -m`, `sed …q`,
`awk …exit` — whenever you test the pipeline's **exit status** rather than its output.

**A test that extracts one shell function.** A few tests pull a single function out of `rivis` or
`addons/android_magisk.sh` by text and run it in a bare shell (`gone`, `cmd_health`, `running_tool_dir`).
If you make one of those call a new helper, the extracted snippet no longer defines it and the test
fails for a reason that has nothing to do with your change. Keep those functions self-contained.

---

## Releases

Packaging and first-run checks live under `install/mirror/` and `release-tools/`. Signing keys, publishing to the mirror/GitHub and cutting a version are the maintainer's job — do not document or handle keys here, and do not bump `install/VERSION` (or any other release pin) unless you are that person. Contributors ship behaviour + tests; the maintainer ships the zip.
