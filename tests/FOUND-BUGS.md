# Product bugs found while building the suite

Nothing here was fixed (the brief says: do not touch the product). Each entry has a standalone repro and the
related test is marked `expectedFailure` (or asserts the correct behaviour and is listed as such), so the suite
flips to "unexpected success" — a failing run — the moment the bug is fixed, which is the cue to delete the marker.

