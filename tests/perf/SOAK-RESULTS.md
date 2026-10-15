# Long-run flow-retention soak

Recorded 2026-10-15 on macOS arm64 against commit `b40e8f9` using the hermetic test harness:

```text
/usr/bin/python3 tests/perf/test_soak.py
calls:                       50,000
workers:                     10
configured maximum:          5,000 flows
retained after completion:   4,636 flows
trimmed:                     45,364 flows
elapsed:                     47.1 s (test process 49.5 s)
RSS at 10,000 calls (warm):  156.5 MiB
RSS at 30,000 calls:         148.4 MiB
RSS at 50,000 calls:         144.5 MiB
RSS final assertion sample:  162.8 MiB
growth after warm-up:        6.2 MiB
```

Result: **PASS**. The store stayed at or below the 5,000-flow cap, retained at least its 4,500-flow
low-water mark, removed every excess completed flow, and remained well below the 120 MiB post-warm-up
RSS-growth guard. The varying RSS snapshots are expected allocator/GC behavior; the assertion uses the
final sample after querying the retained store and panel counters.
