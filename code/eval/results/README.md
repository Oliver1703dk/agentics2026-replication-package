# `eval/results/`

Output directory for the evaluation harness. Each run of
`run_full_evaluation.py` writes a new subdirectory here named with the UTC
timestamp at which the run started.

## Frozen run

`20260404T150245Z/` is the **frozen run** that the paper's Section 5
benchmark numbers (Table 4, B1 through B11 medians, IQR, P95) come from. It
is the canonical evaluation snapshot for the paper submission. The
run's metadata is in `20260404T150245Z/run_summary.json` and
`20260404T150245Z/environment.json`, and the timestamp is also recorded in
the top-level `REPRODUCE.md` Changelog.

Discipline:

- The frozen run is never overwritten or deleted.
- Subsequent re-runs land in sibling directories under this one.
- A re-run is "Reproducible" iff each benchmark's median falls inside the frozen run's IQR (criterion encoded in `../stats.py`) and all 17 empirical failure-mode outcomes match.

## Re-run shipped alongside the frozen run

`20260428T203508Z/` is a re-run that introduces two methodological refinements
the paper's Section 5.2 (Sensitivity) relies on:

1. The sensitivity files under `sensitivity/` are renamed to match the SP-1 through SP-5 nomenclature used in the paper (`SP1_relay_count_*`, `SP2_chain_depth_*`, `SP3_trust_depth_*`, `SP4_prerotation_*`, `SP5_trust_decay_*`). The frozen run predates this rename.
2. `SP4_prerotation_{absent,present}.csv` is shipped only in this run; it backs the SP-4 claim (Section 5.2, "Pre-rotation rejects 100\% of competing rotation attempts"). The frozen run covers the same property through the FM-6 (Key Compromise) failure-modes harness instead.
3. `environment.json` records `nostr_sdk_version: 0.44.2` (resolved at run time); the frozen run records it as `unknown`.

The re-run was produced on the same physical machine as the frozen run.
Absolute medians shift between the two runs because of OS scheduling and Docker
state; the structural ratios in the paper (B6b D_max 45x spread, B3 depth-1
versus depth-4 ratio, decay plateau at d >= 0.5) are stable across both runs
and are the basis for the paper's sensitivity narrative.

Per-run subdirectory layout (matching what is shipped under `20260404T150245Z/`):

```
<UTC_TIMESTAMP>/
|- run_summary.json
|- environment.json
|- benchmarks/           # B1..B11 (and B6b) per-run CSVs
|- sensitivity/          # SP-1..SP-5 per-run CSVs
|- failure_modes/
|   |- failure_mode_results.json   # 17 empirical entries
|- stats/
|   |- statistical_comparisons.json
|- figures/              # LNCS PDFs (the figures the paper imports)
|- tables/               # .tex tables (the tables the paper imports)
```

See `../README.md` for the full output catalog and the mapping from paper
claim to file.
