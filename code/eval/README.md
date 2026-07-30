# `code/eval/` -- evaluation harness and frozen results

Everything quantitative in Section 5 of the paper traces to a file in this
directory. The harness runs benchmarks B1..B11, sensitivity sweeps SP-1..SP-5,
and the 17 empirical failure-mode tests (FM-1, FM-2, FM-4..FM-14, FM-16..FM-19;
FM-3 and FM-15 are analytical, covered in the paper body). It then runs the
within-NostrAgent statistical comparisons, generates the LNCS-styled figures,
and writes the LaTeX tables used in the paper.

## Layout

```
eval/
|- README.md                  # this file
|- __init__.py
|- __main__.py                # enables `python -m eval ...` style invocation
|- bench.py                   # B1..B11 benchmark drivers
|- benchmark_config.py        # seed = 42; warm-up = 100; runs = 1000
|- env_metadata.py            # captures OS, Python, Docker, LND, strfry, hardware
|- stats.py                   # Mann-Whitney U, Cliff's delta, median, IQR, P95
|- plot_figures.py            # LNCS-styled figure generation (matplotlib)
|- generate_paper_artifacts.py # regenerates the .tex tables and figure PDFs the paper imports
|- synthetic_graphs.py        # synthetic trust-graph generators for B6 / SP-1..SP-3
|- SYNTHETIC_GRAPHS_README.md # design notes on the synthetic graph models
|- fm13_sybil_attack.py       # FM-13 standalone driver
|- run_full_evaluation.py     # orchestrator: the one command that produces everything
|
|- results/
|   |- README.md              # placeholder; populated at first run
|   |- <FROZEN_RUN>/          # exactly one directory at submission; the snapshot the paper's numbers come from
|       |- run_summary.json   # rolled-up medians, IQR, P95; FM pass / fail; provenance
|       |- environment.json   # OS, Python, Docker, LND, strfry, hardware fingerprint
|       |- benchmarks/        # B1..B11 (and B6b) per-run CSVs
|       |- sensitivity/       # SP-1..SP-5 per-run CSVs
|       |- failure_modes/
|       |   |- failure_mode_results.json  # 17 empirical entries
|       |- stats/
|       |   |- statistical_comparisons.json
|       |- figures/           # LNCS PDFs (the figures the paper imports)
|       |- tables/            # .tex tables (the tables the paper imports)
```

All commands below assume the current working directory is `code/` (one level
up from here).

## Run a fresh evaluation

```bash
uv run python -m eval.run_full_evaluation
```

`run_full_evaluation.py` writes a new `eval/results/<UTC_TIMESTAMP>/` directory
each time it runs. It refuses to overwrite an existing timestamped directory.

To run just the B1..B11 benchmarks without the sensitivity / failure-mode
phases:

```bash
uv run python -m eval.bench --all
uv run python -m eval.bench --metrics B1,B2,B6
uv run python -m eval.bench --metrics B6 --runs 500 --warmup 50
```

To regenerate only the figures or only the LaTeX tables from the latest run:

```bash
uv run python -m eval.plot_figures
uv run python -m eval.generate_paper_artifacts
```

To run the FM-13 Sybil attack standalone:

```bash
uv run python -m eval.fm13_sybil_attack
```

## The frozen run

The submitted paper's numbers were produced from exactly one run, recorded in
`results/<FROZEN_RUN>/`. The run's timestamp is in `run_summary.json` and in
the Changelog of the top-level `REPRODUCE.md` (`../../REPRODUCE.md`).

Discipline:

- The frozen run never gets deleted or overwritten.
- Subsequent re-runs land in sibling directories under `results/`.
- A re-run is "Reproducible" iff each benchmark's median falls inside the frozen run's IQR (criterion encoded in `stats.py`) and all 17 empirical failure-mode outcomes match.

## Output catalog

### Benchmarks

| File pattern | Backs |
| --- | --- |
| `benchmarks/B1_kind_38100.csv` | B1 handshake latency |
| `benchmarks/B2_kind_3810{0,1,2}.csv` | B2 Schnorr verification across kinds |
| `benchmarks/B3_depth_{1,2,3,4}.csv` | B3 delegation depth effect |
| `benchmarks/B4_relays_{1,2,3}.csv` | B4 multi-relay discovery |
| `benchmarks/B5_kind_38102.csv` | B5 attestation verification |
| `benchmarks/B6_nodes_*.csv` | B6 trust-graph query latency at N = 5..500 |
| `benchmarks/B7_key_rotation.csv` | B7 key rotation latency |
| `benchmarks/B8_revocation_propagation.csv` | B8 revocation propagation |
| `benchmarks/B9_l402_full_flow.csv` | B9 L402 end-to-end on regtest |
| `benchmarks/B10_caveats_{1,5,10,20}.csv` | B10 macaroon attenuation depth |
| `benchmarks/B11_full_5check.csv` | B11 payment verification 5-check |
| `benchmarks/B6b_*.csv` | B6 variant runs feeding SP-3 (D_max sweep) and SP-5 (decay sweep) |

### Sensitivity sweeps

Paper Section 5.2 reports five sensitivity points, SP-1 through SP-5,
with their headline results. The claim-to-file mapping is in the
top-level `REPRODUCE.md` (the "Sensitivity analyses" section), and the
utility-tree priorities they back are in `../../atam/utility_tree.md`.
The CSVs live in the per-run
`sensitivity/` directory and are named under the paper's
nomenclature in the `20260428T203508Z/` re-run:

| File pattern (re-run) | Backs |
| --- | --- |
| `sensitivity/SP1_relay_count_relays_{1,3,5}.csv` | SP-1 relay count (paper headline: 1.4 to 2.3 ms) |
| `sensitivity/SP2_chain_depth_depth_{1,2,4}.csv` | SP-2 chain depth (linear, ~15 microseconds per hop) |
| `sensitivity/SP3_trust_depth_D{2,3,4}_n50.csv` | SP-3 D_max sweep (45x spread at n = 50) |
| `sensitivity/SP4_prerotation_{absent,present}.csv` | SP-4 pre-rotation (100% rejection of competing rotations) |
| `sensitivity/SP5_trust_decay_d0{3,5,7}_n50.csv` | SP-5 decay factor (plateau at d >= 0.5) |

The frozen run (`20260404T150245Z/`) predates the rename. Its SP-1
through SP-5 measurements live under `benchmarks/` as `B4_relays_*`
(SP-1), `B3_depth_*` (SP-2), and `B6b_*` (SP-3, SP-5); SP-4 is
covered there by the FM-6 entry in `failure_modes/failure_mode_results.json`.
The full claim-to-file map is the "Section 5.2 -- Sensitivity analyses" table in `../../REPRODUCE.md`.

The frozen run's `sensitivity/` directory also contains five
harness-internal sweeps (chain depth scan to depth 8, decay scan
over five values, topology scan over five graph models, macaroon
depth scan to caveat-depth 20, L402 5-check breakdown) that share
the SP1..SP5 filename prefix but do not correspond to the paper's
SP-1..SP-5. They were exploratory sweeps retained for completeness.

### Failure modes

`failure_modes/failure_mode_results.json` -- one entry per empirical FM with
definition, validation method, expected outcome, observed outcome, pass / fail
flag, and the test or eval block that produced it.

### Statistics

`stats/statistical_comparisons.json` -- Mann-Whitney U and Cliff's delta for
each within-NostrAgent comparison (B3 across depths, B6 across topologies,
SP-2 across decays, SP-3 across depth limits, etc.).

### Figures and tables

`figures/*.pdf` -- the eight LNCS-styled PDFs that appear as figures in the paper.
`tables/*.tex` -- the .tex tables that appear in the paper.

## Determinism and provenance

- Seed: `random.seed(42)` for benchmark per-run randomness, set in `benchmark_config.py`.
- Warm-up: first 100 runs discarded, leaving 900 effective runs per metric.
- Run count: 1000 per metric.
- Environment fingerprint: `environment.json` records OS, kernel, CPU model, Python interpreter, Docker version, LND version, strfry version, and the git revision the harness was run against.
- Hardware sensitivity is real for B9 / B11 (Lightning RPC round-trips). Linux x86 numbers will differ from Apple Silicon numbers; the paper reports the latter and the artifact's "Reproducible" criterion uses the IQR rather than the exact median.

## Pointers

- Code overview: `../README.md`
- Reproduction guide (claim -> command map): `../../REPRODUCE.md`
- Python implementation: `../src/nostr_agent/`
- Infrastructure required for B4, B7, B8, B9, B11 and the Docker-dependent failure modes: `../infra/`
