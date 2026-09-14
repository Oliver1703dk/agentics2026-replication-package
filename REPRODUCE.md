# Reproducing the NostrAgent paper results

This file maps every quantitative claim in the paper to the exact command that
regenerates it, plus the output file that backs the claim. Benchmark numbers
in the paper (Table 4, B1 through B11) come from a single frozen evaluation
run; the SP-1 through SP-5 sensitivity files use the nomenclature finalized
in a later re-run. Both are shipped under `code/eval/results/`.

The discipline:

1. The first run of `code/eval/run_full_evaluation.py` is the **frozen run** (`20260404T150245Z/`). Do not delete it. Do not overwrite it. All B1 through B11 benchmark medians in the paper trace back to this run.
2. Any subsequent re-run produces a new timestamped sibling directory under `code/eval/results/`. Reported re-run medians must fall within the frozen run's IQR.
3. One re-run is shipped (`20260428T203508Z/`) to satisfy point 2 and to ship the SP-1 through SP-5 sensitivity files under the names the paper uses, plus the dedicated `SP4_prerotation_*.csv` sweep. See `code/eval/results/README.md` for the relationship between runs.
4. Every claim below is reproducible from a clean checkout, a clean Docker volume, and the three commands in the Setup section.

If a claim cannot be reproduced from the listed command and output file, that
is a bug in this artifact.

All commands in this file assume the working directory is `code/` unless
explicitly stated otherwise.

---

## Setup (run once before anything else)

```bash
cd code

# 1. Install Python dependencies (pinned via uv.lock; fixed seed = 42; warm-up = 100; runs = 1000)
uv sync --python 3.11 --extra dev

# 2. Bring up the regtest infrastructure (strfry relays + LND alice + LND bob + bitcoind)
docker compose -f infra/docker-compose.yml up -d
docker exec nostragent-bitcoind bitcoin-cli -regtest -rpcuser=nostr -rpcpassword=nostr createwallet "default" 2>/dev/null || true
bash infra/scripts/bootstrap.sh

# 3. Verify relays are reachable and LND nodes synced (9 checks)
uv run python infra/verify_relays.py
```

If `verify_relays.py` exits non-zero, the rest of the pipeline will fail. Fix
it before going further. Common failure modes and their fixes are in
`code/infra/README.md`.

A bundled one-shot script that runs the entire reproduction pipeline (install,
infra bring-up, test suite, benchmarks, demo, environment metadata) is
available:

```bash
cd code && bash reproduce.sh
```

---

## The single command that produces (almost) everything

```bash
cd code && uv run python -m eval.run_full_evaluation
```

This runs all benchmarks (B1..B11), all sensitivity sweeps (SP-1..SP-5), all
empirical failure-mode tests (17 modes; FM-3 and FM-15 are analytical and
covered in the paper body), the statistical comparisons, and writes everything
under a new `code/eval/results/<UTC_TIMESTAMP>/` directory. The directory
layout is described in `code/eval/README.md`.

Plot the LNCS-styled figures from the latest run:

```bash
cd code && uv run python -m eval.plot_figures
```

Regenerate the LaTeX tables used in the paper:

```bash
cd code && uv run python -m eval.generate_paper_artifacts
```

---

## Section-by-section claim map

Paper section numbers below refer to the published paper, not to any file in
this repository.

### Section 5.2 (RQ1) -- ATAM mini-Delphi expert panel

| Claim in paper | Reproduce with | Output |
| --- | --- | --- |
| Krippendorff alpha Round 2 = 0.94, averaged across importance and difficulty, ordinal metric (per-axis: importance 1.00, difficulty 0.88; 95% bootstrap CI [0.78, 1.00]) | `cd atam && uv run agreement.py` | `atam/agreement_results.json` (the `round2.alpha_*` fields; CI in `alpha_average_bootstrap_95ci`) |
| Round 1 alpha (averaged) = 0.79 | (same command writes both rounds) | `atam/agreement_results.json` (the `round1.alpha_average` field) |
| Fleiss kappa = 0.78 in Round 2, 0.46 in Round 1 (each (importance, difficulty) pair treated as one joint nominal category) | (same command) | `atam/agreement_results.json` (the `fleiss_kappa_joint` fields) |
| Twelve-leaf utility tree with final Round 2 priorities; three persistent difficulty dissents (O2, T1, T4) | inspection of `atam/utility_tree.md`; the dissents are visible directly in `atam/round2_ratings.csv` | `atam/utility_tree.md`, `atam/round1_ratings.csv`, `atam/round2_ratings.csv`, `atam/panel_notes.md` (movement and dissent rationale) |
| Five tradeoff points TP-1 through TP-5, with TP-2 and TP-5 most significant | inspection of `atam/tradeoff_points.md` | `atam/tradeoff_points.md` |
| Panel composition and protocol: three anonymous human experts (architecture, identity, security), two-round mini-Delphi | inspection of `atam/README.md`; the briefing packet the panel reviewed is `atam/briefing.md`; the instrument each expert filled in is `atam/rating_form.md` | `atam/README.md`, `atam/briefing.md`, `atam/rating_form.md` |

### Section 5.1 -- Benchmarks B1..B11

Cryptographic benchmarks use 1000 runs per metric (100 warmup discarded, seed
42); Docker-dependent benchmarks use 100 runs due to per-run latency on
the regtest stack (B7 through B9 discard 10 warmup, B4 reports all 100). Each benchmark below
has its raw per-run CSV under `code/eval/results/<FROZEN_RUN>/benchmarks/`.
Median, IQR, and P95 are computed from these CSVs by `code/eval/stats.py`.

| Claim | Output CSV |
| --- | --- |
| B1: Authentication handshake latency | `B1_kind_38100.csv` |
| B2: Schnorr verification cost on Kind 38100 / 38101 / 38102 | `B2_kind_38100.csv`, `B2_kind_38101.csv`, `B2_kind_38102.csv` |
| B3: Delegation chain depth effect (depths 1..4) | `B3_depth_1.csv`, `B3_depth_2.csv`, `B3_depth_3.csv`, `B3_depth_4.csv` |
| B4: Relay discovery latency across N relays (N = 1, 2, 3) | `B4_relays_1.csv`, `B4_relays_2.csv`, `B4_relays_3.csv` |
| B5: Attestation verification time (Kind 38102) | `B5_kind_38102.csv` |
| B6: Trust graph query latency at N = 5, 10, 20, 50, 100, 200, 500 | `B6_nodes_*.csv` |
| B7: Key rotation latency | `B7_key_rotation.csv` |
| B8: Old-key revocation propagation time | `B8_revocation_propagation.csv` |
| B9: L402 end-to-end flow latency on regtest | `B9_l402_full_flow.csv` |
| B10: Macaroon attenuation depth effect (1, 5, 10, 20 caveats) | `B10_caveats_1.csv`, `B10_caveats_5.csv`, `B10_caveats_10.csv`, `B10_caveats_20.csv` |
| B11: Payment verification time (5-check pipeline) | `B11_full_5check.csv` |

Statistical comparisons (Mann-Whitney U, Cliff's delta) across
within-NostrAgent configurations live in
`code/eval/results/<FROZEN_RUN>/stats/statistical_comparisons.json`.

Figures regenerated by `plot_figures.py`:

| Paper figure | Output PDF |
| --- | --- |
| Benchmark overview | `fig_bench_overview.pdf` |
| Delegation chain depth | `fig_b3_delegation_depth.pdf` |
| Trust graph scaling | `fig_b6_trust_scaling.pdf` |
| Macaroon attenuation depth | `fig_b10_macaroon.pdf` |
| Docker-dependent benchmarks | `fig_docker_benchmarks.pdf` |
| Sensitivity SP-2 decay sweep | `fig_sp2_decay.pdf` |
| Sensitivity SP-3 topology | `fig_sp3_topology.pdf` |
| Sensitivity SP-5 L402 5-check breakdown | `fig_sp5_l402_checks.pdf` |

### Section 5.2 -- Sensitivity analyses SP-1..SP-5

Sensitivity sweeps probe the robustness of the architectural defaults under
varied parameters. The SP-1 through SP-5 mapping below is the one used in
the paper. The frozen run (`20260404T150245Z/`) predates the rename and
ships these as B3, B4, and B6b sweeps under `benchmarks/`; the
`20260428T203508Z/` re-run ships dedicated `sensitivity/SP*_*.csv` files
under the paper's names. Both sources are listed.

| Sweep (paper) | Varied parameter | Output CSV(s) |
| --- | --- | --- |
| SP-1 | relay count N in {1, 3, 5} (resolves identities in 1.4 to 2.3 ms) | `20260404T150245Z/benchmarks/B4_relays_{1,2,3}.csv` (frozen-run sweep over N in {1, 2, 3}); `20260428T203508Z/sensitivity/SP1_relay_count_relays_{1,3,5}.csv` (paper-canonical sweep over N in {1, 3, 5}) |
| SP-2 | delegation chain depth (linear at ~15 microseconds per hop) | `20260404T150245Z/benchmarks/B3_depth_{1,2,3,4}.csv`; renamed in `20260428T203508Z/sensitivity/SP2_chain_depth_depth_{1,2,4}.csv` |
| SP-3 | trust-graph depth limit D_max in {2, 3, 4} (45x spread at n = 50) | `20260404T150245Z/benchmarks/B6b_Dmax_D{2,3,4}_n50.csv`; renamed in `20260428T203508Z/sensitivity/SP3_trust_depth_D{2,3,4}_n50.csv` |
| SP-4 | pre-rotation present versus absent (100% rejection of competing rotations) | `20260428T203508Z/sensitivity/SP4_prerotation_{absent,present}.csv` (covered only in the re-run; the frozen run validates the same property through FM-6) |
| SP-5 | trust decay factor d in {0.3, 0.5, 0.7} (plateau at d >= 0.5) | `20260404T150245Z/benchmarks/B6b_decay_d0{3,5,7}_n50.csv`; renamed in `20260428T203508Z/sensitivity/SP5_trust_decay_d0{3,5,7}_n50.csv` |

### Section 5.4 -- Failure modes FM-1..FM-19

Empirical results for 17 modes (FM-3 and FM-15 are analytical, covered in
paper Section 5.4 and the compressed catalog in the paper body):

```
code/eval/results/<FROZEN_RUN>/failure_modes/failure_mode_results.json
```

The JSON has one entry per FM with: definition, validation method, expected
outcome, observed outcome, pass / fail / analytical, and a pointer back to the
adversarial test or eval block that produced the outcome.

| Failure mode | Tag | Drives which paper claim |
| --- | --- | --- |
| FM-1 Relay Partition | Empirical | resilience to relay disconnection |
| FM-2 Relay Operator Malice | Empirical | event-drop detection via multi-relay |
| FM-3 Relay Data Loss | Analytical | multi-relay redundancy argument |
| FM-4 Lightning Node Unavailability | Empirical | L402 degradation behaviour |
| FM-5 Delegation Revocation Propagation Delay | Empirical | revocation timing bound |
| FM-6 Key Compromise | Empirical | pre-rotation under compromise |
| FM-7 Key Loss (no compromise) | Empirical | pre-rotation recovery path |
| FM-8 Trust Graph Poisoning | Empirical | bounded-sum decay impact under attack |
| FM-9 Delegation Chain Depth Explosion | Empirical | depth-limit enforcement |
| FM-10 Clock Skew / Temporal Validity | Empirical | validity disagreement under skew |
| FM-11 Event Kind Filtering by Relays | Empirical | acceptance of 38100..38102 on public relays |
| FM-12 Operator Key Rotation with Active Delegations | Empirical | re-issuance latency |
| FM-13 Sybil Attack on Trust Graph | Empirical | cost-to-influence ratio under L402 |
| FM-14 Cross-Relay Consistency Failure | Empirical | convergence time |
| FM-15 Conflicting Kind 38100 Events (KERI duplicity gap) | Analytical | comparison vs KERI witness model |
| FM-16 Relay Event Flood / Spam DoS | Empirical | spam-DoS tolerance |
| FM-17 Delegation Scope Bypass via Ambiguous Semantics | Empirical | scope-enforcement strictness |
| FM-18 Key Reuse / Shared Identity Across Operators | Empirical | identity-uniqueness enforcement |
| FM-19 BIP340 Implementation Bug / Side-Channel | Empirical | reliance on audited Rust crypto |

The single-FM driver for FM-13 (Sybil) is also runnable standalone:

```bash
cd code && uv run python -m eval.fm13_sybil_attack
```

### Section 5.6 -- Threats to validity

This subsection is qualitative and has no commands. The honesty claims it makes (regtest
vs mainnet boundary, prototype scale, measurement asymmetry against literature
baselines, panel-sourced utility-tree ratings versus author-assigned STRIDE
and comparison marks) are backed by
inspection of `code/infra/README.md`, `code/eval/README.md`, and `atam/README.md`.

### Section 4 -- Architecture diagrams

Hero figure, delegation sequence, L402 sequence, and deployment view are TikZ
sources embedded in the paper. They are not regenerated by this artifact.

### Table 2 -- Comparison matrix

The 10-system x 7-axis comparison matrix is a qualitative summary embedded in
the paper. It is not regenerated by this artifact. Its scoring rubric will
are included in the `v1.0` camera-ready release where applicable.

---

## Reproducing on a different machine

A re-run must:

1. Produce a new `code/eval/results/<UTC_TIMESTAMP>/` directory without touching the frozen run.
2. Yield benchmark medians that fall inside the frozen run's reported IQR (this is the "Reproducible" badge criterion, with tolerance defined in `code/eval/stats.py`).
3. Produce a `failure_mode_results.json` whose 17 empirical entries all match the frozen outcome (FM-3 and FM-15 are analytical, no JSON entry).
4. Yield Fleiss kappa and Krippendorff alpha bit-identical to `atam/agreement_results.json` (via `cd atam && uv run agreement.py`), because the panel CSVs do not change.

If the medians fall outside the IQR, the recommended diagnostic order is:
Docker version, Apple Silicon vs Linux x86, LND version, strfry version, then
Python interpreter version. The `environment.json` in each results directory
records all five.

---

## Changelog

| Date | Tag | Frozen run | Notes |
| --- | --- | --- | --- |
| 2026-04-04 (run) / 2026-05-13 (package) | `v1.0-submission` (pending tag) | `20260404T150245Z` | initial package; the frozen evaluation run lives at `code/eval/results/20260404T150245Z/` and supplies all B1 through B11 numbers in Table 4 |
| 2026-04-28 (re-run) | (same submission) | (unchanged) | reproducibility re-run shipped under `code/eval/results/20260428T203508Z/`; ships the SP-1 through SP-5 sensitivity files under the paper's nomenclature and the dedicated `SP4_prerotation_*.csv` |
| 2026-07-22 (revision) | (same submission) | (unchanged) | anonymized double-blind artifact; panel materials consolidated under `atam/` (rating instrument, raw ratings, combined alpha + kappa recomputation) |
| 2026-09-11 | `v1.0` | (unchanged) | camera-ready release: authors restored, `CITATION.cff` added |
| 2026-09-14 | `v1.0.1` | (unchanged) | Zenodo DOI minted: https://doi.org/10.5281/zenodo.22744263 |

The frozen run was produced by `code/eval/run_full_evaluation.py` on 2026-04-04
(UTC) and contains: B1..B11 benchmark CSVs under `benchmarks/`,
`failure_modes/failure_mode_results.json` covering 17 empirical FMs,
`stats/statistical_comparisons.json` with the Mann-Whitney U and Cliff's delta
results, eight LNCS-styled PDFs under `figures/`, three .tex tables under
`tables/`, and the environment fingerprint in `environment.json`. The
`20260428T203508Z/` re-run additionally ships SP-1 through SP-5 sensitivity
CSVs under the paper's nomenclature in `sensitivity/`. Throughout this
document, any reference to `<FROZEN_RUN>` substitutes `20260404T150245Z`.
