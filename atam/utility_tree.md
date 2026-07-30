# ATAM utility tree: final Round 2 priorities

The twelve utility-tree leaves (Sovereignty S1 through S4, Operability
O1 through O4, Trust T1 through T4) with the final Round 2 priority
ratings from the mini-Delphi expert panel. Ratings are (importance,
difficulty) on the ATAM H/M/L scale. Leaf definitions are in
`rating_form.md`; raw per-expert ratings are in `round1_ratings.csv`
and `round2_ratings.csv`.

## Branch 1: Sovereignty

| ID | Leaf | Round 2 priority |
| --- | --- | --- |
| **S1** | Offline verifiability | **H,H** unanimous |
| **S2** | Censorship-resistance and relay migration | H,M unanimous |
| **S3** | Key portability and rotation enforcement | **H,H** unanimous (Round 1 dissent converged in Round 2) |
| **S4** | Infrastructure independence | M,L unanimous |

## Branch 2: Operability

| ID | Leaf | Round 2 priority |
| --- | --- | --- |
| **O1** | Performance (verification latency) | H,M unanimous (Round 1 dissent converged in Round 2) |
| **O2** | Interoperability (framework integration) | M,M majority (one persistent difficulty dissent) |
| **O3** | Auditability (chain reconstruction) | H,M unanimous |
| **O4** | Modifiability (schema extension) | M,L unanimous |

## Branch 3: Trust

| ID | Leaf | Round 2 priority |
| --- | --- | --- |
| **T1** | Attestation validity (forgery rejection) | H,L majority (one persistent difficulty dissent) |
| **T2** | Trust graph integrity after rotation | **H,H** unanimous |
| **T3** | Sybil deterrence (ring bounding) | **H,H** unanimous (Round 1 dissent converged in Round 2) |
| **T4** | Trust bootstrapping (cold start) | M,M majority (one persistent difficulty dissent) |

## Priority distribution (Round 2)

| Priority | Leaves |
| --- | --- |
| H,H | S1, S3, T2, T3 |
| H,M | S2, O1, O3 |
| H,L | T1 |
| M,M | O2, T4 |
| M,L | S4, O4 |

Importance was unanimous on all twelve leaves in Round 2 (alpha = 1.00
on the importance axis). The three persistent dissents (O2, T1, T4)
are all on the difficulty axis and are visible directly in
`round2_ratings.csv`. The four H,H leaves are the differentiators
anchoring the empirical sensitivity analysis in Section 5.2 of the
paper.
