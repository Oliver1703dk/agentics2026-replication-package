# Panel notes: movements and dissents

Condensed from the panel's per-leaf rationale (the full per-expert
reviews are retained by the authors; anonymised rationale was
circulated to all three experts between rounds). The raw ratings are in
`round1_ratings.csv` and `round2_ratings.csv`; this file records why
cells moved between rounds and why three did not converge.

## Round 1 to Round 2 movements

- **S3 difficulty, Expert B, M to H.** Moved after Expert C's FM-6
  race-condition walkthrough: the cryptographic pre-rotation argument
  stands, but keeping the pre-committed key in a separate security
  domain, plus the 3600 s grace-period race under stale relay views,
  makes the response measure operationally hard.
- **S4 difficulty, Expert B, M to L.** The Round 1 rating had folded
  operator-experience concerns into the axis; Expert A pointed out
  that S4 is structurally about whether identity creation requires
  external service calls (it does not), which is low difficulty.
- **O1 importance, Expert C, M to H.** The benchmark data (B2 at
  0.015 ms, B3 at 0.062 ms for depth 4, B6 at 3 ms for n = 100) plus
  Expert A's reframing: slow verification at scale is a DoS
  amplification vector, so performance is a security property under
  adversarial load rather than a benign latency budget.
- **T3 difficulty, Expert A, M to H.** Expert C argued that
  graph-topology adversaries (colluding attestations through paid
  bridges) are harder to bound than the single-bottleneck closed form
  captures; the Round 1 rating had reflected the closed form's
  elegance rather than deployment-realistic adversarial difficulty.
- **T4 difficulty, Expert B, L to M; T4 importance, Expert C, L to M.**
  Expert A clarified that ATAM difficulty is response-measure
  achievability, and the first attestation depends on interaction
  patterns the protocol cannot enforce; cold start is also
  stakeholder-visible, which raised its importance.

## Persistent dissents (all Expert C, all on the difficulty axis)

- **O2 at M,L against majority M,M.** Integration is a library-level
  engineering task; comparable auth-layer integrations complete in
  under a week in C's industry experience, and the harder concerns
  live in the target framework's own auth surface, outside the ATAM
  scope of NostrAgent itself. A boundary disagreement, not a factual
  one.
- **T1 at H,M against majority H,L.** The cryptographic guarantee is
  necessary but not sufficient in deployment: side-channel leaks,
  library bugs, and nonce reuse have produced real-world forgeries
  under sound schemes. The majority reading is that ATAM difficulty
  asks how hard the architecture's response measure is to achieve,
  not how hard the underlying library is to operate in production.
- **T4 at M,L against majority M,M.** "Documented and bounded" is a
  weaker bar than C would accept for a production identity system
  (an out-of-band verification ceremony, a PKI anchor, or a larger
  financial stake). A dissent about where the bar sits, not about
  whether the architecture meets its stated measure.

## Tradeoff points

A TP-6 candidate (single-level versus multi-level pre-rotation) was
floated and withdrawn: the panel concluded that TP-3's design
rationale already records the simultaneous-compromise concern. All
five tradeoff points were endorsed `agree` by all three experts in
both rounds.

Convergence reflects discussion of specific evidence, not recoding;
the three dissents were documented and stand.
