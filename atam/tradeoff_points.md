# Tradeoff points

Five tradeoff points where improving one quality attribute demonstrably
harms another. Each is a conscious design choice with explicit
rationale.

## Provenance

The tradeoff points are an author-drafted part of the ATAM analysis,
constructed during the initial architecture analysis before the panel
convened. They are not rated on the H/M/L scale; that scale applies
only to the twelve utility-tree leaves (see `rating_form.md`). The
panel reviewed each tradeoff point in both rounds; all five were
endorsed `agree` by all three experts in both rounds, and none was
added, removed, or restructured. The paper's identification of TP-2
and TP-5 as the most significant concessions is the authors'
analytical conclusion, informed by panel feedback; the panel did not
rank the tradeoffs against one another.

Each entry records the decision, the quality attribute gained, the
quality attribute harmed, the evidence backing the assessment, and the
ATAM risk band.

## TP-1: Relay federation, censorship-resistance vs. consistency

- **Decision:** events publish to multiple independent relays with no consensus protocol between them.
- **QA gained:** censorship-resistance (S2). Availability under relay partition (S1).
- **QA harmed:** cross-relay consistency (FM-14). Verifiers may see different event subsets at any point in time.
- **Backed by:** B4 (relay discovery latency across N relays). FM-14 (cross-relay consistency convergence). FM-15 bounds the duplicity gap (analytical).
- **ATAM risk:** medium. The consistency gap is bounded by event infrequency plus the multi-relay union-query mitigation.

## TP-2: Public attestation events, auditability vs. privacy [most significant]

- **Decision:** Kind 38102 peer attestations are public. Any querying party sees the full trust graph.
- **QA gained:** auditability (O3). Independent reconstruction of the trust graph from relay-published events alone.
- **QA harmed:** privacy (STRIDE Information Disclosure on TB2, residual 4 of 5). The attestation graph leaks organisational relationships, trust hierarchies, and capability profiles.
- **Backed by:** qualitative analysis in the STRIDE matrix. There is no benchmark for this tradeoff because privacy here is a QA, not a measurable latency or throughput.
- **ATAM risk:** high for privacy-sensitive deployments. Medium for the stated agent-infrastructure use case where the operator already treats agent identity as public.

## TP-3: Pre-rotation, security vs. propagation delay

- **Decision:** SHA256(next_pubkey) is committed in Kind 38100. Rotation reveals the pre-committed key.
- **QA gained:** security (S3). Post-compromise recovery is sound because an attacker cannot produce a valid rotation event without knowing `sk_next`.
- **QA harmed:** rotation latency (multi-step atomic procedure plus re-issuing active delegations), and a bounded grace period (default 3600 s) during which old-key delegations remain valid.
- **Backed by:** B7 (key rotation latency). B8 (old-key revocation propagation). FM-6 (key compromise recovery). FM-12 (rotation during active delegations).
- **ATAM risk:** medium. The grace period is a known, bounded vulnerability window that operators tune to their risk tolerance.

## TP-4: L402 unified flow, sovereignty vs. Lightning dependency

- **Decision:** L402 integrates Lightning payment into the identity-authorisation flow. Agents authenticate by paying a Lightning invoice.
- **QA gained:** sovereignty (no payment-intermediary lock-in, Lightning is peer-to-peer). Sybil cost floor of O(Nc). Unified identity-payment flow (RQ2).
- **QA harmed:** availability (FM-4). When the agent's Lightning node is unavailable, the L402 path fails. Identity creation remains offline, so the dependency is conditional, scoped to L402-gated TB3 interactions, not universal.
- **Backed by:** B9 (L402 end-to-end flow on regtest). FM-4 (Lightning unavailability). FM-13 (Sybil cost analysis under L402).
- **ATAM risk:** medium. The dependency is scoped to L402-gated services. Non-L402 interactions are unaffected.

## TP-5: Tag-based scoping, simplicity vs. policy expressiveness [most significant]

- **Decision:** delegation scope in Kind 38101 is exact set containment over capability, resource, and action arrays. No logical rules, no negation, no variables.
- **QA gained:** simplicity (scope verification reduces to set intersection at O(n)). Verification independence (no Datalog engine, no policy compiler, no external evaluator). Auditability O3 (scope is human-readable in event tags).
- **QA harmed:** policy expressiveness. Cannot express conditional rules ("allow read if time < 17:00"), negation ("allow all except /admin"), or parameterised policies ("allow amounts under 100 sats"). AIP's Biscuit / Datalog engine is strictly more expressive than set containment.
- **Backed by:** qualitative analysis in the comparison rubric. There is no benchmark for expressiveness because expressiveness is itself a qualitative QA.
- **ATAM risk:** medium for simple agent-to-agent capability sharing. High for enterprise deployments with complex RBAC / ABAC requirements that set containment cannot express.

---

**Significance summary.** TP-2 (the public-attestation-graph privacy
tradeoff) and TP-5 (the deliberately limited policy language) are the
two concessions the paper revisits in the concessions discussion
(Section 5.5). TP-1, TP-3, and TP-4 are bounded by their respective
mitigations (multi-relay union query, grace-period discipline, opt-in
L402 use) and are treated as standard architectural choices rather
than concessions.
