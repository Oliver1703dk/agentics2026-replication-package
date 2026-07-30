# Architecture briefing: what the panel reviewed

## 1. What NostrAgent is

NostrAgent is a decentralized identity, delegation, trust, and payment architecture for autonomous AI agents. It addresses the gap that existing approaches (OAuth 2.1, W3C DIDs, KERI, AIP, SAGA) leave open: no single substrate provides operator-sovereign identity, scoped delegation, peer attestation, discovery, and payment together. The intended audience is operators who deploy long-lived agents that cross organizational boundaries and need persistent, verifiable identity without a centralized registration authority.

## 2. Design principles (P1 to P5)

The architecture rests on five operator-sovereignty predicates.

- **P1 Existence Independence.** An agent keypair is created locally with no external service.
- **P2 Verification Independence.** Any party verifies identity and delegation using only the public key and signed events.
- **P3 Infrastructure Portability.** Identity, delegations, and attestations migrate to any compatible relay without re-registration.
- **P4 Operator Supremacy.** The operator can unilaterally revoke, rotate, or re-scope identity and delegations.
- **P5 Non-Forgery by Infrastructure.** No relay or Lightning node can forge identity without the private key.

P1, P2, P5 are unconditional given key custody. P3 is conditional on at least one cooperative (substitutable) relay.

## 3. Core components

**Agent identity (Kind 38100).** A NIP-01 parameterized replaceable Nostr event keyed by (kind, author pubkey, d-tag). The operator-chosen d-tag is a stable agent id; p-tag references the operator's pubkey; t-tags declare capabilities. JSON content carries name, version, MCP/A2A endpoints, trust policy. A `next_key_hash` tag stores SHA256 of the successor key. Lifecycle: active, rotated, decommissioned.

**Delegation chains (Kind 38101).** A delegation event encodes scope (capabilities, resources, actions), constraints (expiration, max depth, current depth), and an a-tag pointing to the parent delegation or root identity. Verification walks leaf to root, checking seven invariants at each hop: INV-1 child capabilities are a subset of parent, INV-2 child resources are a subset of parent (empty means unrestricted), INV-3 child actions are a subset of parent (empty means unrestricted), INV-4 current depth does not exceed max depth, INV-5 child expiration does not exceed parent expiration, INV-6 chain continuity (delegatee of hop n equals author of hop n+1), INV-7 cycle freedom via a visited set. Together these enforce monotonic attenuation. Cascade revocation falls out of parameterized replaceable semantics: replacing a hop with `revocation_status="revoked"` invalidates all downstream hops.

**Peer attestation and trust graph (Kind 38102).** Agent A signs that agent B has capability C with confidence w in [0,1]. Trust is computed locally via DFS from a querying agent's anchors; there is no global score. A single path of length |p| has trust `t_p = (prod w_i) * d^|p|` with decay d=0.5. Multi-path aggregation uses noisy-OR: `trust(A,B) = 1 - prod(1 - t_p)` over all paths within depth limit 4. Paths whose accumulated trust falls below epsilon = 0.01 are pruned. Attestations are positive only (no distrust propagation).

**Relay-based discovery.** NIP-01 multi-relay union queries fan out to N relays, deduplicate by event id, and resolve conflicts by highest `created_at`. Operators choose their own relay set. Discovery is a query over untrusted transport.

**Key rotation with pre-rotation.** At creation, `next_key_hash` commits the agent to a successor key. At rotation, the old key publishes a Kind 38100 with status `rotated`; the new key publishes Kind 38100 with status `active`, a `prev_key` tag, and a `rotation_proof` (BIP340 signature by the new key over `SHA256(old_pk || new_pk || timestamp)`). A grace period (default 3600 s) allows propagation. Measured rotation latency is 236 ms (B7).

**L402 unified identity-payment.** Three phases. Challenge: agent presents BIP340 pubkey, service responds with HTTP 402 carrying a macaroon and Lightning invoice. The 65-byte macaroon identifier is version (1 B) plus payment hash (32 B) plus agent pubkey (32 B), binding the credential to the agent's identity. Payment: agent pays via LND, obtains the preimage. Access: agent resubmits with macaroon, preimage, and a BIP340 signature over the canonical request body. The service runs five checks: preimage validity, identity match, signature verification, timestamp freshness, caveat satisfaction. The credential is non-transferable (unlike standard bearer macaroons). Measured end-to-end latency is 157 ms (B9), dominated by the Lightning round-trip.

## 4. Trust boundaries

| Boundary | Crosses |
|---|---|
| **TB1 Agent to Relay** | Signed events leave the agent host and enter untrusted relay infrastructure for storage and replication. |
| **TB2 Agent to Agent** | Signed delegations and attestations move between agents that do not share a trust root, evaluated locally. |
| **TB3 Agent to Service** | A request, macaroon, preimage, and BIP340 signature cross to a service that gates access on identity and payment. |

## 5. Business drivers

- **BD-1 Operator sovereignty.** Operators must create, rotate, revoke, and migrate agent identities with no dependency on a registration authority or IdP.
- **BD-2 Delegatable, auditable authorization.** Relying services need to verify scoped authority and reconstruct chains of provenance for audit.
- **BD-3 Programmable identity-payment integration.** Agent-to-service flows need unified identity verification and payment settlement, enabling economic Sybil deterrence and pay-per-use.

## 6. ATAM utility tree branches

- **Sovereignty** (traces to BD-1, decomposes P1 to P5). Scenarios S1 offline verification, S2 censorship-resistant relay migration, S3 key rotation enforcement, S4 air-gapped identity creation.
- **Operability** (traces to BD-2, BD-3). Scenarios O1 verification latency, O2 framework integration, O3 audit chain reconstruction, O4 schema extension.
- **Trust** (traces to BD-1, BD-3). Scenarios T1 attestation forgery rejection, T2 trust graph integrity across rotation, T3 Sybil ring bounding, T4 cold-start trust bootstrapping.

## 7. Deliberate non-goals and acknowledged limitations

- This is a research prototype validating architectural feasibility, not a production system.
- Relay-only substrate. No consensus layer, no witness network, no duplicity detection. Strictly weaker than KERI's KEL plus witnesses.
- Tag-based scope attenuation over set containment. Less expressive than AIP's Biscuit/Datalog policy engine; no logical rules, no negation, no variables.
- Sybil-deterrent via the L402 economic floor (linear cost), not formally Sybil-resistant. Attestation edges are free, so internal trust mass within a paid ring can grow quadratically.
- L402 is implemented and benchmarked on regtest Lightning, with a secondary testnet path. No mainnet validation.
- Comprehensive test suite (unit, Hypothesis property-based, STRIDE adversarial, and end-to-end integration tests) is shipped under `../code/tests/`. Deployment is Docker Compose: 3 strfry relays, 2 LND nodes, 1 bitcoind. Random seed 42, pinned dependencies.

## 8. What the experts were asked to do

Each expert participated as an external reviewer in a mini-Delphi ATAM panel: rate the twelve utility-tree leaves (S1 to S4, O1 to O4, T1 to T4) on importance and difficulty and review the tradeoff points, independently, blind to the other experts' ratings and with no candidate ratings provided, using the rating form provided (`rating_form.md`). The briefing told experts explicitly that disagreement was the signal being paid for: rate what the architecture earns, not what the authors want to hear.

## 9. Provenance

This briefing is the background document circulated to the panel in the
Round 1 packet (March 2026), shipped so a third party can audit exactly
what the experts were shown when producing the ratings in
`round1_ratings.csv` and `round2_ratings.csv`. The utility-tree leaves
it lists are formalised in `rating_form.md`, and the tradeoffs in
`tradeoff_points.md`. The packet also included the FM-1 through FM-19
failure-mode catalog; its canonical per-mode definitions ship with the
frozen results in
`../code/eval/results/20260404T150245Z/failure_modes/failure_mode_results.json`
and in the paper's failure-mode table. The paper's architecture section
has been editorially revised since the panel ran; the architecture
itself is unchanged.
