# Rating form: the instrument each expert filled in

Each expert completed this form twice: once in Round 1 (asynchronous
and blind, with no discussion, no visibility into the other experts'
ratings, and no candidate ratings provided) and once in Round 2
(re-rating after the facilitated convergence discussion).

## Task 1: rate the twelve utility-tree leaves

For each leaf, assign:

- **Importance** (H, M, or L): how much the quality captured by the
  leaf matters for an operator-sovereign agent identity architecture.
- **Difficulty** (H, M, or L): how hard it is for the architecture to
  achieve the leaf's response measure. This is a property of the
  architecture, not of operating any particular library in production.
- A short free-text rationale per leaf.

### Branch 1: Sovereignty

| ID | Leaf |
| --- | --- |
| **S1** | Offline verifiability: a relying service verifies a Kind 38100 identity and a Kind 38101 delegation chain without contacting any relay or external service. |
| **S2** | Censorship-resistance and relay migration: an operator migrates an agent's full identity, delegation chain, and attestations to a new set of relays without losing identity continuity or trust position. |
| **S3** | Key portability and rotation enforcement: an agent's key is rotated via the pre-rotation protocol (SHA256 commitment of the next pubkey in Kind 38100) and verifiers reject the old key within a bounded window. |
| **S4** | Infrastructure independence: an operator creates a new agent identity on an air-gapped machine with no network connectivity, and the identity is fully formed and verifiable before any relay interaction. |

### Branch 2: Operability

| ID | Leaf |
| --- | --- |
| **O1** | Performance: local verification of a Kind 38101 delegation chain of depth 2 (BIP340 signature checks plus scope attenuation). |
| **O2** | Interoperability: a new agentic framework (e.g., CrewAI, AutoGen) integrates NostrAgent for identity and delegation without changing the protocol or event schema. |
| **O3** | Auditability: a compliance auditor reconstructs the complete delegation chain from an agent's current authority back to the operator's root identity, using only relay-published events. |
| **O4** | Modifiability: a future version adds a new tag to Kind 38100 without breaking existing verifiers or relay queries. |

### Branch 3: Trust

| ID | Leaf |
| --- | --- |
| **T1** | Attestation validity: an adversary constructs a Kind 38102 attestation with a forged pubkey; the verifier rejects it. |
| **T2** | Trust graph integrity after rotation: existing Kind 38102 attestations signed by an old key remain valid if the `prev_key` chain is traceable within the depth limit. |
| **T3** | Sybil deterrence: an adversary creates N Sybil identities (each requiring one L402 payment) that mutually attest; the ring's trust influence on an external evaluating agent is bounded. NostrAgent claims Sybil-deterrent, not Sybil-resistant. |
| **T4** | Trust bootstrapping: a newly created agent has zero peer attestations; the time and mechanism to reach a minimum viable trust floor is documented and bounded. |

## Task 2: review the tradeoff points

For each of TP-1 through TP-5 (definitions in `tradeoff_points.md`),
record an agreement verdict (`agree`, `partially agree`, or `disagree`)
with free-text feedback. Experts could also propose adding, removing,
or restructuring tradeoff points.

## Where the responses are

The ratings from Task 1 are in `round1_ratings.csv` and
`round2_ratings.csv` (3 experts x 12 leaves, each cell an
"importance,difficulty" pair such as "H,M"). For Task 2, all five
tradeoff points were endorsed `agree` by all three experts in both
rounds; none was added, removed, or restructured.
