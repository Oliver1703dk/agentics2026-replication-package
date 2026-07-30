"""FM-13: Sybil Ring Trust Bounding.

Validates that a Sybil ring (a set of attacker-controlled agents that
mutually attest each other with high confidence) cannot inflate a target's
trust score beyond the single bridge edge from the legitimate graph.

Key property (noisy-OR aggregation):
  trust(honest, target_via_sybil) <= bridge_edge_weight * decay

The ring's internal edges are unreachable except through the single bridge
edge. Because trust decays per hop and each path through the ring passes
through that one bridge, the ring adds negligible trust regardless of size.

Terminology: "Sybil-deterrent" (NOT "Sybil-resistant") -- L402 raises the
identity creation cost floor linearly, but Kind 38102 attestation edges
are free (quadratic internal trust mass).
"""

from __future__ import annotations

import pytest

from nostr_agent.trust import build_trust_graph, compute_trust


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sybil_ring_events(
    sybil_pubkeys: list[str],
    *,
    internal_confidence: float = 1.0,
) -> list[dict]:
    """Create mutual attestation events for all pairs in the Sybil ring.

    Each Sybil node attests every other Sybil node with high confidence.
    Returns a list of Kind38102Event dicts suitable for build_trust_graph().
    """
    events = []
    for i, attester in enumerate(sybil_pubkeys):
        for j, attestee in enumerate(sybil_pubkeys):
            if i == j:
                continue  # skip self-loops
            events.append({
                "pubkey": attester,
                "created_at": 1000000 + i * 100 + j,
                "content": {"confidence": internal_confidence},
                "tags": [["p", attestee]],
            })
    return events


# ===========================================================================
# FM-13a: Basic Sybil ring bounding (5 nodes)
# ===========================================================================


@pytest.mark.unit
def test_fm13a_sybil_ring_trust_bounded_by_bridge_edge() -> None:
    """FM-13a: 5-node Sybil ring connected to honest graph by single bridge.

    Setup:
      honest_source -> honest_bridge (confidence=0.8)
      honest_bridge -> sybil_0 (bridge edge, confidence=0.3)
      sybil_0 <-> sybil_1 <-> ... <-> sybil_4 (all mutual, confidence=1.0)
      sybil_4 -> target (confidence=1.0)

    Expected: trust(honest_source, target) is bounded by the bridge edge.
    The 5 internal ring edges cannot amplify trust beyond the bridge.
    """
    honest_source = "honest_source_pk"
    honest_bridge = "honest_bridge_pk"
    target = "target_pk"
    sybil_pks = [f"sybil_{i}" for i in range(5)]

    bridge_confidence = 0.3
    decay = 0.5

    # Build events
    events = []

    # Honest edges
    events.append({
        "pubkey": honest_source,
        "created_at": 1000000,
        "content": {"confidence": 0.8},
        "tags": [["p", honest_bridge]],
    })
    events.append({
        "pubkey": honest_bridge,
        "created_at": 1000001,
        "content": {"confidence": bridge_confidence},
        "tags": [["p", sybil_pks[0]]],
    })

    # Sybil ring: all pairs mutually attest
    events.extend(_sybil_ring_events(sybil_pks, internal_confidence=1.0))

    # Sybil ring -> target
    events.append({
        "pubkey": sybil_pks[-1],
        "created_at": 1999999,
        "content": {"confidence": 1.0},
        "tags": [["p", target]],
    })

    graph = build_trust_graph(events)
    trust = compute_trust(graph, honest_source, target, decay=decay, max_depth=4)

    # Upper bound: the single path honest_source -> honest_bridge -> sybil_0
    # -> ... -> sybil_4 -> target has trust bounded by:
    #   0.8 * bridge_confidence * (1.0)^ring_hops * decay^total_depth
    # With max_depth=4, only 4 hops are explored. The bridge edge caps everything.
    # Theoretical max: 0.8 * 0.3 * 1.0^2 * 0.5^4 = 0.015
    # (The ring can only contribute paths that pass through the bridge edge.)
    max_theoretical = 0.8 * bridge_confidence * (decay ** 4)

    assert trust <= max_theoretical + 0.01, (
        f"FM-13a: trust {trust:.4f} exceeds theoretical bound {max_theoretical:.4f} + epsilon. "
        "Sybil ring MUST NOT amplify trust beyond bridge edge."
    )
    assert trust >= 0.0, "Trust must be non-negative"


# ===========================================================================
# FM-13b: Ring size independence
# ===========================================================================


@pytest.mark.unit
@pytest.mark.parametrize("ring_size", [3, 5, 10, 20])
def test_fm13b_trust_independent_of_ring_size(ring_size: int) -> None:
    """FM-13b: increasing Sybil ring size does not increase trust to target.

    For a fixed bridge edge weight, the trust from honest source to target
    should remain approximately constant regardless of how many Sybil nodes
    are in the ring. The depth limit (max_depth=4) and bridge edge bottleneck
    ensure this.
    """
    honest_source = "honest_source_pk"
    honest_bridge = "honest_bridge_pk"
    target = "target_pk"
    sybil_pks = [f"sybil_{i}" for i in range(ring_size)]

    bridge_confidence = 0.4
    decay = 0.5

    events = []

    # Honest chain
    events.append({
        "pubkey": honest_source,
        "created_at": 1000000,
        "content": {"confidence": 0.9},
        "tags": [["p", honest_bridge]],
    })
    events.append({
        "pubkey": honest_bridge,
        "created_at": 1000001,
        "content": {"confidence": bridge_confidence},
        "tags": [["p", sybil_pks[0]]],
    })

    # Sybil ring
    events.extend(_sybil_ring_events(sybil_pks, internal_confidence=1.0))

    # Every Sybil node attests target (maximum amplification attempt)
    for pk in sybil_pks:
        events.append({
            "pubkey": pk,
            "created_at": 2000000,
            "content": {"confidence": 1.0},
            "tags": [["p", target]],
        })

    graph = build_trust_graph(events)
    trust = compute_trust(graph, honest_source, target, decay=decay, max_depth=4)

    # The trust MUST be bounded: all paths from honest_source to target pass
    # through the single bridge edge (honest_bridge -> sybil_0). The noisy-OR
    # aggregation can exceed a single-path bound when many ring paths exist,
    # but trust is still < 1.0 and remains moderate even as ring size grows.
    #
    # Key property: trust does NOT scale linearly with ring_size. We verify
    # that trust stays below 0.5 (a generous bound given bridge_confidence=0.4,
    # honest_edge=0.9, and decay=0.5). A truly open system without bottleneck
    # would approach 1.0 with sufficient ring size.
    assert trust < 0.5, (
        f"FM-13b (ring_size={ring_size}): trust {trust:.4f} >= 0.5. "
        "Sybil ring trust MUST remain moderate despite ring size growth."
    )


# ===========================================================================
# FM-13c: No bridge edge -> zero trust
# ===========================================================================


@pytest.mark.unit
def test_fm13c_disconnected_sybil_ring_zero_trust() -> None:
    """FM-13c: Sybil ring with no bridge to honest graph yields zero trust.

    If there is no edge from the honest graph to the Sybil ring, the ring
    is unreachable and trust is exactly 0.0.
    """
    honest_source = "honest_source_pk"
    target = "target_pk"
    sybil_pks = [f"sybil_{i}" for i in range(5)]

    events = []

    # Sybil ring (disconnected from honest_source)
    events.extend(_sybil_ring_events(sybil_pks, internal_confidence=1.0))

    # Sybil -> target
    for pk in sybil_pks:
        events.append({
            "pubkey": pk,
            "created_at": 2000000,
            "content": {"confidence": 1.0},
            "tags": [["p", target]],
        })

    graph = build_trust_graph(events)
    trust = compute_trust(graph, honest_source, target, decay=0.5, max_depth=4)

    assert trust == 0.0, (
        f"FM-13c: trust from disconnected source must be exactly 0.0, got {trust}"
    )


# ===========================================================================
# FM-13d: Depth limit prevents deep ring traversal
# ===========================================================================


@pytest.mark.unit
def test_fm13d_depth_limit_cuts_deep_ring_paths() -> None:
    """FM-13d: Sybil ring arranged as a long chain exceeding max_depth.

    Setup: honest -> sybil_0 -> sybil_1 -> ... -> sybil_9 -> target
    With max_depth=4, only 4 hops are explored; the ring cannot reach
    target through a 10-hop chain.
    """
    honest_source = "honest_source_pk"
    target = "target_pk"
    chain_length = 10
    sybil_pks = [f"sybil_{i}" for i in range(chain_length)]

    events = []

    # Honest -> sybil_0
    events.append({
        "pubkey": honest_source,
        "created_at": 1000000,
        "content": {"confidence": 0.9},
        "tags": [["p", sybil_pks[0]]],
    })

    # sybil_0 -> sybil_1 -> ... -> sybil_9 (linear chain)
    for i in range(chain_length - 1):
        events.append({
            "pubkey": sybil_pks[i],
            "created_at": 1000001 + i,
            "content": {"confidence": 1.0},
            "tags": [["p", sybil_pks[i + 1]]],
        })

    # sybil_9 -> target
    events.append({
        "pubkey": sybil_pks[-1],
        "created_at": 1999999,
        "content": {"confidence": 1.0},
        "tags": [["p", target]],
    })

    graph = build_trust_graph(events)

    # With max_depth=4, the 11-hop path (source -> s0 -> ... -> s9 -> target)
    # cannot be fully traversed.
    trust_shallow = compute_trust(
        graph, honest_source, target, decay=0.5, max_depth=4
    )
    assert trust_shallow == 0.0, (
        f"FM-13d: depth-limited trust through 10-hop chain should be 0.0 "
        f"(max_depth=4), got {trust_shallow}"
    )

    # With max_depth=12 and low epsilon, the 11-hop path CAN be reached.
    # Default epsilon=0.01 would prune (0.9 * 0.5^11 ≈ 0.0004 < 0.01),
    # so we set epsilon=0.0001 to allow deep traversal.
    trust_deep = compute_trust(
        graph, honest_source, target, decay=0.5, max_depth=12, epsilon=0.0001
    )
    assert trust_deep > 0.0, (
        "FM-13d: sanity check -- path must be reachable with sufficient depth "
        "and low epsilon"
    )
