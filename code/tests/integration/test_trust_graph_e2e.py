"""Integration tests: Kind 38102 Trust Graph end-to-end against live relays.

Tests mutual attestation, trust graph construction from relay-fetched data,
trust computation via noisy-OR, attestation retraction, and multi-attester
aggregation.

Each test uses unique d-tags (derived from test name) to avoid cross-test
pollution. Agents are created fresh per test to isolate trust graph edges.

Run: pytest tests/integration/test_trust_graph_e2e.py -m integration -v
Requires: docker compose up -d (3 relays)
"""

from __future__ import annotations

import asyncio
import json
import math

import nostr_sdk as ns
import pytest

from nostr_agent.identity import AgentIdentity
from nostr_agent.trust import TrustManager, build_trust_graph, compute_trust

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("docker_env")]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_and_publish(
    operator_keys: ns.Keys,
    d_tag: str,
    name: str,
    capabilities: list[str],
    relay_urls: list[str],
) -> AgentIdentity:
    """Shorthand: create + publish an identity."""
    identity = await AgentIdentity.create(
        operator_keys=operator_keys,
        agent_name=name,
        d_tag=d_tag,
        description=f"Trust graph test: {name}",
        capabilities=capabilities,
        relay_urls=relay_urls,
    )
    result = await identity.publish(relay_urls)
    assert result.success_count >= 1, f"Failed to publish {name}: {result.failed}"
    return identity


# ---------------------------------------------------------------------------
# Test: Mutual attestation
# ---------------------------------------------------------------------------


class TestMutualAttestation:
    """Two agents attest each other and the attestations are queryable."""

    async def test_mutual_attestation(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """A attests B and B attests A; both queryable from relays."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        capability = "weather-forecast"

        # Create agents A and B.
        a_d_tag = unique_d_tag("mutual-a")
        identity_a = await _create_and_publish(
            operator_keys, a_d_tag, "mutual-agent-a",
            [capability], relay_urls,
        )

        b_d_tag = unique_d_tag("mutual-b")
        identity_b = await _create_and_publish(
            operator_keys, b_d_tag, "mutual-agent-b",
            [capability], relay_urls,
        )

        # A attests B.
        tm_a = TrustManager(identity_a)
        result_ab = await tm_a.attest(
            attestee_pubkey=identity_b.pubkey_hex,
            attestee_d_tag=b_d_tag,
            capability=capability,
            confidence=0.85,
            relay_urls=relay_urls,
        )
        assert result_ab.success_count >= 1, f"A->B attestation failed: {result_ab.failed}"

        # B attests A.
        tm_b = TrustManager(identity_b)
        result_ba = await tm_b.attest(
            attestee_pubkey=identity_a.pubkey_hex,
            attestee_d_tag=a_d_tag,
            capability=capability,
            confidence=0.80,
            relay_urls=relay_urls,
        )
        assert result_ba.success_count >= 1, f"B->A attestation failed: {result_ba.failed}"

        await asyncio.sleep(0.5)

        # Query attestations about A (should find B's attestation).
        attestations_about_a = await TrustManager.get_attestations(
            identity_a.pubkey_hex, relay_urls, capability=capability,
        )
        found_b_to_a = any(
            ev.author().to_hex() == identity_b.pubkey_hex
            for ev in attestations_about_a
        )
        assert found_b_to_a, "B's attestation of A not found on relays"

        # Query attestations about B (should find A's attestation).
        attestations_about_b = await TrustManager.get_attestations(
            identity_b.pubkey_hex, relay_urls, capability=capability,
        )
        found_a_to_b = any(
            ev.author().to_hex() == identity_a.pubkey_hex
            for ev in attestations_about_b
        )
        assert found_a_to_b, "A's attestation of B not found on relays"


# ---------------------------------------------------------------------------
# Test: Trust graph construction from relays
# ---------------------------------------------------------------------------


class TestTrustGraphConstruction:
    """Build a trust graph from relay-fetched attestation events."""

    async def test_build_trust_graph(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """Publish attestations, build graph, verify nodes and edges."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        capability = "data-analysis"

        a_d_tag = unique_d_tag("graph-a")
        identity_a = await _create_and_publish(
            operator_keys, a_d_tag, "graph-agent-a",
            [capability], relay_urls,
        )

        b_d_tag = unique_d_tag("graph-b")
        identity_b = await _create_and_publish(
            operator_keys, b_d_tag, "graph-agent-b",
            [capability], relay_urls,
        )

        c_d_tag = unique_d_tag("graph-c")
        identity_c = await _create_and_publish(
            operator_keys, c_d_tag, "graph-agent-c",
            [capability], relay_urls,
        )

        # A -> B (0.9), A -> C (0.7), B -> C (0.8)
        tm_a = TrustManager(identity_a)
        await tm_a.attest(
            identity_b.pubkey_hex, b_d_tag, capability, 0.9,
            relay_urls=relay_urls,
        )
        await tm_a.attest(
            identity_c.pubkey_hex, c_d_tag, capability, 0.7,
            relay_urls=relay_urls,
        )

        tm_b = TrustManager(identity_b)
        await tm_b.attest(
            identity_c.pubkey_hex, c_d_tag, capability, 0.8,
            relay_urls=relay_urls,
        )

        await asyncio.sleep(0.5)

        # Build trust graph from relays.
        graph = await TrustManager.build_trust_graph(capability, relay_urls)

        # Verify structure: A should have edges, B should have an edge to C.
        a_hex = identity_a.pubkey_hex
        b_hex = identity_b.pubkey_hex
        c_hex = identity_c.pubkey_hex

        assert a_hex in graph.adjacency, "A should be in the graph"
        a_edges = {target: conf for target, conf in graph.adjacency.get(a_hex, [])}
        assert b_hex in a_edges, "A -> B edge should exist"
        assert c_hex in a_edges, "A -> C edge should exist"
        assert abs(a_edges[b_hex] - 0.9) < 0.01, f"A->B confidence: {a_edges[b_hex]}"
        assert abs(a_edges[c_hex] - 0.7) < 0.01, f"A->C confidence: {a_edges[c_hex]}"

        b_edges = {target: conf for target, conf in graph.adjacency.get(b_hex, [])}
        assert c_hex in b_edges, "B -> C edge should exist"
        assert abs(b_edges[c_hex] - 0.8) < 0.01, f"B->C confidence: {b_edges[c_hex]}"


# ---------------------------------------------------------------------------
# Test: Trust computation end-to-end
# ---------------------------------------------------------------------------


class TestTrustComputation:
    """Compute trust scores from relay-built graphs."""

    async def test_trust_via_intermediate(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """Compute trust from A to C via intermediate B using noisy-OR."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        capability = "code-review"

        a_d_tag = unique_d_tag("trust-a")
        identity_a = await _create_and_publish(
            operator_keys, a_d_tag, "trust-agent-a",
            [capability], relay_urls,
        )

        b_d_tag = unique_d_tag("trust-b")
        identity_b = await _create_and_publish(
            operator_keys, b_d_tag, "trust-agent-b",
            [capability], relay_urls,
        )

        c_d_tag = unique_d_tag("trust-c")
        identity_c = await _create_and_publish(
            operator_keys, c_d_tag, "trust-agent-c",
            [capability], relay_urls,
        )

        # A -> B (0.9), B -> C (0.8)
        # Also A -> C (0.5) directly for noisy-OR test.
        tm_a = TrustManager(identity_a)
        await tm_a.attest(
            identity_b.pubkey_hex, b_d_tag, capability, 0.9,
            relay_urls=relay_urls,
        )
        await tm_a.attest(
            identity_c.pubkey_hex, c_d_tag, capability, 0.5,
            relay_urls=relay_urls,
        )

        tm_b = TrustManager(identity_b)
        await tm_b.attest(
            identity_c.pubkey_hex, c_d_tag, capability, 0.8,
            relay_urls=relay_urls,
        )

        await asyncio.sleep(0.5)

        # Build graph and compute trust.
        graph = await TrustManager.build_trust_graph(capability, relay_urls)

        a_hex = identity_a.pubkey_hex
        c_hex = identity_c.pubkey_hex

        # Use the module-level compute_trust (same algorithm as TrustManager.compute_trust).
        score = compute_trust(
            graph.adjacency, a_hex, c_hex,
            decay=0.5, max_depth=4, epsilon=0.01,
        )

        assert score > 0.0, f"Trust score should be positive, got {score}"
        assert score <= 1.0, f"Trust score should be <= 1.0, got {score}"

        # Expected calculation (noisy-OR of two paths):
        # Path 1 (direct): A->C: 0.5 * 0.5 (decay) = 0.25
        # Path 2 (via B):  A->B->C: 0.9 * 0.8 * 0.5^2 = 0.18
        # noisy-OR: 1 - (1-0.25)(1-0.18) = 1 - 0.75 * 0.82 = 1 - 0.615 = 0.385
        expected = 1 - (1 - 0.25) * (1 - 0.18)
        assert abs(score - expected) < 0.05, (
            f"Trust score {score:.4f} deviates significantly from expected {expected:.4f}"
        )


# ---------------------------------------------------------------------------
# Test: Retraction removes edge
# ---------------------------------------------------------------------------


class TestRetraction:
    """Retracting an attestation (confidence=0.0) removes the edge."""

    async def test_retraction_removes_edge(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """After retraction, trust graph should not contain the edge."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        capability = "translation"

        a_d_tag = unique_d_tag("retract-a")
        identity_a = await _create_and_publish(
            operator_keys, a_d_tag, "retract-agent-a",
            [capability], relay_urls,
        )

        b_d_tag = unique_d_tag("retract-b")
        identity_b = await _create_and_publish(
            operator_keys, b_d_tag, "retract-agent-b",
            [capability], relay_urls,
        )

        # A attests B with confidence 0.8.
        tm_a = TrustManager(identity_a)
        await tm_a.attest(
            identity_b.pubkey_hex, b_d_tag, capability, 0.8,
            relay_urls=relay_urls,
        )

        await asyncio.sleep(0.5)

        # Verify edge exists.
        graph_before = await TrustManager.build_trust_graph(capability, relay_urls)
        a_hex = identity_a.pubkey_hex
        b_hex = identity_b.pubkey_hex

        a_edges_before = {t: c for t, c in graph_before.adjacency.get(a_hex, [])}
        assert b_hex in a_edges_before, "A->B edge should exist before retraction"

        # Retract (confidence=0.0) -- uses NIP-33 replacement (same d-tag, newer).
        await tm_a.retract(
            attestee_pubkey=identity_b.pubkey_hex,
            capability=capability,
            relay_urls=relay_urls,
        )

        await asyncio.sleep(0.5)

        # After retraction, edge should be gone.
        graph_after = await TrustManager.build_trust_graph(capability, relay_urls)
        a_edges_after = {t: c for t, c in graph_after.adjacency.get(a_hex, [])}
        assert b_hex not in a_edges_after, (
            "A->B edge should be absent after retraction"
        )

        # Trust computation should return 0.0.
        score = compute_trust(graph_after.adjacency, a_hex, b_hex)
        assert score == 0.0, f"Trust should be 0.0 after retraction, got {score}"


# ---------------------------------------------------------------------------
# Test: Attestation update (new confidence replaces old)
# ---------------------------------------------------------------------------


class TestAttestationUpdate:
    """Publishing a new attestation with different confidence replaces the old."""

    async def test_updated_confidence(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """A attests B with 0.4, then updates to 0.9; graph reflects latest."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        capability = "summarization"

        a_d_tag = unique_d_tag("update-a")
        identity_a = await _create_and_publish(
            operator_keys, a_d_tag, "update-agent-a",
            [capability], relay_urls,
        )

        b_d_tag = unique_d_tag("update-b")
        identity_b = await _create_and_publish(
            operator_keys, b_d_tag, "update-agent-b",
            [capability], relay_urls,
        )

        tm_a = TrustManager(identity_a)

        # First attestation: confidence 0.4.
        await tm_a.attest(
            identity_b.pubkey_hex, b_d_tag, capability, 0.4,
            relay_urls=relay_urls,
        )

        await asyncio.sleep(0.5)

        # Update attestation: confidence 0.9 (same d-tag, newer created_at).
        await tm_a.attest(
            identity_b.pubkey_hex, b_d_tag, capability, 0.9,
            relay_urls=relay_urls,
        )

        await asyncio.sleep(0.5)

        # Build graph: should reflect 0.9, not 0.4.
        graph = await TrustManager.build_trust_graph(capability, relay_urls)
        a_hex = identity_a.pubkey_hex
        b_hex = identity_b.pubkey_hex

        a_edges = {t: c for t, c in graph.adjacency.get(a_hex, [])}
        assert b_hex in a_edges, "A->B edge should exist"
        assert abs(a_edges[b_hex] - 0.9) < 0.05, (
            f"A->B confidence should be ~0.9 (updated), got {a_edges[b_hex]}"
        )


# ---------------------------------------------------------------------------
# Test: Multiple attesters for same capability (noisy-OR aggregation)
# ---------------------------------------------------------------------------


class TestMultipleAttesters:
    """Multiple agents attest the same target; noisy-OR aggregation tested."""

    async def test_multi_attester_trust(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """Source trusts target via two independent attesters; noisy-OR applies."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        capability = "classification"

        # Create source S, attesters A1/A2, and target T.
        s_d_tag = unique_d_tag("multi-s")
        identity_s = await _create_and_publish(
            operator_keys, s_d_tag, "multi-source",
            [capability], relay_urls,
        )

        a1_d_tag = unique_d_tag("multi-a1")
        identity_a1 = await _create_and_publish(
            operator_keys, a1_d_tag, "multi-attester-1",
            [capability], relay_urls,
        )

        a2_d_tag = unique_d_tag("multi-a2")
        identity_a2 = await _create_and_publish(
            operator_keys, a2_d_tag, "multi-attester-2",
            [capability], relay_urls,
        )

        t_d_tag = unique_d_tag("multi-t")
        identity_t = await _create_and_publish(
            operator_keys, t_d_tag, "multi-target",
            [capability], relay_urls,
        )

        s_hex = identity_s.pubkey_hex
        a1_hex = identity_a1.pubkey_hex
        a2_hex = identity_a2.pubkey_hex
        t_hex = identity_t.pubkey_hex

        # S -> A1 (0.9), S -> A2 (0.8), A1 -> T (0.7), A2 -> T (0.6)
        tm_s = TrustManager(identity_s)
        await tm_s.attest(a1_hex, a1_d_tag, capability, 0.9, relay_urls=relay_urls)
        await tm_s.attest(a2_hex, a2_d_tag, capability, 0.8, relay_urls=relay_urls)

        tm_a1 = TrustManager(identity_a1)
        await tm_a1.attest(t_hex, t_d_tag, capability, 0.7, relay_urls=relay_urls)

        tm_a2 = TrustManager(identity_a2)
        await tm_a2.attest(t_hex, t_d_tag, capability, 0.6, relay_urls=relay_urls)

        await asyncio.sleep(0.5)

        # Build graph and compute trust.
        graph = await TrustManager.build_trust_graph(capability, relay_urls)

        score = compute_trust(
            graph.adjacency, s_hex, t_hex,
            decay=0.5, max_depth=4, epsilon=0.01,
        )

        # Two paths (each depth 2):
        # Path 1: S->A1->T: 0.9 * 0.7 * 0.5^2 = 0.1575
        # Path 2: S->A2->T: 0.8 * 0.6 * 0.5^2 = 0.12
        # noisy-OR: 1 - (1-0.1575)(1-0.12) = 1 - 0.8425*0.88 = 1 - 0.7414 = 0.2586
        path1 = 0.9 * 0.7 * 0.5 * 0.5
        path2 = 0.8 * 0.6 * 0.5 * 0.5
        expected = 1 - (1 - path1) * (1 - path2)

        assert score > 0.0, "Score should be positive with two paths"
        assert abs(score - expected) < 0.05, (
            f"Trust score {score:.4f} deviates from expected noisy-OR {expected:.4f}"
        )
