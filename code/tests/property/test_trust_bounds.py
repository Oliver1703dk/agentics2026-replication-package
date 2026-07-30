"""Property-based tests for trust score algebraic bounds.

Tests the noisy-OR aggregation, decay, and monotonicity properties of the
trust computation algorithm:
1. Trust score bounded [0.0, 1.0]
2. Disconnected nodes -> trust = 0.0
3. Additional paths never decrease trust (noisy-OR monotonicity)
4. Trust decays with depth (single path at depth D <= d^D)
5. Self-trust always 1.0
6. Zero-confidence edge contributes nothing

References:
- trust.py: compute_trust, compute_trust_detailed
- paper Section 4 (trust model: noisy-OR with decay d = 0.5, depth limit 4)
"""

from __future__ import annotations

import math

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from nostr_agent.trust import compute_trust, compute_trust_detailed
from nostr_agent.types import TrustGraph as TrustGraphType

from .strategies import trust_graph_st

pytestmark = pytest.mark.property

_SETTINGS = settings(max_examples=500, deadline=None)


# ===================================================================
# Property 1: Trust score bounded [0.0, 1.0]
# ===================================================================


class TestTrustBounded:
    """Trust scores must always lie in [0.0, 1.0]."""

    @_SETTINGS
    @given(graph=trust_graph_st(min_nodes=3, max_nodes=12))
    def test_score_in_unit_interval(self, graph: TrustGraphType) -> None:
        """For any graph and any source-target pair, 0 <= score <= 1."""
        # Collect all nodes in the graph.
        nodes = set(graph.adjacency.keys())
        for edges in graph.adjacency.values():
            for target, _ in edges:
                nodes.add(target)

        if len(nodes) < 2:
            return

        node_list = sorted(nodes)
        # Test a sample of pairs (source, target).
        for source in node_list[:5]:
            for target in node_list[:5]:
                score = compute_trust(
                    graph.adjacency, source, target,
                    decay=0.5, max_depth=4, epsilon=0.0,
                )
                assert 0.0 <= score <= 1.0, (
                    f"score {score} out of bounds for {source}->{target}"
                )

    @_SETTINGS
    @given(
        decay=st.floats(min_value=0.01, max_value=1.0, allow_nan=False),
        weight=st.floats(min_value=0.01, max_value=1.0, allow_nan=False),
    )
    def test_single_hop_bounded(self, decay: float, weight: float) -> None:
        """Single direct edge: score = weight * decay, must be in [0, 1]."""
        graph = {"A": [("B", weight)], "B": []}
        score = compute_trust(graph, "A", "B", decay=decay, max_depth=4, epsilon=0.0)
        assert 0.0 <= score <= 1.0
        assert abs(score - weight * decay) < 1e-9

    @_SETTINGS
    @given(
        n_paths=st.integers(min_value=1, max_value=20),
        weight=st.floats(min_value=0.01, max_value=1.0, allow_nan=False),
        decay=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
    )
    def test_many_parallel_paths_bounded(
        self, n_paths: int, weight: float, decay: float
    ) -> None:
        """Multiple parallel single-hop paths: noisy-OR still in [0, 1]."""
        graph: dict[str, list[tuple[str, float]]] = {
            "source": [(f"mid{i}", weight) for i in range(n_paths)],
            "target": [],
        }
        for i in range(n_paths):
            graph[f"mid{i}"] = [("target", weight)]

        score = compute_trust(
            graph, "source", "target", decay=decay, max_depth=4, epsilon=0.0
        )
        assert 0.0 <= score <= 1.0


# ===================================================================
# Property 2: Disconnected nodes -> trust = 0.0
# ===================================================================


class TestDisconnectedZero:
    """No path between source and target implies zero trust."""

    @_SETTINGS
    @given(
        n_source=st.integers(min_value=1, max_value=5),
        n_target=st.integers(min_value=1, max_value=5),
        weight=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
    )
    def test_separate_components(
        self, n_source: int, n_target: int, weight: float
    ) -> None:
        """Two disconnected cliques have zero trust between them."""
        graph: dict[str, list[tuple[str, float]]] = {}

        # Source component: nodes s0..s(n-1).
        for i in range(n_source):
            graph[f"s{i}"] = []
            for j in range(n_source):
                if i != j:
                    graph[f"s{i}"].append((f"s{j}", weight))

        # Target component: nodes t0..t(n-1). No edges to source component.
        for i in range(n_target):
            graph[f"t{i}"] = []
            for j in range(n_target):
                if i != j:
                    graph[f"t{i}"].append((f"t{j}", weight))

        score = compute_trust(graph, "s0", "t0", decay=0.5, max_depth=4, epsilon=0.0)
        assert score == 0.0

    @_SETTINGS
    @given(st.data())
    def test_source_not_in_graph(self, data: st.DataObject) -> None:
        """Source node absent from graph implies zero trust."""
        graph = data.draw(trust_graph_st(min_nodes=3, max_nodes=8))
        score = compute_trust(
            graph.adjacency, "nonexistent_source", "node0000",
            decay=0.5, max_depth=4, epsilon=0.0,
        )
        assert score == 0.0

    @_SETTINGS
    @given(st.data())
    def test_detailed_zero_paths(self, data: st.DataObject) -> None:
        """Disconnected nodes have paths_found == 0 in detailed result."""
        result = compute_trust_detailed(
            {"A": [("B", 0.5)]}, "A", "C",
            decay=0.5, max_depth=4, epsilon=0.0,
        )
        assert result.score == 0.0
        assert result.paths_found == 0


# ===================================================================
# Property 3: Additional paths never decrease trust (noisy-OR monotonicity)
# ===================================================================


class TestNoisyORMonotonicity:
    """Adding a new path can only increase (or leave unchanged) the trust score."""

    @_SETTINGS
    @given(
        weight_ab=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
        weight_ac=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
        weight_cb=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
        decay=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
    )
    def test_adding_path_increases_trust(
        self, weight_ab: float, weight_ac: float, weight_cb: float, decay: float
    ) -> None:
        """Trust(A->B) with one path <= Trust(A->B) with two paths."""
        # Graph 1: single direct path A -> B.
        g1: dict[str, list[tuple[str, float]]] = {
            "A": [("B", weight_ab)],
            "B": [],
        }
        score1 = compute_trust(g1, "A", "B", decay=decay, max_depth=4, epsilon=0.0)

        # Graph 2: add an indirect path A -> C -> B.
        g2: dict[str, list[tuple[str, float]]] = {
            "A": [("B", weight_ab), ("C", weight_ac)],
            "B": [],
            "C": [("B", weight_cb)],
        }
        score2 = compute_trust(g2, "A", "B", decay=decay, max_depth=4, epsilon=0.0)

        assert score2 >= score1 - 1e-9, (
            f"adding path decreased trust: {score1} -> {score2}"
        )

    @_SETTINGS
    @given(
        w1=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
        w2=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
        w3=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
        decay=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
    )
    def test_adding_edge_to_graph_monotone(
        self, w1: float, w2: float, w3: float, decay: float
    ) -> None:
        """Inserting one additional edge into the graph never decreases trust."""
        # Base graph: A -> B -> D.
        g_base: dict[str, list[tuple[str, float]]] = {
            "A": [("B", w1)],
            "B": [("D", w2)],
            "D": [],
        }
        base_score = compute_trust(
            g_base, "A", "D", decay=decay, max_depth=4, epsilon=0.0
        )

        # Extended graph: add A -> C -> D.
        g_ext: dict[str, list[tuple[str, float]]] = {
            "A": [("B", w1), ("C", w3)],
            "B": [("D", w2)],
            "C": [("D", w3)],
            "D": [],
        }
        ext_score = compute_trust(
            g_ext, "A", "D", decay=decay, max_depth=4, epsilon=0.0
        )

        assert ext_score >= base_score - 1e-9


# ===================================================================
# Property 4: Trust decays with depth
# ===================================================================


class TestTrustDecay:
    """Single-path trust at depth D is bounded by d^D (times edge weight product)."""

    @_SETTINGS
    @given(
        depth=st.integers(min_value=1, max_value=4),
        weight=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
        decay=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
    )
    def test_single_path_trust_equals_decay_formula(
        self, depth: int, weight: float, decay: float
    ) -> None:
        """For a linear chain of length `depth` with uniform weight w and decay d,
        trust = w^depth * d^depth = (w*d)^depth.

        DFS computes: accumulated starts at 1.0, each hop multiplies by
        edge_weight then by decay. So after D hops: product(w_i) * d^D.
        With uniform weight: w^D * d^D.
        """
        # Build linear chain: 0 -> 1 -> 2 -> ... -> depth.
        graph: dict[str, list[tuple[str, float]]] = {}
        for i in range(depth):
            graph[str(i)] = [(str(i + 1), weight)]
        graph[str(depth)] = []

        score = compute_trust(
            graph, "0", str(depth),
            decay=decay, max_depth=depth + 1, epsilon=0.0,
        )

        expected = (weight * decay) ** depth
        assert abs(score - expected) < 1e-9, (
            f"depth={depth}, w={weight}, d={decay}: got {score}, expected {expected}"
        )

    @_SETTINGS
    @given(
        weight=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
        decay=st.floats(min_value=0.1, max_value=0.99, allow_nan=False),
    )
    def test_deeper_path_lower_trust(self, weight: float, decay: float) -> None:
        """Trust strictly decreases with path length (for decay < 1, weight < 1)."""
        assume(weight * decay < 1.0)

        scores = []
        for depth in range(1, 5):
            graph: dict[str, list[tuple[str, float]]] = {}
            for i in range(depth):
                graph[str(i)] = [(str(i + 1), weight)]
            graph[str(depth)] = []

            score = compute_trust(
                graph, "0", str(depth),
                decay=decay, max_depth=6, epsilon=0.0,
            )
            scores.append(score)

        # Each subsequent depth should have strictly lower trust.
        for i in range(1, len(scores)):
            assert scores[i] < scores[i - 1] + 1e-9, (
                f"trust did not decrease: depth {i}: {scores[i-1]} -> {scores[i]}"
            )

    @_SETTINGS
    @given(
        weight=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
        decay=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
    )
    def test_single_path_bounded_by_decay_power(
        self, weight: float, decay: float
    ) -> None:
        """For any single-path graph of depth D, trust <= d^D."""
        for depth in range(1, 5):
            graph: dict[str, list[tuple[str, float]]] = {}
            for i in range(depth):
                graph[str(i)] = [(str(i + 1), weight)]
            graph[str(depth)] = []

            score = compute_trust(
                graph, "0", str(depth),
                decay=decay, max_depth=6, epsilon=0.0,
            )
            upper_bound = decay ** depth
            assert score <= upper_bound + 1e-9, (
                f"score {score} > d^D={upper_bound} for depth={depth}"
            )


# ===================================================================
# Property 5: Self-trust always 1.0
# ===================================================================


class TestSelfTrust:
    """compute_trust(source, source) always returns 1.0."""

    @_SETTINGS
    @given(graph=trust_graph_st(min_nodes=3, max_nodes=10))
    def test_self_trust_is_one(self, graph: TrustGraphType) -> None:
        """Self-trust for any node in any graph is 1.0."""
        nodes = set(graph.adjacency.keys())
        for edges in graph.adjacency.values():
            for target, _ in edges:
                nodes.add(target)

        for node in list(nodes)[:5]:
            score = compute_trust(
                graph.adjacency, node, node,
                decay=0.5, max_depth=4, epsilon=0.0,
            )
            assert score == 1.0, f"self-trust for {node} is {score}, expected 1.0"

    @_SETTINGS
    @given(
        decay=st.floats(min_value=0.01, max_value=1.0, allow_nan=False),
        max_depth=st.integers(min_value=1, max_value=10),
    )
    def test_self_trust_independent_of_params(
        self, decay: float, max_depth: int
    ) -> None:
        """Self-trust is 1.0 regardless of decay and max_depth."""
        graph: dict[str, list[tuple[str, float]]] = {"X": [("Y", 0.5)], "Y": []}
        score = compute_trust(graph, "X", "X", decay=decay, max_depth=max_depth)
        assert score == 1.0

    @_SETTINGS
    @given(
        decay=st.floats(min_value=0.01, max_value=1.0, allow_nan=False),
    )
    def test_self_trust_detailed_returns_zero_paths(self, decay: float) -> None:
        """Self-trust via compute_trust_detailed returns score=1.0, paths_found=0."""
        result = compute_trust_detailed(
            {"A": [("B", 0.9)]}, "A", "A",
            decay=decay, max_depth=4,
        )
        assert result.score == 1.0
        assert result.paths_found == 0


# ===================================================================
# Property 6: Zero-confidence edge contributes nothing
# ===================================================================


class TestZeroConfidence:
    """An edge with confidence=0.0 does not contribute to trust."""

    @_SETTINGS
    @given(
        weight=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
        decay=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
    )
    def test_zero_edge_same_as_no_edge(self, weight: float, decay: float) -> None:
        """Graph with zero-weight edge A->C->B gives same score as graph without it.

        Note: zero-confidence edges contribute edge_trust = 0 to path product,
        resulting in zero path contribution to noisy-OR.
        """
        # Graph without the zero-edge path.
        g1: dict[str, list[tuple[str, float]]] = {
            "A": [("B", weight)],
            "B": [],
        }
        score1 = compute_trust(g1, "A", "B", decay=decay, max_depth=4, epsilon=0.0)

        # Graph with a zero-weight bypass A -> C -> B (contributes nothing).
        g2: dict[str, list[tuple[str, float]]] = {
            "A": [("B", weight), ("C", 0.0)],
            "B": [],
            "C": [("B", 1.0)],
        }
        score2 = compute_trust(g2, "A", "B", decay=decay, max_depth=4, epsilon=0.0)

        assert abs(score1 - score2) < 1e-9, (
            f"zero edge changed score: {score1} -> {score2}"
        )

    @_SETTINGS
    @given(
        decay=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
    )
    def test_only_zero_edges_gives_zero(self, decay: float) -> None:
        """A graph where all edges have weight 0 produces trust = 0."""
        graph: dict[str, list[tuple[str, float]]] = {
            "A": [("B", 0.0), ("C", 0.0)],
            "B": [("D", 0.0)],
            "C": [("D", 0.0)],
            "D": [],
        }
        score = compute_trust(graph, "A", "D", decay=decay, max_depth=4, epsilon=0.0)
        assert score == 0.0


# ===================================================================
# Property: Higher decay -> higher per-hop contribution
# ===================================================================


class TestDecayOrdering:
    """For the same graph, higher decay parameter means higher trust.

    decay is a multiplier per hop: path_trust = product(weights) * decay^depth.
    Higher decay -> higher multiplier -> higher trust (all else equal).
    So for decay_a < decay_b: score(decay_a) <= score(decay_b).
    """

    @_SETTINGS
    @given(
        weight=st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
        decay_lo=st.floats(min_value=0.1, max_value=0.5, allow_nan=False),
        decay_hi=st.floats(min_value=0.5, max_value=1.0, allow_nan=False),
    )
    def test_higher_decay_higher_trust(
        self, weight: float, decay_lo: float, decay_hi: float
    ) -> None:
        """score(decay_lo) <= score(decay_hi) for decay_lo < decay_hi."""
        assume(decay_lo < decay_hi)

        graph: dict[str, list[tuple[str, float]]] = {
            "A": [("B", weight)],
            "B": [("C", weight)],
            "C": [],
        }
        score_lo = compute_trust(
            graph, "A", "C", decay=decay_lo, max_depth=4, epsilon=0.0
        )
        score_hi = compute_trust(
            graph, "A", "C", decay=decay_hi, max_depth=4, epsilon=0.0
        )
        assert score_lo <= score_hi + 1e-9, (
            f"decay ordering violated: score({decay_lo})={score_lo} > score({decay_hi})={score_hi}"
        )


# ===================================================================
# Property: Depth limit respected
# ===================================================================


class TestDepthLimitRespected:
    """Paths longer than max_depth are not used in trust computation."""

    @_SETTINGS
    @given(
        weight=st.floats(min_value=0.5, max_value=1.0, allow_nan=False),
        decay=st.floats(min_value=0.5, max_value=1.0, allow_nan=False),
    )
    def test_path_beyond_max_depth_gives_zero(
        self, weight: float, decay: float
    ) -> None:
        """A linear chain of length 6 with max_depth=3 gives zero trust end-to-end."""
        chain_len = 6
        graph: dict[str, list[tuple[str, float]]] = {}
        for i in range(chain_len):
            graph[str(i)] = [(str(i + 1), weight)]
        graph[str(chain_len)] = []

        score = compute_trust(
            graph, "0", str(chain_len),
            decay=decay, max_depth=3, epsilon=0.0,
        )
        assert score == 0.0, (
            f"path of length {chain_len} with max_depth=3 gave score {score}"
        )

    @_SETTINGS
    @given(
        weight=st.floats(min_value=0.5, max_value=1.0, allow_nan=False),
        decay=st.floats(min_value=0.5, max_value=1.0, allow_nan=False),
        max_depth=st.integers(min_value=1, max_value=4),
    )
    def test_score_at_max_depth_equals_direct_formula(
        self, weight: float, decay: float, max_depth: int
    ) -> None:
        """Score through a chain of exactly max_depth hops matches (w*d)^max_depth."""
        graph: dict[str, list[tuple[str, float]]] = {}
        for i in range(max_depth):
            graph[str(i)] = [(str(i + 1), weight)]
        graph[str(max_depth)] = []

        score = compute_trust(
            graph, "0", str(max_depth),
            decay=decay, max_depth=max_depth, epsilon=0.0,
        )
        expected = (weight * decay) ** max_depth
        assert abs(score - expected) < 1e-9, (
            f"max_depth={max_depth}: got {score}, expected {expected}"
        )

    @_SETTINGS
    @given(
        weight=st.floats(min_value=0.5, max_value=1.0, allow_nan=False),
        decay=st.floats(min_value=0.5, max_value=1.0, allow_nan=False),
        max_depth=st.integers(min_value=1, max_value=4),
    )
    def test_one_hop_beyond_max_depth_is_zero(
        self, weight: float, decay: float, max_depth: int
    ) -> None:
        """A chain of length max_depth+1 gives zero trust (last hop is unreachable)."""
        chain_len = max_depth + 1
        graph: dict[str, list[tuple[str, float]]] = {}
        for i in range(chain_len):
            graph[str(i)] = [(str(i + 1), weight)]
        graph[str(chain_len)] = []

        score = compute_trust(
            graph, "0", str(chain_len),
            decay=decay, max_depth=max_depth, epsilon=0.0,
        )
        assert score == 0.0
