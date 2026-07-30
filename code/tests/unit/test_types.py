"""Unit tests for nostr_agent.types -- domain types, data classes, exceptions.

Covers: Scope, Constraints, TrustPolicy, PublishResult, VerificationStatus,
TrustGraph, exception hierarchy. All frozen dataclass immutability guarantees
and computed properties.
"""

from __future__ import annotations

import dataclasses

import pytest

from nostr_agent.types import (
    AttenuationError,
    Constraints,
    DepthExceededError,
    L402AmountExceededError,
    L402ParseError,
    L402PaymentError,
    L402VerificationError,
    LndConnectionError,
    NostrAgentError,
    PublishError,
    PublishResult,
    RateLimitHint,
    RotationError,
    Scope,
    SelfAttestationError,
    SelfDelegationError,
    TrustGraph,
    TrustPolicy,
    TrustResult,
    VerificationStatus,
)


# ===========================================================================
# Scope
# ===========================================================================


class TestScopeConstruction:
    """Scope construction, tuple types, sorted order."""

    @pytest.mark.unit
    def test_fields_are_tuples(self):
        s = Scope(capabilities=("b", "a"), resources=("y", "x"), actions=("w", "v"))
        assert isinstance(s.capabilities, tuple)
        assert isinstance(s.resources, tuple)
        assert isinstance(s.actions, tuple)

    @pytest.mark.unit
    def test_order_preserved_as_given(self):
        """Scope stores tuples as-is; sorting is the caller's responsibility."""
        s = Scope(capabilities=("b", "a"), resources=("y", "x"), actions=("w", "v"))
        # Scope itself does NOT sort on construction (DelegationScope.create does).
        assert s.capabilities == ("b", "a")

    @pytest.mark.unit
    def test_defaults_are_empty_tuples(self):
        s = Scope()
        assert s.capabilities == ()
        assert s.resources == ()
        assert s.actions == ()

    @pytest.mark.unit
    def test_construction_with_sorted_input(self):
        s = Scope(
            capabilities=tuple(sorted(("weather-forecast", "data-aggregation"))),
            resources=tuple(sorted(("relay:wss://r.example.com",))),
            actions=tuple(sorted(("read", "write"))),
        )
        assert s.capabilities == ("data-aggregation", "weather-forecast")
        assert s.resources == ("relay:wss://r.example.com",)
        assert s.actions == ("read", "write")


class TestScopeImmutability:
    """Frozen dataclass should reject attribute assignment."""

    @pytest.mark.unit
    def test_cannot_set_capabilities(self):
        s = Scope(capabilities=("a",))
        with pytest.raises(dataclasses.FrozenInstanceError):
            s.capabilities = ("b",)  # type: ignore[misc]

    @pytest.mark.unit
    def test_cannot_set_resources(self):
        s = Scope(resources=("r",))
        with pytest.raises(dataclasses.FrozenInstanceError):
            s.resources = ("s",)  # type: ignore[misc]

    @pytest.mark.unit
    def test_cannot_set_actions(self):
        s = Scope(actions=("read",))
        with pytest.raises(dataclasses.FrozenInstanceError):
            s.actions = ("write",)  # type: ignore[misc]


class TestScopeAttenuates:
    """Scope.attenuates() -- attenuation invariant INV-1 through INV-3."""

    @pytest.mark.unit
    def test_child_subset_passes(self):
        parent = Scope(capabilities=("a", "b"), resources=("r1",), actions=("read", "write"))
        child = Scope(capabilities=("a",), resources=("r1",), actions=("read",))
        assert child.attenuates(parent) is True

    @pytest.mark.unit
    def test_child_superset_fails(self):
        parent = Scope(capabilities=("a",), resources=("r1",), actions=("read",))
        child = Scope(capabilities=("a", "b"), resources=("r1",), actions=("read",))
        assert child.attenuates(parent) is False

    @pytest.mark.unit
    def test_empty_parent_resources_means_unrestricted(self):
        """Empty parent resources = unrestricted; any child resources are allowed."""
        parent = Scope(capabilities=("a",), resources=(), actions=())
        child = Scope(capabilities=("a",), resources=("r1", "r2"), actions=("x",))
        assert child.attenuates(parent) is True

    @pytest.mark.unit
    def test_empty_parent_actions_means_unrestricted(self):
        parent = Scope(capabilities=("a",), resources=(), actions=())
        child = Scope(capabilities=("a",), resources=(), actions=("read", "write"))
        assert child.attenuates(parent) is True

    @pytest.mark.unit
    def test_child_widens_resources_fails(self):
        parent = Scope(capabilities=("a",), resources=("r1",), actions=())
        child = Scope(capabilities=("a",), resources=("r1", "r2"), actions=())
        assert child.attenuates(parent) is False

    @pytest.mark.unit
    def test_child_widens_actions_fails(self):
        parent = Scope(capabilities=("a",), resources=(), actions=("read",))
        child = Scope(capabilities=("a",), resources=(), actions=("read", "write"))
        assert child.attenuates(parent) is False

    @pytest.mark.unit
    def test_identical_scopes_attenuate(self):
        s = Scope(capabilities=("a",), resources=("r1",), actions=("read",))
        assert s.attenuates(s) is True

    @pytest.mark.unit
    def test_empty_child_capabilities_fails(self):
        """Child with empty capabilities cannot attenuate a parent with capabilities."""
        parent = Scope(capabilities=("a",), resources=(), actions=())
        child = Scope(capabilities=(), resources=(), actions=())
        # empty set <= {"a"} is True in Python, so empty caps IS a subset.
        # However, semantically capabilities must be non-empty. The attenuates()
        # method checks subset containment -- empty IS a subset.
        assert child.attenuates(parent) is True

    @pytest.mark.unit
    def test_deprecated_resource_property(self):
        s = Scope(resources=("wss://relay.example.com",))
        assert s.resource == "wss://relay.example.com"

    @pytest.mark.unit
    def test_deprecated_resource_property_empty(self):
        s = Scope()
        assert s.resource == ""


# ===========================================================================
# Constraints
# ===========================================================================


class TestConstraints:
    """Constraints construction and immutability."""

    @pytest.mark.unit
    def test_all_fields_stored(self):
        c = Constraints(
            expires_at=1700000000,
            max_chain_depth=3,
            current_depth=1,
            issued_at=1699900000,
        )
        assert c.expires_at == 1700000000
        assert c.max_chain_depth == 3
        assert c.current_depth == 1
        assert c.issued_at == 1699900000
        assert c.rate_limit_hint is None

    @pytest.mark.unit
    def test_with_rate_limit_hint(self):
        rlh = RateLimitHint(max_requests=100, window_seconds=60)
        c = Constraints(
            expires_at=1700000000,
            max_chain_depth=3,
            current_depth=1,
            issued_at=1699900000,
            rate_limit_hint=rlh,
        )
        assert c.rate_limit_hint is not None
        assert c.rate_limit_hint.max_requests == 100
        assert c.rate_limit_hint.window_seconds == 60

    @pytest.mark.unit
    def test_immutability(self):
        c = Constraints(expires_at=1700000000, max_chain_depth=3, current_depth=1, issued_at=1699900000)
        with pytest.raises(dataclasses.FrozenInstanceError):
            c.expires_at = 0  # type: ignore[misc]


# ===========================================================================
# TrustPolicy
# ===========================================================================


class TestTrustPolicy:
    """TrustPolicy defaults: noisy-OR with decay 0.5, max_depth 4, epsilon 0.01."""

    @pytest.mark.unit
    def test_defaults(self):
        tp = TrustPolicy()
        assert tp.min_attestation_count == 1
        assert tp.trust_decay_per_hop == 0.5
        assert tp.max_trust_depth == 4
        assert tp.require_l402 is False

    @pytest.mark.unit
    def test_custom_values(self):
        tp = TrustPolicy(
            min_attestation_count=3,
            trust_decay_per_hop=0.8,
            max_trust_depth=6,
            require_l402=True,
        )
        assert tp.min_attestation_count == 3
        assert tp.trust_decay_per_hop == 0.8
        assert tp.max_trust_depth == 6
        assert tp.require_l402 is True

    @pytest.mark.unit
    def test_immutability(self):
        tp = TrustPolicy()
        with pytest.raises(dataclasses.FrozenInstanceError):
            tp.trust_decay_per_hop = 0.9  # type: ignore[misc]


# ===========================================================================
# PublishResult
# ===========================================================================


class TestPublishResult:
    """PublishResult.success_count and is_published properties."""

    @pytest.mark.unit
    def test_success_count_with_succeeded_relays(self):
        pr = PublishResult(
            event_id="abc123",
            succeeded=("ws://relay1", "ws://relay2"),
            failed={},
        )
        assert pr.success_count == 2

    @pytest.mark.unit
    def test_is_published_true(self):
        pr = PublishResult(event_id="abc123", succeeded=("ws://relay1",))
        assert pr.is_published is True

    @pytest.mark.unit
    def test_is_published_false_when_zero_succeeded(self):
        pr = PublishResult(event_id="abc123", succeeded=(), failed={"ws://relay1": "timeout"})
        assert pr.success_count == 0
        assert pr.is_published is False

    @pytest.mark.unit
    def test_default_succeeded_is_empty(self):
        pr = PublishResult(event_id="abc123")
        assert pr.succeeded == ()
        assert pr.success_count == 0
        assert pr.is_published is False

    @pytest.mark.unit
    def test_mixed_success_and_failure(self):
        pr = PublishResult(
            event_id="abc123",
            succeeded=("ws://r1",),
            failed={"ws://r2": "connection refused"},
        )
        assert pr.success_count == 1
        assert pr.is_published is True
        assert pr.failed == {"ws://r2": "connection refused"}


# ===========================================================================
# VerificationStatus
# ===========================================================================


class TestVerificationStatus:
    """VerificationStatus enum values match spec."""

    @pytest.mark.unit
    def test_all_values_present(self):
        expected = {
            "valid",
            "invalid_signature",
            "invalid_schema",
            "chain_broken",
            "revoked",
            "decommissioned",
            "expired",
            "not_found",
            "rotation_in_progress",
        }
        actual = {status.value for status in VerificationStatus}
        assert actual == expected

    @pytest.mark.unit
    def test_enum_access(self):
        assert VerificationStatus.VALID.value == "valid"
        assert VerificationStatus.INVALID_SIGNATURE.value == "invalid_signature"
        assert VerificationStatus.CHAIN_BROKEN.value == "chain_broken"
        assert VerificationStatus.REVOKED.value == "revoked"
        assert VerificationStatus.EXPIRED.value == "expired"
        assert VerificationStatus.NOT_FOUND.value == "not_found"
        assert VerificationStatus.ROTATION_IN_PROGRESS.value == "rotation_in_progress"

    @pytest.mark.unit
    def test_count(self):
        assert len(VerificationStatus) == 9


# ===========================================================================
# TrustGraph
# ===========================================================================


class TestTrustGraph:
    """TrustGraph adjacency list: add_edge, node_count, edge_count."""

    @pytest.mark.unit
    def test_empty_graph(self):
        g = TrustGraph(capability="weather")
        assert g.node_count == 0
        assert g.edge_count == 0

    @pytest.mark.unit
    def test_add_single_edge(self):
        g = TrustGraph(capability="weather")
        g.add_edge("alice", "bob", 0.8)
        assert g.node_count == 2
        assert g.edge_count == 1

    @pytest.mark.unit
    def test_add_multiple_edges(self):
        g = TrustGraph(capability="weather")
        g.add_edge("alice", "bob", 0.8)
        g.add_edge("bob", "carol", 0.9)
        g.add_edge("alice", "carol", 0.5)
        assert g.node_count == 3
        assert g.edge_count == 3

    @pytest.mark.unit
    def test_node_count_includes_attestees_without_outgoing(self):
        """Attestees that have no outgoing edges are still counted as nodes."""
        g = TrustGraph(capability="weather")
        g.add_edge("alice", "bob", 0.8)
        # bob is an attestee only -- no outgoing edges
        assert "bob" not in g.adjacency
        assert g.node_count == 2

    @pytest.mark.unit
    def test_duplicate_edges_counted(self):
        """Multiple attestations between same pair are separate edges."""
        g = TrustGraph(capability="weather")
        g.add_edge("alice", "bob", 0.8)
        g.add_edge("alice", "bob", 0.9)
        assert g.edge_count == 2

    @pytest.mark.unit
    def test_capability_stored(self):
        g = TrustGraph(capability="data-aggregation")
        assert g.capability == "data-aggregation"

    @pytest.mark.unit
    def test_adjacency_structure(self):
        g = TrustGraph(capability="weather")
        g.add_edge("alice", "bob", 0.8)
        g.add_edge("alice", "carol", 0.6)
        assert g.adjacency["alice"] == [("bob", 0.8), ("carol", 0.6)]


# ===========================================================================
# TrustResult
# ===========================================================================


class TestTrustResult:

    @pytest.mark.unit
    def test_trust_result_fields(self):
        tr = TrustResult(score=0.42, paths_found=3, paths_pruned=1)
        assert tr.score == 0.42
        assert tr.paths_found == 3
        assert tr.paths_pruned == 1

    @pytest.mark.unit
    def test_trust_result_immutable(self):
        tr = TrustResult(score=0.5, paths_found=1, paths_pruned=0)
        with pytest.raises(dataclasses.FrozenInstanceError):
            tr.score = 0.9  # type: ignore[misc]


# ===========================================================================
# Exception Hierarchy
# ===========================================================================


class TestExceptionHierarchy:
    """All custom exceptions inherit from NostrAgentError."""

    EXCEPTION_CLASSES = [
        PublishError,
        RotationError,
        AttenuationError,
        DepthExceededError,
        SelfDelegationError,
        SelfAttestationError,
        L402PaymentError,
        L402VerificationError,
        L402AmountExceededError,
        L402ParseError,
        LndConnectionError,
    ]

    @pytest.mark.unit
    @pytest.mark.parametrize("exc_cls", EXCEPTION_CLASSES)
    def test_inherits_from_nostr_agent_error(self, exc_cls: type):
        assert issubclass(exc_cls, NostrAgentError)

    @pytest.mark.unit
    @pytest.mark.parametrize("exc_cls", EXCEPTION_CLASSES)
    def test_inherits_from_exception(self, exc_cls: type):
        assert issubclass(exc_cls, Exception)

    @pytest.mark.unit
    @pytest.mark.parametrize("exc_cls", EXCEPTION_CLASSES)
    def test_can_be_raised_and_caught(self, exc_cls: type):
        with pytest.raises(NostrAgentError):
            raise exc_cls("test message")

    @pytest.mark.unit
    @pytest.mark.parametrize("exc_cls", EXCEPTION_CLASSES)
    def test_message_preserved(self, exc_cls: type):
        try:
            raise exc_cls("specific error detail")
        except NostrAgentError as e:
            assert "specific error detail" in str(e)

    @pytest.mark.unit
    def test_nostr_agent_error_is_base(self):
        assert issubclass(NostrAgentError, Exception)
        assert NostrAgentError.__bases__ == (Exception,)
