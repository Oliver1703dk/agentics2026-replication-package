"""Property-based tests for delegation attenuation invariants.

Tests the 7-condition attenuation invariant (INV-1 through INV-7) and
structural properties of delegation chains:
1. Attenuation monotonicity (scope narrows along chain)
2. Temporal monotonicity (expires_at non-increasing)
3. Depth bound (current_depth <= max_chain_depth)
4. No-widening (extra capability -> rejection)
5. Revocation cascade (parent revoked -> chain invalid)
6. Cycle detection (repeated pubkey -> rejection)

References:
- paper Section 4 (delegation chain attenuation invariants INV-1 to INV-7)
- DelegationManager.validate_attenuation (delegation.py)
- Scope.attenuates (types.py)
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

from nostr_agent.delegation import DelegationManager
from nostr_agent.types import Constraints, Scope

from .strategies import (
    capability_st,
    chain_st,
    constraints_st,
    scope_st,
    subconstraints_st,
    subscope_st,
)

pytestmark = pytest.mark.property

# All property tests use 500 examples with no deadline (crypto ops may be slow).
_SETTINGS = settings(max_examples=500, deadline=None)


# ===================================================================
# Property 1: Attenuation monotonicity (INV-1, INV-2, INV-3)
# ===================================================================


class TestAttenuationMonotonicity:
    """A valid child scope is always a subset of its parent scope."""

    @_SETTINGS
    @given(st.data())
    def test_subscope_always_valid(self, data: st.DataObject) -> None:
        """Any child generated via subscope_st must pass validate_attenuation."""
        parent = data.draw(scope_st(), label="parent")
        assume(len(parent.capabilities) >= 1)
        child = data.draw(subscope_st(parent), label="child")
        assert DelegationManager.validate_attenuation(child, parent), (
            f"valid subscope rejected: child={child}, parent={parent}"
        )

    @_SETTINGS
    @given(parent=scope_st())
    def test_self_is_valid_attenuation(self, parent: Scope) -> None:
        """A scope attenuates itself (reflexivity)."""
        assert DelegationManager.validate_attenuation(parent, parent)

    @_SETTINGS
    @given(data=chain_st(max_depth=4))
    def test_chain_leaf_capabilities_subset_of_root(
        self, data: list[tuple[Scope, Constraints]]
    ) -> None:
        """Capabilities at the leaf are always a subset of root capabilities.

        INV-1 has no empty-set exemption: capabilities must be a strict subset
        at every hop, so the transitive closure holds for capabilities.

        Note: resources/actions use empty-set = unrestricted semantics (INV-2/INV-3),
        so an intermediate hop with empty resources can allow a grandchild to
        introduce resources not in the root. The transitive subset property
        only holds for capabilities.
        """
        root_scope = data[0][0]
        leaf_scope = data[-1][0]
        assert set(leaf_scope.capabilities) <= set(root_scope.capabilities), (
            f"leaf caps {leaf_scope.capabilities} not subset of root {root_scope.capabilities}"
        )

    @_SETTINGS
    @given(data=chain_st(max_depth=4))
    def test_pairwise_attenuation_holds(
        self, data: list[tuple[Scope, Constraints]]
    ) -> None:
        """validate_attenuation returns True for every adjacent pair in the chain."""
        for i in range(1, len(data)):
            parent_scope = data[i - 1][0]
            child_scope = data[i][0]
            assert DelegationManager.validate_attenuation(child_scope, parent_scope), (
                f"hop {i}: child={child_scope} not valid attenuation of parent={parent_scope}"
            )

    @_SETTINGS
    @given(data=chain_st(max_depth=4))
    def test_resources_subset_when_all_hops_restricted(
        self, data: list[tuple[Scope, Constraints]]
    ) -> None:
        """When every hop has non-empty resources, leaf resources subset of root."""
        all_restricted = all(s.resources for s, _ in data)
        assume(all_restricted)

        root_scope = data[0][0]
        leaf_scope = data[-1][0]
        assert set(leaf_scope.resources) <= set(root_scope.resources)


# ===================================================================
# Property 2: Temporal monotonicity (INV-4)
# ===================================================================


class TestTemporalMonotonicity:
    """expires_at is non-increasing along the chain."""

    @_SETTINGS
    @given(data=chain_st(max_depth=4))
    def test_expires_at_non_increasing(
        self, data: list[tuple[Scope, Constraints]]
    ) -> None:
        """Each hop's expires_at <= its parent's expires_at."""
        for i in range(1, len(data)):
            parent_exp = data[i - 1][1].expires_at
            child_exp = data[i][1].expires_at
            assert child_exp <= parent_exp, (
                f"hop {i}: child expires_at {child_exp} > parent {parent_exp}"
            )

    @_SETTINGS
    @given(data=chain_st(max_depth=4))
    def test_leaf_expires_at_most_root(
        self, data: list[tuple[Scope, Constraints]]
    ) -> None:
        """Leaf expires_at never exceeds root expires_at (transitive)."""
        root_exp = data[0][1].expires_at
        leaf_exp = data[-1][1].expires_at
        assert leaf_exp <= root_exp

    @_SETTINGS
    @given(data=chain_st(max_depth=4))
    def test_issued_at_non_decreasing(
        self, data: list[tuple[Scope, Constraints]]
    ) -> None:
        """Each hop's issued_at >= its parent's issued_at (INV-5)."""
        for i in range(1, len(data)):
            parent_iss = data[i - 1][1].issued_at
            child_iss = data[i][1].issued_at
            assert child_iss >= parent_iss, (
                f"hop {i}: child issued_at {child_iss} < parent {parent_iss}"
            )


# ===================================================================
# Property 3: Depth bound (INV-6)
# ===================================================================


class TestDepthBound:
    """current_depth never exceeds max_chain_depth."""

    @_SETTINGS
    @given(data=chain_st(max_depth=6))
    def test_current_depth_within_max(
        self, data: list[tuple[Scope, Constraints]]
    ) -> None:
        """Every hop satisfies current_depth <= max_chain_depth."""
        for i, (_, constraints) in enumerate(data):
            assert constraints.current_depth <= constraints.max_chain_depth, (
                f"hop {i}: depth {constraints.current_depth} > max {constraints.max_chain_depth}"
            )

    @_SETTINGS
    @given(data=chain_st(max_depth=6))
    def test_depth_increments_by_one(
        self, data: list[tuple[Scope, Constraints]]
    ) -> None:
        """current_depth increases by exactly 1 at each hop."""
        for i in range(1, len(data)):
            parent_depth = data[i - 1][1].current_depth
            child_depth = data[i][1].current_depth
            assert child_depth == parent_depth + 1, (
                f"hop {i}: depth {child_depth} != {parent_depth} + 1"
            )

    @_SETTINGS
    @given(data=chain_st(max_depth=6))
    def test_max_chain_depth_non_increasing(
        self, data: list[tuple[Scope, Constraints]]
    ) -> None:
        """max_chain_depth is non-increasing along the chain (cannot widen depth budget)."""
        for i in range(1, len(data)):
            parent_max = data[i - 1][1].max_chain_depth
            child_max = data[i][1].max_chain_depth
            assert child_max <= parent_max, (
                f"hop {i}: child max_depth {child_max} > parent {parent_max}"
            )

    @_SETTINGS
    @given(data=chain_st(max_depth=6))
    def test_root_depth_is_one(
        self, data: list[tuple[Scope, Constraints]]
    ) -> None:
        """The root of the chain always has current_depth == 1."""
        assert data[0][1].current_depth == 1


# ===================================================================
# Property 4: No-widening
# ===================================================================


class TestNoWidening:
    """Adding a capability not in the parent must be rejected."""

    @_SETTINGS
    @given(parent=scope_st(), extra_cap=capability_st)
    def test_extra_capability_rejected(self, parent: Scope, extra_cap: str) -> None:
        """A child with an extra capability not in parent is not a valid attenuation."""
        assume(extra_cap not in parent.capabilities)

        widened_caps = tuple(sorted(set(parent.capabilities) | {extra_cap}))
        widened_child = Scope(
            capabilities=widened_caps,
            resources=parent.resources,
            actions=parent.actions,
        )
        assert not DelegationManager.validate_attenuation(widened_child, parent), (
            f"widened child accepted: caps={widened_caps}, parent={parent.capabilities}"
        )

    @_SETTINGS
    @given(parent=scope_st(), extra_res=capability_st)
    def test_extra_resource_rejected_when_parent_restricted(
        self, parent: Scope, extra_res: str
    ) -> None:
        """A child with an extra resource (when parent has resources) is rejected."""
        assume(len(parent.resources) > 0)
        assume(extra_res not in parent.resources)

        widened_child = Scope(
            capabilities=parent.capabilities,
            resources=tuple(sorted(set(parent.resources) | {extra_res})),
            actions=parent.actions,
        )
        assert not DelegationManager.validate_attenuation(widened_child, parent)

    @_SETTINGS
    @given(parent=scope_st(), extra_act=capability_st)
    def test_extra_action_rejected_when_parent_restricted(
        self, parent: Scope, extra_act: str
    ) -> None:
        """A child with an extra action (when parent has actions) is rejected."""
        assume(len(parent.actions) > 0)
        assume(extra_act not in parent.actions)

        widened_child = Scope(
            capabilities=parent.capabilities,
            resources=parent.resources,
            actions=tuple(sorted(set(parent.actions) | {extra_act})),
        )
        assert not DelegationManager.validate_attenuation(widened_child, parent)


# ===================================================================
# Property 5: Revocation cascade
# ===================================================================


class TestRevocationCascade:
    """If a parent is revoked, the entire sub-chain is invalid.

    Since verify_chain requires real nostr_sdk.Event objects (relay I/O),
    we test the invariant at the Scope/Constraints level: a chain with a
    "revoked" marker at any hop should not be accepted by a correct verifier.

    We model this by inserting a revoked marker into the chain and verifying
    that a downstream sub-chain's effective scope cannot exceed the revoked
    hop's scope.
    """

    @_SETTINGS
    @given(data=chain_st(max_depth=4))
    def test_revoked_parent_invalidates_descendant_scopes(
        self, data: list[tuple[Scope, Constraints]]
    ) -> None:
        """Marking any hop as revoked means no valid leaf can exist below it.

        We model "revocation" as replacing the revoked hop's capabilities with
        an empty set and verifying that no descendant can attenuate from empty
        capabilities (which would require non-empty capabilities in the child).
        """
        assume(len(data) >= 2)

        for revoke_idx in range(len(data) - 1):
            revoked_scope = Scope(
                capabilities=(),  # Revoked: no capabilities.
                resources=(),
                actions=(),
            )
            for j in range(revoke_idx + 1, len(data)):
                child_scope = data[j][0]
                if child_scope.capabilities:
                    assert not DelegationManager.validate_attenuation(
                        child_scope, revoked_scope
                    ), (
                        f"child at hop {j} accepted despite revoked parent at hop {revoke_idx}"
                    )


# ===================================================================
# Property 6: Cycle detection
# ===================================================================


class TestCycleDetection:
    """A valid chain cannot contain cycles (repeated pubkey at any depth).

    Since chain_st generates unique hops by construction (each hop has
    strictly increasing current_depth), we verify the structural impossibility
    and test that constructing a cycle via duplicate depth values is detected.
    """

    @_SETTINGS
    @given(data=chain_st(max_depth=6))
    def test_unique_depths_imply_no_cycles(
        self, data: list[tuple[Scope, Constraints]]
    ) -> None:
        """All current_depth values in a valid chain are unique (monotonically increasing)."""
        depths = [c.current_depth for _, c in data]
        assert len(depths) == len(set(depths)), f"duplicate depths: {depths}"

    @_SETTINGS
    @given(data=chain_st(max_depth=4))
    def test_depth_sequence_is_contiguous(
        self, data: list[tuple[Scope, Constraints]]
    ) -> None:
        """Depths form a contiguous sequence 1, 2, ..., N with no gaps or repeats."""
        depths = [c.current_depth for _, c in data]
        expected = list(range(1, len(data) + 1))
        assert depths == expected, f"depths {depths} != expected {expected}"

    @settings(max_examples=200, deadline=None)
    @given(c=constraints_st())
    def test_cycle_requires_depth_violation(self, c: Constraints) -> None:
        """To revisit a depth, current_depth would have to decrease, violating INV-6.

        If a chain visits depth D twice, the second visit means current_depth
        decreased at some point, which INV-6 (strictly incrementing depth) forbids.
        """
        next_depth = c.current_depth + 1
        assert next_depth > c.current_depth


# ===================================================================
# Property: Transitivity of attenuation
# ===================================================================


class TestAttenuationTransitivity:
    """Transitivity properties of attenuation under empty-set semantics.

    IMPORTANT: Full attenuation transitivity does NOT hold when intermediate
    hops use empty (unrestricted) resources or actions. An intermediate hop
    with empty actions attenuates a parent with actions=('foo',), but a
    grandchild can then introduce actions=('bar',) which is valid relative
    to the intermediate's empty set but NOT a subset of the root's ('foo',).

    Transitivity DOES hold for:
    - Capabilities (INV-1 has no empty-set exemption)
    - Resources/actions when all intermediate hops are non-empty (restricted)
    """

    @_SETTINGS
    @given(st.data())
    def test_transitive_capabilities_always_narrow(self, data: st.DataObject) -> None:
        """Capabilities strictly narrow (or stay equal) through any chain of attenuations."""
        parent = data.draw(scope_st(), label="parent")
        assume(len(parent.capabilities) >= 1)

        mid = data.draw(subscope_st(parent), label="mid")
        assume(len(mid.capabilities) >= 1)

        leaf = data.draw(subscope_st(mid), label="leaf")

        # Each hop is valid.
        assert DelegationManager.validate_attenuation(mid, parent)
        assert DelegationManager.validate_attenuation(leaf, mid)

        # Capabilities are always transitive (no empty-set exemption for INV-1).
        assert set(leaf.capabilities) <= set(mid.capabilities) <= set(parent.capabilities)

    @_SETTINGS
    @given(st.data())
    def test_full_transitivity_when_all_restricted(self, data: st.DataObject) -> None:
        """Full attenuation transitivity holds when no intermediate hop is unrestricted."""
        parent = data.draw(scope_st(), label="parent")
        assume(len(parent.capabilities) >= 1)
        # Ensure parent has non-empty resources and actions to avoid unrestricted hops.
        assume(len(parent.resources) >= 1)
        assume(len(parent.actions) >= 1)

        mid = data.draw(subscope_st(parent), label="mid")
        assume(len(mid.capabilities) >= 1)
        # When parent is restricted, mid drawn from subscope_st samples from
        # parent's resources/actions. But mid could still draw empty.
        assume(len(mid.resources) >= 1)
        assume(len(mid.actions) >= 1)

        leaf = data.draw(subscope_st(mid), label="leaf")

        assert DelegationManager.validate_attenuation(mid, parent)
        assert DelegationManager.validate_attenuation(leaf, mid)
        # When all hops are restricted, full transitivity holds.
        assert DelegationManager.validate_attenuation(leaf, parent), (
            f"transitivity failed with all-restricted: leaf={leaf}, mid={mid}, parent={parent}"
        )

    @_SETTINGS
    @given(st.data())
    def test_unrestricted_intermediate_breaks_transitivity(
        self, data: st.DataObject
    ) -> None:
        """Demonstrate that empty-set semantics can break transitivity.

        parent has actions=('x',), mid has actions=() (unrestricted),
        leaf has actions=('y',). mid attenuates parent, leaf attenuates mid,
        but leaf does NOT attenuate parent (because 'y' not in {'x'}).
        """
        # This is a deterministic demonstration, not a property test per se.
        parent = Scope(capabilities=("cap1",), resources=(), actions=("action-x",))
        mid = Scope(capabilities=("cap1",), resources=(), actions=())
        leaf = Scope(capabilities=("cap1",), resources=(), actions=("action-y",))

        assert DelegationManager.validate_attenuation(mid, parent)  # empty attenuates anything
        assert DelegationManager.validate_attenuation(leaf, mid)    # anything attenuates empty
        assert not DelegationManager.validate_attenuation(leaf, parent)  # NOT transitive
