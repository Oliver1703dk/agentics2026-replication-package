"""Integration tests: Kind 38101 Delegation Chain end-to-end against live relays.

Tests operator->agent root delegation, agent->sub-agent sub-delegation,
chain verification across relays, revocation cascade, expiry, and list queries.

Each test uses unique d-tags to avoid cross-test pollution.

Run: pytest tests/integration/test_delegation_chain_e2e.py -m integration -v
Requires: docker compose up -d (3 relays)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time

import nostr_sdk as ns
import pytest

_KEY_CTR = 0


def _det_keys() -> ns.Keys:
    """Deterministic key generation for reproducible tests."""
    global _KEY_CTR
    _KEY_CTR += 1
    return ns.Keys.parse(hashlib.sha256(f"det-deleg-e2e-{_KEY_CTR}".encode()).hexdigest())

from nostr_agent.delegation import DelegationManager
from nostr_agent.identity import AgentIdentity
from nostr_agent.types import (
    AttenuationError,
    Constraints,
    DepthExceededError,
    Scope,
)

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("docker_env")]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_and_publish_identity(
    operator_keys: ns.Keys,
    d_tag: str,
    name: str,
    capabilities: list[str],
    relay_urls: list[str],
) -> AgentIdentity:
    """Create and publish an identity, returning the AgentIdentity instance."""
    identity = await AgentIdentity.create(
        operator_keys=operator_keys,
        agent_name=name,
        d_tag=d_tag,
        description=f"Integration test: {name}",
        capabilities=capabilities,
        relay_urls=relay_urls,
    )
    result = await identity.publish(relay_urls)
    assert result.success_count >= 1, f"Failed to publish {name}: {result.failed}"
    return identity


# ---------------------------------------------------------------------------
# Test: Root delegation (operator -> agent)
# ---------------------------------------------------------------------------


class TestRootDelegation:
    """Operator delegates to an agent (depth 1)."""

    async def test_root_delegation_publish(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """Create operator identity, delegate to agent, verify on relay."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        now = int(time.time())
        capabilities = ["relay-read", "relay-write"]

        # Create and publish operator identity.
        op_d_tag = unique_d_tag("root-del-op")
        operator_identity = await _create_and_publish_identity(
            operator_keys, op_d_tag, "root-del-operator", capabilities, relay_urls,
        )

        # Create agent identity (separate keys).
        agent_keys = _det_keys()
        agent_d_tag = unique_d_tag("root-del-agent")
        agent_identity = await _create_and_publish_identity(
            operator_keys, agent_d_tag, "root-del-agent", capabilities, relay_urls,
        )

        # Operator delegates to agent.
        dm = DelegationManager(operator_identity)
        scope = Scope(
            capabilities=("relay-read", "relay-write"),
            resources=(),
            actions=("read", "write"),
        )
        constraints = Constraints(
            expires_at=now + 7200,
            max_chain_depth=3,
            current_depth=1,
            issued_at=now,
        )

        result = await dm.delegate(
            delegatee_pubkey=agent_identity.pubkey_hex,
            scope=scope,
            constraints=constraints,
            parent_event=None,  # Root delegation.
            relay_urls=relay_urls,
        )

        assert result.success_count >= 1, f"Delegation publish failed: {result.failed}"
        assert len(result.event_id) == 64

    async def test_root_delegation_queryable(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """Published root delegation should be queryable via list_active."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        now = int(time.time())
        capabilities = ["relay-read"]

        op_d_tag = unique_d_tag("rootq-op")
        operator_identity = await _create_and_publish_identity(
            operator_keys, op_d_tag, "rootq-operator", capabilities, relay_urls,
        )

        agent_d_tag = unique_d_tag("rootq-agent")
        agent_identity = await _create_and_publish_identity(
            operator_keys, agent_d_tag, "rootq-agent", capabilities, relay_urls,
        )

        dm = DelegationManager(operator_identity)
        scope = Scope(capabilities=("relay-read",))
        constraints = Constraints(
            expires_at=now + 7200,
            max_chain_depth=3,
            current_depth=1,
            issued_at=now,
        )
        await dm.delegate(
            delegatee_pubkey=agent_identity.pubkey_hex,
            scope=scope,
            constraints=constraints,
            relay_urls=relay_urls,
        )

        await asyncio.sleep(0.5)

        # Query active delegations by operator.
        active = await DelegationManager.list_active(
            operator_identity.pubkey_hex, relay_urls,
        )
        # Should find at least 1 delegation (may find others from other tests).
        assert len(active) >= 1, "list_active should return at least 1 delegation"

        # Verify one of them is for our agent.
        found_delegatee = False
        for ev in active:
            for tag in ev.tags().to_vec():
                vec = tag.as_vec()
                if len(vec) >= 2 and vec[0] == "p" and vec[1] == agent_identity.pubkey_hex:
                    found_delegatee = True
                    break
        assert found_delegatee, "Delegation to agent not found in list_active results"


# ---------------------------------------------------------------------------
# Test: Sub-delegation (agent A -> agent B)
# ---------------------------------------------------------------------------


class TestSubDelegation:
    """Agent A (depth 1) delegates to agent B (depth 2) with attenuation."""

    async def test_sub_delegation_attenuated(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """Sub-delegation with attenuated scope succeeds and is verifiable."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        now = int(time.time())
        parent_caps = ["relay-read", "relay-write"]
        child_caps = ["relay-read"]  # Attenuated: subset of parent.

        # Create operator + publish identity.
        op_d_tag = unique_d_tag("subdel-op")
        operator_identity = await _create_and_publish_identity(
            operator_keys, op_d_tag, "subdel-operator", parent_caps, relay_urls,
        )

        # Create agent A.
        agent_a_d_tag = unique_d_tag("subdel-a")
        agent_a_identity = await _create_and_publish_identity(
            operator_keys, agent_a_d_tag, "subdel-agent-a", parent_caps, relay_urls,
        )

        # Create agent B.
        agent_b_d_tag = unique_d_tag("subdel-b")
        agent_b_identity = await _create_and_publish_identity(
            operator_keys, agent_b_d_tag, "subdel-agent-b", child_caps, relay_urls,
        )

        # Root delegation: operator -> A.
        dm_op = DelegationManager(operator_identity)
        parent_scope = Scope(capabilities=tuple(sorted(parent_caps)))
        parent_constraints = Constraints(
            expires_at=now + 7200,
            max_chain_depth=3,
            current_depth=1,
            issued_at=now,
        )
        parent_result = await dm_op.delegate(
            delegatee_pubkey=agent_a_identity.pubkey_hex,
            scope=parent_scope,
            constraints=parent_constraints,
            relay_urls=relay_urls,
        )
        assert parent_result.success_count >= 1

        await asyncio.sleep(0.5)

        # Fetch the parent delegation event for A to use as parent_event.
        active_for_a = await DelegationManager.list_received(
            agent_a_identity.pubkey_hex, relay_urls,
        )
        assert len(active_for_a) >= 1, "Agent A should have received delegation"
        parent_event = active_for_a[0]

        # Sub-delegation: A -> B (attenuated scope).
        dm_a = DelegationManager(agent_a_identity)
        child_scope = Scope(capabilities=("relay-read",))
        child_constraints = Constraints(
            expires_at=now + 3600,  # Narrower than parent.
            max_chain_depth=3,
            current_depth=2,
            issued_at=now,
        )
        child_result = await dm_a.delegate(
            delegatee_pubkey=agent_b_identity.pubkey_hex,
            scope=child_scope,
            constraints=child_constraints,
            parent_event=parent_event,
            relay_urls=relay_urls,
        )
        assert child_result.success_count >= 1

        await asyncio.sleep(0.5)

        # Verify: list_received for B should include the sub-delegation.
        received_b = await DelegationManager.list_received(
            agent_b_identity.pubkey_hex, relay_urls,
        )
        assert len(received_b) >= 1, "Agent B should have received sub-delegation"

    async def test_widened_scope_rejected(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """Attempting to widen scope on sub-delegation raises AttenuationError."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        now = int(time.time())

        op_d_tag = unique_d_tag("widen-op")
        operator_identity = await _create_and_publish_identity(
            operator_keys, op_d_tag, "widen-operator",
            ["relay-read"], relay_urls,
        )

        agent_a_d_tag = unique_d_tag("widen-a")
        agent_a_identity = await _create_and_publish_identity(
            operator_keys, agent_a_d_tag, "widen-agent-a",
            ["relay-read", "relay-write"], relay_urls,
        )

        agent_b_d_tag = unique_d_tag("widen-b")
        agent_b_identity = await _create_and_publish_identity(
            operator_keys, agent_b_d_tag, "widen-agent-b",
            ["relay-read", "relay-write"], relay_urls,
        )

        # Root delegation: operator -> A with narrow scope.
        dm_op = DelegationManager(operator_identity)
        narrow_scope = Scope(capabilities=("relay-read",))
        constraints = Constraints(
            expires_at=now + 7200,
            max_chain_depth=3,
            current_depth=1,
            issued_at=now,
        )
        await dm_op.delegate(
            delegatee_pubkey=agent_a_identity.pubkey_hex,
            scope=narrow_scope,
            constraints=constraints,
            relay_urls=relay_urls,
        )

        await asyncio.sleep(0.5)

        # Fetch parent event for A.
        received_a = await DelegationManager.list_received(
            agent_a_identity.pubkey_hex, relay_urls,
        )
        assert len(received_a) >= 1
        parent_event = received_a[0]

        # Attempt sub-delegation with WIDER scope: should fail.
        dm_a = DelegationManager(agent_a_identity)
        wide_scope = Scope(capabilities=("relay-read", "relay-write"))  # Wider!
        child_constraints = Constraints(
            expires_at=now + 3600,
            max_chain_depth=3,
            current_depth=2,
            issued_at=now,
        )

        with pytest.raises(AttenuationError):
            await dm_a.delegate(
                delegatee_pubkey=agent_b_identity.pubkey_hex,
                scope=wide_scope,
                constraints=child_constraints,
                parent_event=parent_event,
                relay_urls=relay_urls,
            )


# ---------------------------------------------------------------------------
# Test: Chain verification across relays
# ---------------------------------------------------------------------------


class TestChainVerification:
    """Verify a multi-hop delegation chain from relays."""

    async def test_chain_verify_depth_2(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """Build operator -> A -> B chain, verify B's chain from relays."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        now = int(time.time())
        caps = ["relay-read", "relay-write"]

        op_d_tag = unique_d_tag("chainv-op")
        operator_identity = await _create_and_publish_identity(
            operator_keys, op_d_tag, "chainv-operator", caps, relay_urls,
        )

        agent_a_d_tag = unique_d_tag("chainv-a")
        agent_a_identity = await _create_and_publish_identity(
            operator_keys, agent_a_d_tag, "chainv-agent-a", caps, relay_urls,
        )

        agent_b_d_tag = unique_d_tag("chainv-b")
        agent_b_identity = await _create_and_publish_identity(
            operator_keys, agent_b_d_tag, "chainv-agent-b", ["relay-read"], relay_urls,
        )

        # Root: operator -> A.
        dm_op = DelegationManager(operator_identity)
        await dm_op.delegate(
            delegatee_pubkey=agent_a_identity.pubkey_hex,
            scope=Scope(capabilities=tuple(sorted(caps))),
            constraints=Constraints(
                expires_at=now + 7200,
                max_chain_depth=3,
                current_depth=1,
                issued_at=now,
            ),
            relay_urls=relay_urls,
        )

        await asyncio.sleep(0.5)

        # Sub: A -> B.
        received_a = await DelegationManager.list_received(
            agent_a_identity.pubkey_hex, relay_urls,
        )
        assert len(received_a) >= 1
        parent_event = received_a[0]

        dm_a = DelegationManager(agent_a_identity)
        await dm_a.delegate(
            delegatee_pubkey=agent_b_identity.pubkey_hex,
            scope=Scope(capabilities=("relay-read",)),
            constraints=Constraints(
                expires_at=now + 3600,
                max_chain_depth=3,
                current_depth=2,
                issued_at=now,
            ),
            parent_event=parent_event,
            relay_urls=relay_urls,
        )

        await asyncio.sleep(0.5)

        # Fetch B's delegation event and verify the chain.
        received_b = await DelegationManager.list_received(
            agent_b_identity.pubkey_hex, relay_urls,
        )
        assert len(received_b) >= 1
        leaf_event = received_b[0]

        chain_result = await DelegationManager.verify_chain(leaf_event, relay_urls)
        assert chain_result.is_valid, (
            f"Chain verification failed: {chain_result.errors}, "
            f"violated: {chain_result.violated_invariant}"
        )
        assert chain_result.chain_depth == 2, (
            f"Expected chain_depth=2, got {chain_result.chain_depth}"
        )


# ---------------------------------------------------------------------------
# Test: Revocation cascade
# ---------------------------------------------------------------------------


class TestRevocationCascade:
    """Revoking a parent delegation invalidates child chains."""

    async def test_revoke_parent_invalidates_child(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """Build op->A->B chain, revoke op->A, verify B's chain fails."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        now = int(time.time())
        caps = ["relay-read"]

        op_d_tag = unique_d_tag("revoke-op")
        operator_identity = await _create_and_publish_identity(
            operator_keys, op_d_tag, "revoke-operator", caps, relay_urls,
        )

        agent_a_d_tag = unique_d_tag("revoke-a")
        agent_a_identity = await _create_and_publish_identity(
            operator_keys, agent_a_d_tag, "revoke-agent-a", caps, relay_urls,
        )

        agent_b_d_tag = unique_d_tag("revoke-b")
        agent_b_identity = await _create_and_publish_identity(
            operator_keys, agent_b_d_tag, "revoke-agent-b", caps, relay_urls,
        )

        # Root: operator -> A.
        dm_op = DelegationManager(operator_identity)
        parent_scope = Scope(capabilities=("relay-read",))
        parent_result = await dm_op.delegate(
            delegatee_pubkey=agent_a_identity.pubkey_hex,
            scope=parent_scope,
            constraints=Constraints(
                expires_at=now + 7200,
                max_chain_depth=3,
                current_depth=1,
                issued_at=now,
            ),
            relay_urls=relay_urls,
        )

        await asyncio.sleep(0.5)

        # Sub: A -> B.
        received_a = await DelegationManager.list_received(
            agent_a_identity.pubkey_hex, relay_urls,
        )
        assert len(received_a) >= 1
        parent_event = received_a[0]

        # Extract the d-tag of the parent delegation for later revocation.
        parent_d_tag = parent_event.tags().identifier()
        assert parent_d_tag, "Parent delegation must have a d-tag"

        dm_a = DelegationManager(agent_a_identity)
        await dm_a.delegate(
            delegatee_pubkey=agent_b_identity.pubkey_hex,
            scope=parent_scope,
            constraints=Constraints(
                expires_at=now + 3600,
                max_chain_depth=3,
                current_depth=2,
                issued_at=now,
            ),
            parent_event=parent_event,
            relay_urls=relay_urls,
        )

        await asyncio.sleep(0.5)

        # Verify B's chain is valid BEFORE revocation.
        received_b = await DelegationManager.list_received(
            agent_b_identity.pubkey_hex, relay_urls,
        )
        assert len(received_b) >= 1
        leaf_event = received_b[0]

        pre_revoke = await DelegationManager.verify_chain(leaf_event, relay_urls)
        assert pre_revoke.is_valid, "Chain should be valid before revocation"

        # Revoke the operator -> A delegation.
        revoke_result = await dm_op.revoke(parent_d_tag, relay_urls=relay_urls)
        assert revoke_result.success_count >= 1, "Revocation publish failed"

        await asyncio.sleep(0.5)

        # Verify B's chain now FAILS (cascade revocation).
        post_revoke = await DelegationManager.verify_chain(leaf_event, relay_urls)
        assert not post_revoke.is_valid, (
            "Chain should be INVALID after parent revocation"
        )
        assert post_revoke.violated_invariant is not None
        assert "REVOKED" in post_revoke.violated_invariant, (
            f"Expected REVOKED violation, got: {post_revoke.violated_invariant}"
        )


# ---------------------------------------------------------------------------
# Test: Expired delegation
# ---------------------------------------------------------------------------


class TestExpiredDelegation:
    """Delegation with short TTL expires and fails verification."""

    @pytest.mark.slow
    async def test_delegation_expires(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """Create delegation expiring in 2 seconds, wait 3s, verify it fails."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        now = int(time.time())
        caps = ["relay-read"]

        op_d_tag = unique_d_tag("expire-op")
        operator_identity = await _create_and_publish_identity(
            operator_keys, op_d_tag, "expire-operator", caps, relay_urls,
        )

        agent_d_tag = unique_d_tag("expire-agent")
        agent_identity = await _create_and_publish_identity(
            operator_keys, agent_d_tag, "expire-agent", caps, relay_urls,
        )

        # Create delegation expiring in 2 seconds.
        dm = DelegationManager(operator_identity)
        scope = Scope(capabilities=("relay-read",))
        constraints = Constraints(
            expires_at=now + 2,  # Expires in 2 seconds!
            max_chain_depth=3,
            current_depth=1,
            issued_at=now,
        )
        await dm.delegate(
            delegatee_pubkey=agent_identity.pubkey_hex,
            scope=scope,
            constraints=constraints,
            relay_urls=relay_urls,
        )

        await asyncio.sleep(3)  # Wait past expiry.

        # list_active should NOT include the expired delegation.
        active = await DelegationManager.list_active(
            operator_identity.pubkey_hex, relay_urls,
        )
        expired_found = False
        for ev in active:
            for tag in ev.tags().to_vec():
                vec = tag.as_vec()
                if len(vec) >= 2 and vec[0] == "p" and vec[1] == agent_identity.pubkey_hex:
                    expired_found = True
                    break
        assert not expired_found, (
            "Expired delegation should not appear in list_active results"
        )


# ---------------------------------------------------------------------------
# Test: list_active and list_received
# ---------------------------------------------------------------------------


class TestListQueries:
    """Verify list_active and list_received query methods."""

    async def test_list_received_returns_delegations(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """list_received returns delegations TO a specific agent."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        now = int(time.time())
        caps = ["relay-read"]

        op_d_tag = unique_d_tag("listr-op")
        operator_identity = await _create_and_publish_identity(
            operator_keys, op_d_tag, "listr-operator", caps, relay_urls,
        )

        agent_d_tag = unique_d_tag("listr-agent")
        agent_identity = await _create_and_publish_identity(
            operator_keys, agent_d_tag, "listr-agent", caps, relay_urls,
        )

        dm = DelegationManager(operator_identity)
        scope = Scope(capabilities=("relay-read",))
        constraints = Constraints(
            expires_at=now + 7200,
            max_chain_depth=3,
            current_depth=1,
            issued_at=now,
        )
        await dm.delegate(
            delegatee_pubkey=agent_identity.pubkey_hex,
            scope=scope,
            constraints=constraints,
            relay_urls=relay_urls,
        )

        await asyncio.sleep(0.5)

        received = await DelegationManager.list_received(
            agent_identity.pubkey_hex, relay_urls,
        )
        assert len(received) >= 1, "list_received should find at least 1 delegation"

    async def test_revoked_delegation_excluded_from_list_active(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """After revoking a delegation, list_active should exclude it."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        now = int(time.time())
        caps = ["relay-read"]

        op_d_tag = unique_d_tag("listrev-op")
        operator_identity = await _create_and_publish_identity(
            operator_keys, op_d_tag, "listrev-operator", caps, relay_urls,
        )

        agent_d_tag = unique_d_tag("listrev-agent")
        agent_identity = await _create_and_publish_identity(
            operator_keys, agent_d_tag, "listrev-agent", caps, relay_urls,
        )

        dm = DelegationManager(operator_identity)
        scope = Scope(capabilities=("relay-read",))
        constraints = Constraints(
            expires_at=now + 7200,
            max_chain_depth=3,
            current_depth=1,
            issued_at=now,
        )
        del_result = await dm.delegate(
            delegatee_pubkey=agent_identity.pubkey_hex,
            scope=scope,
            constraints=constraints,
            relay_urls=relay_urls,
        )

        await asyncio.sleep(0.5)

        # Find the delegation d-tag.
        received = await DelegationManager.list_received(
            agent_identity.pubkey_hex, relay_urls,
        )
        assert len(received) >= 1
        del_d_tag = received[0].tags().identifier()
        assert del_d_tag

        # Revoke.
        await dm.revoke(del_d_tag, relay_urls=relay_urls)

        await asyncio.sleep(0.5)

        # list_active should not include the revoked delegation for this agent.
        active = await DelegationManager.list_active(
            operator_identity.pubkey_hex, relay_urls,
        )
        revoked_still_listed = False
        for ev in active:
            if ev.tags().identifier() == del_d_tag:
                revoked_still_listed = True
                break
        assert not revoked_still_listed, (
            "Revoked delegation should be excluded from list_active"
        )
