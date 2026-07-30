"""Integration tests: Kind 38100 Agent Identity lifecycle against live relays.

Tests the full create -> publish -> resolve -> verify -> rotate -> decommission
lifecycle using the AgentIdentity class and 3 live strfry relay instances.

Each test uses unique d-tags (incorporating test name + timestamp) to avoid
cross-test pollution on the shared relay state.

Run: pytest tests/integration/test_identity_lifecycle.py -m integration -v
Requires: docker compose up -d (3 relays + LND nodes)
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
    return ns.Keys.parse(hashlib.sha256(f"det-lifecycle-{_KEY_CTR}".encode()).hexdigest())

from nostr_agent.identity import AgentIdentity
from nostr_agent.types import VerificationStatus

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("docker_env")]


# ---------------------------------------------------------------------------
# Test: Create and publish identity
# ---------------------------------------------------------------------------


class TestCreateAndPublish:
    """Verify basic identity creation and relay publication."""

    async def test_create_and_publish(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """Create AgentIdentity, publish to all 3 relays, verify success."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        d_tag = unique_d_tag("create-pub")
        identity = await AgentIdentity.create(
            operator_keys=operator_keys,
            agent_name="test-create-agent",
            d_tag=d_tag,
            description="Integration test agent for create-and-publish",
            capabilities=["relay-read", "relay-write"],
            relay_urls=relay_urls,
        )

        result = await identity.publish(relay_urls)

        assert result.success_count >= 2, (
            f"Expected >= 2 relays to accept, got {result.success_count}. "
            f"Failed: {result.failed}"
        )
        assert len(result.event_id) == 64, "event_id should be 64 hex chars"
        assert all(c in "0123456789abcdef" for c in result.event_id)

    async def test_published_identity_has_correct_status(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """Published identity should have status 'active'."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        d_tag = unique_d_tag("status-check")
        identity = await AgentIdentity.create(
            operator_keys=operator_keys,
            agent_name="test-status-agent",
            d_tag=d_tag,
            description="Status verification test",
            capabilities=["relay-read"],
            relay_urls=relay_urls,
        )
        await identity.publish(relay_urls)

        assert identity.status == "active"
        assert identity.d_tag == d_tag


# ---------------------------------------------------------------------------
# Test: Resolve published identity
# ---------------------------------------------------------------------------


class TestResolveIdentity:
    """Verify identity resolution from relays."""

    async def test_resolve_returns_published_event(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """After publishing, resolve() returns the event with matching fields."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        d_tag = unique_d_tag("resolve")
        identity = await AgentIdentity.create(
            operator_keys=operator_keys,
            agent_name="resolve-test-agent",
            d_tag=d_tag,
            description="Integration test agent for resolve",
            capabilities=["relay-read", "relay-write"],
            relay_urls=relay_urls,
        )
        pub_result = await identity.publish(relay_urls)

        # Small delay to ensure relay propagation.
        await asyncio.sleep(0.5)

        # Resolve by d-tag (no pubkey filter -- search across all pubkeys for this d-tag).
        resolved = await AgentIdentity.resolve(d_tag, relay_urls)

        assert resolved is not None, f"resolve() returned None for d_tag={d_tag}"

        # Verify content matches.
        content = json.loads(resolved.content())
        assert content["name"] == "resolve-test-agent"
        assert content["status"] == "active"
        assert "relay-read" in content["capabilities"]
        assert "relay-write" in content["capabilities"]

    async def test_resolve_nonexistent_returns_none(
        self, relay_urls,
    ) -> None:
        """resolve() for a d-tag that was never published returns None."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        resolved = await AgentIdentity.resolve(
            "nonexistent-dtag-12345678", relay_urls,
        )
        assert resolved is None


# ---------------------------------------------------------------------------
# Test: Multi-relay consistency
# ---------------------------------------------------------------------------


class TestMultiRelayConsistency:
    """Verify events are consistently available across all 3 relays."""

    async def test_all_relays_serve_same_event(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """Publish to all 3 relays, query each individually, verify same event_id."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        d_tag = unique_d_tag("multi-relay")
        identity = await AgentIdentity.create(
            operator_keys=operator_keys,
            agent_name="multi-relay-agent",
            d_tag=d_tag,
            description="Multi-relay consistency test",
            capabilities=["relay-read"],
            relay_urls=relay_urls,
        )
        pub_result = await identity.publish(relay_urls)
        expected_event_id = pub_result.event_id

        await asyncio.sleep(0.5)

        # Query each relay individually.
        for i, single_url in enumerate(relay_urls):
            resolved = await AgentIdentity.resolve(d_tag, [single_url])
            assert resolved is not None, (
                f"Relay {single_url} (index {i}) did not return the event"
            )
            assert resolved.id().to_hex() == expected_event_id, (
                f"Relay {single_url} returned different event_id: "
                f"{resolved.id().to_hex()} != {expected_event_id}"
            )


# ---------------------------------------------------------------------------
# Test: Key rotation end-to-end
# ---------------------------------------------------------------------------


class TestKeyRotation:
    """Verify the 3-step atomic key rotation protocol."""

    async def test_rotation_end_to_end(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """Create identity with pre-rotation, rotate, verify chain."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        d_tag = unique_d_tag("rotation")

        # Step 1: Create identity (auto-generates next key for pre-rotation).
        identity = await AgentIdentity.create(
            operator_keys=operator_keys,
            agent_name="rotation-test-agent",
            d_tag=d_tag,
            description="Key rotation integration test",
            capabilities=["relay-read"],
            relay_urls=relay_urls,
        )
        old_pubkey = identity.pubkey_hex
        assert identity.next_key_hash, "Pre-rotation hash should be set"

        # Publish initial identity.
        pub1 = await identity.publish(relay_urls)
        assert pub1.success_count >= 2

        # Step 2: Rotate using the pre-committed key.
        # The create() method stored _next_keys internally.
        next_sk = identity._next_secret_key
        assert next_sk is not None, "Internal next secret key should be stored"

        # Generate the next-next key for the new pre-rotation commitment.
        next_next_keys = _det_keys()

        rotation_result = await identity.rotate(
            new_secret_key=next_sk,
            next_next_public_key=next_next_keys.public_key(),
            relay_urls=relay_urls,
        )

        assert rotation_result.old_pubkey == old_pubkey
        assert rotation_result.new_pubkey != old_pubkey
        assert rotation_result.rotation_timestamp > 0

        await asyncio.sleep(0.5)

        # Step 3: Resolve by d-tag should return the NEW active identity.
        resolved = await AgentIdentity.resolve(d_tag, relay_urls)
        assert resolved is not None, "resolve() should find the new active identity"

        new_content = json.loads(resolved.content())
        assert new_content["status"] == "active"
        assert "rotation_proof" in new_content

    async def test_rotation_chain_verification(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """After rotation, verify() on the new event should report chain_depth >= 1."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        d_tag = unique_d_tag("rot-verify")

        identity = await AgentIdentity.create(
            operator_keys=operator_keys,
            agent_name="rot-verify-agent",
            d_tag=d_tag,
            description="Rotation verification test",
            capabilities=["relay-read"],
            relay_urls=relay_urls,
        )
        await identity.publish(relay_urls)

        next_sk = identity._next_secret_key
        next_next_keys = _det_keys()
        await identity.rotate(
            new_secret_key=next_sk,
            next_next_public_key=next_next_keys.public_key(),
            relay_urls=relay_urls,
        )

        await asyncio.sleep(0.5)

        resolved = await AgentIdentity.resolve(d_tag, relay_urls)
        assert resolved is not None

        vr = await AgentIdentity.verify(resolved, relay_urls)
        assert vr.is_valid, f"Verification failed: {vr.errors}"
        assert vr.chain_depth >= 1, f"Expected chain_depth >= 1, got {vr.chain_depth}"


# ---------------------------------------------------------------------------
# Test: Decommission
# ---------------------------------------------------------------------------


class TestDecommission:
    """Verify permanent identity retirement."""

    async def test_decommission_changes_status(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """Decommissioned identity shows status 'decommissioned' on relays."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        d_tag = unique_d_tag("decomm")
        identity = await AgentIdentity.create(
            operator_keys=operator_keys,
            agent_name="decomm-test-agent",
            d_tag=d_tag,
            description="Decommission integration test",
            capabilities=["relay-read"],
            relay_urls=relay_urls,
        )
        await identity.publish(relay_urls)
        assert identity.status == "active"

        decomm_result = await identity.decommission(relay_urls)
        assert decomm_result.pubkey == identity.pubkey_hex
        assert decomm_result.timestamp > 0

        # Identity object should now be decommissioned.
        assert identity.status == "decommissioned"

    async def test_resolve_returns_none_after_decommission(
        self, operator_keys, relay_urls, unique_d_tag,
    ) -> None:
        """resolve() should return None for a decommissioned identity (no active event)."""
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        d_tag = unique_d_tag("decomm-resolve")
        identity = await AgentIdentity.create(
            operator_keys=operator_keys,
            agent_name="decomm-resolve-agent",
            d_tag=d_tag,
            description="Decommission resolve test",
            capabilities=["relay-read"],
            relay_urls=relay_urls,
        )
        await identity.publish(relay_urls)
        await identity.decommission(relay_urls)

        await asyncio.sleep(0.5)

        resolved = await AgentIdentity.resolve(d_tag, relay_urls)
        assert resolved is None, (
            "resolve() should return None after decommission -- "
            "no active identity should remain"
        )
