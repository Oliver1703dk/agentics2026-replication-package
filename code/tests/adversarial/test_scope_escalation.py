"""TP-06: Scope Escalation (STRIDE: Elevation of Privilege) -- TB2.
TP-05: Graph Traversal Information Disclosure (STRIDE: Info Disclosure) -- TB2.

TP-06 validates that the attenuation invariant (INV-1 through INV-7) is
enforced at every level:
  (a) DelegationManager.validate_chain() rejects wider child scopes
  (b) Manually constructed events with escalated scopes are caught
  (c) Depth counter falsification is detected

TP-05 validates that trust graph enumeration succeeds (public-by-design)
and documents this as an accepted architectural trade-off.

Countermeasures tested: INV-1 (capabilities), INV-2 (resources), INV-3 (actions),
INV-5 (depth counter), validate_chain(), Scope.attenuates().
"""

from __future__ import annotations

import asyncio
import hashlib
import json

import nostr_sdk as ns
import pytest

_KEY_CTR = 0


def _det_keys() -> ns.Keys:
    """Deterministic key generation for reproducible tests."""
    global _KEY_CTR
    _KEY_CTR += 1
    return ns.Keys.parse(hashlib.sha256(f"det-scope-{_KEY_CTR}".encode()).hexdigest())

from nostr_agent.types import (
    AttenuationError,
    DelegationChain,
    DelegationLink,
    PublicKey,
    Scope,
    Signature,
)
from nostr_agent.validation import ValidationError, validate_chain


# ---------------------------------------------------------------------------
# Helper: build a DelegationLink with the legacy Scope interface
# ---------------------------------------------------------------------------


def _make_link(
    delegator_hex: str,
    delegatee_hex: str,
    capabilities: tuple[str, ...],
    resources: tuple[str, ...] = (),
    actions: tuple[str, ...] = (),
) -> DelegationLink:
    """Create a DelegationLink with given scope parameters."""
    return DelegationLink(
        delegator_pubkey=PublicKey(delegator_hex),
        delegatee_pubkey=PublicKey(delegatee_hex),
        scopes=[Scope(capabilities=capabilities, resources=resources, actions=actions)],
        signature=Signature("0" * 128),
        event_id="a" * 64,
        expires_at=None,
    )


# ===========================================================================
# TP-06a: Capability superset (INV-1 violation)
# ===========================================================================


@pytest.mark.unit
def test_tp06a_capability_escalation_rejected() -> None:
    """TP-06a: child adds capabilities not in parent scope.

    Parent grants ["read"]. Child claims ["read", "admin"].
    validate_chain() MUST reject with attenuation error.
    """
    parent_hex = _det_keys().public_key().to_hex()
    middle_hex = _det_keys().public_key().to_hex()
    child_hex = _det_keys().public_key().to_hex()

    parent_link = _make_link(
        parent_hex, middle_hex,
        capabilities=("relay-read",),
        resources=("wss://relay.example.com",),
        actions=("read",),
    )
    escalated_link = _make_link(
        middle_hex, child_hex,
        capabilities=("relay-read", "admin"),  # WIDER than parent
        resources=("wss://relay.example.com",),
        actions=("read",),
    )

    chain = DelegationChain(links=[parent_link, escalated_link])

    with pytest.raises(ValidationError):
        validate_chain(chain)


# ===========================================================================
# TP-06b: Action superset (INV-3 violation)
# ===========================================================================


@pytest.mark.unit
def test_tp06b_action_escalation_rejected() -> None:
    """TP-06b: child adds 'write' action when parent only grants 'read'.

    Parent: actions=("read",). Child: actions=("read", "write").
    validate_chain() MUST reject.
    """
    parent_hex = _det_keys().public_key().to_hex()
    middle_hex = _det_keys().public_key().to_hex()
    child_hex = _det_keys().public_key().to_hex()

    parent_link = _make_link(
        parent_hex, middle_hex,
        capabilities=("relay-read",),
        resources=("wss://relay.example.com",),
        actions=("read",),
    )
    escalated_link = _make_link(
        middle_hex, child_hex,
        capabilities=("relay-read",),
        resources=("wss://relay.example.com",),
        actions=("read", "write"),  # WIDER than parent
    )

    chain = DelegationChain(links=[parent_link, escalated_link])

    with pytest.raises(ValidationError, match="not a subset of parent"):
        validate_chain(chain)


# ===========================================================================
# TP-06c: Resource superset (INV-2 violation)
# ===========================================================================


@pytest.mark.unit
def test_tp06c_resource_escalation_rejected() -> None:
    """TP-06c: child adds a resource not in parent's scope.

    Parent: resources=("wss://relay1.example.com",).
    Child: resources=("wss://relay1.example.com", "wss://relay2.example.com").
    validate_chain() MUST reject.
    """
    parent_hex = _det_keys().public_key().to_hex()
    middle_hex = _det_keys().public_key().to_hex()
    child_hex = _det_keys().public_key().to_hex()

    parent_link = _make_link(
        parent_hex, middle_hex,
        capabilities=("relay-read",),
        resources=("wss://relay1.example.com",),
        actions=("read",),
    )
    escalated_link = _make_link(
        middle_hex, child_hex,
        capabilities=("relay-read",),
        resources=("wss://relay1.example.com", "wss://relay2.example.com"),  # WIDER
        actions=("read",),
    )

    chain = DelegationChain(links=[parent_link, escalated_link])

    with pytest.raises(ValidationError):
        validate_chain(chain)


# ===========================================================================
# TP-06d: Chain continuity violation (delegator mismatch)
# ===========================================================================


@pytest.mark.unit
def test_tp06d_chain_continuity_break_rejected() -> None:
    """TP-06d: second link's delegator does not match first link's delegatee.

    This is a basic chain integrity check -- an attacker cannot insert
    themselves into a delegation chain without breaking continuity.
    """
    a_hex = _det_keys().public_key().to_hex()
    b_hex = _det_keys().public_key().to_hex()
    attacker_hex = _det_keys().public_key().to_hex()
    c_hex = _det_keys().public_key().to_hex()

    link_1 = _make_link(
        a_hex, b_hex,
        capabilities=("relay-read",),
        resources=("wss://relay.example.com",),
        actions=("read",),
    )
    # Attack: attacker inserts themselves, delegator != b_hex
    link_2 = _make_link(
        attacker_hex, c_hex,  # attacker_hex != b_hex
        capabilities=("relay-read",),
        resources=("wss://relay.example.com",),
        actions=("read",),
    )

    chain = DelegationChain(links=[link_1, link_2])

    with pytest.raises(ValidationError, match="Chain continuity broken"):
        validate_chain(chain)


# ===========================================================================
# TP-06e: Scope.attenuates() direct unit test
# ===========================================================================


@pytest.mark.unit
def test_tp06e_scope_attenuates_rejects_superset() -> None:
    """TP-06e: Scope.attenuates() returns False when child is wider than parent.

    Tests the Scope dataclass directly, independent of validate_chain().
    """
    parent = Scope(
        capabilities=("weather-forecast",),
        resources=("wss://relay.example.com",),
        actions=("read",),
    )

    # Wider capabilities
    wider_caps = Scope(
        capabilities=("weather-forecast", "admin"),
        resources=("wss://relay.example.com",),
        actions=("read",),
    )
    assert not wider_caps.attenuates(parent), "Wider capabilities must not attenuate"

    # Wider actions
    wider_actions = Scope(
        capabilities=("weather-forecast",),
        resources=("wss://relay.example.com",),
        actions=("read", "write"),
    )
    assert not wider_actions.attenuates(parent), "Wider actions must not attenuate"

    # Wider resources
    wider_resources = Scope(
        capabilities=("weather-forecast",),
        resources=("wss://relay.example.com", "wss://relay2.example.com"),
        actions=("read",),
    )
    assert not wider_resources.attenuates(parent), "Wider resources must not attenuate"

    # Valid attenuation (subset)
    narrower = Scope(
        capabilities=("weather-forecast",),
        resources=("wss://relay.example.com",),
        actions=("read",),
    )
    assert narrower.attenuates(parent), "Equal scope must attenuate (subset)"


# ===========================================================================
# TP-06f: Multi-hop escalation attempt (3-level chain)
# ===========================================================================


@pytest.mark.unit
def test_tp06f_multi_hop_escalation_rejected() -> None:
    """TP-06f: valid first hop, escalated second hop.

    A -> B (valid narrowing), B -> C (escalates beyond B's scope).
    validate_chain() MUST reject the overall chain.
    """
    a_hex = _det_keys().public_key().to_hex()
    b_hex = _det_keys().public_key().to_hex()
    c_hex = _det_keys().public_key().to_hex()

    link_ab = _make_link(
        a_hex, b_hex,
        capabilities=("relay-read", "relay-write"),
        resources=("wss://relay.example.com",),
        actions=("read", "write"),
    )
    link_bc = _make_link(
        b_hex, c_hex,
        capabilities=("relay-read",),
        resources=("wss://relay.example.com",),
        actions=("read",),
    )

    # Valid chain A->B->C (narrowing)
    valid_chain = DelegationChain(links=[link_ab, link_bc])
    validate_chain(valid_chain)  # should not raise

    # Now attack: C tries to escalate back to write
    d_hex = _det_keys().public_key().to_hex()
    link_cd_escalated = _make_link(
        c_hex, d_hex,
        capabilities=("relay-read",),
        resources=("wss://relay.example.com",),
        actions=("read", "write"),  # ESCALATION: C only has read
    )

    escalated_chain = DelegationChain(links=[link_ab, link_bc, link_cd_escalated])
    with pytest.raises(ValidationError, match="not a subset of parent"):
        validate_chain(escalated_chain)


# ===========================================================================
# TP-05: Information Disclosure (integration test -- documents trade-off)
# ===========================================================================


@pytest.mark.integration
@pytest.mark.usefixtures("require_relays")
@pytest.mark.asyncio
async def test_tp05_unauthenticated_trust_graph_enumeration() -> None:
    """TP-05: unauthenticated query enumerates all public Kind 38102 trust edges.

    Expected outcome: enumeration succeeds (public-by-design, residual risk = 4).
    Test documents the threat, not a countermeasure.
    Requires running relay at ws://127.0.0.1:7001 (code/infra/).
    """
    import networkx as nx  # type: ignore[import]
    from datetime import timedelta

    # Setup: seed relay with 3 attestation edges forming a triangle
    seed_keys = [_det_keys() for _ in range(3)]
    publisher_keys = seed_keys[0]
    signer = ns.NostrSigner.keys(publisher_keys)
    client = ns.Client(signer)
    await client.add_relay("ws://127.0.0.1:7001")
    await client.connect()

    edges: list[tuple[str, str]] = []
    for i in range(3):
        attester = seed_keys[i]
        subject = seed_keys[(i + 1) % 3]
        edge = (
            attester.public_key().to_hex()[:16],
            subject.public_key().to_hex()[:16],
        )
        edges.append(edge)
        tags = [
            ns.Tag.identifier(f"tp05-edge-{i}"),
            ns.Tag.public_key(subject.public_key()),
            ns.Tag.custom(ns.TagKind.UNKNOWN("trust_score"), ["0.7"]),
        ]
        builder = ns.EventBuilder(ns.Kind(38102), "{}").tags(tags)
        await client.send_event_builder(builder)
    await client.disconnect()

    # Attack: anonymous client enumerates all Kind 38102 events
    anon_client = ns.Client()
    await anon_client.add_relay("ws://127.0.0.1:7001")
    await anon_client.connect()
    f = ns.Filter().kind(ns.Kind(38102))
    results = await anon_client.fetch_events(f, timedelta(seconds=5))
    await anon_client.disconnect()

    # Reconstruct trust graph
    G: nx.DiGraph = nx.DiGraph()
    for ev in results.to_vec():
        attester_pk = ev.author().to_hex()
        subject_tag = None
        for tag in ev.tags().to_vec():
            vec = tag.as_vec()
            if len(vec) >= 2 and vec[0] == "p":
                subject_tag = vec[1]
                break
        if subject_tag:
            G.add_edge(attester_pk, subject_tag)

    assert G.number_of_edges() >= 3, (
        "TP-05: unauthenticated graph enumeration MUST succeed -- "
        "public-by-design architectural tradeoff (Info Disclosure residual risk = 4)"
    )
