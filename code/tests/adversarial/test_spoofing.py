"""TP-01: Forged Signature (STRIDE: Spoofing) -- TB1, TB2.

TP-01 validates that BIP340 signature verification rejects events where:
  (a) the pubkey field does not match the signing key
  (b) an attacker forges a Kind 38101 delegation claiming to be the operator

TP-03 (Repudiation / Relay Partition Audit) is also included here as it
tests non-repudiation via signed events on surviving relays.

Countermeasures tested: S-TB1a (BIP340 mandatory verification), S-TB2 (identity binding).
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
    return ns.Keys.parse(hashlib.sha256(f"det-spoof-{_KEY_CTR}".encode()).hexdigest())


# ---------------------------------------------------------------------------
# Inline helpers (also defined in conftest.py, duplicated here to avoid
# cross-package import issues with pytest's test collection)
# ---------------------------------------------------------------------------


def event_to_dict(event: ns.Event) -> dict:
    """Convert a nostr-sdk Event to a mutable dict via JSON round-trip."""
    return json.loads(event.as_json())


def make_raw_event(
    kind: int,
    pubkey_hex: str,
    content: str,
    tags: list[list[str]],
    sig_hex: str = "0" * 128,
    created_at: int | None = None,
) -> dict:
    """Build a raw Nostr event dict without signing."""
    import time as _time
    ts = created_at or int(_time.time())
    raw = json.dumps(
        [0, pubkey_hex, ts, kind, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    event_id = hashlib.sha256(raw).hexdigest()
    return {
        "id": event_id,
        "pubkey": pubkey_hex,
        "created_at": ts,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": sig_hex,
    }


def build_signed_kind_38101(
    delegator_keys: ns.Keys,
    delegatee_keys: ns.Keys,
    *,
    delegation_id: str = "adv-test-del",
    scopes: list[str] | None = None,
) -> ns.Event:
    """Build and sign a minimal valid Kind 38101 delegation event."""
    _scopes = scopes or ["read"]
    tags = [
        ns.Tag.identifier(delegation_id),
        ns.Tag.public_key(delegator_keys.public_key()),
        ns.Tag.public_key(delegatee_keys.public_key()),
    ]
    for s in _scopes:
        tags.append(ns.Tag.custom(ns.TagKind.UNKNOWN("scope"), [s]))
    builder = ns.EventBuilder(ns.Kind(38101), "{}").tags(tags)
    return builder.sign_with_keys(delegator_keys)


# ---------------------------------------------------------------------------
# TP-01a: Forged pubkey on Kind 38100 (identity spoofing)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_tp01a_forged_pubkey_identity(attacker_keys: ns.Keys) -> None:
    """TP-01a: attacker signs Kind 38100 then injects victim's pubkey.

    BIP340 verification MUST reject because the signature was made with
    the attacker's key but the pubkey field claims to be the victim.
    """
    victim_keys = _det_keys()

    # Build a legitimate Kind 38100 signed by the attacker
    tags = [
        ns.Tag.identifier("tp01a-agent"),
        ns.Tag.public_key(attacker_keys.public_key()),
    ]
    builder = ns.EventBuilder(ns.Kind(38100), "{}").tags(tags)
    event = builder.sign_with_keys(attacker_keys)

    # Tamper: replace pubkey with victim's
    d = event_to_dict(event)
    d["pubkey"] = victim_keys.public_key().to_hex()

    tampered = ns.Event.from_json(json.dumps(d))

    assert not tampered.verify(), (
        "TP-01a: BIP340 verify MUST reject -- pubkey does not match signing key"
    )


# ---------------------------------------------------------------------------
# TP-01b: Forged Kind 38101 delegation (operator impersonation)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_tp01b_forged_delegation_operator_impersonation(
    attacker_keys: ns.Keys,
) -> None:
    """TP-01b: attacker forges a Kind 38101 claiming to delegate on behalf of operator.

    The attacker creates a Kind 38101 event with the same d-tag and content
    as a legitimate delegation but signed with their own key. The pubkey field
    is then replaced with the operator's pubkey. BIP340 MUST reject.
    """
    operator_keys = _det_keys()
    agent_keys = _det_keys()

    # Legitimate delegation (for reference -- establishes the d-tag)
    legit = build_signed_kind_38101(
        operator_keys, agent_keys, delegation_id="tp01b-deleg"
    )
    assert legit.verify(), "Precondition: legitimate delegation verifies"

    # Attack: attacker signs same structure, then overwrites pubkey
    forged = build_signed_kind_38101(
        attacker_keys, agent_keys, delegation_id="tp01b-deleg"
    )
    d = event_to_dict(forged)
    d["pubkey"] = operator_keys.public_key().to_hex()  # claim to be operator

    tampered = ns.Event.from_json(json.dumps(d))
    assert not tampered.verify(), (
        "TP-01b: forged delegation with swapped operator pubkey MUST fail BIP340"
    )


# ---------------------------------------------------------------------------
# TP-01c: Entirely fabricated event with raw construction
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_tp01c_fabricated_raw_event() -> None:
    """TP-01c: raw event dict with placeholder sig MUST fail id+sig verification.

    Tests the case where an attacker constructs an event from scratch with
    a random signature. nostr-sdk MUST reject on both id mismatch and
    signature invalidity.
    """
    victim_keys = _det_keys()
    raw = make_raw_event(
        kind=38101,
        pubkey_hex=victim_keys.public_key().to_hex(),
        content="{}",
        tags=[["d", "tp01c-fabricated"]],
        sig_hex="ab" * 64,  # random garbage signature
    )

    event = ns.Event.from_json(json.dumps(raw))
    assert not event.verify(), (
        "TP-01c: fabricated event with garbage BIP340 signature MUST fail"
    )


# ===========================================================================
# TP-03: Relay Partition Audit (STRIDE: Repudiation) -- integration only
# ===========================================================================


@pytest.mark.integration
@pytest.mark.usefixtures("require_relays")
@pytest.mark.asyncio
async def test_tp03_audit_trail_survives_relay_loss() -> None:
    """TP-03: signed Kind 38102 on surviving relay provides non-repudiation.

    Publishes an attestation event to 3 relays, stops 2 via Docker SDK,
    and verifies the event is still fetchable and verifiable from relay 3.

    Requires 3 relays running in Docker (see code/infra/).
    """
    import docker  # type: ignore[import]
    from datetime import timedelta

    attester_keys = _det_keys()
    subject_keys = _det_keys()

    relay_urls = [
        "ws://127.0.0.1:7001",
        "ws://127.0.0.1:7002",
        "ws://127.0.0.1:7003",
    ]
    relay_containers = ["nostr-relay-1", "nostr-relay-2", "nostr-relay-3"]

    # Setup: publish Kind 38102 to all 3 relays
    tags = [
        ns.Tag.identifier("tp03-attestation"),
        ns.Tag.public_key(subject_keys.public_key()),
        ns.Tag.custom(ns.TagKind.UNKNOWN("trust_score"), ["0.9"]),
    ]
    builder = ns.EventBuilder(ns.Kind(38102), "{}").tags(tags)
    event = builder.sign_with_keys(attester_keys)
    event_id_hex = event.id().to_hex()

    signer = ns.NostrSigner.keys(attester_keys)
    client = ns.Client(signer)
    for url in relay_urls:
        await client.add_relay(url)
    await client.connect()
    await client.send_event(event)
    await client.disconnect()

    # Attack: take 2 of 3 relays offline
    docker_client = docker.from_env()
    for name in relay_containers[:2]:
        docker_client.containers.get(name).stop()

    await asyncio.sleep(1)  # allow disconnect to propagate

    # Verification: surviving relay still serves the signed event
    fetch_client = ns.Client()
    await fetch_client.add_relay(relay_urls[2])
    await fetch_client.connect()
    f = ns.Filter().kind(ns.Kind(38102)).identifier("tp03-attestation")
    results = await fetch_client.fetch_events(f, timedelta(seconds=5))
    await fetch_client.disconnect()

    events = results.to_vec()
    assert len(events) == 1, "Audit trail MUST survive on remaining relay"
    surviving = events[0]
    assert surviving.id().to_hex() == event_id_hex, "Recovered event id mismatch"
    assert surviving.verify(), "Recovered event BIP340 signature MUST be valid"

    # Cleanup: restart stopped relays
    for name in relay_containers[:2]:
        docker_client.containers.get(name).start()
