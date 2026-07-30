"""TP-02: Tampered Content (STRIDE: Tampering) -- TB2.

TP-02 validates that post-signature modification of event fields is detected:
  (a) NIP-01 id recomputation catches any content/tag mutation
  (b) BIP340 signature verification fails on the tampered event
  (c) Multiple mutation vectors are tested (scope, expiry, content, pubkey)

TP-04 (Denial of Service / Event Flood) is included here as a relay-level
tampering/disruption test.

Countermeasures tested: T-TB2 (mandatory id recomputation + BIP340), NST-1/NST-2.
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
    return ns.Keys.parse(hashlib.sha256(f"det-tamper-{_KEY_CTR}".encode()).hexdigest())

import hashlib as _hashlib


# ---------------------------------------------------------------------------
# Inline helpers (also defined in conftest.py, duplicated here to avoid
# cross-package import issues with pytest's test collection)
# ---------------------------------------------------------------------------


def event_to_dict(event: ns.Event) -> dict:
    """Convert a nostr-sdk Event to a mutable dict via JSON round-trip."""
    return json.loads(event.as_json())


def recompute_event_id(event_dict: dict) -> str:
    """Recompute the NIP-01 canonical event id from the current fields."""
    raw = json.dumps(
        [
            0,
            event_dict["pubkey"],
            event_dict["created_at"],
            event_dict["kind"],
            event_dict["tags"],
            event_dict["content"],
        ],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return _hashlib.sha256(raw).hexdigest()


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
# TP-02a: Scope tag mutation (read -> write escalation)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_tp02a_scope_tag_mutation_detected() -> None:
    """TP-02a: changing a scope tag value after signing invalidates id + sig.

    Attack: flip 'read' to 'write' in a scope tag.
    Both id recomputation and BIP340 verification MUST detect this.
    """
    delegator_keys = _det_keys()
    delegatee_keys = _det_keys()

    tags = [
        ns.Tag.identifier("tp02a-delegation"),
        ns.Tag.public_key(delegator_keys.public_key()),
        ns.Tag.public_key(delegatee_keys.public_key()),
        ns.Tag.custom(ns.TagKind.UNKNOWN("scope"), ["read"]),
    ]
    builder = ns.EventBuilder(ns.Kind(38101), "{}").tags(tags)
    valid_event = builder.sign_with_keys(delegator_keys)
    assert valid_event.verify(), "Precondition: valid event must pass verification"

    # Attack: escalate scope read -> write
    d = event_to_dict(valid_event)
    for tag in d["tags"]:
        if tag[0] == "scope":
            tag[1] = "write"
            break

    # Verify id no longer matches
    new_id = recompute_event_id(d)
    assert new_id != d["id"], "TP-02a: id recomputation MUST detect scope mutation"

    # Verify BIP340 rejects
    tampered = ns.Event.from_json(json.dumps(d))
    assert not tampered.verify(), "TP-02a: BIP340 MUST reject tampered event"


# ---------------------------------------------------------------------------
# TP-02b: Expiry extension (temporal scope widening)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_tp02b_expiry_extension_detected() -> None:
    """TP-02b: extending expires_at in content after signing.

    Attack: modify the JSON content to push expiry far into the future.
    """
    delegator_keys = _det_keys()
    delegatee_keys = _det_keys()

    content = json.dumps({"expires_at": int(time.time()) + 3600})
    tags = [
        ns.Tag.identifier("tp02b-delegation"),
        ns.Tag.public_key(delegator_keys.public_key()),
        ns.Tag.public_key(delegatee_keys.public_key()),
    ]
    builder = ns.EventBuilder(ns.Kind(38101), content).tags(tags)
    valid_event = builder.sign_with_keys(delegator_keys)
    assert valid_event.verify(), "Precondition: valid event verifies"

    # Attack: extend expiry by 1 year
    d = event_to_dict(valid_event)
    modified_content = json.loads(d["content"])
    modified_content["expires_at"] = int(time.time()) + 365 * 86400
    d["content"] = json.dumps(modified_content)

    new_id = recompute_event_id(d)
    assert new_id != d["id"], "TP-02b: id recomputation MUST detect content mutation"

    tampered = ns.Event.from_json(json.dumps(d))
    assert not tampered.verify(), "TP-02b: BIP340 MUST reject tampered event"


# ---------------------------------------------------------------------------
# TP-02c: Content injection (add extra capabilities)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_tp02c_content_injection_detected() -> None:
    """TP-02c: injecting extra capabilities into content JSON.

    Attack: add 'admin' capability to a delegation that only grants 'read'.
    """
    delegator_keys = _det_keys()
    delegatee_keys = _det_keys()

    original_content = json.dumps({
        "scope": {"capabilities": ["read"]},
    })
    tags = [
        ns.Tag.identifier("tp02c-delegation"),
        ns.Tag.public_key(delegator_keys.public_key()),
        ns.Tag.public_key(delegatee_keys.public_key()),
    ]
    builder = ns.EventBuilder(ns.Kind(38101), original_content).tags(tags)
    valid_event = builder.sign_with_keys(delegator_keys)
    assert valid_event.verify(), "Precondition"

    # Attack: inject 'admin' capability
    d = event_to_dict(valid_event)
    modified_content = json.loads(d["content"])
    modified_content["scope"]["capabilities"].append("admin")
    d["content"] = json.dumps(modified_content)

    new_id = recompute_event_id(d)
    assert new_id != d["id"], "TP-02c: id recomputation MUST detect capability injection"

    tampered = ns.Event.from_json(json.dumps(d))
    assert not tampered.verify(), "TP-02c: BIP340 MUST reject tampered event"


# ---------------------------------------------------------------------------
# TP-02d: Delegatee pubkey swap (redirect delegation to attacker)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_tp02d_delegatee_pubkey_swap_detected(attacker_keys: ns.Keys) -> None:
    """TP-02d: swapping the delegatee p-tag to redirect delegation to attacker.

    Attack: replace the legitimate delegatee's pubkey with the attacker's in
    the 'p' tag array.
    """
    delegator_keys = _det_keys()
    delegatee_keys = _det_keys()

    event = build_signed_kind_38101(
        delegator_keys, delegatee_keys, delegation_id="tp02d-deleg"
    )
    assert event.verify(), "Precondition"

    # Attack: swap delegatee pubkey in tags
    d = event_to_dict(event)
    for tag in d["tags"]:
        if tag[0] == "p" and tag[1] == delegatee_keys.public_key().to_hex():
            tag[1] = attacker_keys.public_key().to_hex()
            break

    new_id = recompute_event_id(d)
    assert new_id != d["id"], "TP-02d: id recomputation MUST detect p-tag swap"

    tampered = ns.Event.from_json(json.dumps(d))
    assert not tampered.verify(), "TP-02d: BIP340 MUST reject tampered event"


# ===========================================================================
# TP-04: Event Flood DoS (STRIDE: Denial of Service) -- integration only
# ===========================================================================


@pytest.mark.integration
@pytest.mark.usefixtures("require_relays")
@pytest.mark.asyncio
@pytest.mark.parametrize("events_per_second", [100, 500, 1000])
async def test_tp04_event_flood_latency(events_per_second: int) -> None:
    """TP-04: flood relay and measure latency degradation.

    Asserts median publish latency < 500 ms under flood load.
    Requires running relay at ws://127.0.0.1:7001 (code/infra/).
    """
    from datetime import timedelta

    attacker_keys = _det_keys()
    signer = ns.NostrSigner.keys(attacker_keys)
    client = ns.Client(signer)
    await client.add_relay("ws://127.0.0.1:7001")
    await client.connect()

    # Flood: burst of events at target rate
    burst = min(events_per_second, 200)  # cap to 200 for test runtime
    interval = 1.0 / events_per_second
    latencies: list[float] = []

    for i in range(burst):
        tags = [ns.Tag.identifier(f"flood-{i}")]
        builder = ns.EventBuilder(ns.Kind(38100), "{}").tags(tags)
        t0 = time.perf_counter()
        await client.send_event_builder(builder)
        latencies.append(time.perf_counter() - t0)
        await asyncio.sleep(max(0.0, interval - latencies[-1]))

    await client.disconnect()

    median_ms = sorted(latencies)[len(latencies) // 2] * 1000
    p95_ms = sorted(latencies)[int(len(latencies) * 0.95)] * 1000

    assert median_ms < 500, (
        f"TP-04 @ {events_per_second}/s: median latency {median_ms:.1f} ms >= 500 ms "
        "(relay rate-limiting may be suppressing flood but latency is unacceptable)"
    )
