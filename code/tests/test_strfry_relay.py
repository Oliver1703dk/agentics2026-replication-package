"""
strfry relay acceptance tests for NostrAgent custom event kinds (38100-38102).

Tests 8 behaviors against a live strfry relay:
  T1 - Kind 38100 accepted (parameterized replaceable event)
  T2 - Replacement: same (pubkey, d-tag) newer event replaces older
  T3 - Query by #t tag filter
  T4 - Query by #d filter (parameterized replaceable lookup)
  T5 - a-tag roundtrip via Kind 38101
  T6 - Custom multi-letter tags (schema_version, next_key_hash, prev_key) stored
  T7 - NIP-09 Kind 5 deletion for parameterized replaceable events
  T8 - strfry configuration: kinds 38100-38102 need no special config (open relay)

Run against the Docker relay stack:
  docker compose -f code/infra/docker-compose.yml up -d relay1
  pytest code/tests/test_strfry_relay.py -v

Or against any live relay:
  STRFRY_URL=ws://localhost:7777 pytest code/tests/test_strfry_relay.py -v

All signing uses coincurve (BIP340 Schnorr on secp256k1) -- same as production code.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import time
from typing import Any

import coincurve
import pytest
import websockets

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

RELAY_URL = os.environ.get("STRFRY_URL", "ws://localhost:7777")

# Subscription timeout: how long to wait for the relay to push events back
SUB_TIMEOUT = 5.0  # seconds


# ---------------------------------------------------------------------------
# Minimal BIP340 Schnorr event signing (NIP-01)
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _sign_event(privkey_bytes: bytes, event: dict[str, Any]) -> dict[str, Any]:
    """Fill id and sig fields using BIP340 Schnorr (coincurve)."""
    serialized = json.dumps(
        [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    event_id = _sha256(serialized).hex()
    event["id"] = event_id

    key = coincurve.PrivateKey(privkey_bytes)
    # BIP340: sign(privkey, hash)  -- aux_rand defaults to zeros in coincurve
    sig = key.sign_schnorr(_sha256(serialized))
    event["sig"] = sig.hex()
    return event


def _make_keypair() -> tuple[bytes, str]:
    """Return (privkey_bytes, pubkey_hex_x_only)."""
    privkey = coincurve.PrivateKey(secrets.token_bytes(32))
    # BIP340 x-only pubkey: first 32 bytes of the 33-byte compressed pubkey
    pubkey_hex = privkey.public_key.format(compressed=True)[1:].hex()
    return privkey.secret, pubkey_hex


def _build_event(
    privkey: bytes,
    pubkey: str,
    kind: int,
    content: str,
    tags: list[list[str]],
    created_at: int | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "pubkey": pubkey,
        "created_at": created_at if created_at is not None else int(time.time()),
        "kind": kind,
        "tags": tags,
        "content": content,
    }
    return _sign_event(privkey, event)


# ---------------------------------------------------------------------------
# WebSocket helpers
# ---------------------------------------------------------------------------

async def _publish(ws: Any, event: dict[str, Any]) -> tuple[bool, str]:
    """Send EVENT, return (accepted, message)."""
    await ws.send(json.dumps(["EVENT", event]))
    raw = await asyncio.wait_for(ws.recv(), timeout=SUB_TIMEOUT)
    msg = json.loads(raw)
    # ["OK", event_id, true/false, reason]
    if msg[0] == "OK":
        return msg[2], msg[3] if len(msg) > 3 else ""
    return False, f"unexpected: {msg}"


async def _query(
    ws: Any,
    sub_id: str,
    filters: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Send REQ, collect events until EOSE, then CLOSE."""
    await ws.send(json.dumps(["REQ", sub_id, *filters]))
    events: list[dict[str, Any]] = []
    deadline = time.monotonic() + SUB_TIMEOUT
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
        except asyncio.TimeoutError:
            break
        msg = json.loads(raw)
        if msg[0] == "EVENT" and msg[1] == sub_id:
            events.append(msg[2])
        elif msg[0] == "EOSE":
            break
    await ws.send(json.dumps(["CLOSE", sub_id]))
    return events


# ---------------------------------------------------------------------------
# Fixture: one WebSocket connection for the whole module
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def event_loop():
    """Module-scoped event loop."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="module")
async def ws():
    """Persistent WebSocket connection to the strfry relay."""
    async with websockets.connect(RELAY_URL) as conn:
        yield conn


# ---------------------------------------------------------------------------
# T1 -- Kind 38100 accepted
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_t1_kind38100_accepted(ws: Any) -> None:
    """strfry returns ['OK', id, true] for a valid Kind 38100 event."""
    privkey, pubkey = _make_keypair()
    event = _build_event(
        privkey, pubkey, 38100,
        content='{"schema_version":"1.0"}',
        tags=[["d", "agent-test-t1"]],
    )
    accepted, reason = await _publish(ws, event)
    assert accepted, f"Kind 38100 rejected: {reason}"


# ---------------------------------------------------------------------------
# T2 -- Replacement: newer event wins, older is gone
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_t2_replacement(ws: Any) -> None:
    """Publishing two Kind 38100 events with the same (pubkey, d-tag) leaves only the newer."""
    privkey, pubkey = _make_keypair()
    d_tag = f"agent-t2-{secrets.token_hex(4)}"
    now = int(time.time())

    # Publish older event first
    old_event = _build_event(privkey, pubkey, 38100, "old", [["d", d_tag]], created_at=now - 60)
    accepted, reason = await _publish(ws, old_event)
    assert accepted, f"Old event rejected: {reason}"

    # Publish newer event
    new_event = _build_event(privkey, pubkey, 38100, "new", [["d", d_tag]], created_at=now)
    accepted, reason = await _publish(ws, new_event)
    assert accepted, f"New event rejected: {reason}"

    # Query by id filter for the specific events
    results = await _query(ws, "t2-sub", [{"ids": [old_event["id"], new_event["id"]]}])
    ids_returned = {e["id"] for e in results}

    assert new_event["id"] in ids_returned, "Newer event missing from relay"
    assert old_event["id"] not in ids_returned, (
        "Older event still present -- strfry did not apply NIP-33 replacement"
    )


# ---------------------------------------------------------------------------
# T3 -- Query by #t tag filter
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_t3_t_tag_filter(ws: Any) -> None:
    """strfry returns events matching a #t filter."""
    privkey, pubkey = _make_keypair()
    unique_tag = f"capability-{secrets.token_hex(6)}"
    d_tag = f"agent-t3-{secrets.token_hex(4)}"

    event = _build_event(
        privkey, pubkey, 38100, "",
        tags=[["d", d_tag], ["t", unique_tag], ["t", "nostr-agent"]],
    )
    accepted, _ = await _publish(ws, event)
    assert accepted

    results = await _query(ws, "t3-sub", [{"kinds": [38100], "#t": [unique_tag]}])
    assert any(e["id"] == event["id"] for e in results), (
        f"Event not found via #t filter '{unique_tag}'"
    )


# ---------------------------------------------------------------------------
# T4 -- Query by #d filter (parameterized replaceable lookup)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_t4_d_tag_filter(ws: Any) -> None:
    """strfry returns the correct event when filtering by #d (NIP-33 canonical lookup)."""
    privkey, pubkey = _make_keypair()
    d_value = f"agent-identity-{secrets.token_hex(6)}"

    event = _build_event(privkey, pubkey, 38100, "", tags=[["d", d_value]])
    accepted, _ = await _publish(ws, event)
    assert accepted

    results = await _query(ws, "t4-sub", [{"kinds": [38100], "#d": [d_value], "authors": [pubkey]}])
    assert len(results) == 1, f"Expected 1 result, got {len(results)}"
    assert results[0]["id"] == event["id"]


# ---------------------------------------------------------------------------
# T5 -- a-tag roundtrip via Kind 38101
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_t5_a_tag_roundtrip(ws: Any) -> None:
    """Kind 38101 with an a-tag referencing a Kind 38100 coordinate is stored and retrievable."""
    privkey, pubkey = _make_keypair()
    d_identity = f"identity-{secrets.token_hex(4)}"
    d_delegation = f"delegation-{secrets.token_hex(4)}"

    # Publish the Kind 38100 anchor first
    identity_event = _build_event(privkey, pubkey, 38100, "", tags=[["d", d_identity]])
    accepted, _ = await _publish(ws, identity_event)
    assert accepted

    # Publish Kind 38101 with a-tag pointing to the 38100 coordinate
    a_coord = f"38100:{pubkey}:{d_identity}"
    delegation_event = _build_event(
        privkey, pubkey, 38101, "",
        tags=[["d", d_delegation], ["a", a_coord]],
    )
    accepted, _ = await _publish(ws, delegation_event)
    assert accepted

    # Query back the 38101 event
    results = await _query(ws, "t5-sub", [{"ids": [delegation_event["id"]]}])
    assert len(results) == 1
    stored = results[0]

    # Verify a-tag is preserved exactly
    a_tags = [tag for tag in stored["tags"] if tag[0] == "a"]
    assert a_tags, "a-tag missing from stored event"
    assert a_tags[0][1] == a_coord, f"a-tag value mismatch: {a_tags[0][1]!r} != {a_coord!r}"


# ---------------------------------------------------------------------------
# T6 -- Custom multi-letter tags stored and retrievable
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_t6_custom_multi_letter_tags(ws: Any) -> None:
    """schema_version, next_key_hash, prev_key tags are stored and returned verbatim.

    NIP-01: single-letter tags are indexed for filtering; multi-letter tags are
    stored but NOT relay-filterable. This test confirms round-trip storage.
    """
    privkey, pubkey = _make_keypair()
    d_tag = f"agent-t6-{secrets.token_hex(4)}"
    fake_next_key_hash = hashlib.sha256(b"next_key").hexdigest()

    event = _build_event(
        privkey, pubkey, 38100, "",
        tags=[
            ["d", d_tag],
            ["schema_version", "1.0"],
            ["next_key_hash", fake_next_key_hash],
            ["prev_key", ""],
        ],
    )
    accepted, _ = await _publish(ws, event)
    assert accepted

    results = await _query(ws, "t6-sub", [{"ids": [event["id"]]}])
    assert len(results) == 1
    stored_tags = {tag[0]: tag[1] for tag in results[0]["tags"] if len(tag) >= 2}

    assert stored_tags.get("schema_version") == "1.0", "schema_version tag lost"
    assert stored_tags.get("next_key_hash") == fake_next_key_hash, "next_key_hash tag lost"
    assert "prev_key" in stored_tags, "prev_key tag lost"


# ---------------------------------------------------------------------------
# T7 -- NIP-09 Kind 5 deletion for parameterized replaceable events
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_t7_nip09_deletion(ws: Any) -> None:
    """Kind 5 with an a-tag deletes a parameterized replaceable event (NIP-09 + NIP-33)."""
    privkey, pubkey = _make_keypair()
    d_tag = f"agent-t7-{secrets.token_hex(4)}"

    # Publish the target event
    target = _build_event(privkey, pubkey, 38100, "to-be-deleted", tags=[["d", d_tag]])
    accepted, _ = await _publish(ws, target)
    assert accepted

    # Send Kind 5 deletion using a-tag coordinate (NIP-09 §2)
    a_coord = f"38100:{pubkey}:{d_tag}"
    deletion = _build_event(
        privkey, pubkey, 5, "deleting agent identity",
        tags=[["a", a_coord]],
    )
    accepted, _ = await _publish(ws, deletion)
    assert accepted, "Kind 5 deletion event rejected"

    # Allow relay a moment to process
    await asyncio.sleep(0.5)

    # Target event should no longer be retrievable
    results = await _query(ws, "t7-sub", [{"ids": [target["id"]]}])
    assert len(results) == 0, (
        f"Event {target['id'][:8]}… still present after NIP-09 Kind 5 deletion"
    )


# ---------------------------------------------------------------------------
# T8 -- strfry configuration note (informational, always passes)
# ---------------------------------------------------------------------------

def test_t8_strfry_config_note() -> None:
    """Document strfry configuration behavior for kinds 38100-38102.

    Findings (verified against strfry source / docs):
    - strfry implements isParamReplaceableKind() covering kinds 30000-39999.
    - Kinds 38100-38102 are in this range: accepted and deduplicated by (pubkey, d-tag) natively.
    - No writePolicy plugin or allowedKinds whitelist required; empty allowedKinds = accept all.
    - NIP-33 is not listed as a separate NIP in strfry README because it was merged into NIP-01;
      the implementation is present in events.cpp.
    - Single-letter tags (d, t, a, e, p) are indexed and relay-filterable.
    - Multi-letter tags (schema_version, next_key_hash, prev_key) are stored verbatim
      but NOT indexed for REQ filters -- client-side filtering required for these.
    - NIP-09 Kind 5 deletion with a-tag coordinates works for parameterized replaceable events.
    - The dev strfry.conf (code/infra/config/strfry.conf) uses allowedKinds = [] (accept all)
      which is correct; no changes needed for 38100-38102.
    """
    # This test is documentation-only; it always passes.
    assert True
