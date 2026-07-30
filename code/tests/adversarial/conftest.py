"""Shared fixtures and helpers for STRIDE adversarial tests.

Provides:
- Attacker keypair fixture (distinct from legitimate agents in parent conftest)
- Helper to construct raw tampered events (bypass normal constructors)
- Auto-applied ``adversarial`` marker via pytestmark
"""

from __future__ import annotations

import hashlib
import json

import nostr_sdk as ns
import pytest


# ---------------------------------------------------------------------------
# Auto-apply the adversarial marker to every test in this directory
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.adversarial


# ---------------------------------------------------------------------------
# Attacker keypair fixtures -- always distinct from legitimate agents
# ---------------------------------------------------------------------------

_SEED_ATTACKER = b"\xaa" * 32
_SEED_ATTACKER_2 = b"\xbb" * 32


def _seed_hex(seed: bytes) -> str:
    """SHA256 of seed as a stable 64-char hex string."""
    return hashlib.sha256(seed).hexdigest()


@pytest.fixture()
def attacker_keys() -> ns.Keys:
    """Keypair for the primary attacker (distinct from all legitimate agents)."""
    return ns.Keys.parse(_seed_hex(_SEED_ATTACKER))


@pytest.fixture()
def attacker_keys_2() -> ns.Keys:
    """Second attacker keypair for multi-party attack scenarios."""
    return ns.Keys.parse(_seed_hex(_SEED_ATTACKER_2))


# ---------------------------------------------------------------------------
# Raw event construction helpers (bypass normal library validation)
# ---------------------------------------------------------------------------


def make_raw_event(
    kind: int,
    pubkey_hex: str,
    content: str,
    tags: list[list[str]],
    sig_hex: str = "0" * 128,
    created_at: int | None = None,
) -> dict:
    """Build a raw Nostr event dict (NIP-01 format) without signing.

    The returned dict has a computed ``id`` from canonical serialization but
    a placeholder signature. Callers can tamper with fields after construction
    to simulate attacks.
    """
    import time

    ts = created_at or int(time.time())
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


def tamper_event_field(event_dict: dict, field: str, value) -> dict:
    """Return a copy of event_dict with one field changed (id NOT recomputed).

    This simulates an attacker modifying a field in transit without
    recomputing the id -- the resulting event should fail NIP-01 id
    verification.
    """
    d = dict(event_dict)
    d[field] = value
    return d


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
    return hashlib.sha256(raw).hexdigest()


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


def event_to_dict(event: ns.Event) -> dict:
    """Convert a nostr-sdk Event to a mutable dict via JSON round-trip."""
    return json.loads(event.as_json())
