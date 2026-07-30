"""BIP340 Schnorr signature helpers.

Provides two layers:
1. nostr-sdk wrappers (event signing/verification via Rust crypto)
2. coincurve-based BIP340 functions for arbitrary message signing
   (rotation proofs, request signing, scope hashing, etc.)

All secp256k1 arithmetic is handled by the underlying C/Rust libraries.
Do not reimplement BIP340 primitives here.
"""

from __future__ import annotations

import hashlib
import json
import struct

import coincurve  # type: ignore[import]
import nostr_sdk  # type: ignore[import]

from nostr_agent.types import PublicKey, Signature

# ---------------------------------------------------------------------------
# 1. nostr-sdk wrappers (event-level operations)
# ---------------------------------------------------------------------------


def generate_keypair() -> tuple[nostr_sdk.Keys, PublicKey]:
    """Generate a fresh BIP340 keypair via nostr-sdk. Returns (Keys, hex pubkey)."""
    keys = nostr_sdk.Keys.generate()
    pubkey = PublicKey(keys.public_key().to_hex())
    return keys, pubkey


def sign_event(keys: nostr_sdk.Keys, event_builder: nostr_sdk.EventBuilder) -> nostr_sdk.Event:
    """Sign an event builder with the given keys."""
    return event_builder.sign_with_keys(keys)


def verify_event(event: nostr_sdk.Event) -> bool:
    """Verify BIP340 Schnorr signature on a Nostr event."""
    return event.verify()


def pubkey_from_hex(hex_key: str) -> nostr_sdk.PublicKey:
    """Parse a hex-encoded public key into a nostr-sdk PublicKey."""
    return nostr_sdk.PublicKey.parse(hex_key)


def signature_from_hex(hex_sig: str) -> Signature:
    """Wrap a hex signature string as a typed Signature."""
    return Signature(hex_sig)


# ---------------------------------------------------------------------------
# 2. Low-level BIP340 operations via coincurve
# ---------------------------------------------------------------------------


def sha256(data: bytes) -> bytes:
    """SHA-256 hash. Returns 32 bytes."""
    return hashlib.sha256(data).digest()


def tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).

    Used by BIP340 for domain separation. The tag is UTF-8 encoded before
    hashing. Returns 32 bytes.
    """
    tag_hash = sha256(tag.encode("utf-8"))
    return sha256(tag_hash + tag_hash + data)


def generate_keypair_raw() -> tuple[bytes, bytes]:
    """Generate a fresh BIP340 keypair using coincurve.

    Returns (secret_key_32bytes, x_only_pubkey_32bytes).
    """
    sk = coincurve.PrivateKey()
    pk_bytes = sk.public_key_xonly.format()
    return sk.secret, pk_bytes


def pubkey_from_secret(secret_key_bytes: bytes) -> bytes:
    """Derive the 32-byte x-only public key from a 32-byte secret key."""
    return coincurve.PublicKeyXOnly.from_secret(secret_key_bytes).format()


def sign_schnorr(secret_key_bytes: bytes, message_32: bytes) -> bytes:
    """Sign a 32-byte message with BIP340 Schnorr.

    Args:
        secret_key_bytes: 32-byte secret key.
        message_32: Pre-hashed message, exactly 32 bytes.

    Returns:
        64-byte Schnorr signature.

    Raises:
        AssertionError: If message is not exactly 32 bytes.
    """
    assert len(message_32) == 32, f"Message must be 32 bytes, got {len(message_32)}"
    sk = coincurve.PrivateKey(secret_key_bytes)
    return sk.sign_schnorr(message_32)


def verify_schnorr(pubkey_bytes: bytes, message_32: bytes, signature: bytes) -> bool:
    """Verify a BIP340 Schnorr signature.

    Args:
        pubkey_bytes: 32-byte x-only public key.
        message_32: The 32-byte message that was signed.
        signature: 64-byte Schnorr signature.

    Returns:
        True if valid, False otherwise. Never raises on invalid input.
    """
    try:
        pk = coincurve.PublicKeyXOnly(pubkey_bytes)
        return pk.verify(signature, message_32)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 3. Higher-level cryptographic operations
# ---------------------------------------------------------------------------


def compute_rotation_proof(
    sk_new: bytes, pk_old: bytes, pk_new: bytes, timestamp: int
) -> bytes:
    """Compute a rotation proof: new key signs commitment to old->new transition.

    The message is SHA256(pk_old || pk_new || timestamp_big_endian_8bytes).
    This proves the new key holder authorises the rotation at a specific time.

    Args:
        sk_new: 32-byte secret key of the new keypair.
        pk_old: 32-byte x-only public key being rotated away from.
        pk_new: 32-byte x-only public key being rotated to.
        timestamp: Unix timestamp, encoded as big-endian uint64.

    Returns:
        64-byte Schnorr signature over the rotation commitment.
    """
    msg = sha256(pk_old + pk_new + struct.pack(">Q", timestamp))
    return sign_schnorr(sk_new, msg)


def compute_scope_hash(
    capabilities: tuple[str, ...],
    resources: tuple[str, ...],
    actions: tuple[str, ...],
) -> str:
    """Compute a deterministic hash of a delegation scope.

    Builds a canonical JSON object with sorted arrays, then returns the
    SHA-256 hex digest. Used in delegation d-tag generation to ensure
    identical scopes produce identical hashes regardless of input order.

    Args:
        capabilities: Capability strings (e.g. ("text-generation", "tool-use")).
        resources: Resource strings (e.g. ("relay:wss://r.example.com",)).
        actions: Action strings (e.g. ("read", "write")).

    Returns:
        64-character lowercase hex SHA-256 digest.
    """
    canonical = json.dumps(
        {
            "actions": sorted(actions),
            "capabilities": sorted(capabilities),
            "resources": sorted(resources),
        },
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
