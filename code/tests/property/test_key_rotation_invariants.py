"""Property-based tests for the key rotation protocol.

Tests the pre-rotation binding, rotation-proof binding, and rotation-chain
verification properties of `nostr_agent.key_rotation`. These are the
load-bearing invariants behind paper claim S3 (key portability under
pre-rotation; H,H priority) and FM-6 (key compromise recovery).

References:
- paper Section 4 (key rotation with pre-rotation)
- src/nostr_agent/key_rotation.py
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from nostr_agent.key_rotation import (
    KeyPair,
    create_identity,
    decommission,
    rotate_step3_new_identity,
    rotate_step1_validate,
    rotation_proof_msg,
    verify_rotation_chain,
)


# A 32-byte blob strategy used as a stand-in for "any plausible public key"
random_pk32 = st.binary(min_size=32, max_size=32)


# ============================================================================
# Pre-rotation binding (the load-bearing security property)
# ============================================================================


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(random_pk32)
def test_prerotation_rejects_keys_not_matching_commitment(random_pk: bytes) -> None:
    """rotate_step1_validate must raise when new_pk's hash doesn't match next_key_hash.

    This is the core defense against FM-6 race conditions: an attacker
    presenting a competing new_pk that hashes to a different value cannot
    pass step 1, regardless of what signature they produce.
    """
    kp = KeyPair.generate()
    next_kp = KeyPair.generate()
    genesis = create_identity(kp, next_kp)

    # The 32-byte hypothesis blob is statistically certain not to be the
    # pre-committed key; skip the degenerate case where they happen to align.
    if random_pk == next_kp.pk:
        pytest.skip("random key happens to equal the pre-committed key")

    with pytest.raises(ValueError, match="pre-image mismatch"):
        rotate_step1_validate(genesis, random_pk)


def test_prerotation_accepts_the_committed_key() -> None:
    """The pre-committed key passes step 1 validation."""
    kp = KeyPair.generate()
    next_kp = KeyPair.generate()
    genesis = create_identity(kp, next_kp)
    rotate_step1_validate(genesis, next_kp.pk)  # must not raise


def test_decommissioned_identity_cannot_rotate() -> None:
    """rotate_step1_validate must raise when the identity is decommissioned."""
    kp = KeyPair.generate()
    decommissioned = decommission(kp)
    new_kp = KeyPair.generate()
    with pytest.raises(ValueError, match="decommissioned"):
        rotate_step1_validate(decommissioned, new_kp.pk)


# ============================================================================
# Rotation chain verification
# ============================================================================


@settings(max_examples=20, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.integers(min_value=0, max_value=4))
def test_legitimate_chain_of_arbitrary_length_verifies(chain_length: int) -> None:
    """A canonical chain produced by the protocol passes verify_rotation_chain.

    Builds [genesis, rotation_1, ..., rotation_n] honestly and asserts that
    verification succeeds for every length in {0, 1, 2, 3, 4}.
    """
    kps = [KeyPair.generate() for _ in range(chain_length + 2)]
    genesis = create_identity(kps[0], kps[1])
    chain = [genesis]
    for i in range(chain_length):
        rotated = rotate_step3_new_identity(
            kp_new=kps[i + 1],
            kp_next=kps[i + 2],
            pk_old=kps[i].pk,
        )
        chain.append(rotated)
    assert verify_rotation_chain(chain, genesis_pk=kps[0].pk)


def test_tampered_rotation_proof_fails_chain_verify() -> None:
    """Flipping a bit in rotation_proof must cause verify_rotation_chain to reject."""
    kp0 = KeyPair.generate()
    kp1 = KeyPair.generate()
    kp2 = KeyPair.generate()

    genesis = create_identity(kp0, kp1)
    rotated = rotate_step3_new_identity(kp1, kp2, kp0.pk)
    assert rotated.rotation_proof is not None

    tampered = bytearray(rotated.rotation_proof)
    tampered[0] ^= 0x01
    rotated.rotation_proof = bytes(tampered)

    assert not verify_rotation_chain([genesis, rotated], genesis_pk=kp0.pk)


def test_prev_key_mismatch_fails_chain_verify() -> None:
    """Replacing prev_key with an unrelated pubkey must cause rejection."""
    kp0 = KeyPair.generate()
    kp1 = KeyPair.generate()
    kp2 = KeyPair.generate()
    other = KeyPair.generate()

    genesis = create_identity(kp0, kp1)
    rotated = rotate_step3_new_identity(kp1, kp2, kp0.pk)
    rotated.prev_key = other.pk
    assert not verify_rotation_chain([genesis, rotated], genesis_pk=kp0.pk)


def test_wrong_genesis_pk_fails_chain_verify() -> None:
    """A chain whose first event does not match the claimed genesis_pk is rejected."""
    kp0 = KeyPair.generate()
    kp1 = KeyPair.generate()
    other = KeyPair.generate()
    genesis = create_identity(kp0, kp1)
    assert not verify_rotation_chain([genesis], genesis_pk=other.pk)


# ============================================================================
# rotation_proof_msg properties
# ============================================================================


def test_rotation_proof_msg_is_deterministic() -> None:
    """Same inputs always yield the same 32-byte message."""
    pk_old = b"\x01" * 32
    pk_new = b"\x02" * 32
    ts = 1700000000
    m1 = rotation_proof_msg(pk_old, pk_new, ts)
    m2 = rotation_proof_msg(pk_old, pk_new, ts)
    assert m1 == m2
    assert len(m1) == 32  # SHA256 output


def test_rotation_proof_msg_changes_with_inputs() -> None:
    """Distinct inputs produce distinct messages (collision-resistance smoke test)."""
    pk_old = b"\x01" * 32
    base_ts = 1700000000
    m_base = rotation_proof_msg(pk_old, b"\x02" * 32, base_ts)
    m_diff_new = rotation_proof_msg(pk_old, b"\x03" * 32, base_ts)
    m_diff_ts = rotation_proof_msg(pk_old, b"\x02" * 32, base_ts + 1)
    m_diff_old = rotation_proof_msg(b"\xff" * 32, b"\x02" * 32, base_ts)
    assert m_base != m_diff_new
    assert m_base != m_diff_ts
    assert m_base != m_diff_old
