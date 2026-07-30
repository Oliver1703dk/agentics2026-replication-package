"""Unit tests for nostr_agent.crypto -- BIP340 Schnorr helpers via coincurve.

Covers: sha256, tagged_hash, sign_schnorr/verify_schnorr roundtrip,
tampered message, wrong pubkey, compute_rotation_proof, compute_scope_hash
determinism, generate_keypair_raw.
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from nostr_agent.crypto import (
    compute_rotation_proof,
    compute_scope_hash,
    generate_keypair_raw,
    pubkey_from_secret,
    sha256,
    sign_schnorr,
    tagged_hash,
    verify_schnorr,
)


# ===========================================================================
# sha256
# ===========================================================================


class TestSha256:
    """sha256() known vectors -- compare with hashlib directly."""

    @pytest.mark.unit
    def test_empty_input(self):
        expected = hashlib.sha256(b"").digest()
        assert sha256(b"") == expected

    @pytest.mark.unit
    def test_known_vector(self):
        """SHA256("abc") = ba7816bf..."""
        result = sha256(b"abc")
        expected = bytes.fromhex(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        assert result == expected

    @pytest.mark.unit
    def test_returns_32_bytes(self):
        result = sha256(b"test data")
        assert len(result) == 32

    @pytest.mark.unit
    def test_deterministic(self):
        assert sha256(b"hello") == sha256(b"hello")

    @pytest.mark.unit
    def test_different_inputs_different_outputs(self):
        assert sha256(b"a") != sha256(b"b")


# ===========================================================================
# tagged_hash
# ===========================================================================


class TestTaggedHash:
    """tagged_hash() -- BIP340 domain-separated hash pattern."""

    @pytest.mark.unit
    def test_returns_32_bytes(self):
        result = tagged_hash("BIP0340/challenge", b"\x00" * 32)
        assert len(result) == 32

    @pytest.mark.unit
    def test_bip340_pattern(self):
        """Verify: SHA256(SHA256(tag) || SHA256(tag) || data)."""
        tag = "BIP0340/challenge"
        data = b"\x01" * 32
        tag_hash = hashlib.sha256(tag.encode("utf-8")).digest()
        expected = hashlib.sha256(tag_hash + tag_hash + data).digest()
        assert tagged_hash(tag, data) == expected

    @pytest.mark.unit
    def test_different_tags_different_outputs(self):
        data = b"\x00" * 32
        h1 = tagged_hash("BIP0340/challenge", data)
        h2 = tagged_hash("BIP0340/aux", data)
        assert h1 != h2

    @pytest.mark.unit
    def test_deterministic(self):
        tag = "NostrAgent/test"
        data = b"some payload"
        assert tagged_hash(tag, data) == tagged_hash(tag, data)


# ===========================================================================
# sign_schnorr + verify_schnorr roundtrip
# ===========================================================================


class TestSignVerifySchnorr:
    """sign_schnorr/verify_schnorr roundtrip and failure modes."""

    @pytest.fixture()
    def keypair(self) -> tuple[bytes, bytes]:
        sk, pk = generate_keypair_raw()
        return sk, pk

    @pytest.mark.unit
    def test_roundtrip(self, keypair: tuple[bytes, bytes]):
        sk, pk = keypair
        msg = sha256(b"test message")
        sig = sign_schnorr(sk, msg)
        assert verify_schnorr(pk, msg, sig) is True

    @pytest.mark.unit
    def test_signature_is_64_bytes(self, keypair: tuple[bytes, bytes]):
        sk, pk = keypair
        msg = sha256(b"roundtrip test")
        sig = sign_schnorr(sk, msg)
        assert len(sig) == 64

    @pytest.mark.unit
    def test_tampered_message_fails(self, keypair: tuple[bytes, bytes]):
        sk, pk = keypair
        msg = sha256(b"original message")
        sig = sign_schnorr(sk, msg)
        tampered = sha256(b"tampered message")
        assert verify_schnorr(pk, tampered, sig) is False

    @pytest.mark.unit
    def test_wrong_pubkey_fails(self, keypair: tuple[bytes, bytes]):
        sk, pk = keypair
        msg = sha256(b"test message")
        sig = sign_schnorr(sk, msg)
        _, wrong_pk = generate_keypair_raw()
        assert verify_schnorr(wrong_pk, msg, sig) is False

    @pytest.mark.unit
    def test_non_32_byte_message_raises(self, keypair: tuple[bytes, bytes]):
        sk, _ = keypair
        with pytest.raises(AssertionError, match="32 bytes"):
            sign_schnorr(sk, b"short")

    @pytest.mark.unit
    def test_non_32_byte_message_too_long_raises(self, keypair: tuple[bytes, bytes]):
        sk, _ = keypair
        with pytest.raises(AssertionError, match="32 bytes"):
            sign_schnorr(sk, b"\x00" * 64)

    @pytest.mark.unit
    def test_verify_invalid_pubkey_returns_false(self):
        """verify_schnorr should never raise, even on garbage input."""
        msg = sha256(b"test")
        sig = b"\x00" * 64
        bad_pk = b"\xff" * 32
        # Should return False, not raise
        result = verify_schnorr(bad_pk, msg, sig)
        assert result is False

    @pytest.mark.unit
    def test_verify_empty_signature_returns_false(self, keypair: tuple[bytes, bytes]):
        _, pk = keypair
        msg = sha256(b"test")
        assert verify_schnorr(pk, msg, b"") is False

    @pytest.mark.unit
    def test_deterministic_signature(self, keypair: tuple[bytes, bytes]):
        """BIP340 Schnorr with deterministic nonce should produce same sig."""
        sk, pk = keypair
        msg = sha256(b"determinism check")
        sig1 = sign_schnorr(sk, msg)
        sig2 = sign_schnorr(sk, msg)
        # BIP340 uses auxiliary randomness by default in some implementations,
        # so signatures MAY differ. Both must verify.
        assert verify_schnorr(pk, msg, sig1) is True
        assert verify_schnorr(pk, msg, sig2) is True


# ===========================================================================
# compute_rotation_proof
# ===========================================================================


class TestComputeRotationProof:
    """compute_rotation_proof -- new key signs old->new transition."""

    @pytest.mark.unit
    def test_produces_64_byte_signature(self):
        sk_old, pk_old = generate_keypair_raw()
        sk_new, pk_new = generate_keypair_raw()
        timestamp = 1700000000
        proof = compute_rotation_proof(sk_new, pk_old, pk_new, timestamp)
        assert len(proof) == 64

    @pytest.mark.unit
    def test_proof_verifiable_with_new_pubkey(self):
        """The rotation proof is signed by sk_new, so it verifies with pk_new."""
        sk_old, pk_old = generate_keypair_raw()
        sk_new, pk_new = generate_keypair_raw()
        timestamp = 1700000000
        proof = compute_rotation_proof(sk_new, pk_old, pk_new, timestamp)
        # Reconstruct the message the same way the function does
        msg = sha256(pk_old + pk_new + struct.pack(">Q", timestamp))
        assert verify_schnorr(pk_new, msg, proof) is True

    @pytest.mark.unit
    def test_proof_does_not_verify_with_old_pubkey(self):
        sk_old, pk_old = generate_keypair_raw()
        sk_new, pk_new = generate_keypair_raw()
        timestamp = 1700000000
        proof = compute_rotation_proof(sk_new, pk_old, pk_new, timestamp)
        msg = sha256(pk_old + pk_new + struct.pack(">Q", timestamp))
        assert verify_schnorr(pk_old, msg, proof) is False

    @pytest.mark.unit
    def test_different_timestamps_different_proofs(self):
        sk_old, pk_old = generate_keypair_raw()
        sk_new, pk_new = generate_keypair_raw()
        proof1 = compute_rotation_proof(sk_new, pk_old, pk_new, 1700000000)
        proof2 = compute_rotation_proof(sk_new, pk_old, pk_new, 1700000001)
        # Proofs should differ because the message differs
        assert proof1 != proof2


# ===========================================================================
# compute_scope_hash
# ===========================================================================


class TestComputeScopeHash:
    """compute_scope_hash -- deterministic, order-independent."""

    @pytest.mark.unit
    def test_deterministic_same_input(self):
        h1 = compute_scope_hash(("a", "b"), ("r1",), ("read",))
        h2 = compute_scope_hash(("a", "b"), ("r1",), ("read",))
        assert h1 == h2

    @pytest.mark.unit
    def test_different_order_same_output(self):
        """Internally sorts, so order of input shouldn't matter."""
        h1 = compute_scope_hash(("b", "a"), ("r2", "r1"), ("write", "read"))
        h2 = compute_scope_hash(("a", "b"), ("r1", "r2"), ("read", "write"))
        assert h1 == h2

    @pytest.mark.unit
    def test_different_scopes_different_hashes(self):
        h1 = compute_scope_hash(("a",), (), ("read",))
        h2 = compute_scope_hash(("b",), (), ("read",))
        assert h1 != h2

    @pytest.mark.unit
    def test_returns_64_char_hex(self):
        h = compute_scope_hash(("cap",), ("res",), ("act",))
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    @pytest.mark.unit
    def test_empty_inputs(self):
        """Empty tuples are valid (unrestricted)."""
        h = compute_scope_hash((), (), ())
        assert len(h) == 64

    @pytest.mark.unit
    def test_capabilities_vs_actions_not_interchangeable(self):
        """Swapping capabilities and actions should produce different hash."""
        h1 = compute_scope_hash(("read",), (), ("weather",))
        h2 = compute_scope_hash(("weather",), (), ("read",))
        assert h1 != h2


# ===========================================================================
# generate_keypair_raw
# ===========================================================================


class TestGenerateKeypairRaw:
    """generate_keypair_raw -- returns 32-byte keys."""

    @pytest.mark.unit
    def test_secret_key_32_bytes(self):
        sk, _ = generate_keypair_raw()
        assert len(sk) == 32

    @pytest.mark.unit
    def test_public_key_32_bytes(self):
        _, pk = generate_keypair_raw()
        assert len(pk) == 32

    @pytest.mark.unit
    def test_keys_are_bytes(self):
        sk, pk = generate_keypair_raw()
        assert isinstance(sk, bytes)
        assert isinstance(pk, bytes)

    @pytest.mark.unit
    def test_different_calls_produce_different_keys(self):
        sk1, pk1 = generate_keypair_raw()
        sk2, pk2 = generate_keypair_raw()
        assert sk1 != sk2
        assert pk1 != pk2

    @pytest.mark.unit
    def test_pubkey_derived_from_secret(self):
        """The public key from generate_keypair_raw matches pubkey_from_secret."""
        sk, pk = generate_keypair_raw()
        derived_pk = pubkey_from_secret(sk)
        assert pk == derived_pk
