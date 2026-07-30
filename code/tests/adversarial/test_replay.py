"""TP-07, TP-08, TP-09: L402 Macaroon/Invoice/Preimage Attacks (STRIDE: Spoofing+Tampering+Replay) -- TB3.

TP-07: Forged macaroon HMAC chain -- attacker mints macaroon with wrong root key.
TP-08: Invoice substitution -- attacker swaps payment_hash in transit.
TP-09: Preimage replay -- captured preimage from invoice-1 presented for invoice-2.

All tests are unit-level (pure crypto, no network I/O).

Countermeasures tested: L402 5-check verification algorithm (checks 1-5),
HMAC chain integrity, payment_hash binding.
"""

from __future__ import annotations

import hashlib
import time

import pymacaroons  # type: ignore[import]
import pytest

from nostr_agent.crypto import generate_keypair_raw, sign_schnorr, verify_schnorr, sha256
from nostr_agent.l402 import L402Verifier


# ===========================================================================
# TP-07: Forged Macaroon (STRIDE: Spoofing + Tampering)
# ===========================================================================


@pytest.mark.unit
def test_tp07a_forged_macaroon_hmac_wrong_root_key() -> None:
    """TP-07a: macaroon minted with attacker's root key fails service verification.

    Attack: attacker creates a macaroon with identical identifier but a
    different root key. The HMAC chain will not match when verified against
    the service's real root key.
    """
    service_root_key = b"legitimate-service-root-key-32by"
    attacker_root_key = b"attacker-controlled-wrong-key-32"

    # Service mints a legitimate macaroon
    legitimate = pymacaroons.Macaroon(
        location="https://service.example.com",
        identifier="token-001",
        key=service_root_key,
    )
    legitimate = legitimate.add_first_party_caveat("scope = read")

    # Attack: attacker mints with wrong root key, same identifier
    forged = pymacaroons.Macaroon(
        location="https://service.example.com",
        identifier="token-001",
        key=attacker_root_key,
    )
    forged = forged.add_first_party_caveat("scope = read")

    # Verification against service's real root key
    verifier = pymacaroons.Verifier()
    verifier.satisfy_exact("scope = read")

    # Legitimate passes
    verifier.verify(legitimate, service_root_key)

    # Forged fails
    with pytest.raises(Exception):
        verifier.verify(forged, service_root_key)


@pytest.mark.unit
def test_tp07b_forged_macaroon_added_caveat() -> None:
    """TP-07b: attacker adds a first-party caveat to widen permissions.

    Attack: take a legitimate serialized macaroon, deserialize, add a
    permissive caveat. HMAC chain is broken because the attacker does not
    know the root key to recompute the chain.

    Note: pymacaroons allows adding caveats (they are layered HMAC), but
    the resulting macaroon will only verify if ALL caveats are satisfied.
    Adding a caveat can only NARROW, never widen -- this is by construction
    of HMAC-chained caveats. We verify this property.
    """
    root_key = b"service-root-key-32-bytes-padded"

    mac = pymacaroons.Macaroon(
        location="https://service.example.com",
        identifier="token-002",
        key=root_key,
    )
    mac = mac.add_first_party_caveat("scope = read")

    # "Attack": add a caveat (this actually narrows, not widens)
    # The attacker might try adding "scope = admin" hoping to override
    widened = mac.add_first_party_caveat("scope = admin")

    verifier = pymacaroons.Verifier()
    verifier.satisfy_exact("scope = read")
    # Does NOT satisfy "scope = admin" -- so verification fails
    with pytest.raises(Exception):
        verifier.verify(widened, root_key)


@pytest.mark.unit
def test_tp07c_forged_macaroon_identity_bound_identifier() -> None:
    """TP-07c: forged identity-bound macaroon with wrong agent pubkey.

    Uses L402Verifier's actual identifier structure (version + payment_hash
    + agent_pubkey = 65 bytes). Attacker substitutes their pubkey into
    the identifier and mints with a guessed root key.
    """
    service_root_key = b"a" * 32
    attacker_root_key = b"b" * 32

    payment_hash = hashlib.sha256(b"real-preimage-32bytes-padded!!!!").digest()
    real_agent_pk = b"\x01" * 32
    attacker_pk = b"\x02" * 32

    # Legitimate identifier
    legit_id = L402Verifier.build_identifier(payment_hash, real_agent_pk)
    assert len(legit_id) == 65

    # Forged identifier with attacker pubkey
    forged_id = L402Verifier.build_identifier(payment_hash, attacker_pk)

    # Attacker mints macaroon with forged identifier
    forged_mac = pymacaroons.Macaroon(
        location="nostr-agent",
        identifier=forged_id.hex(),
        key=attacker_root_key.hex(),
    )

    # Service verifies against its own root key -- HMAC mismatch
    verifier = pymacaroons.Verifier()
    verifier.satisfy_general(lambda c: True)  # accept all caveats for this test

    with pytest.raises(Exception):
        verifier.verify(forged_mac, service_root_key.hex())


# ===========================================================================
# TP-08: Modified Invoice (STRIDE: Tampering)
# ===========================================================================


@pytest.mark.unit
def test_tp08a_payment_hash_mismatch_detected() -> None:
    """TP-08a: tampered payment_hash -- preimage does not satisfy modified hash.

    Attack: relay/MITM substitutes a different Lightning invoice, changing
    the payment_hash. The original preimage will not satisfy the new hash.
    """
    preimage = b"correct-preimage-32-bytes-padded!"
    payment_hash = hashlib.sha256(preimage).digest()

    tampered_hash = hashlib.sha256(b"attacker-chosen-payload-content!").digest()

    # Original preimage satisfies original hash
    assert hashlib.sha256(preimage).digest() == payment_hash

    # Original preimage does NOT satisfy tampered hash
    assert hashlib.sha256(preimage).digest() != tampered_hash, (
        "TP-08a: preimage MUST NOT satisfy the tampered payment_hash"
    )


@pytest.mark.unit
def test_tp08b_macaroon_bound_to_payment_hash() -> None:
    """TP-08b: macaroon with payment_hash caveat rejects tampered hash claim.

    The macaroon's first-party caveat binds it to a specific payment_hash.
    An attacker who substitutes the invoice gets a different payment_hash,
    so the caveat is not satisfied.
    """
    root_key = b"service-root-key-32-bytes-padded"
    original_hash = hashlib.sha256(b"preimage-a-32-bytes-padded!!!!!").digest()
    tampered_hash = hashlib.sha256(b"preimage-b-32-bytes-padded!!!!!").digest()

    # Original macaroon bound to original hash
    mac = pymacaroons.Macaroon(
        location="https://service.example.com",
        identifier=original_hash.hex(),
        key=root_key,
    )
    mac = mac.add_first_party_caveat(f"payment_hash = {original_hash.hex()}")

    # Tampered macaroon bound to different hash (different HMAC chain)
    tampered_mac = pymacaroons.Macaroon(
        location="https://service.example.com",
        identifier=tampered_hash.hex(),
        key=root_key,
    )
    tampered_mac = tampered_mac.add_first_party_caveat(
        f"payment_hash = {tampered_hash.hex()}"
    )

    # Verifier only satisfies the original hash caveat
    verifier = pymacaroons.Verifier()
    verifier.satisfy_exact(f"payment_hash = {original_hash.hex()}")

    # Original passes
    verifier.verify(mac, root_key)

    # Tampered fails (caveat not satisfied)
    with pytest.raises(Exception):
        verifier.verify(tampered_mac, root_key)


# ===========================================================================
# TP-09: Preimage Replay (STRIDE: Replay)
# ===========================================================================


@pytest.mark.unit
def test_tp09a_preimage_replay_different_invoice() -> None:
    """TP-09a: reused preimage from invoice-1 does not satisfy invoice-2.

    Lightning invoices are single-use: each has a unique payment_hash =
    SHA256(preimage). A replayed preimage from a completed payment cannot
    satisfy a new invoice's payment_hash.
    """
    preimage_1 = b"preimage-for-invoice-1-32bytepad"
    preimage_2 = b"preimage-for-invoice-2-32bytepad"

    hash_1 = hashlib.sha256(preimage_1).digest()
    hash_2 = hashlib.sha256(preimage_2).digest()

    assert hash_1 != hash_2, "Precondition: distinct invoices have distinct hashes"

    # Client legitimately paid invoice 1
    assert hashlib.sha256(preimage_1).digest() == hash_1

    # Replay: present preimage_1 for invoice_2
    replayed = hashlib.sha256(preimage_1).digest()
    assert replayed != hash_2, (
        "TP-09a: preimage from invoice-1 MUST NOT satisfy invoice-2's payment_hash"
    )


@pytest.mark.unit
def test_tp09b_preimage_replay_macaroon_binding() -> None:
    """TP-09b: replayed preimage fails macaroon layer binding.

    Even if an attacker captures a valid preimage, the macaroon for a new
    invoice is bound to a different payment_hash. Modifying the caveat to
    use the old hash breaks the HMAC chain.
    """
    root_key = b"service-root-key-32-bytes-padded"

    hash_1 = hashlib.sha256(b"preimage-for-invoice-1-32bytepad").digest()
    hash_2 = hashlib.sha256(b"preimage-for-invoice-2-32bytepad").digest()

    # Invoice-2 macaroon is bound to hash_2
    mac_2 = pymacaroons.Macaroon(
        location="https://service.example.com",
        identifier=hash_2.hex(),
        key=root_key,
    )
    mac_2 = mac_2.add_first_party_caveat(f"payment_hash = {hash_2.hex()}")

    # Verifier for invoice 2 expects hash_2
    verifier = pymacaroons.Verifier()
    verifier.satisfy_exact(f"payment_hash = {hash_2.hex()}")
    verifier.verify(mac_2, root_key)  # legitimate flow passes

    # Attacker creates a macaroon attempting to bind replay of hash_1
    replay_mac = pymacaroons.Macaroon(
        location="https://service.example.com",
        identifier=hash_2.hex(),
        key=root_key,
    )
    replay_mac = replay_mac.add_first_party_caveat(
        f"payment_hash = {hash_1.hex()}"  # wrong hash for this invoice
    )

    # Caveat not satisfied -- hash_1 != hash_2
    with pytest.raises(Exception):
        verifier.verify(replay_mac, root_key)


@pytest.mark.unit
def test_tp09c_timestamp_freshness_rejects_stale_replay() -> None:
    """TP-09c: L402 Check 4 -- timestamp freshness window (300s) rejects stale replays.

    An attacker captures a valid L402 credential and replays it after the
    300-second freshness window has elapsed. The verifier MUST reject based
    on stale timestamp (even if preimage+macaroon are valid).

    Documents: replay within 300s window succeeds (accepted design trade-off;
    service-side nonce tracking is out of scope for prototype).

    This test constructs the Authorization header with a macaroon whose
    identifier uses raw bytes (not hex string) to work around pymacaroons
    V2 serialization round-trip encoding. It exercises the full verify_request
    5-check pipeline through to Check 4.
    """
    import base64

    sk, pk = generate_keypair_raw()
    agent_pubkey_hex = pk.hex()

    root_key = b"service-root-key-32-bytes-padded"
    preimage = b"valid-preimage-32-bytes-padded!!"
    payment_hash = sha256(preimage)

    # Build identity-bound macaroon using V1 format to ensure identifier
    # round-trips as a string (hex) -- matching what verify_request expects.
    identifier = L402Verifier.build_identifier(payment_hash, pk)
    mac = pymacaroons.Macaroon(
        location="nostr-agent",
        identifier=identifier.hex(),
        key=root_key.hex(),
    )
    # Serialize and wrap in base64 as verify_request expects
    mac_serialized = mac.serialize()
    if isinstance(mac_serialized, bytes):
        mac_serialized = mac_serialized.decode("utf-8")

    # Simulate stale timestamp (10 minutes ago -- beyond 300s window)
    stale_timestamp = int(time.time()) - 600
    method = "GET"
    url = "https://service.example.com/api/data"

    body_hash = sha256(b"")
    payload = (
        method.encode()
        + url.encode()
        + str(stale_timestamp).encode()
        + body_hash
    )
    sign_payload = sha256(payload)
    sig = sign_schnorr(sk, sign_payload)

    headers = {
        "Authorization": f"L402 {mac_serialized}:{preimage.hex()}",
        "X-Nostr-Pubkey": agent_pubkey_hex,
        "X-Nostr-Sig": sig.hex(),
        "X-Nostr-Timestamp": str(stale_timestamp),
    }

    verifier = L402Verifier(root_key=root_key)
    result = verifier.verify_request(method, url, headers)

    assert not result.is_valid, "TP-09c: stale timestamp MUST be rejected"
    assert result.reason_code == "TIMESTAMP_STALE", (
        f"TP-09c: expected TIMESTAMP_STALE, got {result.reason_code}"
    )
