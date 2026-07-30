"""Key rotation protocol for NostrAgent.

Three-step rotation: pre-rotation commitment -> rotation event -> new identity event.
Grace period: verifiers accept delegations from old key for `grace_seconds` after rotation.

Crypto: pure-Python BIP340 Schnorr (secp256k1) using stdlib only. The BIP340
verification path here is for the rotation-proof signature; production crypto
in the rest of the package uses the audited Rust implementation in nostr-sdk.
"""

from __future__ import annotations

import hashlib
import secrets
import struct
import time
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# secp256k1 constants & pure-Python BIP340
# ---------------------------------------------------------------------------

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _point_add(
    p1: tuple[int, int] | None, p2: tuple[int, int] | None
) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = (3 * p1[0] ** 2 * pow(2 * p1[1], _P - 2, _P)) % _P
    else:
        lam = ((p2[1] - p1[1]) * pow(p2[0] - p1[0], _P - 2, _P)) % _P
    x = (lam**2 - p1[0] - p2[0]) % _P
    return (x, (lam * (p1[0] - x) - p1[1]) % _P)


def _point_mul(pt: tuple[int, int], n: int) -> tuple[int, int] | None:
    r: tuple[int, int] | None = None
    for i in range(255, -1, -1):
        r = _point_add(r, r)
        if (n >> i) & 1:
            r = _point_add(r, pt)
    return r


def _tagged_hash(tag: str, data: bytes) -> bytes:
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + data).digest()


def _lift_x(x: int) -> tuple[int, int] | None:
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if pow(y, 2, _P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else _P - y)


def _bip340_sign(sk_int: int, msg32: bytes, aux: bytes | None = None) -> bytes:
    if aux is None:
        aux = secrets.token_bytes(32)
    pt = _point_mul(_G, sk_int)
    assert pt is not None
    px = pt[0]
    d = sk_int if pt[1] % 2 == 0 else _N - sk_int
    a = _tagged_hash("BIP0340/aux", aux)
    t = (d ^ int.from_bytes(a, "big")).to_bytes(32, "big")
    rand = _tagged_hash("BIP0340/nonce", t + px.to_bytes(32, "big") + msg32)
    k0 = int.from_bytes(rand, "big") % _N
    assert k0 != 0
    r_pt = _point_mul(_G, k0)
    assert r_pt is not None
    k = k0 if r_pt[1] % 2 == 0 else _N - k0
    e = int.from_bytes(
        _tagged_hash(
            "BIP0340/challenge", r_pt[0].to_bytes(32, "big") + px.to_bytes(32, "big") + msg32
        ),
        "big",
    ) % _N
    return r_pt[0].to_bytes(32, "big") + ((k + e * d) % _N).to_bytes(32, "big")


def _bip340_verify(pk32: bytes, msg32: bytes, sig64: bytes) -> bool:
    try:
        p_pt = _lift_x(int.from_bytes(pk32, "big"))
        if p_pt is None:
            return False
        r = int.from_bytes(sig64[:32], "big")
        s = int.from_bytes(sig64[32:], "big")
        if r >= _P or s >= _N:
            return False
        e = int.from_bytes(
            _tagged_hash(
                "BIP0340/challenge", sig64[:32] + pk32 + msg32
            ),
            "big",
        ) % _N
        r_pt = _point_add(_point_mul(_G, s), _point_mul(p_pt, _N - e))
        return r_pt is not None and r_pt[1] % 2 == 0 and r_pt[0] == r
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Key pair
# ---------------------------------------------------------------------------

@dataclass
class KeyPair:
    sk_int: int   # private key as integer
    pk: bytes     # 32-byte x-only public key

    @classmethod
    def generate(cls) -> KeyPair:
        sk_int = int.from_bytes(secrets.token_bytes(32), "big") % _N
        pt = _point_mul(_G, sk_int)
        assert pt is not None
        return cls(sk_int=sk_int, pk=pt[0].to_bytes(32, "big"))

    def sign(self, msg32: bytes) -> bytes:
        return _bip340_sign(self.sk_int, msg32)


def verify(pk32: bytes, msg32: bytes, sig64: bytes) -> bool:
    return _bip340_verify(pk32, msg32, sig64)


# ---------------------------------------------------------------------------
# Data structures (Kind 38100 and Kind 38101)
# ---------------------------------------------------------------------------

@dataclass
class Kind38100:
    """Kind 38100 Agent Identity Declaration (minimal fields for rotation)."""

    pubkey: bytes           # 32-byte x-only
    created_at: int         # Unix timestamp
    status: str             # "active" | "rotated" | "decommissioned"
    next_key_hash: bytes | None = None    # SHA256(next_pubkey); absent when decommissioned
    prev_key: bytes | None = None         # x-only pubkey of predecessor
    rotation_proof: bytes | None = None   # 64-byte BIP340 sig by new key
    successor: bytes | None = None        # x-only pubkey (Step 2 old-key announcement)


@dataclass
class Kind38101:
    """Kind 38101 Delegation Chain Event (minimal)."""

    delegator_pk: bytes
    delegatee_pk: bytes
    scope: str
    created_at: int
    expires_at: int
    signature: bytes = field(default_factory=bytes)

    def signing_msg(self) -> bytes:
        return hashlib.sha256(
            self.delegator_pk
            + self.delegatee_pk
            + self.scope.encode()
            + struct.pack(">QQ", self.created_at, self.expires_at)
        ).digest()


# ---------------------------------------------------------------------------
# Rotation proof message
# ---------------------------------------------------------------------------

def rotation_proof_msg(pk_old: bytes, pk_new: bytes, created_at: int) -> bytes:
    """SHA256(pk_old || pk_new || created_at_be8) -- 32-byte BIP340 message."""
    return hashlib.sha256(pk_old + pk_new + struct.pack(">Q", created_at)).digest()


# ---------------------------------------------------------------------------
# Identity lifecycle
# ---------------------------------------------------------------------------

def create_identity(kp: KeyPair, next_kp: KeyPair) -> Kind38100:
    """Genesis Kind 38100 with pre-rotation commitment to next_kp."""
    return Kind38100(
        pubkey=kp.pk,
        created_at=int(time.time()),
        status="active",
        next_key_hash=hashlib.sha256(next_kp.pk).digest(),
    )


def rotate_step1_validate(current: Kind38100, new_pk: bytes) -> None:
    """Raise ValueError if new_pk does not satisfy the pre-rotation commitment."""
    if current.next_key_hash is None:
        raise ValueError("Identity is decommissioned; rotation not possible.")
    if hashlib.sha256(new_pk).digest() != current.next_key_hash:
        raise ValueError("SHA256(new_pk) != current.next_key_hash -- pre-image mismatch.")


def rotate_step2_old_announces(kp_old: KeyPair, new_pk: bytes) -> Kind38100:
    """Optional Step 2: old key publishes Kind 38100 with status='rotated'."""
    return Kind38100(
        pubkey=kp_old.pk,
        created_at=int(time.time()),
        status="rotated",
        successor=new_pk,
    )


def rotate_step3_new_identity(
    kp_new: KeyPair,
    kp_next: KeyPair,
    pk_old: bytes,
) -> Kind38100:
    """Step 3: new key publishes active Kind 38100 with rotation_proof and fresh next_key_hash."""
    created_at = int(time.time())
    msg = rotation_proof_msg(pk_old, kp_new.pk, created_at)
    proof = kp_new.sign(msg)   # new key signs proof
    return Kind38100(
        pubkey=kp_new.pk,
        created_at=created_at,
        status="active",
        prev_key=pk_old,
        rotation_proof=proof,
        next_key_hash=hashlib.sha256(kp_next.pk).digest(),
    )


def decommission(kp: KeyPair) -> Kind38100:
    """Publish Kind 38100 with status='decommissioned'. All delegations immediately invalid."""
    return Kind38100(
        pubkey=kp.pk,
        created_at=int(time.time()),
        status="decommissioned",
        next_key_hash=None,
    )


# ---------------------------------------------------------------------------
# Delegation re-issuance
# ---------------------------------------------------------------------------

def reissue_delegations(old_delegations: list[Kind38101], kp_new: KeyPair) -> list[Kind38101]:
    """Re-sign all non-expired delegations with the new key after rotation."""
    now = int(time.time())
    reissued: list[Kind38101] = []
    for d in old_delegations:
        if d.expires_at <= now:
            continue
        new_d = Kind38101(
            delegator_pk=kp_new.pk,
            delegatee_pk=d.delegatee_pk,
            scope=d.scope,
            created_at=now,
            expires_at=d.expires_at,
        )
        new_d.signature = kp_new.sign(new_d.signing_msg())
        reissued.append(new_d)
    return reissued


# ---------------------------------------------------------------------------
# Grace period verification
# ---------------------------------------------------------------------------

def delegation_valid(
    delegation: Kind38101,
    current_identity: Kind38100,
    old_identity: Kind38100 | None = None,
    grace_seconds: int = 3600,
) -> bool:
    """Return True if delegation signature is valid.

    Accepts signatures from the current key, or from the old key within
    the grace period after rotation (old_identity.status == 'rotated').
    Delegations from a decommissioned identity are always invalid.
    """
    now = int(time.time())
    if current_identity.status == "decommissioned":
        return False
    if delegation.expires_at <= now:
        return False

    msg = delegation.signing_msg()

    # Check new key
    if delegation.delegator_pk == current_identity.pubkey:
        return _bip340_verify(current_identity.pubkey, msg, delegation.signature)

    # Grace period: accept old key's signature if rotation is recent
    if (
        old_identity is not None
        and old_identity.status == "rotated"
        and delegation.delegator_pk == old_identity.pubkey
        and (now - old_identity.created_at) <= grace_seconds
    ):
        return _bip340_verify(old_identity.pubkey, msg, delegation.signature)

    return False


# ---------------------------------------------------------------------------
# Rotation chain verification
# ---------------------------------------------------------------------------

def verify_rotation_chain(chain: list[Kind38100], genesis_pk: bytes) -> bool:
    """Walk prev_key links from genesis to current, verifying each rotation_proof.

    chain[0] must be the genesis event (pubkey == genesis_pk).
    Each subsequent event must carry a valid rotation_proof signed by its own pubkey.
    """
    if not chain or chain[0].pubkey != genesis_pk:
        return False

    for i in range(1, len(chain)):
        ev = chain[i]
        prev_ev = chain[i - 1]

        if ev.prev_key != prev_ev.pubkey:
            return False
        if ev.rotation_proof is None:
            return False

        msg = rotation_proof_msg(prev_ev.pubkey, ev.pubkey, ev.created_at)
        if not _bip340_verify(ev.pubkey, msg, ev.rotation_proof):
            return False

    return True


# ---------------------------------------------------------------------------
# Working example
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Three key pairs: genesis (kp0), rotation target (kp1), next pre-rotation (kp2)
    kp0 = KeyPair.generate()
    kp1 = KeyPair.generate()
    kp2 = KeyPair.generate()

    # 1. Create genesis identity with pre-rotation commitment to kp1
    genesis = create_identity(kp0, kp1)
    print(f"[1] Genesis: pubkey={kp0.pk.hex()[:16]}...  status={genesis.status}")
    print(f"    next_key_hash={genesis.next_key_hash.hex()[:16]}...")  # type: ignore[union-attr]

    # 2. Validate pre-image (Step 1) -- would raise on mismatch
    rotate_step1_validate(genesis, kp1.pk)

    # 3. (Optional) Old key announces rotation
    step2_ev = rotate_step2_old_announces(kp0, kp1.pk)
    print(f"\n[2] Old key announces: status={step2_ev.status}, successor={kp1.pk.hex()[:16]}...")

    # 4. New key publishes active identity with rotation_proof
    new_identity = rotate_step3_new_identity(kp1, kp2, kp0.pk)
    print(f"[3] New identity: pubkey={kp1.pk.hex()[:16]}...  status={new_identity.status}")

    # 5. Re-issue delegations signed by old key
    delegatee = KeyPair.generate()
    now = int(time.time())
    old_del = Kind38101(
        delegator_pk=kp0.pk,
        delegatee_pk=delegatee.pk,
        scope="read:events",
        created_at=now - 60,
        expires_at=now + 7200,
    )
    old_del.signature = kp0.sign(old_del.signing_msg())

    reissued = reissue_delegations([old_del], kp1)
    print(f"\n[4] Re-issued {len(reissued)} delegation(s) with new key")

    # 6. Grace period: old delegation still accepted within grace window
    grace_ok = delegation_valid(old_del, new_identity, step2_ev, grace_seconds=3600)
    print(f"[5] Old delegation valid in grace period: {grace_ok}")

    new_ok = delegation_valid(reissued[0], new_identity)
    print(f"[6] New delegation valid: {new_ok}")

    # 7. Verify rotation chain (genesis -> new_identity)
    chain_ok = verify_rotation_chain([genesis, new_identity], kp0.pk)
    print(f"\n[7] verify_rotation_chain (depth=1): {chain_ok}")

    # Double rotation to verify depth-2 chain
    kp3 = KeyPair.generate()
    identity2 = rotate_step3_new_identity(kp2, kp3, kp1.pk)
    chain2_ok = verify_rotation_chain([genesis, new_identity, identity2], kp0.pk)
    print(f"[8] verify_rotation_chain (depth=2): {chain2_ok}")

    # 8. Decommission
    decomm = decommission(kp2)
    print(f"\n[9] Decommissioned: status={decomm.status}, next_key_hash={decomm.next_key_hash}")
    decomm_del_ok = delegation_valid(reissued[0], decomm)
    print(f"[10] Delegation valid after decommission: {decomm_del_ok}")
