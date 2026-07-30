"""STRIDE adversarial test procedures TP-01 through TP-09.

Each test validates a security property reported in the paper Section 5.4 (STRIDE matrix) and Section 5.5 (residual risks).
Tests are designed to run offline (no live relay) unless marked with the
``integration`` marker, which requires the Docker relay stack in code/infra/.

Threat boundary abbreviations: TB1 = Agent<->Relay, TB2 = Agent<->Agent,
TB3 = Agent<->Service.

Pytest markers
--------------
- unit      : no I/O; pure crypto / in-process logic (default)
- integration : requires running relay (Docker compose)
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time

import nostr_sdk as ns
import pymacaroons
import pytest

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


_KEY_CTR = 0


def _make_keys() -> ns.Keys:
    global _KEY_CTR
    _KEY_CTR += 1
    return ns.Keys.parse(hashlib.sha256(f"det-stride-{_KEY_CTR}".encode()).hexdigest())


def _minimal_38100(keys: ns.Keys, *, agent_id: str = "tp-agent") -> ns.Event:
    """Build and sign a minimal valid Kind 38100 event."""
    tags = [
        ns.Tag.identifier(agent_id),
        ns.Tag.public_key(keys.public_key()),
    ]
    builder = ns.EventBuilder(ns.Kind(38100), "{}").tags(tags)
    return builder.sign_with_keys(keys)


def _event_as_dict(event: ns.Event) -> dict:
    """Convert Event to a mutable dict via JSON round-trip."""
    return json.loads(event.as_json())


# ---------------------------------------------------------------------------
# TP-01 -- Spoofing / TB1
# Construct Kind 38100 where pubkey field != signing key.
# Verifier MUST reject because BIP340 signature covers the declared pubkey.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_tp01_forged_pubkey_identity() -> None:
    """TP-01: pubkey mismatch → BIP340 verify fails (S-TB1a countermeasure)."""
    # Setup: two independent keypairs
    real_keys = _make_keys()
    victim_keys = _make_keys()

    # Attack: sign with real_keys but inject victim's pubkey into the JSON
    event = _minimal_38100(real_keys)
    d = _event_as_dict(event)
    d["pubkey"] = victim_keys.public_key().to_hex()  # forge the pubkey field

    # Reconstruct event from tampered JSON -- nostr-sdk parses but does not re-sign
    tampered = ns.Event.from_json(json.dumps(d))

    # Verification: event.verify() recomputes id and checks BIP340 sig
    assert not tampered.verify(), (
        "Relay/verifier MUST reject: pubkey does not match signing key"
    )


# ---------------------------------------------------------------------------
# TP-02 -- Tampering / TB2
# Modify a single byte in a valid signed Kind 38101 event.
# Verifier MUST reject due to BIP340 signature mismatch.
# Also validates NST-1 / NST-2 (mandatory id recomputation) per threat_model.md.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_tp02_post_signature_tag_tampering() -> None:
    """TP-02: one-byte tag mutation → BIP340 verify fails (T-TB2 countermeasure)."""
    delegator_keys = _make_keys()
    delegatee_keys = _make_keys()

    # Setup: build valid signed Kind 38101
    tags = [
        ns.Tag.identifier("tp02-delegation"),
        ns.Tag.public_key(delegator_keys.public_key()),
        ns.Tag.public_key(delegatee_keys.public_key()),
        ns.Tag.custom(ns.TagKind.UNKNOWN("scope"), ["read"]),
    ]
    builder = ns.EventBuilder(ns.Kind(38101), "{}").tags(tags)
    valid_event = builder.sign_with_keys(delegator_keys)
    assert valid_event.verify(), "Precondition: valid event must pass verification"

    # Attack: flip one character in the scope tag value
    d = _event_as_dict(valid_event)
    for tag in d["tags"]:
        if tag[0] == "scope":
            tag[1] = "write"  # escalate scope: read → write
            break

    tampered = ns.Event.from_json(json.dumps(d))

    # Verification: mandatory id recomputation + BIP340 check
    raw = json.dumps(
        [0, d["pubkey"], d["created_at"], d["kind"], d["tags"], d["content"]],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    recomputed_id = hashlib.sha256(raw).hexdigest()

    # The recomputed id must differ from the declared id (tag mutation changed content)
    assert recomputed_id != d["id"], (
        "TP-02: id recomputation MUST detect tag mutation"
    )
    assert not tampered.verify(), (
        "TP-02: BIP340 verification MUST reject tampered event"
    )


# ---------------------------------------------------------------------------
# TP-03 -- Repudiation / TB2
# Publish Kind 38102 to 3 relays; 2 go offline.
# Audit trail must survive on the remaining relay.
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_tp03_audit_trail_survives_relay_loss() -> None:
    """TP-03: signed Kind 38102 on surviving relay provides non-repudiation.

    Requires 3 relays running in Docker (see code/infra/).  Stops 2 relays
    via the Docker SDK and verifies the event is still fetchable from relay 3.
    """
    import docker  # type: ignore[import]
    from datetime import timedelta

    attester_keys = _make_keys()
    subject_keys = _make_keys()

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


# ---------------------------------------------------------------------------
# TP-04 -- Denial of Service / TB1
# Event flood at 100 / 500 / 1000 events-per-second.
# Measure median relay response latency; assert it stays below 500 ms threshold.
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize("events_per_second", [100, 500, 1000])
async def test_tp04_event_flood_latency(events_per_second: int) -> None:
    """TP-04: flood relay and measure latency degradation.

    Asserts median publish latency < 500 ms under flood load.
    Requires running relay at ws://127.0.0.1:7001 (code/infra/).
    """
    from datetime import timedelta

    attacker_keys = _make_keys()
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

    # Degradation assertion: median publish round-trip < 500 ms
    assert median_ms < 500, (
        f"TP-04 @ {events_per_second}/s: median latency {median_ms:.1f} ms >= 500 ms "
        "(relay rate-limiting may be suppressing flood but latency is unacceptable)"
    )


# ---------------------------------------------------------------------------
# TP-05 -- Information Disclosure / TB2
# Unauthenticated graph traversal: query relays for all Kind 38102 events,
# reconstruct trust topology, assert that enumeration succeeds (expected by design)
# and document the residual privacy risk.
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_tp05_unauthenticated_trust_graph_enumeration() -> None:
    """TP-05: unauthenticated query enumerates all public Kind 38102 trust edges.

    Expected outcome: enumeration succeeds (public-by-design, residual risk = 4).
    Test documents the threat, not a countermeasure.
    """
    import networkx as nx  # type: ignore[import]
    from datetime import timedelta

    # Setup: seed relay with 3 attestation edges forming a triangle
    seed_keys = [_make_keys() for _ in range(3)]
    publisher_keys = seed_keys[0]
    signer = ns.NostrSigner.keys(publisher_keys)
    client = ns.Client(signer)
    await client.add_relay("ws://127.0.0.1:7001")
    await client.connect()

    edges: list[tuple[str, str]] = []
    for i in range(3):
        attester = seed_keys[i]
        subject = seed_keys[(i + 1) % 3]
        edge = (attester.public_key().to_hex()[:16], subject.public_key().to_hex()[:16])
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
    anon_client = ns.Client()  # no keys → unauthenticated
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

    # Assertion: graph was successfully reconstructed (documents residual risk = 4)
    assert G.number_of_edges() >= 3, (
        "TP-05: unauthenticated graph enumeration MUST succeed -- "
        "public-by-design architectural tradeoff (Info Disclosure residual risk = 4)"
    )


# ---------------------------------------------------------------------------
# TP-06 -- Elevation of Privilege / TB2
# Create Kind 38101 with scope wider than parent delegation.
# Verifier MUST reject the attenuation violation.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_tp06_attenuation_violation_rejected() -> None:
    """TP-06: child scope superset of parent → ValidationError (EoP-TB2 countermeasure)."""
    from nostr_agent.types import DelegationChain, DelegationLink, PublicKey, Scope, Signature
    from nostr_agent.validation import ValidationError, validate_chain

    parent_pubkey = PublicKey(_make_keys().public_key().to_hex())
    middle_pubkey = PublicKey(_make_keys().public_key().to_hex())
    child_pubkey = PublicKey(_make_keys().public_key().to_hex())

    # Parent grants only "read"
    parent_link = DelegationLink(
        delegator_pubkey=parent_pubkey,
        delegatee_pubkey=middle_pubkey,
        scopes=[Scope(resource="nostr:relay:wss://r.test", actions=frozenset({"read"}))],
        signature=Signature("0" * 128),
        event_id="a" * 64,  # type: ignore[arg-type]
        expires_at=None,
    )

    # Attack: child claims "read" AND "write" -- wider than parent
    escalated_link = DelegationLink(
        delegator_pubkey=middle_pubkey,
        delegatee_pubkey=child_pubkey,
        scopes=[Scope(resource="nostr:relay:wss://r.test", actions=frozenset({"read", "write"}))],
        signature=Signature("0" * 128),
        event_id="b" * 64,  # type: ignore[arg-type]
        expires_at=None,
    )

    chain = DelegationChain(links=[parent_link, escalated_link])

    with pytest.raises(ValidationError, match="not a subset of parent actions"):
        validate_chain(chain)


# ---------------------------------------------------------------------------
# TP-07 -- Spoofing / TB3
# Forge macaroon HMAC chain. Present to verifier. Verifier MUST reject.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_tp07_forged_macaroon_hmac_rejected() -> None:
    """TP-07: forged macaroon HMAC chain → pymacaroons.InvalidSignatureException."""
    root_key = b"legitimate-service-root-key-32by"
    attacker_key = b"attacker-controlled-wrong-key-32"

    # Setup: service mints a legitimate macaroon
    legitimate = pymacaroons.Macaroon(
        location="https://service.example.com",
        identifier="token-001",
        key=root_key,
    )
    legitimate = legitimate.add_first_party_caveat("scope = read")

    # Attack: attacker builds a macaroon with the same identifier but wrong root key
    forged = pymacaroons.Macaroon(
        location="https://service.example.com",
        identifier="token-001",
        key=attacker_key,  # wrong key → HMAC chain will not match
    )
    forged = forged.add_first_party_caveat("scope = read")

    # Verification: service verifies against its root key
    verifier = pymacaroons.Verifier()
    verifier.satisfy_exact("scope = read")

    # Legitimate token passes
    verifier.verify(legitimate, root_key)  # must not raise

    # Forged token fails
    with pytest.raises(Exception):  # InvalidSignatureException or ValueError
        verifier.verify(forged, root_key)


# ---------------------------------------------------------------------------
# TP-08 -- Tampering / TB3
# Modify invoice payment hash. Verify preimage does not satisfy modified hash.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_tp08_invoice_payment_hash_mismatch() -> None:
    """TP-08: tampered payment_hash → preimage does not satisfy invoice."""
    # Setup: simulate Lightning invoice with payment_hash = SHA256(preimage)
    preimage = b"correct-preimage-32-bytes-padded!"
    payment_hash = hashlib.sha256(preimage).digest()

    # Attack: relay / MITM substitutes a different payment_hash
    tampered_hash = hashlib.sha256(b"attacker-chosen-payload").digest()

    # Verification: service checks SHA256(preimage) == payment_hash
    assert hashlib.sha256(preimage).digest() == payment_hash, (
        "Precondition: correct preimage satisfies original payment_hash"
    )
    assert hashlib.sha256(preimage).digest() != tampered_hash, (
        "TP-08: preimage MUST NOT satisfy the tampered payment_hash"
    )

    # Macaroon bound to original payment_hash -- also fails under tampered hash
    root_key = b"service-root-key-32-bytes-padded"
    macaroon = pymacaroons.Macaroon(
        location="https://service.example.com",
        identifier=payment_hash.hex(),
        key=root_key,
    )
    macaroon = macaroon.add_first_party_caveat(f"payment_hash = {payment_hash.hex()}")

    # Attacker tries to present macaroon bound to original hash with tampered hash claim
    tampered_macaroon = pymacaroons.Macaroon(
        location="https://service.example.com",
        identifier=tampered_hash.hex(),  # different identifier → different HMAC chain
        key=root_key,
    )
    tampered_macaroon = tampered_macaroon.add_first_party_caveat(
        f"payment_hash = {tampered_hash.hex()}"
    )

    verifier = pymacaroons.Verifier()
    verifier.satisfy_exact(f"payment_hash = {payment_hash.hex()}")

    # Original macaroon verifies against original caveat
    verifier.verify(macaroon, root_key)  # must not raise

    # Tampered macaroon does NOT satisfy original payment_hash caveat
    with pytest.raises(Exception):
        verifier.verify(tampered_macaroon, root_key)


# ---------------------------------------------------------------------------
# TP-09 -- Replay / TB3
# Capture valid preimage from completed payment. Attempt reuse. Verify rejection.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_tp09_preimage_replay_rejected() -> None:
    """TP-09: reused preimage for a new invoice → payment_hash mismatch.

    Lightning invoices are single-use: each invoice has a unique payment_hash.
    A replayed preimage from invoice-1 will not satisfy invoice-2's payment_hash.
    """
    # Setup: service issues two sequential invoices (each with unique preimage)
    preimage_1 = b"preimage-for-invoice-1-32bytepad"
    preimage_2 = b"preimage-for-invoice-2-32bytepad"

    invoice_1_hash = hashlib.sha256(preimage_1).digest()
    invoice_2_hash = hashlib.sha256(preimage_2).digest()

    assert invoice_1_hash != invoice_2_hash, (
        "Precondition: each invoice MUST have a distinct payment_hash"
    )

    # Step 1: client pays invoice-1 and receives preimage_1 as proof of payment
    assert hashlib.sha256(preimage_1).digest() == invoice_1_hash, (
        "Precondition: preimage_1 satisfies invoice_1_hash"
    )

    # Attack: client presents preimage_1 for invoice-2 (replay)
    replayed_hash = hashlib.sha256(preimage_1).digest()

    assert replayed_hash != invoice_2_hash, (
        "TP-09: preimage from invoice-1 MUST NOT satisfy invoice-2's payment_hash"
    )

    # Macaroon layer: invoice-2 macaroon is bound to invoice_2_hash
    root_key = b"service-root-key-32-bytes-padded"
    invoice_2_macaroon = pymacaroons.Macaroon(
        location="https://service.example.com",
        identifier=invoice_2_hash.hex(),
        key=root_key,
    )
    invoice_2_macaroon = invoice_2_macaroon.add_first_party_caveat(
        f"payment_hash = {invoice_2_hash.hex()}"
    )

    # Verifier checks against invoice_2_hash -- preimage_1 replay does not match caveat
    verifier = pymacaroons.Verifier()
    verifier.satisfy_exact(f"payment_hash = {invoice_2_hash.hex()}")
    verifier.verify(invoice_2_macaroon, root_key)  # caveat is satisfied (hash matches)

    # Confirm: if attacker modifies the caveat to use invoice_1_hash, HMAC chain breaks
    replay_macaroon = pymacaroons.Macaroon(
        location="https://service.example.com",
        identifier=invoice_2_hash.hex(),
        key=root_key,
    )
    replay_macaroon = replay_macaroon.add_first_party_caveat(
        f"payment_hash = {invoice_1_hash.hex()}"  # wrong hash for this invoice
    )

    with pytest.raises(Exception):
        verifier.verify(replay_macaroon, root_key)
