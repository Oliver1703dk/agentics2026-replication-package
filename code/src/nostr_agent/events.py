"""
nostr_sdk v0.44.2 -- working patterns for Kind 38100/38101/38102 events.

All code here is verified against the installed 0.44.2 wheel.
Import as part of the installed package (python -m nostr_agent or via pyproject.toml).
Note: do NOT run this file directly with `python events.py` from inside the package
directory -- types.py shadows stdlib `types`, causing a circular import at load time.
"""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta

import nostr_sdk as ns


# ---------------------------------------------------------------------------
# BOOTSTRAP: must be called once before any await on nostr_sdk coroutines.
# Pass your running event loop.  Call at top of your async entrypoint.
# ---------------------------------------------------------------------------
def bootstrap(loop: asyncio.AbstractEventLoop | None = None) -> None:
    ns.uniffi_set_event_loop(loop or asyncio.get_event_loop())


# ---------------------------------------------------------------------------
# 1. KEY MANAGEMENT
# ---------------------------------------------------------------------------

def generate_keys() -> ns.Keys:
    return ns.Keys.generate()

def load_keys(nsec_or_hex: str) -> ns.Keys:
    """Accept nsec1… bech32 or 64-char hex secret key."""
    return ns.Keys.parse(nsec_or_hex)

def pubkey_hex(keys: ns.Keys) -> str:
    return keys.public_key().to_hex()

def pubkey_bech32(keys: ns.Keys) -> str:
    return keys.public_key().to_bech32()


# ---------------------------------------------------------------------------
# 2. TAG CONSTRUCTION -- exact API for every tag used in 38100/38101/38102
# ---------------------------------------------------------------------------

def make_tags_38100(
    *,
    agent_id: str,                  # d-tag -- replaceable event identifier
    operator_pubkey: ns.PublicKey,  # p-tag -- operator public key
    relay_url: str,                 # r-tag -- home relay
    schema_version: str = "1",
    next_key_hash: str | None = None,   # SHA256 of next rotation key (pre-rotation)
    prev_key: str | None = None,        # hex pubkey of rotated-from key
    ttl_seconds: int = 86400 * 90,
) -> list[ns.Tag]:
    tags: list[ns.Tag] = [
        # --- NIP-33 required ---
        ns.Tag.identifier(agent_id),

        # --- Reference tags ---
        ns.Tag.public_key(operator_pubkey),

        # --- Human-readable description ---
        ns.Tag.alt("Kind 38100: NostrAgent Identity Declaration"),

        # --- Hashtag for discovery ---
        ns.Tag.hashtag("nostr-agent"),

        # --- Expiration ---
        ns.Tag.expiration(
            ns.Timestamp.from_secs(ns.Timestamp.now().as_secs() + ttl_seconds)
        ),

        # --- Relay hint ---
        ns.Tag.custom(
            ns.TagKind.SINGLE_LETTER(ns.SingleLetterTag.lowercase(ns.Alphabet.R)),
            [relay_url],
        ),

        # --- Custom multi-letter tags (TagKind.UNKNOWN for arbitrary names) ---
        ns.Tag.custom(ns.TagKind.UNKNOWN("schema_version"), [schema_version]),
    ]

    if next_key_hash:
        tags.append(ns.Tag.custom(ns.TagKind.UNKNOWN("next_key_hash"), [next_key_hash]))

    if prev_key:
        tags.append(ns.Tag.custom(ns.TagKind.UNKNOWN("prev_key"), [prev_key]))

    return tags


def make_tags_38101(
    *,
    delegation_id: str,             # d-tag
    delegator_pubkey: ns.PublicKey, # p-tag (parent key)
    delegatee_pubkey: ns.PublicKey, # p-tag (child key)
    parent_event_coord: ns.Coordinate | None = None,  # a-tag to parent 38100
    scopes: list[str] | None = None,
    ttl_seconds: int = 86400 * 7,
) -> list[ns.Tag]:
    tags: list[ns.Tag] = [
        ns.Tag.identifier(delegation_id),
        ns.Tag.public_key(delegator_pubkey),
        ns.Tag.public_key(delegatee_pubkey),
        ns.Tag.alt("Kind 38101: Delegation Chain Event"),
        ns.Tag.expiration(
            ns.Timestamp.from_secs(ns.Timestamp.now().as_secs() + ttl_seconds)
        ),
    ]
    if parent_event_coord:
        tags.append(ns.Tag.coordinate(parent_event_coord, None))
    if scopes:
        for scope in scopes:
            tags.append(ns.Tag.custom(ns.TagKind.UNKNOWN("scope"), [scope]))
    return tags


def make_tags_38102(
    *,
    attestation_id: str,            # d-tag
    attester_pubkey: ns.PublicKey,  # signer = attester
    subject_pubkey: ns.PublicKey,   # p-tag (who is attested)
    trust_score: float,             # 0.0-1.0
    subject_event_coord: ns.Coordinate | None = None,
) -> list[ns.Tag]:
    tags: list[ns.Tag] = [
        ns.Tag.identifier(attestation_id),
        ns.Tag.public_key(subject_pubkey),
        ns.Tag.alt("Kind 38102: Peer Attestation"),
        ns.Tag.custom(ns.TagKind.UNKNOWN("trust_score"), [str(trust_score)]),
    ]
    if subject_event_coord:
        tags.append(ns.Tag.coordinate(subject_event_coord, None))
    return tags


# ---------------------------------------------------------------------------
# 3. EVENT CONSTRUCTION + SIGNING
# ---------------------------------------------------------------------------

def build_and_sign(
    kind: int,
    content_dict: dict,
    tags: list[ns.Tag],
    keys: ns.Keys,
) -> ns.Event:
    """Synchronous sign -- no relay, no async needed."""
    content = json.dumps(content_dict)
    builder = ns.EventBuilder(ns.Kind(kind), content).tags(tags)
    return builder.sign_with_keys(keys)


# ---------------------------------------------------------------------------
# 4. CLIENT: PUBLISH + QUERY
# ---------------------------------------------------------------------------

async def publish_event(
    event: ns.Event,
    relay_urls: list[str],
    keys: ns.Keys,
) -> ns.SendEventOutput:
    """
    Publish a pre-signed event.  Returns SendEventOutput with:
      .id        -- EventId
      .success   -- list[RelayUrl] that accepted
      .failed    -- dict[RelayUrl, str] with error reason
    """
    signer = ns.NostrSigner.keys(keys)
    client = ns.Client(signer)
    for url in relay_urls:
        await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
    await client.connect()
    output = await client.send_event(event)
    await client.disconnect()
    return output


async def publish_builder(
    builder: ns.EventBuilder,
    relay_urls: list[str],
    keys: ns.Keys,
) -> ns.SendEventOutput:
    """Sign + publish in one call (client signs internally)."""
    signer = ns.NostrSigner.keys(keys)
    client = ns.Client(signer)
    for url in relay_urls:
        await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
    await client.connect()
    output = await client.send_event_builder(builder)
    await client.disconnect()
    return output


async def fetch_agent_identity(
    agent_id: str,
    relay_urls: list[str],
    timeout: timedelta = timedelta(seconds=5),
) -> list[ns.Event]:
    """Fetch Kind 38100 by d-tag identifier."""
    client = ns.Client()
    for url in relay_urls:
        await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
    await client.connect()

    f = ns.Filter().kind(ns.Kind(38100)).identifier(agent_id)
    events = await client.fetch_events(f, timeout)
    await client.disconnect()
    return events.to_vec()


async def fetch_delegations_for(
    delegatee_pubkey: ns.PublicKey,
    relay_urls: list[str],
    timeout: timedelta = timedelta(seconds=5),
) -> list[ns.Event]:
    """Fetch Kind 38101 events where #p matches delegatee."""
    client = ns.Client()
    for url in relay_urls:
        await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
    await client.connect()

    f = (ns.Filter()
         .kind(ns.Kind(38101))
         .custom_tag(ns.SingleLetterTag.lowercase(ns.Alphabet.P),
                     delegatee_pubkey.to_hex()))
    events = await client.fetch_events(f, timeout)
    await client.disconnect()
    return events.to_vec()


# ---------------------------------------------------------------------------
# 5. READING TAGS BACK FROM A RECEIVED EVENT
# ---------------------------------------------------------------------------

def extract_custom_tag(event: ns.Event, tag_name: str) -> str | None:
    """Extract first value of a multi-letter custom tag."""
    tags = event.tags()
    found = tags.find(ns.TagKind.UNKNOWN(tag_name))
    if found is None:
        return None
    vec = found.as_vec()
    return vec[1] if len(vec) > 1 else None


def extract_schema_version(event: ns.Event) -> str | None:
    return extract_custom_tag(event, "schema_version")


def extract_next_key_hash(event: ns.Event) -> str | None:
    return extract_custom_tag(event, "next_key_hash")


# ---------------------------------------------------------------------------
# 6. REAL-TIME SUBSCRIPTION via stream_events()
# ---------------------------------------------------------------------------

async def stream_agent_events(
    relay_urls: list[str],
    timeout: timedelta = timedelta(seconds=30),
) -> None:
    """Print all 38100/38101/38102 events as they arrive."""
    client = ns.Client()
    for url in relay_urls:
        await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
    await client.connect()

    f = ns.Filter().kinds([ns.Kind(38100), ns.Kind(38101), ns.Kind(38102)])
    stream: ns.EventStream = await client.stream_events(f, timeout)

    while True:
        event: ns.Event | None = await stream.next()
        if event is None:
            break
        print(f"kind={event.kind().as_u16()} id={event.id().to_hex()[:16]}…")

    await client.disconnect()


# ---------------------------------------------------------------------------
# COMPLETE WORKING EXAMPLE -- Kind 38100 round-trip (offline, no relay)
# ---------------------------------------------------------------------------

async def demo_offline() -> None:
    keys = generate_keys()
    print(f"operator pubkey: {pubkey_hex(keys)}")

    tags = make_tags_38100(
        agent_id="demo-agent-001",
        operator_pubkey=keys.public_key(),
        relay_url="wss://relay.example.com",
        schema_version="1",
        next_key_hash="a" * 64,  # placeholder SHA256
    )

    event = build_and_sign(
        kind=38100,
        content_dict={"name": "demo-agent", "version": "0.1.0"},
        tags=tags,
        keys=keys,
    )

    # Verify locally
    assert event.verify(), "BIP340 signature invalid"
    print(f"event id:        {event.id().to_hex()}")
    print(f"kind:            {event.kind().as_u16()}")
    print(f"d-tag:           {event.tags().identifier()}")
    print(f"schema_version:  {extract_schema_version(event)}")
    print(f"next_key_hash:   {extract_next_key_hash(event)}")

    # JSON round-trip
    json_str = event.as_json()
    event2 = ns.Event.from_json(json_str)
    assert event2.verify()
    print("JSON round-trip: OK")


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    ns.uniffi_set_event_loop(loop)
    loop.run_until_complete(demo_offline())
