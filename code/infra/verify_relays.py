"""Verify all 3 strfry relays accept custom kinds 38100-38102.

For each kind, publishes a minimal valid event to each relay, then queries
it back and verifies the event is returned. Prints per-relay per-kind results
and a final summary.

Usage (run from inside code/):
    uv run python infra/verify_relays.py

Requires:
    - nostr-sdk==0.44.2 (installed via `uv sync --extra dev` from code/)
    - 3 strfry relays running (docker compose -f infra/docker-compose.yml up -d)
"""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import timedelta

import nostr_sdk as ns

RELAY_URLS = [
    "ws://localhost:7771",
    "ws://localhost:7772",
    "ws://localhost:7773",
]

KINDS = [38100, 38101, 38102]

KIND_LABELS = {
    38100: "Agent Identity Declaration",
    38101: "Delegation Chain Event",
    38102: "Peer Attestation",
}

FETCH_TIMEOUT = timedelta(seconds=5)


def _build_content(kind: int) -> str:
    if kind == 38100:
        return json.dumps({"name": "verify-test", "version": "0.1.0"})
    if kind == 38101:
        return json.dumps({"scope": {"capabilities": ["test"]}, "schema_version": "1.0"})
    # 38102
    return json.dumps({"confidence": 0.9, "capability": "test"})


def _build_tags(kind: int) -> list[ns.Tag]:
    d_tag = f"test-verify-{kind}"
    tags = [
        ns.Tag.identifier(d_tag),
        ns.Tag.alt(f"verify test kind {kind}"),
    ]
    return tags


async def _publish_and_verify(
    relay_url: str,
    kind: int,
    keys: ns.Keys,
) -> tuple[bool, str]:
    """Publish a test event to a single relay and query it back.

    Returns (success, detail_message).
    """
    d_tag = f"test-verify-{kind}"
    content = _build_content(kind)
    tags = _build_tags(kind)
    builder = ns.EventBuilder(ns.Kind(kind), content).tags(tags)

    # --- publish ---
    signer = ns.NostrSigner.keys(keys)
    client = ns.Client(signer)
    await client.add_relay(ns.RelayUrl.parse(relay_url))
    await client.connect()
    try:
        output = await client.send_event_builder(builder)
    except Exception as exc:
        await client.disconnect()
        return False, f"publish failed: {exc}"

    success_relays = output.success
    failed_relays = output.failed
    if failed_relays:
        reasons = ", ".join(f"{url}: {reason}" for url, reason in failed_relays.items())
        await client.disconnect()
        return False, f"relay rejected event: {reasons}"

    # --- query back ---
    f = ns.Filter().kind(ns.Kind(kind)).identifier(d_tag)
    try:
        events = await client.fetch_events(f, FETCH_TIMEOUT)
        event_list = events.to_vec()
    except Exception as exc:
        await client.disconnect()
        return False, f"query failed: {exc}"

    await client.disconnect()

    if not event_list:
        return False, "event published but not returned by query"

    # Verify at least one returned event matches our kind and d-tag
    for ev in event_list:
        if ev.kind().as_u16() == kind:
            ev_d_tag = ev.tags().identifier()
            if ev_d_tag == d_tag:
                return True, "OK"

    return False, f"query returned {len(event_list)} event(s) but none matched kind={kind} d={d_tag}"


async def main() -> None:
    ns.uniffi_set_event_loop(asyncio.get_running_loop())

    keys = ns.Keys.generate()
    print(f"Test pubkey: {keys.public_key().to_hex()[:16]}...")
    print()

    failures: list[str] = []
    total = 0
    passed = 0

    for kind in KINDS:
        label = KIND_LABELS[kind]
        print(f"--- Kind {kind} ({label}) ---")

        for relay_url in RELAY_URLS:
            total += 1
            ok, detail = await _publish_and_verify(relay_url, kind, keys)

            if ok:
                passed += 1
                print(f"  {relay_url}: PASS")
            else:
                failures.append(f"Kind {kind} @ {relay_url}: {detail}")
                print(f"  {relay_url}: FAIL - {detail}")

        print()

    # Summary
    print("=" * 60)
    if not failures:
        print(f"All relays accept kinds 38100-38102 ({passed}/{total} checks passed)")
        sys.exit(0)
    else:
        print(f"FAILURES ({passed}/{total} passed):")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
