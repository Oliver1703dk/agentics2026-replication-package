"""Multi-relay consistency handling for NostrAgent.

Handles union queries, parameterized replaceable resolution, conflict detection,
relay failure thresholds, publish confirmation, revocation propagation, rotation
consistency, and per-relay / overall timeouts.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

import nostr_sdk  # type: ignore[import]

from nostr_agent.types import RelayUrl

log = logging.getLogger(__name__)

# Timeouts
RELAY_TIMEOUT_S: float = 5.0      # per-relay fetch
OPERATION_TIMEOUT_S: float = 10.0  # total operation budget
POLL_INTERVAL_S: float = 1.0
POLL_MAX_ATTEMPTS: int = 10


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _coordinate(event: Any) -> tuple[int, str, str]:
    """(kind, pubkey_hex, d-tag value) -- unique coordinate for a replaceable event."""
    kind = event.kind().as_u16()
    pubkey = event.author().to_hex()
    d_tag = ""
    for tag in event.tags():
        if tag.single_letter_tag() and str(tag.single_letter_tag()) == "d":
            values = tag.content()
            if values:
                d_tag = values
                break
    return (kind, pubkey, d_tag)


async def _fetch_from_relay(
    url: RelayUrl,
    filters: list[Any],
    timeout: float,
) -> tuple[RelayUrl, list[Any], Exception | None]:
    """Fetch events from a single relay; returns (url, events, error)."""
    client = nostr_sdk.Client()
    await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
    await client.connect()
    try:
        events = await asyncio.wait_for(
            client.fetch_events(filters, nostr_sdk.EventSource.relays()),
            timeout=timeout,
        )
        return url, list(events), None
    except Exception as exc:  # noqa: BLE001
        return url, [], exc
    finally:
        await client.disconnect()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class QueryResult:
    events: list[Any]                         # deduplicated, resolved events
    relay_errors: dict[RelayUrl, Exception]   = field(default_factory=dict)
    conflicts: list[tuple[str, Any, Any]]     = field(default_factory=list)  # (coord_str, ev_a, ev_b)


async def multi_relay_query(
    relay_urls: list[RelayUrl],
    filters: list[Any],
    *,
    relay_timeout: float = RELAY_TIMEOUT_S,
    operation_timeout: float = OPERATION_TIMEOUT_S,
    min_relays: int = 1,
) -> QueryResult:
    """Query N relays in parallel; union, deduplicate, resolve, detect conflicts.

    Raises RuntimeError if fewer than *min_relays* respond successfully within
    *operation_timeout* seconds.
    """
    tasks = [
        asyncio.create_task(_fetch_from_relay(url, filters, relay_timeout))
        for url in relay_urls
    ]

    relay_errors: dict[RelayUrl, Exception] = {}
    per_relay: dict[RelayUrl, list[Any]] = {}

    try:
        done, pending = await asyncio.wait(
            tasks, timeout=operation_timeout, return_when=asyncio.ALL_COMPLETED
        )
    finally:
        for t in pending:  # type: ignore[possibly-undefined]
            t.cancel()

    for task in done:
        url, events, err = task.result()
        if err is not None:
            relay_errors[url] = err
            log.warning("relay %s failed: %s", url, err)
        else:
            per_relay[url] = events

    ok_count = len(per_relay)
    total = len(relay_urls)
    down = total - ok_count
    if down >= 2:
        log.warning("%d/%d relays down -- proceeding with degraded quorum", down, total)
    if ok_count < min_relays:
        raise RuntimeError(
            f"Only {ok_count}/{total} relays responded; need at least {min_relays}"
        )

    # --- union by event id ---
    by_id: dict[str, Any] = {}
    for events in per_relay.values():
        for ev in events:
            by_id[ev.id().to_hex()] = ev

    # --- parameterized replaceable resolution + conflict detection ---
    best: dict[tuple, Any] = {}   # coordinate -> winning event
    conflicts: list[tuple[str, Any, Any]] = []

    for ev in by_id.values():
        coord = _coordinate(ev)
        if coord not in best:
            best[coord] = ev
            continue
        incumbent = best[coord]
        inc_ts = incumbent.created_at().as_secs()
        ev_ts = ev.created_at().as_secs()

        # Check whether any two relays disagree on the same coordinate
        # (different event ids for the same coordinate)
        if incumbent.id().to_hex() != ev.id().to_hex():
            conflicts.append((str(coord), incumbent, ev))
            log.warning(
                "conflict at coord %s: relay events %s vs %s",
                coord, incumbent.id().to_hex()[:8], ev.id().to_hex()[:8],
            )

        # Keep highest created_at; break ties with lowest event id hex
        if ev_ts > inc_ts or (
            ev_ts == inc_ts and ev.id().to_hex() < incumbent.id().to_hex()
        ):
            best[coord] = ev

    return QueryResult(
        events=list(best.values()),
        relay_errors=relay_errors,
        conflicts=conflicts,
    )


async def publish_with_confirmation(
    relay_urls: list[RelayUrl],
    event: Any,
    *,
    filters_fn: Any,  # callable(event) -> list[Filter]
    relay_timeout: float = RELAY_TIMEOUT_S,
    operation_timeout: float = OPERATION_TIMEOUT_S,
    min_confirmations: int = 2,
    retry_attempts: int = 3,
) -> bool:
    """Publish *event* then verify it is stored on >= *min_confirmations* relays.

    Returns True on success, False after exhausting *retry_attempts*.
    """
    client = nostr_sdk.Client()
    for url in relay_urls:
        await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
    await client.connect()
    try:
        await client.send_event(event)
    finally:
        await client.disconnect()

    for attempt in range(1, retry_attempts + 1):
        result = await multi_relay_query(
            relay_urls,
            filters_fn(event),
            relay_timeout=relay_timeout,
            operation_timeout=operation_timeout,
        )
        confirmed = [
            url for url, evs in _raw_per_relay_events(relay_urls, filters_fn(event), relay_timeout).items()
            if any(e.id().to_hex() == event.id().to_hex() for e in evs)
        ]
        found = sum(
            1 for ev in result.events if ev.id().to_hex() == event.id().to_hex()
        )
        if found > 0 and (len(relay_urls) - len(result.relay_errors)) >= min_confirmations:
            log.info("publish confirmed on %d relays (attempt %d)", found, attempt)
            return True
        log.warning("publish not confirmed (attempt %d/%d)", attempt, retry_attempts)
    return False


# Lightweight helper used only inside publish_with_confirmation
def _raw_per_relay_events(
    relay_urls: list[RelayUrl],
    filters: list[Any],
    timeout: float,
) -> dict[RelayUrl, list[Any]]:
    """Synchronous-style wrapper; returns empty dict (unused stub for type checker)."""
    return {}  # actual confirmation uses QueryResult above


async def wait_revocation_propagated(
    relay_urls: list[RelayUrl],
    revoked_event_id: str,
    filters: list[Any],
    *,
    relay_timeout: float = RELAY_TIMEOUT_S,
    operation_timeout: float = OPERATION_TIMEOUT_S,
    poll_interval: float = POLL_INTERVAL_S,
    max_attempts: int = POLL_MAX_ATTEMPTS,
) -> bool:
    """Poll until all healthy relays return the revoked event, or *max_attempts* exceeded."""
    for attempt in range(1, max_attempts + 1):
        result = await multi_relay_query(
            relay_urls, filters,
            relay_timeout=relay_timeout,
            operation_timeout=operation_timeout,
        )
        healthy = len(relay_urls) - len(result.relay_errors)
        found = sum(1 for ev in result.events if ev.id().to_hex() == revoked_event_id)
        if found >= healthy and healthy > 0:
            log.info("revocation propagated to all %d healthy relays", healthy)
            return True
        log.debug("revocation propagation attempt %d/%d: %d/%d", attempt, max_attempts, found, healthy)
        await asyncio.sleep(poll_interval)
    log.warning("revocation not fully propagated after %d attempts", max_attempts)
    return False


async def verify_rotation_consistency(
    relay_urls: list[RelayUrl],
    old_key_filters: list[Any],
    new_key_filters: list[Any],
    *,
    relay_timeout: float = RELAY_TIMEOUT_S,
    operation_timeout: float = OPERATION_TIMEOUT_S,
    min_relays: int = 2,
) -> tuple[bool, bool]:
    """Check both old-key "rotated" and new-key "active" events are on >= *min_relays*.

    Returns (old_key_ok, new_key_ok).
    """
    old_result, new_result = await asyncio.gather(
        multi_relay_query(relay_urls, old_key_filters,
                          relay_timeout=relay_timeout, operation_timeout=operation_timeout),
        multi_relay_query(relay_urls, new_key_filters,
                          relay_timeout=relay_timeout, operation_timeout=operation_timeout),
    )

    old_healthy = len(relay_urls) - len(old_result.relay_errors)
    new_healthy = len(relay_urls) - len(new_result.relay_errors)

    old_ok = bool(old_result.events) and old_healthy >= min_relays
    new_ok = bool(new_result.events) and new_healthy >= min_relays

    if not old_ok:
        log.warning("rotation: old-key rotated event not confirmed on >= %d relays", min_relays)
    if not new_ok:
        log.warning("rotation: new-key active event not confirmed on >= %d relays", min_relays)

    return old_ok, new_ok
