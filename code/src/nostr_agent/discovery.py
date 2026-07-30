"""Relay-based agent discovery (TB1 trust boundary).

Subscribes to Kind 38100/38101/38102 events on one or more relays
and resolves AgentIdentity / DelegationLink / Attestation objects.

All multi-relay fan-out, deduplication, replaceable resolution, and conflict
detection is handled by relay_consistency.multi_relay_query.

The RelayDiscovery class provides a higher-level API: capability-based
agent lookup, identity resolution, operator-based discovery, publish-to-all,
and generic event fetching -- all with multi-relay deduplication.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from datetime import timedelta

import nostr_sdk  # type: ignore[import]

from nostr_agent.identity import KIND_AGENT_IDENTITY, parse_identity_event
from nostr_agent.delegation import KIND_DELEGATION, parse_delegation_link
from nostr_agent.trust import KIND_ATTESTATION, parse_attestation
from nostr_agent.types import (
    AgentIdentity,
    AgentInfo,
    Attestation,
    DelegationLink,
    PublicKey,
    PublishResult,
    RelayUrl,
    TrustPolicy,
)
from nostr_agent.relay_consistency import (
    RELAY_TIMEOUT_S,
    OPERATION_TIMEOUT_S,
    multi_relay_query,
)
from nostr_agent.validation import validate_relay_urls

logger = logging.getLogger(__name__)


async def fetch_identity(
    relay_urls: list[RelayUrl],
    pubkey: PublicKey,
    *,
    timeout: float = RELAY_TIMEOUT_S,
    operation_timeout: float = OPERATION_TIMEOUT_S,
) -> AgentIdentity | None:
    """Fetch the most-recent Kind 38100 for *pubkey* from *relay_urls*.

    Uses multi-relay union query with conflict logging.  Returns None if no
    event is found within *operation_timeout* seconds.
    """
    pk = nostr_sdk.PublicKey.parse(pubkey)
    filters = [
        nostr_sdk.Filter()
        .kind(nostr_sdk.Kind(KIND_AGENT_IDENTITY))
        .author(pk)
        .limit(1)
    ]

    try:
        result = await multi_relay_query(
            relay_urls, filters,
            relay_timeout=timeout,
            operation_timeout=operation_timeout,
        )
    except RuntimeError:
        return None

    if not result.events:
        return None
    # Resolution already applied by multi_relay_query; take the single winner.
    latest = max(result.events, key=lambda e: e.created_at().as_secs())
    return parse_identity_event(latest)


async def stream_attestations(
    relay_urls: list[RelayUrl],
    subject_pubkey: PublicKey,
    *,
    timeout: float = RELAY_TIMEOUT_S,
    operation_timeout: float = OPERATION_TIMEOUT_S,
) -> AsyncIterator[Attestation]:
    """Yield Kind 38102 attestations for *subject_pubkey* from *relay_urls*."""
    pk = nostr_sdk.PublicKey.parse(subject_pubkey)
    filters = [
        nostr_sdk.Filter()
        .kind(nostr_sdk.Kind(KIND_ATTESTATION))
        .pubkey(pk)
    ]

    try:
        result = await multi_relay_query(
            relay_urls, filters,
            relay_timeout=timeout,
            operation_timeout=operation_timeout,
        )
    except RuntimeError:
        return

    for event in result.events:
        yield parse_attestation(event)


async def fetch_delegation_chain_events(
    relay_urls: list[RelayUrl],
    delegatee_pubkey: PublicKey,
    *,
    timeout: float = RELAY_TIMEOUT_S,
    operation_timeout: float = OPERATION_TIMEOUT_S,
) -> list[DelegationLink]:
    """Fetch Kind 38101 delegation events where *delegatee_pubkey* is the delegatee."""
    filters = [
        nostr_sdk.Filter()
        .kind(nostr_sdk.Kind(KIND_DELEGATION))
        .custom_tag(
            nostr_sdk.SingleLetterTag.lowercase(nostr_sdk.Alphabet.P),
            delegatee_pubkey,
        )
    ]

    try:
        result = await multi_relay_query(
            relay_urls, filters,
            relay_timeout=timeout,
            operation_timeout=operation_timeout,
        )
    except RuntimeError:
        return []

    return [parse_delegation_link(e) for e in result.events]


# ============================================================================
# Parsing helpers
# ============================================================================


def _parse_agent_info(event: nostr_sdk.Event) -> AgentInfo:
    """Parse a Kind 38100 event into an AgentInfo dataclass.

    Extracts all fields from tags and content JSON. Tolerant of missing
    fields -- returns sensible defaults for anything absent.
    """
    tags = event.tags()

    # --- pubkey ---
    pubkey = event.author().to_hex()

    # --- d-tag ---
    d_tag = tags.identifier() or ""

    # --- relay URLs from r-tags ---
    relay_urls: list[str] = []
    for tag in tags.to_vec():
        vec = tag.as_vec()
        if vec and vec[0] == "r" and len(vec) > 1:
            relay_urls.append(vec[1])

    # --- operator pubkey from p-tag ---
    p_tag = tags.find(
        nostr_sdk.TagKind.SINGLE_LETTER(
            nostr_sdk.SingleLetterTag.lowercase(nostr_sdk.Alphabet.P)
        )
    )
    operator_pubkey = ""
    if p_tag is not None:
        p_vec = p_tag.as_vec()
        if len(p_vec) > 1:
            operator_pubkey = p_vec[1]

    # --- capabilities from t-tags ---
    capabilities_from_tags: list[str] = []
    for tag in tags.to_vec():
        vec = tag.as_vec()
        if vec and vec[0] == "t" and len(vec) > 1:
            capabilities_from_tags.append(vec[1])

    # --- created_at ---
    created_at = event.created_at().as_secs()

    # --- Parse content JSON ---
    name = ""
    description = ""
    status = "active"
    capabilities: list[str] = capabilities_from_tags
    endpoints: dict[str, str] = {}
    trust_policy = TrustPolicy()

    try:
        content = json.loads(event.content())
        name = content.get("name", "")
        description = content.get("description", "")
        status = content.get("status", "active")

        # Capabilities from content override t-tag extraction if present.
        content_caps = content.get("capabilities")
        if content_caps and isinstance(content_caps, list):
            capabilities = content_caps

        content_endpoints = content.get("endpoints")
        if content_endpoints and isinstance(content_endpoints, dict):
            endpoints = {str(k): str(v) for k, v in content_endpoints.items()}

        tp = content.get("trust_policy")
        if tp and isinstance(tp, dict):
            trust_policy = TrustPolicy(
                min_attestation_count=int(tp.get("min_attestation_count", 1)),
                trust_decay_per_hop=float(tp.get("trust_decay_per_hop", 0.5)),
                max_trust_depth=int(tp.get("max_trust_depth", 4)),
                require_l402=bool(tp.get("require_l402", False)),
            )

        # operator may also be in content.operator
        if not operator_pubkey:
            operator_pubkey = content.get("operator", "")
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    return AgentInfo(
        pubkey=pubkey,
        d_tag=d_tag,
        name=name,
        description=description,
        capabilities=tuple(capabilities),
        relay_urls=tuple(relay_urls),
        status=status,
        created_at=created_at,
        operator_pubkey=operator_pubkey,
        endpoints=endpoints,
        trust_policy=trust_policy,
    )


def _dedup_by_d_tag(agents: list[AgentInfo]) -> list[AgentInfo]:
    """Deduplicate AgentInfo by (pubkey, d_tag), keeping latest created_at."""
    best: dict[tuple[str, str], AgentInfo] = {}
    for info in agents:
        key = (info.pubkey, info.d_tag)
        existing = best.get(key)
        if existing is None or info.created_at > existing.created_at:
            best[key] = info
    return list(best.values())


# ============================================================================
# RelayDiscovery -- high-level discovery class (spec §1.3)
# ============================================================================


class RelayDiscovery:
    """Multi-relay discovery and publication for NostrAgent events.

    Manages relay pool connections, provides capability-based agent lookup,
    identity resolution across multiple relays, and multi-relay event publishing
    with per-relay success/failure tracking.
    """

    def __init__(self, relay_urls: list[str], timeout_seconds: float = 10.0) -> None:
        """Initialize relay pool.

        Args:
            relay_urls: WebSocket URLs for the relay pool. 1-10 URLs, wss?://.
            timeout_seconds: Default timeout for relay queries.

        Raises:
            ValueError: If relay_urls fail validation.
        """
        if not validate_relay_urls(relay_urls):
            raise ValueError(
                f"Invalid relay_urls: need 1-10 wss?:// URLs, got {relay_urls!r}"
            )
        self._relay_urls = list(relay_urls)
        self._timeout = timeout_seconds
        self._client: nostr_sdk.Client | None = None

    @property
    def relay_urls(self) -> list[str]:
        return list(self._relay_urls)

    @property
    def timeout_seconds(self) -> float:
        return self._timeout

    @property
    def is_connected(self) -> bool:
        return self._client is not None

    # ------------------------------------------------------------------
    # connect / disconnect
    # ------------------------------------------------------------------

    async def connect(self) -> dict[str, bool]:
        """Connect to all relays in the pool.

        Calls uniffi_set_event_loop for nostr-sdk async compatibility.
        If already connected, disconnects first and reconnects.

        Returns:
            Dict mapping relay URL -> connection success.
        """
        nostr_sdk.uniffi_set_event_loop(asyncio.get_running_loop())

        if self._client is not None:
            try:
                await self._client.disconnect()
            except Exception:  # noqa: BLE001
                pass

        client = nostr_sdk.Client()
        status: dict[str, bool] = {}

        for url in self._relay_urls:
            try:
                await client.add_relay(nostr_sdk.RelayUrl.parse(url) if isinstance(url, str) else url)
                status[url] = True
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to add relay %s: %s", url, exc)
                status[url] = False

        await client.connect()
        self._client = client
        return status

    async def disconnect(self) -> None:
        """Disconnect from all relays and release the client."""
        if self._client is not None:
            try:
                await self._client.disconnect()
            except Exception:  # noqa: BLE001
                pass
            self._client = None

    async def _ensure_connected(self) -> nostr_sdk.Client:
        """Ensure connected; lazy-connect if needed. Returns the client."""
        if self._client is None:
            await self.connect()
        assert self._client is not None  # noqa: S101 -- post-connect invariant
        return self._client

    # ------------------------------------------------------------------
    # _effective_relays -- resolve override vs pool URLs
    # ------------------------------------------------------------------

    def _effective_relays(self, relay_urls: list[str] | None) -> list[str]:
        """Return the relay URLs to use: override if given, else pool."""
        return relay_urls if relay_urls else self._relay_urls

    # ------------------------------------------------------------------
    # discover -- capability-based agent lookup
    # ------------------------------------------------------------------

    async def discover(
        self,
        capability: str,
        relay_urls: list[str] | None = None,
        limit: int = 50,
    ) -> list[AgentInfo]:
        """Discover agents by capability across relays.

        Queries Kind 38100 events with #t filter for the given capability.
        Deduplicates by (pubkey, d_tag) keeping latest created_at.
        Filters for status == "active" only.

        Args:
            capability: Capability label to search for (e.g., "weather-forecast").
            relay_urls: Override relay set. Defaults to pool.
            limit: Maximum results per relay query.

        Returns:
            List of AgentInfo for matching active agents, sorted by created_at desc.
        """
        urls = self._effective_relays(relay_urls)
        filters = [
            nostr_sdk.Filter()
            .kind(nostr_sdk.Kind(KIND_AGENT_IDENTITY))
            .custom_tag(
                nostr_sdk.SingleLetterTag.lowercase(nostr_sdk.Alphabet.T),
                capability,
            )
            .limit(limit)
        ]

        try:
            result = await multi_relay_query(
                urls, filters,
                relay_timeout=self._timeout,
                operation_timeout=self._timeout,
            )
        except RuntimeError:
            return []

        agents = [_parse_agent_info(ev) for ev in result.events]
        agents = _dedup_by_d_tag(agents)
        agents = [a for a in agents if a.status == "active"]
        agents.sort(key=lambda a: a.created_at, reverse=True)
        return agents

    # ------------------------------------------------------------------
    # resolve -- identity resolution by d-tag
    # ------------------------------------------------------------------

    async def resolve(
        self,
        d_tag: str,
        relay_urls: list[str] | None = None,
        pubkey: str | None = None,
    ) -> nostr_sdk.Event | None:
        """Resolve agent identity across multiple relays.

        Queries Kind 38100 by d-tag. If pubkey is given, restricts to that
        author. Among all events, finds the one with status == "active" and
        latest created_at.

        Args:
            d_tag: Agent identifier.
            relay_urls: Override relay set. Defaults to pool.
            pubkey: If known, restrict to specific pubkey (hex).

        Returns:
            The active Kind 38100 event with latest created_at, or None.
        """
        urls = self._effective_relays(relay_urls)

        f = (
            nostr_sdk.Filter()
            .kind(nostr_sdk.Kind(KIND_AGENT_IDENTITY))
            .identifier(d_tag)
        )
        if pubkey:
            f = f.author(nostr_sdk.PublicKey.parse(pubkey))

        try:
            result = await multi_relay_query(
                urls, [f],
                relay_timeout=self._timeout,
                operation_timeout=self._timeout,
            )
        except RuntimeError:
            return None

        if not result.events:
            return None

        # Among all events for this d-tag, prefer active status, latest created_at.
        active_events: list[nostr_sdk.Event] = []
        for ev in result.events:
            try:
                content = json.loads(ev.content())
                if content.get("status", "active") == "active":
                    active_events.append(ev)
            except (json.JSONDecodeError, TypeError):
                # If we can't parse content, include it as a candidate.
                active_events.append(ev)

        candidates = active_events if active_events else result.events
        return max(candidates, key=lambda e: e.created_at().as_secs())

    # ------------------------------------------------------------------
    # discover_by_operator -- all agents under an operator
    # ------------------------------------------------------------------

    async def discover_by_operator(
        self,
        operator_pubkey: str,
        relay_urls: list[str] | None = None,
    ) -> list[AgentInfo]:
        """Discover all agents belonging to an operator.

        Queries Kind 38100 events with #p filter for the operator's pubkey.
        Deduplicates by (pubkey, d_tag), filters for active.

        Args:
            operator_pubkey: Operator's hex public key.
            relay_urls: Override relay set. Defaults to pool.

        Returns:
            List of AgentInfo for all active agents under this operator.
        """
        urls = self._effective_relays(relay_urls)
        filters = [
            nostr_sdk.Filter()
            .kind(nostr_sdk.Kind(KIND_AGENT_IDENTITY))
            .custom_tag(
                nostr_sdk.SingleLetterTag.lowercase(nostr_sdk.Alphabet.P),
                operator_pubkey,
            )
        ]

        try:
            result = await multi_relay_query(
                urls, filters,
                relay_timeout=self._timeout,
                operation_timeout=self._timeout,
            )
        except RuntimeError:
            return []

        agents = [_parse_agent_info(ev) for ev in result.events]
        agents = _dedup_by_d_tag(agents)
        agents = [a for a in agents if a.status == "active"]
        agents.sort(key=lambda a: a.created_at, reverse=True)
        return agents

    # ------------------------------------------------------------------
    # publish_to_all -- multi-relay event publication
    # ------------------------------------------------------------------

    async def publish_to_all(
        self,
        event: nostr_sdk.Event,
        relay_urls: list[str] | None = None,
    ) -> PublishResult:
        """Publish an event to all relays in the pool.

        Creates a fresh client for the publish operation (matches the pattern
        in events.py publish_event). Returns per-relay success/failure.

        Args:
            event: Signed Nostr event to publish.
            relay_urls: Override relay set. Defaults to pool.

        Returns:
            PublishResult with event_id, succeeded relay URLs, failed relay URLs.
        """
        nostr_sdk.uniffi_set_event_loop(asyncio.get_running_loop())

        urls = self._effective_relays(relay_urls)
        client = nostr_sdk.Client()
        for url in urls:
            await client.add_relay(nostr_sdk.RelayUrl.parse(url) if isinstance(url, str) else url)
        await client.connect()

        try:
            output = await client.send_event(event)
        except Exception as exc:
            await client.disconnect()
            return PublishResult(
                event_id=event.id().to_hex(),
                succeeded=(),
                failed={url: str(exc) for url in urls},
            )

        await client.disconnect()

        # nostr-sdk SendEventOutput: .success -> list of relay URLs,
        # .failed -> dict of relay URL -> error string.
        succeeded: list[str] = []
        failed: dict[str, str] = {}
        try:
            for relay_url in output.success:
                succeeded.append(str(relay_url))
            for relay_url, reason in output.failed.items():
                failed[str(relay_url)] = str(reason) if reason else "unknown"
        except (AttributeError, TypeError):
            # Fallback: if output shape differs, mark all as succeeded.
            succeeded = list(urls)

        return PublishResult(
            event_id=event.id().to_hex(),
            succeeded=tuple(succeeded),
            failed=failed,
        )

    # ------------------------------------------------------------------
    # fetch_events -- generic event query with dedup
    # ------------------------------------------------------------------

    async def fetch_events(
        self,
        filters: list[nostr_sdk.Filter],
        relay_urls: list[str] | None = None,
    ) -> list[nostr_sdk.Event]:
        """Fetch events matching filters from relay pool.

        Queries all relays via multi_relay_query, deduplicates by event id.
        Returns the union of events from all relays.

        Args:
            filters: nostr-sdk Filter objects.
            relay_urls: Override relay set. Defaults to pool.

        Returns:
            Deduplicated list of events.
        """
        urls = self._effective_relays(relay_urls)

        try:
            result = await multi_relay_query(
                urls, filters,
                relay_timeout=self._timeout,
                operation_timeout=self._timeout,
            )
        except RuntimeError:
            return []

        return result.events
