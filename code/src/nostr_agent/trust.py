"""Trust graph computation for NostrAgent.

Bounded-sum / noisy-OR aggregation:
- Edge weight  = confidence field from Kind 38102 content (float [0, 1])
- Single-path  = product(edge_weights) * d^depth
- Multi-path   = noisy-OR: 1 - prod(1 - path_trust_i)
- Traversal    = DFS with visited-set cycle detection + epsilon pruning
- Parameters   = decay d=0.5, max_depth=4, epsilon=0.01 (all configurable)
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import random
import re
import time
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

import nostr_sdk as ns  # type: ignore[import]

from nostr_agent.types import (
    PublishError,
    PublishResult,
    SelfAttestationError,
    TrustGraph as TrustGraphType,
    TrustResult,
)
from nostr_agent.validation import validate_capability, validate_confidence

if TYPE_CHECKING:
    from nostr_agent.identity import AgentIdentity

logger = logging.getLogger(__name__)

# Kind number for peer attestation events.
KIND_PEER_ATTESTATION = 38102
KIND_ATTESTATION = KIND_PEER_ATTESTATION  # Alias for discovery.py backward compat


def parse_attestation(event: Any) -> dict[str, Any]:
    """Parse a Kind 38102 event into a dict suitable for trust graph construction.

    Returns dict with keys: pubkey, tags (as list of lists), content (parsed JSON).
    This is the minimal representation needed by build_trust_graph().
    """
    import json as _json

    tags_list = []
    for tag in event.tags().to_vec():
        tags_list.append(tag.as_vec())

    content_str = event.content()
    try:
        content = _json.loads(content_str)
    except (ValueError, TypeError):
        content = {}

    return {
        "pubkey": event.author().to_hex(),
        "tags": tags_list,
        "content": content,
        "created_at": event.created_at().as_secs(),
    }

# Default relay query timeout.
_RELAY_TIMEOUT = timedelta(seconds=10)

# Capability regex (same as validation.py -- kept here to avoid import of PATTERN).
_CAPABILITY_RE = re.compile(r"^[a-z0-9-]{1,64}$")

# Monotonic timestamp tracker for parameterized replaceable events.
# Ensures each published event has a strictly increasing created_at per d-tag.
_last_published_ts: dict[str, int] = {}

# ---------------------------------------------------------------------------
# Types (legacy aliases -- kept for backward compatibility with existing code)
# ---------------------------------------------------------------------------

# pubkey (hex str) -> list of (neighbour_pubkey, confidence_weight)
TrustGraph = dict[str, list[tuple[str, float]]]

# Minimal representation of a Kind 38102 event needed for graph construction
Kind38102Event = dict[str, Any]  # keys: pubkey, tags, content (with "confidence")


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def build_trust_graph(events: list[Kind38102Event]) -> TrustGraph:
    """Build adjacency list from Kind 38102 Peer Attestation events.

    Each event contributes one directed edge: attester -> attestee.
    Multiple events for the same (attester, attestee) are deduplicated by
    taking the one with the highest ``created_at`` (NIP-01 replaceable semantics).
    Edges with zero or negative confidence are dropped.

    Args:
        events: Raw Kind 38102 event dicts.  Expected fields:
            - ``pubkey``      str  attester pubkey (hex)
            - ``created_at``  int  Unix timestamp
            - ``content``     dict with ``"confidence"`` float in [0, 1]
            - ``tags``        list; tag ``["p", <attestee_pubkey>]`` gives the target

    Returns:
        TrustGraph adjacency list.
    """
    # (attester, attestee) -> (created_at, confidence)
    best: dict[tuple[str, str], tuple[int, float]] = {}

    for ev in events:
        attester: str = ev["pubkey"]
        content: dict[str, Any] = ev.get("content", {})
        confidence: float = float(content.get("confidence", 0.0))
        if confidence <= 0.0:
            continue
        confidence = min(confidence, 1.0)
        created_at: int = int(ev.get("created_at", 0))

        # Find attestee from "p" tag
        attestee: str | None = None
        for tag in ev.get("tags", []):
            if len(tag) >= 2 and tag[0] == "p":
                attestee = tag[1]
                break
        if attestee is None or attestee == attester:  # skip self-loops
            continue

        key = (attester, attestee)
        if key not in best or created_at > best[key][0]:
            best[key] = (created_at, confidence)

    graph: TrustGraph = {}
    for (attester, attestee), (_, confidence) in best.items():
        graph.setdefault(attester, []).append((attestee, confidence))

    return graph


# ---------------------------------------------------------------------------
# Trust computation
# ---------------------------------------------------------------------------

def compute_trust(
    graph: TrustGraph,
    source: str,
    target: str,
    *,
    decay: float = 0.5,
    max_depth: int = 4,
    epsilon: float = 0.01,
) -> float:
    """Compute trust from ``source`` to ``target`` using DFS + noisy-OR.

    Algorithm:
    1. DFS enumerates all simple paths (visited-set prevents cycles).
    2. Per-path trust = product(edge_weights) * decay^depth.
    3. Epsilon pruning: if accumulated_weight * decay^remaining < epsilon, skip.
    4. Collect all path trusts; aggregate via noisy-OR:
       trust(S,T) = 1 - prod(1 - path_trust_i)

    Edge cases:
    - source not in graph, or no path exists  -> 0.0
    - source == target                         -> 1.0
    - single hop (direct edge)                 -> edge_weight * decay^1

    Args:
        graph:     Adjacency list (output of :func:`build_trust_graph`).
        source:    Starting pubkey.
        target:    Destination pubkey.
        decay:     Multiplicative decay per hop (default 0.5).
        max_depth: Maximum path length in hops (default 4).
        epsilon:   Pruning threshold; paths whose max possible contribution
                   is below this value are not explored (default 0.01).

    Returns:
        Aggregated trust score in [0.0, 1.0].
    """
    if source == target:
        return 1.0
    if source not in graph:
        return 0.0

    path_trusts: list[float] = []

    def _dfs(node: str, accumulated: float, depth: int, visited: set[str]) -> None:
        for neighbour, weight in graph.get(node, []):
            if neighbour in visited:
                continue
            edge_trust = accumulated * weight
            remaining = max_depth - depth  # hops left after this one
            # Epsilon pruning: best possible contribution from this sub-path
            max_possible = edge_trust * (decay ** remaining) if remaining > 0 else edge_trust
            if max_possible < epsilon:
                continue
            path_weight = edge_trust * decay  # apply one hop decay
            if neighbour == target:
                path_trusts.append(path_weight)
            elif depth < max_depth:
                visited.add(neighbour)
                _dfs(neighbour, path_weight, depth + 1, visited)
                visited.discard(neighbour)

    _dfs(source, 1.0, 1, {source})

    if not path_trusts:
        return 0.0

    # noisy-OR: 1 - prod(1 - path_trust_i)
    complement = math.prod(1.0 - pt for pt in path_trusts)
    return 1.0 - complement


def compute_trust_detailed(
    graph: TrustGraph,
    source: str,
    target: str,
    *,
    decay: float = 0.5,
    max_depth: int = 4,
    epsilon: float = 0.01,
) -> TrustResult:
    """Like :func:`compute_trust` but returns a :class:`TrustResult` with path stats.

    Identical algorithm, but tracks ``paths_found`` and ``paths_pruned``.
    """
    if source == target:
        return TrustResult(score=1.0, paths_found=0, paths_pruned=0)
    if source not in graph:
        return TrustResult(score=0.0, paths_found=0, paths_pruned=0)

    path_trusts: list[float] = []
    pruned_count = 0

    def _dfs(node: str, accumulated: float, depth: int, visited: set[str]) -> None:
        nonlocal pruned_count
        for neighbour, weight in graph.get(node, []):
            if neighbour in visited:
                continue
            edge_trust = accumulated * weight
            remaining = max_depth - depth
            max_possible = edge_trust * (decay ** remaining) if remaining > 0 else edge_trust
            if max_possible < epsilon:
                pruned_count += 1
                continue
            path_weight = edge_trust * decay
            if neighbour == target:
                path_trusts.append(path_weight)
            elif depth < max_depth:
                visited.add(neighbour)
                _dfs(neighbour, path_weight, depth + 1, visited)
                visited.discard(neighbour)

    _dfs(source, 1.0, 1, {source})

    if not path_trusts:
        return TrustResult(score=0.0, paths_found=len(path_trusts), paths_pruned=pruned_count)

    complement = math.prod(1.0 - pt for pt in path_trusts)
    score = 1.0 - complement
    return TrustResult(score=score, paths_found=len(path_trusts), paths_pruned=pruned_count)


# ---------------------------------------------------------------------------
# TrustManager class -- wraps existing functions + Kind 38102 lifecycle
# ---------------------------------------------------------------------------


class TrustManager:
    """Kind 38102 Peer Attestation and Trust Computation.

    Manages the creation, publication, and retraction of peer capability
    attestations. Computes trust scores via DFS traversal with multiplicative
    decay and noisy-OR multi-path aggregation.

    Reference: paper Section 4 (peer attestation trust graph).
    """

    def __init__(self, identity: AgentIdentity) -> None:
        """Initialize with the attesting agent's identity.

        Args:
            identity: The AgentIdentity of the agent issuing attestations.
                      Must be an active identity with valid keys.
        """
        self._identity = identity

    # --- Properties ---

    @property
    def identity(self) -> AgentIdentity:
        return self._identity

    # ------------------------------------------------------------------
    # compute_d_tag -- deterministic d-tag generation
    # ------------------------------------------------------------------

    @staticmethod
    def compute_d_tag(attester_pubkey: str, attestee_pubkey: str, capability: str) -> str:
        """Deterministic d-tag generation for Kind 38102.

        Format: ``"{attester[:8]}-{attestee[:8]}-{capability}"``.

        Args:
            attester_pubkey: Hex attester pubkey.
            attestee_pubkey: Hex attestee pubkey.
            capability: Capability label.

        Returns:
            d-tag string.
        """
        return f"{attester_pubkey[:8]}-{attestee_pubkey[:8]}-{capability}"

    # ------------------------------------------------------------------
    # attest -- create and publish Kind 38102
    # ------------------------------------------------------------------

    async def attest(
        self,
        attestee_pubkey: str,
        attestee_d_tag: str,
        capability: str,
        confidence: float,
        evidence: dict | None = None,
        context: str | None = None,
        relay_urls: list[str] | None = None,
    ) -> PublishResult:
        """Create and publish a Kind 38102 peer attestation.

        Constructs attestation with deterministic d-tag, validates all fields,
        signs, and publishes.  ``confidence=0.0`` signals retraction (edge
        removed from trust graph).

        Args:
            attestee_pubkey: Hex public key of the agent being attested.
            attestee_d_tag: d-tag of the attestee's Kind 38100 identity.
            capability: Capability being attested (^[a-z0-9-]{1,64}$).
            confidence: Confidence in [0.0, 1.0]. 0.0 = retraction.
            evidence: Optional evidence metadata dict.
            context: Optional human-readable context (max 1024 chars).
            relay_urls: Override relay set. Falls back to identity relay_urls.

        Returns:
            PublishResult with event_id and per-relay status.

        Raises:
            SelfAttestationError: If attestee_pubkey == attester pubkey.
            ValueError: If confidence out of range or capability invalid.
        """
        attester_hex = self._identity.pubkey_hex

        # --- Validate inputs ---
        if attestee_pubkey == attester_hex:
            raise SelfAttestationError("Cannot attest own capabilities")

        if not validate_confidence(confidence):
            raise ValueError(f"Confidence must be in [0.0, 1.0], got {confidence}")

        if not validate_capability(capability):
            raise ValueError(
                f"Invalid capability: must match ^[a-z0-9-]{{1,64}}$, got {capability!r}"
            )

        if context is not None and len(context) > 1024:
            raise ValueError(
                f"Context must be at most 1024 chars, got {len(context)}"
            )

        # --- Compute deterministic d-tag ---
        d_tag = self.compute_d_tag(attester_hex, attestee_pubkey, capability)

        # --- Construct content JSON ---
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        content_dict: dict[str, Any] = {
            "attestee": attestee_pubkey,
            "capability": capability,
            "confidence": confidence,
            "issued_at": now_iso,
        }
        if evidence is not None:
            content_dict["evidence"] = evidence
        if context is not None:
            content_dict["context"] = context

        # --- Construct tags ---
        attestee_pk = ns.PublicKey.parse(attestee_pubkey)

        tags: list[ns.Tag] = [
            # NIP-33 d-tag (parameterized replaceable)
            ns.Tag.identifier(d_tag),
            # p-tag -- attestee
            ns.Tag.public_key(attestee_pk),
            # a-tag -- reference to attestee's Kind 38100 identity
            ns.Tag.custom(
                ns.TagKind.UNKNOWN("a"),
                [f"38100:{attestee_pubkey}:{attestee_d_tag}"],
            ),
            # t-tag -- capability (for discovery by capability)
            ns.Tag.custom(
                ns.TagKind.UNKNOWN("t"),
                [capability],
            ),
            # alt tag -- human-readable
            ns.Tag.alt("NostrAgent peer attestation"),
            # schema_version
            ns.Tag.custom(ns.TagKind.UNKNOWN("schema_version"), ["1.0"]),
        ]

        # --- Build, sign, and publish ---
        content_json = json.dumps(content_dict)
        builder = ns.EventBuilder(ns.Kind(KIND_PEER_ATTESTATION), content_json).tags(tags)

        # Ensure strictly increasing created_at for parameterized replaceable events
        # (same d-tag, same author). Relays reject if created_at <= existing.
        now = int(time.time())
        prev = _last_published_ts.get(d_tag, 0)
        event_ts = max(now, prev + 1)
        _last_published_ts[d_tag] = event_ts
        builder = builder.custom_created_at(ns.Timestamp.from_secs(event_ts))

        all_relays = list(relay_urls or self._identity.relay_urls)
        keys = self._identity.keys

        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        signer = ns.NostrSigner.keys(keys)
        client = ns.Client(signer)
        try:
            for url in all_relays:
                await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
            await client.connect()
            output = await client.send_event_builder(builder)
        finally:
            await client.disconnect()

        succeeded = [str(r) for r in output.success]
        failed = {str(k): str(v) for k, v in output.failed.items()}

        if not succeeded:
            raise PublishError(
                f"Zero relays accepted Kind 38102 event. Failures: {failed}"
            )

        event_id = output.id.to_hex()

        result = PublishResult(
            event_id=event_id,
            succeeded=tuple(succeeded),
            failed=failed,
        )
        logger.info(
            "Published Kind 38102 attestation (d=%s, cap=%s, conf=%.2f) to %d/%d relays, id=%s",
            d_tag,
            capability,
            confidence,
            len(succeeded),
            len(all_relays),
            event_id[:16],
        )
        return result

    # ------------------------------------------------------------------
    # retract -- convenience wrapper for confidence=0.0
    # ------------------------------------------------------------------

    async def retract(
        self,
        attestee_pubkey: str,
        capability: str,
        relay_urls: list[str] | None = None,
    ) -> PublishResult:
        """Retract an attestation by publishing with confidence=0.0.

        Convenience method. Equivalent to ``attest(..., confidence=0.0)``.
        The attestee_d_tag is not needed for retraction since the d-tag is
        computed solely from the attester, attestee, and capability.

        Args:
            attestee_pubkey: Hex pubkey of the attestee to retract.
            capability: Capability to retract.
            relay_urls: Override relay set.

        Returns:
            PublishResult.
        """
        return await self.attest(
            attestee_pubkey=attestee_pubkey,
            attestee_d_tag="",  # Not used in content for retraction
            capability=capability,
            confidence=0.0,
            relay_urls=relay_urls,
        )

    # ------------------------------------------------------------------
    # compute_trust -- static, wraps the module-level DFS
    # ------------------------------------------------------------------

    @staticmethod
    def compute_trust(
        graph: TrustGraphType,
        source: str,
        target: str,
        decay: float = 0.5,
        max_depth: int = 4,
        epsilon: float = 0.01,
    ) -> TrustResult:
        """Compute trust from source to target via noisy-OR aggregation.

        DFS traversal with visited-set cycle detection, epsilon pruning, and
        multiplicative decay. Graph is pre-filtered to a single capability.

        Uses the ``adjacency`` dict from :class:`TrustGraphType` and delegates
        to :func:`compute_trust_detailed`.

        Args:
            graph: TrustGraph (types.TrustGraph dataclass) for a single capability.
            source: Source agent pubkey (hex).
            target: Target agent pubkey (hex).
            decay: Trust decay per hop. Default 0.5.
            max_depth: Maximum traversal depth. Default 4.
            epsilon: Pruning threshold. Default 0.01.

        Returns:
            TrustResult with score in [0.0, 1.0], paths_found, paths_pruned.
        """
        return compute_trust_detailed(
            graph.adjacency,
            source,
            target,
            decay=decay,
            max_depth=max_depth,
            epsilon=epsilon,
        )

    # ------------------------------------------------------------------
    # get_attestations -- query relays for Kind 38102 events
    # ------------------------------------------------------------------

    @staticmethod
    async def get_attestations(
        pubkey: str,
        relay_urls: list[str],
        capability: str | None = None,
    ) -> list[ns.Event]:
        """Fetch all Kind 38102 attestations about an agent.

        Queries relays for Kind 38102 events with ``#p`` filter for the
        attestee pubkey. Optionally filters by capability via ``#t``.

        Args:
            pubkey: Attestee's hex public key.
            relay_urls: Relays to query.
            capability: Optional capability filter.

        Returns:
            List of Kind 38102 events about this agent.
        """
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        client = ns.Client()
        try:
            for url in relay_urls:
                await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
            await client.connect()

            f = (
                ns.Filter()
                .kind(ns.Kind(KIND_PEER_ATTESTATION))
                .custom_tag(
                    ns.SingleLetterTag.lowercase(ns.Alphabet.P),
                    pubkey,
                )
            )
            if capability is not None:
                f = f.custom_tag(
                    ns.SingleLetterTag.lowercase(ns.Alphabet.T),
                    capability,
                )

            events = await client.fetch_events(f, _RELAY_TIMEOUT)
        finally:
            await client.disconnect()

        return events.to_vec()

    # ------------------------------------------------------------------
    # build_trust_graph -- query relays, build TrustGraphType
    # ------------------------------------------------------------------

    @staticmethod
    async def build_trust_graph(
        capability: str,
        relay_urls: list[str],
    ) -> TrustGraphType:
        """Build a capability-scoped trust graph from relay attestations.

        Queries relays for all Kind 38102 events with ``#t = capability``.
        NIP-01 replaceable semantics: only the latest event per d-tag
        (attester, attestee, capability) is kept. Edges with confidence <= 0
        are dropped (retracted attestations).

        Args:
            capability: Capability label to build graph for.
            relay_urls: Relays to query.

        Returns:
            TrustGraphType adjacency list.
        """
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        client = ns.Client()
        try:
            for url in relay_urls:
                await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
            await client.connect()

            f = (
                ns.Filter()
                .kind(ns.Kind(KIND_PEER_ATTESTATION))
                .custom_tag(
                    ns.SingleLetterTag.lowercase(ns.Alphabet.T),
                    capability,
                )
            )
            events = await client.fetch_events(f, _RELAY_TIMEOUT)
        finally:
            await client.disconnect()

        # Deduplicate by d-tag: keep latest created_at per d-tag.
        best: dict[str, ns.Event] = {}
        for ev in events.to_vec():
            d_tag = ev.tags().identifier()
            if d_tag is None:
                continue
            existing = best.get(d_tag)
            if existing is None or ev.created_at().as_secs() > existing.created_at().as_secs():
                best[d_tag] = ev

        # Build the TrustGraphType adjacency list.
        graph = TrustGraphType(capability=capability)
        for ev in best.values():
            attester = ev.author().to_hex()

            # Parse attestee from p-tag.
            attestee: str | None = None
            for tag in ev.tags().to_vec():
                vec = tag.as_vec()
                if len(vec) >= 2 and vec[0] == "p":
                    attestee = vec[1]
                    break
            if attestee is None or attestee == attester:
                continue

            # Parse confidence from content JSON.
            try:
                content = json.loads(ev.content())
                confidence = float(content.get("confidence", 0.0))
            except (json.JSONDecodeError, TypeError, ValueError):
                continue

            if confidence <= 0.0:
                continue
            confidence = min(confidence, 1.0)

            graph.add_edge(attester, attestee, confidence)

        return graph


# ---------------------------------------------------------------------------
# Synthetic graph generation (for B6b benchmark)
# ---------------------------------------------------------------------------

def make_ring_graph(n: int, weight: float = 0.8) -> TrustGraph:
    """Directed ring: 0->1->2->...->n-1->0.  Source=node 0, target=node n//2."""
    nodes = [str(i) for i in range(n)]
    graph: TrustGraph = {}
    for i in range(n):
        graph[nodes[i]] = [(nodes[(i + 1) % n], weight)]
    return graph


def make_star_graph(n: int, weight: float = 0.8) -> TrustGraph:
    """Hub (node 0) with n-1 leaves.  Edges: hub->leaf and leaf->hub."""
    hub = "0"
    graph: TrustGraph = {hub: []}
    for i in range(1, n):
        leaf = str(i)
        graph[hub].append((leaf, weight))
        graph[leaf] = [(hub, weight)]
    return graph


def make_chain_graph(n: int, weight: float = 0.8) -> TrustGraph:
    """Linear chain: 0->1->2->...->n-1.  Source=0, target=n-1."""
    graph: TrustGraph = {}
    for i in range(n - 1):
        graph[str(i)] = [(str(i + 1), weight)]
    graph[str(n - 1)] = []
    return graph


def make_random_graph(n: int, edge_prob: float = 0.15, seed: int = 42) -> TrustGraph:
    """Erdos-Renyi directed graph with uniform weights in [0.5, 1.0].

    Uses a fixed seed for reproducibility (benchmark requirement).
    """
    rng = random.Random(seed)
    graph: TrustGraph = {str(i): [] for i in range(n)}
    for i in range(n):
        for j in range(n):
            if i != j and rng.random() < edge_prob:
                w = rng.uniform(0.5, 1.0)
                graph[str(i)].append((str(j), w))
    return graph


def make_sybil_graph(
    n_honest: int,
    n_sybil: int,
    n_bridges: int = 3,
    seed: int = 42,
) -> TrustGraph:
    """Sybil cluster topology: k honest nodes + N Sybil nodes with m bridge edges.

    Honest nodes (0..k-1) form full mesh (0.9 weight).
    Sybil nodes (k..k+N-1) form clique (0.95 weight).
    Bridge edges: n_bridges random edges from honest->sybil (0.3 weight).

    Args:
        n_honest:  Number of honest nodes.
        n_sybil:   Number of Sybil nodes.
        n_bridges: Number of bridge edges from honest to sybil cluster.
        seed:      Random seed for reproducibility.

    Returns:
        TrustGraph adjacency list.
    """
    rng = random.Random(seed)
    graph: TrustGraph = {}
    total = n_honest + n_sybil

    # Initialize all nodes
    for i in range(total):
        graph[str(i)] = []

    # Honest clique (full mesh, 0.9 weight)
    for i in range(n_honest):
        for j in range(n_honest):
            if i != j:
                graph[str(i)].append((str(j), 0.9))

    # Sybil clique (full mesh, 0.95 weight)
    for i in range(n_honest, total):
        for j in range(n_honest, total):
            if i != j:
                graph[str(i)].append((str(j), 0.95))

    # Bridge edges: honest -> sybil (0.3 weight, probabilistic)
    for _ in range(n_bridges):
        h = rng.randint(0, n_honest - 1)
        s = rng.randint(n_honest, total - 1)
        if (str(s), 0.3) not in graph[str(h)]:
            graph[str(h)].append((str(s), 0.3))

    return graph


def sample_confidences(
    graph: TrustGraph,
    seed: int = 42,
    dist: str = "uniform",
    alpha: float = 2.0,
    beta: float = 5.0,
) -> TrustGraph:
    """Resample edge weights from a distribution (uniform or beta).

    Args:
        graph:  Existing TrustGraph adjacency list.
        seed:   Random seed.
        dist:   "uniform" for [0.5, 1.0]; "beta" for Beta(alpha, beta) -> [0, 1].
        alpha:  Beta distribution shape parameter (if dist="beta").
        beta:   Beta distribution shape parameter (if dist="beta").

    Returns:
        New TrustGraph with resampled weights.
    """
    rng = random.Random(seed)
    new_graph: TrustGraph = {}

    for node, edges in graph.items():
        new_graph[node] = []
        for neighbor, _ in edges:
            if dist == "uniform":
                w = rng.uniform(0.5, 1.0)
            elif dist == "beta":
                w = rng.betavariate(alpha, beta)
                w = max(0.0, min(1.0, w))  # clamp to [0, 1]
            else:
                raise ValueError(f"Unknown distribution: {dist}")
            new_graph[node].append((neighbor, w))

    return new_graph


# ---------------------------------------------------------------------------
# Quick smoke test (run as __main__)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Single hop
    g: TrustGraph = {"A": [("B", 0.9)], "B": []}
    assert abs(compute_trust(g, "A", "B") - 0.9 * 0.5) < 1e-9

    # Two paths (noisy-OR should exceed each individual path)
    g2: TrustGraph = {
        "A": [("B", 0.8), ("C", 0.7)],
        "B": [("D", 0.9)],
        "C": [("D", 0.6)],
        "D": [],
    }
    t_via_b = 0.8 * 0.9 * (0.5 ** 2)
    t_via_c = 0.7 * 0.6 * (0.5 ** 2)
    expected = 1 - (1 - t_via_b) * (1 - t_via_c)
    result = compute_trust(g2, "A", "D")
    assert abs(result - expected) < 1e-9, f"{result} != {expected}"

    # Empty graph
    assert compute_trust({}, "X", "Y") == 0.0

    # Self-loop
    assert compute_trust(g, "A", "A") == 1.0

    # Chain beyond max_depth is pruned
    chain = make_chain_graph(10)
    assert compute_trust(chain, "0", "9", max_depth=4) == 0.0

    # --- compute_trust_detailed returns TrustResult ---
    r = compute_trust_detailed(g, "A", "B")
    assert abs(r.score - 0.9 * 0.5) < 1e-9
    assert r.paths_found == 1
    assert r.paths_pruned == 0

    r2 = compute_trust_detailed(g2, "A", "D")
    assert abs(r2.score - expected) < 1e-9
    assert r2.paths_found == 2

    r3 = compute_trust_detailed({}, "X", "Y")
    assert r3.score == 0.0
    assert r3.paths_found == 0

    r4 = compute_trust_detailed(g, "A", "A")
    assert r4.score == 1.0

    # --- TrustManager.compute_d_tag ---
    dtag = TrustManager.compute_d_tag("ab" * 32, "cd" * 32, "inference")
    assert dtag == "abababab-cdcdcdcd-inference"

    # --- TrustManager.compute_trust wraps correctly ---
    tg = TrustGraphType(capability="test", adjacency={"A": [("B", 0.9)], "B": []})
    tr = TrustManager.compute_trust(tg, "A", "B")
    assert abs(tr.score - 0.9 * 0.5) < 1e-9
    assert tr.paths_found == 1

    print("All smoke tests passed.")
