"""NostrAgent benchmark harness -- B1 through B11.

Uses real implementations from nostr_agent.crypto, nostr_agent.trust,
nostr_agent.l402, and pymacaroons. Benchmarks requiring Docker infrastructure
(B4, B7-B9) are detected at runtime and skipped with a clear message.

Methodology:
- 1000 runs per metric; first 100 discarded as warm-up.
- gc.disable() during each measurement window.
- time.perf_counter_ns() for sub-millisecond timing.
- CSV output per metric: run_id, metric, value_ms, timestamp, variant.
- Statistics: median, IQR, P95, P99, mean, std.
- Variant comparisons: Mann-Whitney U + Cliff's delta.

Usage:
    python -m eval.bench --all
    python -m eval.bench --metrics B1,B2,B6
    python -m eval.bench --metrics B6 --runs 500 --warmup 50
    python -m eval.bench --all --paper    # 1100/100 offline, 110/10 Docker
"""

from __future__ import annotations

import asyncio
import csv
import gc
import hashlib
import json
import logging
import random
import socket
import sys
import time
from dataclasses import dataclass, field
from datetime import timedelta
from itertools import combinations
from pathlib import Path
from typing import Callable

import numpy as np
import typer
from rich.console import Console
from rich.table import Table

from eval.benchmark_config import (
    CSV_COLUMNS,
    EFFECTIVE_RUNS,
    OUTPUT_DIR,
    RANDOM_SEED,
    RUNS_PER_METRIC,
    WARMUP_RUNS,
)
from eval.env_metadata import capture_environment, save_metadata
from eval.stats import cliffs_delta, mann_whitney_test

_bench_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Imports from nostr_agent (real implementations)
# ---------------------------------------------------------------------------

from nostr_agent.crypto import (
    generate_keypair_raw,
    pubkey_from_secret,
    sha256,
    sign_schnorr,
    verify_schnorr,
)
from nostr_agent.trust import (
    TrustGraph,
    compute_trust,
    compute_trust_detailed,
)
from eval.synthetic_graphs import (
    make_random_graph as sg_make_random_graph,
    make_ring_graph as sg_make_ring_graph,
    make_star_graph as sg_make_star_graph,
    make_chain_graph as sg_make_chain_graph,
    make_sybil_graph as sg_make_sybil_graph,
)

# ---------------------------------------------------------------------------
# Runtime configuration (overridable via CLI)
# ---------------------------------------------------------------------------

_total_runs: int = RUNS_PER_METRIC
_warmup: int = WARMUP_RUNS


# ---------------------------------------------------------------------------
# Measurement primitives
# ---------------------------------------------------------------------------


def measure_ns(fn: Callable[[], None], n: int | None = None, warmup: int | None = None) -> list[float]:
    """Return (n - warmup) timings in milliseconds. GC disabled during each sample.

    Args:
        fn: Zero-argument callable to benchmark.
        n:  Total runs (including warm-up). Defaults to module-level _total_runs.
        warmup: Warm-up runs to discard. Defaults to module-level _warmup.

    Returns:
        List of effective timings in ms (warm-up discarded).
    """
    if n is None:
        n = _total_runs
    if warmup is None:
        warmup = _warmup
    results: list[float] = []
    for i in range(n):
        gc.disable()
        t0 = time.perf_counter_ns()
        try:
            fn()
        except Exception as exc:
            gc.enable()
            if i >= warmup:
                logging.warning("Benchmark iteration %d failed: %s", i, exc)
            continue
        elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000
        gc.enable()
        if i >= warmup:
            results.append(elapsed_ms)
    return results


@dataclass
class BenchResult:
    """Result of a single benchmark run (one metric + variant)."""

    metric: str
    variant: str
    timings: list[float]

    def stats(self) -> dict[str, float]:
        a = np.array(self.timings)
        if len(a) == 0:
            return {"median": 0.0, "iqr": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0, "std": 0.0, "n": 0}
        q25, q75 = float(np.percentile(a, 25)), float(np.percentile(a, 75))
        return {
            "median": float(np.median(a)),
            "iqr": q75 - q25,
            "p95": float(np.percentile(a, 95)),
            "p99": float(np.percentile(a, 99)),
            "mean": float(np.mean(a)),
            "std": float(np.std(a, ddof=1)) if len(a) > 1 else 0.0,
            "n": len(a),
        }


def compare_variants(a: BenchResult, b: BenchResult) -> dict:
    """Mann-Whitney U + Cliff's delta between two result sets."""
    mw = mann_whitney_test(a.timings, b.timings)
    cd = cliffs_delta(a.timings, b.timings)
    return {
        "u_stat": mw["U_statistic"],
        "p_value": mw["p_value"],
        "significant": mw["significant"],
        "cliffs_delta": cd["delta"],
        "cliffs_magnitude": cd["magnitude"],
    }


def write_csv(results: list[BenchResult], output_dir: Path) -> None:
    """Write CSV files per metric/variant to output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    for r in results:
        safe_variant = r.variant.replace("=", "_").replace(",", "_")
        path = output_dir / f"{r.metric}_{safe_variant}.csv"
        with path.open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow(CSV_COLUMNS)
            for i, v in enumerate(r.timings):
                w.writerow([i, r.metric, f"{v:.6f}", ts, r.variant])


# ---------------------------------------------------------------------------
# Fixtures (real crypto, deterministic)
# ---------------------------------------------------------------------------


def _make_bip340_keypair() -> tuple[bytes, bytes]:
    """Return (secret_key_32bytes, x_only_pubkey_32bytes) via coincurve BIP340."""
    return generate_keypair_raw()


def _make_signed_event_id(sk: bytes, pk: bytes) -> tuple[bytes, bytes]:
    """Create a deterministic event-like structure and sign it.

    Returns (event_id_hash_32bytes, signature_64bytes).
    """
    content = json.dumps({"agent": "bench-test", "version": "0.1"})
    created_at = 1700000000  # deterministic
    tags = [["k", "38100"]]
    canonical = json.dumps(
        [0, pk.hex(), created_at, 38100, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    event_id = sha256(canonical)  # 32 bytes
    sig = sign_schnorr(sk, event_id)
    return event_id, sig


def _build_delegation_chain_signed(depth: int) -> list[tuple[bytes, bytes, bytes, bytes]]:
    """Build a delegation chain of given depth with real BIP340 signatures.

    Returns list of (sk, pk, message_hash, signature) tuples.
    Each level signs a commitment binding delegator -> delegatee.
    """
    chain = []
    pairs = [_make_bip340_keypair() for _ in range(depth + 1)]

    for i in range(depth):
        delegator_sk, delegator_pk = pairs[i]
        _, delegatee_pk = pairs[i + 1]
        # Delegation message: SHA256(delegator_pk || delegatee_pk || depth_byte)
        msg = sha256(delegator_pk + delegatee_pk + bytes([i]))
        sig = sign_schnorr(delegator_sk, msg)
        chain.append((delegator_sk, delegator_pk, msg, sig))

    return chain


# ---------------------------------------------------------------------------
# Docker infrastructure detection
# ---------------------------------------------------------------------------

# Relay WebSocket URLs (strfry containers on default ports).
RELAY_URLS = [
    "ws://localhost:7771",
    "ws://localhost:7772",
    "ws://localhost:7773",
]

# LND regtest connection details.
_INFRA_DIR = Path(__file__).resolve().parent.parent / "infra"
_ALICE_LND_HOST = "localhost"
_ALICE_LND_PORT = 10009
_ALICE_MACAROON = str(_INFRA_DIR / "credentials" / "alice" / "admin.macaroon")
_ALICE_TLS_CERT = str(_INFRA_DIR / "credentials" / "alice" / "tls.cert")

_BOB_LND_HOST = "localhost"
_BOB_LND_PORT = 10010
_BOB_MACAROON = str(_INFRA_DIR / "credentials" / "bob" / "admin.macaroon")
_BOB_TLS_CERT = str(_INFRA_DIR / "credentials" / "bob" / "tls.cert")


_DOCKER_SKIP_MSG = (
    "SKIPPED: requires Docker infrastructure (relay/LND containers). "
    "Run with Docker via: docker compose -f code/infra/docker-compose.yml up -d"
)


async def _add_relay_urls(client, urls: list[str]) -> None:
    """Add relay URLs to a nostr-sdk Client, handling str -> RelayUrl conversion."""
    import nostr_sdk as ns  # type: ignore[import]  # noqa: PLC0415
    for url in urls:
        await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)


def _requires_docker(metric_name: str) -> BenchResult:
    """Return a sentinel BenchResult for Docker-dependent benchmarks."""
    console = Console(stderr=True)
    console.print(f"  [yellow]{metric_name}: {_DOCKER_SKIP_MSG}[/yellow]")
    return BenchResult(metric=metric_name, variant="docker_required", timings=[0.0])


def _check_relay_available(host: str = "localhost", port: int = 7771, timeout: float = 2.0) -> bool:
    """Quick TCP check to see if a relay is reachable."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def _check_lnd_available(host: str = "localhost", port: int = 10009, timeout: float = 2.0) -> bool:
    """Quick TCP check to see if an LND gRPC port is reachable."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


# Docker run counts (different from offline: relay/LND benchmarks are slower).
_DOCKER_TOTAL_RUNS: int = 100
_DOCKER_WARMUP: int = 10

# Paper-mode run counts.
_PAPER_OFFLINE_RUNS: int = 1100
_PAPER_OFFLINE_WARMUP: int = 100
_PAPER_DOCKER_RUNS: int = 110
_PAPER_DOCKER_WARMUP: int = 10


# ---------------------------------------------------------------------------
# B1: Auth Handshake Latency
# ---------------------------------------------------------------------------

def bench_b1_auth_handshake() -> BenchResult:
    """B1: Kind 38100 verification -- BIP340 sig check + id recomputation + content parse.

    Uses real BIP340 Schnorr verification via coincurve (same library as
    nostr_agent.crypto.verify_schnorr). Measures the full verification path:
    canonical serialization -> SHA256 -> BIP340 verify -> JSON content parse.
    """
    sk, pk = _make_bip340_keypair()
    event_id, sig = _make_signed_event_id(sk, pk)

    # Pre-build the canonical form for recomputation
    content = json.dumps({"agent": "bench-test", "version": "0.1"})
    created_at = 1700000000
    tags = [["k", "38100"]]
    canonical_bytes = json.dumps(
        [0, pk.hex(), created_at, 38100, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()

    def verify() -> None:
        # 1. Recompute event ID
        recomputed_id = sha256(canonical_bytes)
        assert recomputed_id == event_id
        # 2. BIP340 signature verification (real Schnorr)
        assert verify_schnorr(pk, recomputed_id, sig)
        # 3. Content parsing
        json.loads(content)

    return BenchResult("B1", "kind_38100", measure_ns(verify))


# ---------------------------------------------------------------------------
# B2: Credential Verification Cost
# ---------------------------------------------------------------------------

def bench_b2_credential_verification() -> list[BenchResult]:
    """B2: Isolated BIP340 Schnorr signature verification via crypto.verify_schnorr().

    Three variants for Kind 38100, 38101, 38102 (same crypto, different event kinds
    to confirm no kind-dependent overhead).
    """
    results = []
    for kind_num in (38100, 38101, 38102):
        sk, pk = _make_bip340_keypair()
        msg = sha256(f"test-event-kind-{kind_num}".encode())
        sig = sign_schnorr(sk, msg)

        def verify(pk_=pk, msg_=msg, sig_=sig) -> None:
            verify_schnorr(pk_, msg_, sig_)

        timings = measure_ns(verify)
        results.append(BenchResult("B2", f"kind_{kind_num}", timings))
    return results


# ---------------------------------------------------------------------------
# B3: Delegation Chain Depth Effect
# ---------------------------------------------------------------------------

def bench_b3_delegation_chain(depth: int) -> BenchResult:
    """B3: Delegation chain verification at given depth.

    Builds a real chain of BIP340-signed delegation links and verifies each
    signature in the chain. This mirrors DelegationManager.verify_chain()'s
    per-hop signature verification without requiring relay I/O.
    """
    chain = _build_delegation_chain_signed(depth)

    def verify_chain() -> None:
        for _, delegator_pk, msg, sig in chain:
            assert verify_schnorr(delegator_pk, msg, sig)

    return BenchResult("B3", f"depth_{depth}", measure_ns(verify_chain))


# ---------------------------------------------------------------------------
# B4: Relay Discovery Latency (requires Docker)
# ---------------------------------------------------------------------------

def _b4_seed_test_event(relay_urls: list[str]) -> tuple[str, str]:
    """Publish a Kind 38100 test event to relays for B4; return (pubkey_hex, d_tag)."""
    import nostr_sdk as ns  # type: ignore[import]

    async def _seed() -> tuple[str, str]:
        ns.uniffi_set_event_loop(asyncio.get_running_loop())
        keys = ns.Keys.generate()
        pk_hex = keys.public_key().to_hex()
        d_tag = f"b4-bench-{int(time.time())}"

        content = json.dumps({
            "name": "b4-bench-agent",
            "version": "1.0.0",
            "description": "Benchmark test agent for B4 relay discovery",
            "status": "active",
            "capabilities": ["text-generation"],
        })
        tags = [
            ns.Tag.identifier(d_tag),
            ns.Tag.hashtag("text-generation"),
            ns.Tag.alt(f"NostrAgent identity: b4-bench-agent ({d_tag})"),
        ]
        builder = (
            ns.EventBuilder(ns.Kind(38100), content)
            .tags(tags)
        )

        signer = ns.NostrSigner.keys(keys)
        client = ns.Client(signer)
        try:
            await _add_relay_urls(client, relay_urls)
            await client.connect()
            await client.send_event_builder(builder)
        finally:
            await client.disconnect()

        # Brief pause to let relays index the event.
        await asyncio.sleep(0.5)
        return pk_hex, d_tag

    return asyncio.run(_seed())


def bench_b4_relay_discovery(n_relays: int) -> BenchResult:
    """B4: Relay discovery latency -- time to fetch a Kind 38100 from N relays.

    Pre-seeds a test event, then measures fetch_events latency across N relays.
    200 runs (relay benchmarks are slower), 20 warmup.
    Requires Docker relay infrastructure.
    """
    relay_subset = RELAY_URLS[:n_relays]

    # Check if relays are available.
    if not _check_relay_available():
        return _requires_docker(f"B4_relays_{n_relays}")

    # Seed a test event to all 3 relays (so any subset will find it).
    try:
        pk_hex, d_tag = _b4_seed_test_event(RELAY_URLS)
    except Exception as exc:
        _bench_logger.warning("B4: failed to seed test event: %s", exc)
        return _requires_docker(f"B4_relays_{n_relays}")

    import nostr_sdk as ns  # type: ignore[import]

    async def _fetch() -> None:
        ns.uniffi_set_event_loop(asyncio.get_running_loop())
        client = ns.Client()
        await _add_relay_urls(client, relay_subset)
        await client.connect()
        try:
            f = (
                ns.Filter()
                .kind(ns.Kind(38100))
                .author(ns.PublicKey.parse(pk_hex))
                .identifier(d_tag)
                .limit(1)
            )
            await client.fetch_events(f, timedelta(seconds=5))
        finally:
            await client.disconnect()

    def measure_fn() -> None:
        asyncio.run(_fetch())

    total = min(_total_runs, _DOCKER_TOTAL_RUNS * 2)  # cap at 200 for relay benchmarks
    warmup = min(_warmup, _DOCKER_WARMUP * 2)  # cap at 20
    timings = measure_ns(measure_fn, total)
    # measure_ns already discards warmup based on module-level _warmup,
    # but we passed total as n, so timings are already effective.
    return BenchResult("B4", f"relays_{n_relays}", timings)


# ---------------------------------------------------------------------------
# B5: Attestation Verification Time
# ---------------------------------------------------------------------------

def bench_b5_attestation_verification() -> BenchResult:
    """B5: Kind 38102 attestation validation -- schema check + BIP340 sig.

    Creates a realistic Kind 38102-shaped event with proper tags and content,
    validates the schema (subject tag, trust value range, required fields)
    and verifies the BIP340 signature.
    """
    sk, pk = _make_bip340_keypair()
    _, attestee_pk = _make_bip340_keypair()

    # Build attestation content
    content_dict = {
        "attestee": attestee_pk.hex(),
        "capability": "text-generation",
        "confidence": 0.85,
        "issued_at": "2026-04-01T00:00:00Z",
    }
    content_json = json.dumps(content_dict)

    tags = [
        ["p", attestee_pk.hex()],
        ["t", "text-generation"],
        ["d", f"{pk.hex()[:8]}-{attestee_pk.hex()[:8]}-text-generation"],
        ["schema_version", "1.0"],
    ]

    # Build canonical event and sign
    canonical = json.dumps(
        [0, pk.hex(), 1700000000, 38102, tags, content_json],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    event_id = sha256(canonical)
    sig = sign_schnorr(sk, event_id)

    def verify() -> None:
        # 1. Schema validation
        parsed = json.loads(content_json)
        conf = float(parsed["confidence"])
        assert 0.0 <= conf <= 1.0
        assert "attestee" in parsed
        assert "capability" in parsed

        # Check p-tag presence
        p_tags = [t for t in tags if t[0] == "p"]
        assert len(p_tags) >= 1

        # 2. Recompute event ID
        recomputed = sha256(canonical)
        assert recomputed == event_id

        # 3. BIP340 sig verification (real Schnorr)
        assert verify_schnorr(pk, recomputed, sig)

    return BenchResult("B5", "kind_38102", measure_ns(verify))


# ---------------------------------------------------------------------------
# B6: Trust Graph Query Latency
# ---------------------------------------------------------------------------

def bench_b6_trust_graph(graph_size: int) -> BenchResult:
    """B6: compute_trust() on synthetic graph via real noisy-OR DFS.

    Uses synthetic_graphs.py to build a deterministic Erdos-Renyi graph
    and runs the real compute_trust() from nostr_agent.trust.
    Source = node "0", target = node at graph_size // 2.
    """
    # Use the synthetic_graphs module which returns TrustGraph (dict type
    # matching nostr_agent.trust.TrustGraph)
    graph: TrustGraph = sg_make_random_graph(graph_size, edge_prob=0.15, seed=RANDOM_SEED)

    source = "0"
    target = str(min(graph_size - 1, graph_size // 2))

    def run_trust() -> None:
        compute_trust(graph, source, target, decay=0.5, max_depth=4, epsilon=0.01)

    return BenchResult("B6", f"nodes_{graph_size}", measure_ns(run_trust))


def bench_b6b_trust_graph_detailed(graph_size: int) -> BenchResult:
    """B6b: compute_trust_detailed() returning TrustResult with path stats."""
    graph: TrustGraph = sg_make_random_graph(graph_size, edge_prob=0.15, seed=RANDOM_SEED)
    source = "0"
    target = str(min(graph_size - 1, graph_size // 2))

    def run_trust_detailed() -> None:
        compute_trust_detailed(graph, source, target, decay=0.5, max_depth=4, epsilon=0.01)

    return BenchResult("B6b", f"nodes_{graph_size}", measure_ns(run_trust_detailed))


def bench_b6_trust_topologies(graph_size: int) -> list[BenchResult]:
    """B6 topology variants: Erdos-Renyi, Ring, Star, Chain, Sybil."""
    results = []
    topologies: list[tuple[str, TrustGraph]] = [
        ("erdos_renyi", sg_make_random_graph(graph_size, edge_prob=0.15, seed=RANDOM_SEED)),
        ("ring", sg_make_ring_graph(graph_size, weight=0.8)),
        ("star", sg_make_star_graph(graph_size, weight=0.8)),
        ("chain", sg_make_chain_graph(graph_size, weight=0.8)),
        ("sybil", sg_make_sybil_graph(int(0.8 * graph_size), graph_size - int(0.8 * graph_size),
                                       n_bridges=10, seed=RANDOM_SEED)),
    ]
    source = "0"
    target = str(min(graph_size - 1, graph_size // 2))

    for topo_name, graph in topologies:
        def run_trust(g=graph) -> None:
            compute_trust(g, source, target, decay=0.5, max_depth=4, epsilon=0.01)

        timings = measure_ns(run_trust)
        results.append(BenchResult("B6_topo", f"{topo_name}_n{graph_size}", timings))

    return results


# ---------------------------------------------------------------------------
# B6b: Trust graph parameter sweep variants (ATAM sensitivity analysis)
# ---------------------------------------------------------------------------


def bench_b6b_trust_graph_max_depth(graph_size: int, max_depth: int) -> BenchResult:
    """B6b variant: compute_trust_detailed with different max_depth (D_max).

    Used for ATAM sensitivity analysis of the trust depth parameter.
    """
    graph: TrustGraph = sg_make_random_graph(graph_size, edge_prob=0.15, seed=RANDOM_SEED)
    source = "0"
    target = str(min(graph_size - 1, graph_size // 2))

    def run_trust() -> None:
        compute_trust_detailed(graph, source, target, decay=0.5, max_depth=max_depth, epsilon=0.01)

    return BenchResult("B6b_Dmax", f"D{max_depth}_n{graph_size}", measure_ns(run_trust))


def bench_b6b_trust_graph_decay(graph_size: int, decay: float) -> BenchResult:
    """B6b variant: compute_trust_detailed with different decay parameter.

    Used for ATAM sensitivity analysis of the trust decay parameter.
    """
    graph: TrustGraph = sg_make_random_graph(graph_size, edge_prob=0.15, seed=RANDOM_SEED)
    source = "0"
    target = str(min(graph_size - 1, graph_size // 2))

    decay_label = str(decay).replace(".", "")

    def run_trust() -> None:
        compute_trust_detailed(graph, source, target, decay=decay, max_depth=4, epsilon=0.01)

    return BenchResult("B6b_decay", f"d{decay_label}_n{graph_size}", measure_ns(run_trust))


# ---------------------------------------------------------------------------
# B7: Key Rotation Latency (requires Docker)
# ---------------------------------------------------------------------------

def bench_b7_key_rotation() -> BenchResult:
    """B7: End-to-end key rotation latency via relay publish.

    Per iteration:
    1. Generate fresh keypair triple (old, new, next_next).
    2. Create and publish Kind 38100 identity event with pre-rotation commitment.
    3. Time the full rotation: publish old-key "rotated" + new-key "active" events.
    4. Confirm both events queryable from relays.

    100 runs (relay-dependent), 10 warmup.
    Requires Docker relay infrastructure.
    """
    if not _check_relay_available():
        return _requires_docker("B7")

    import nostr_sdk as ns  # type: ignore[import]

    async def _single_rotation() -> None:
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        # Generate three keypairs: current, next (pre-committed), and next-next.
        keys_old = ns.Keys.generate()
        keys_new = ns.Keys.generate()
        keys_next_next = ns.Keys.generate()

        operator_keys = ns.Keys.generate()
        d_tag = f"b7-bench-{int(time.time() * 1000) % 1_000_000}"

        # Compute pre-rotation commitment: SHA256(new_pk_bytes).
        new_pk_bytes = bytes.fromhex(keys_new.public_key().to_hex())
        next_key_hash = hashlib.sha256(new_pk_bytes).hexdigest()

        # --- Publish initial identity event ---
        content_init = json.dumps({
            "name": "b7-bench-agent",
            "version": "1.0.0",
            "description": "Benchmark agent for B7 key rotation",
            "status": "active",
            "capabilities": ["text-generation"],
            "operator": operator_keys.public_key().to_hex(),
        })
        tags_init = [
            ns.Tag.identifier(d_tag),
            ns.Tag.public_key(operator_keys.public_key()),
            ns.Tag.hashtag("text-generation"),
            ns.Tag.alt(f"NostrAgent identity: b7-bench-agent ({d_tag})"),
            ns.Tag.custom(ns.TagKind.UNKNOWN("next_key_hash"), [next_key_hash]),
        ]
        builder_init = ns.EventBuilder(ns.Kind(38100), content_init).tags(tags_init)

        signer_old = ns.NostrSigner.keys(keys_old)
        client = ns.Client(signer_old)
        try:
            await _add_relay_urls(client, RELAY_URLS)
            await client.connect()
            await client.send_event_builder(builder_init)
        finally:
            await client.disconnect()

        await asyncio.sleep(0.2)

        # --- Timed: rotation (publish old-key "rotated" + new-key "active") ---
        rotation_ts = int(time.time()) + 1

        # Compute next_next_key_hash for the new identity.
        nnk_bytes = bytes.fromhex(keys_next_next.public_key().to_hex())
        next_next_key_hash = hashlib.sha256(nnk_bytes).hexdigest()

        # Old-key "rotated" event.
        content_rotated = json.dumps({
            "name": "b7-bench-agent",
            "version": "1.0.0",
            "description": "Benchmark agent for B7 key rotation",
            "status": "rotated",
            "capabilities": ["text-generation"],
            "operator": operator_keys.public_key().to_hex(),
        })
        tags_rotated = [
            ns.Tag.identifier(d_tag),
            ns.Tag.public_key(operator_keys.public_key()),
            ns.Tag.alt(f"NostrAgent identity: b7-bench-agent ({d_tag}) [ROTATED]"),
        ]
        builder_rotated = (
            ns.EventBuilder(ns.Kind(38100), content_rotated)
            .tags(tags_rotated)
            .custom_created_at(ns.Timestamp.from_secs(rotation_ts))
        )

        client_old = ns.Client(signer_old)
        try:
            await _add_relay_urls(client_old, RELAY_URLS)
            await client_old.connect()
            await client_old.send_event_builder(builder_rotated)
        finally:
            await client_old.disconnect()

        # New-key "active" event.
        content_active = json.dumps({
            "name": "b7-bench-agent",
            "version": "1.0.0",
            "description": "Benchmark agent for B7 key rotation",
            "status": "active",
            "capabilities": ["text-generation"],
            "operator": operator_keys.public_key().to_hex(),
        })
        tags_active = [
            ns.Tag.identifier(d_tag),
            ns.Tag.public_key(operator_keys.public_key()),
            ns.Tag.alt(f"NostrAgent identity: b7-bench-agent ({d_tag})"),
            ns.Tag.custom(ns.TagKind.UNKNOWN("next_key_hash"), [next_next_key_hash]),
            ns.Tag.custom(ns.TagKind.UNKNOWN("prev_key"), [keys_old.public_key().to_hex()]),
        ]
        builder_active = (
            ns.EventBuilder(ns.Kind(38100), content_active)
            .tags(tags_active)
            .custom_created_at(ns.Timestamp.from_secs(rotation_ts + 1))
        )

        signer_new = ns.NostrSigner.keys(keys_new)
        client_new = ns.Client(signer_new)
        try:
            await _add_relay_urls(client_new, RELAY_URLS)
            await client_new.connect()
            await client_new.send_event_builder(builder_active)
        finally:
            await client_new.disconnect()

    def measure_fn() -> None:
        asyncio.run(_single_rotation())

    total = min(_total_runs, _DOCKER_TOTAL_RUNS)
    warmup = min(_warmup, _DOCKER_WARMUP)
    timings = measure_ns(measure_fn, total, warmup=warmup)
    return BenchResult("B7", "key_rotation", timings)


# ---------------------------------------------------------------------------
# B8: Revocation Propagation Time (requires Docker)
# ---------------------------------------------------------------------------

def bench_b8_revocation_propagation() -> BenchResult:
    """B8: Revocation propagation time via relay replaceable events.

    Per iteration:
    1. Pre-publish a Kind 38101 delegation event (status=active).
    2. Publish a revocation (same d-tag, status=revoked, higher created_at).
    3. Poll until all relays serve the revoked version.
    4. Measure total propagation time.

    100 runs, 10 warmup.
    Requires Docker relay infrastructure.
    """
    if not _check_relay_available():
        return _requires_docker("B8")

    import nostr_sdk as ns  # type: ignore[import]

    async def _single_revocation() -> None:
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        delegator_keys = ns.Keys.generate()
        delegatee_keys = ns.Keys.generate()
        d_tag = f"b8-bench-{int(time.time() * 1000) % 1_000_000}"
        base_ts = int(time.time())

        # --- Publish active delegation ---
        content_active = json.dumps({
            "scope": {"capabilities": ["text-generation"], "resources": [], "actions": []},
            "constraints": {
                "expires_at": base_ts + 86400,
                "max_chain_depth": 4,
                "current_depth": 1,
                "issued_at": base_ts,
            },
            "revocation_status": "active",
            "delegation_type": "root",
        })
        tags_active = [
            ns.Tag.identifier(d_tag),
            ns.Tag.public_key(delegatee_keys.public_key()),
            ns.Tag.hashtag("text-generation"),
            ns.Tag.alt("Kind 38101: NostrAgent Delegation Chain Event"),
        ]
        builder_active = (
            ns.EventBuilder(ns.Kind(38101), content_active)
            .tags(tags_active)
            .custom_created_at(ns.Timestamp.from_secs(base_ts))
        )

        signer = ns.NostrSigner.keys(delegator_keys)
        client = ns.Client(signer)
        try:
            await _add_relay_urls(client, RELAY_URLS)
            await client.connect()
            await client.send_event_builder(builder_active)
        finally:
            await client.disconnect()

        await asyncio.sleep(0.3)

        # --- Publish revocation (same d-tag, higher created_at) ---
        content_revoked = json.dumps({
            "revocation_status": "revoked",
            "revocation_reason": "benchmark",
        })
        tags_revoked = [
            ns.Tag.identifier(d_tag),
            ns.Tag.alt("Kind 38101: NostrAgent Delegation [REVOKED]"),
        ]
        builder_revoked = (
            ns.EventBuilder(ns.Kind(38101), content_revoked)
            .tags(tags_revoked)
            .custom_created_at(ns.Timestamp.from_secs(base_ts + 1))
        )

        client2 = ns.Client(signer)
        try:
            await _add_relay_urls(client2, RELAY_URLS)
            await client2.connect()
            output = await client2.send_event_builder(builder_revoked)
            revoked_event_id = output.id.to_hex()
        finally:
            await client2.disconnect()

        # --- Poll until all relays return the revoked event ---
        author_pk = delegator_keys.public_key()
        for _attempt in range(20):
            found_on = 0
            for url in RELAY_URLS:
                poll_client = ns.Client()
                try:
                    await _add_relay_urls(poll_client, [url])
                    await poll_client.connect()
                    f = (
                        ns.Filter()
                        .kind(ns.Kind(38101))
                        .author(author_pk)
                        .identifier(d_tag)
                        .limit(1)
                    )
                    events = await poll_client.fetch_events(f, timedelta(seconds=3))
                    for ev in events.to_vec():
                        if ev.id().to_hex() == revoked_event_id:
                            found_on += 1
                            break
                finally:
                    await poll_client.disconnect()

            if found_on >= len(RELAY_URLS):
                break
            await asyncio.sleep(0.2)

    def measure_fn() -> None:
        asyncio.run(_single_revocation())

    total = min(_total_runs, _DOCKER_TOTAL_RUNS)
    warmup = min(_warmup, _DOCKER_WARMUP)
    timings = measure_ns(measure_fn, total, warmup=warmup)
    return BenchResult("B8", "revocation_propagation", timings)


# ---------------------------------------------------------------------------
# B9: L402 End-to-End Flow (requires Docker)
# ---------------------------------------------------------------------------

def bench_b9_l402_full_flow() -> BenchResult:
    """B9: Full L402 end-to-end flow on regtest Lightning.

    Per iteration:
    1. L402Verifier (bob) creates challenge (invoice + identity-bound macaroon).
    2. L402Client (alice) pays the invoice via LND SendPaymentV2.
    3. L402Verifier verifies the credential (5-check verification).

    Measures the full 3-step flow latency.
    100 runs (LND-dependent), 10 warmup.
    Requires Docker LND infrastructure (alice on 10009, bob on 10010).

    Note: gRPC channels are tied to event loops, so the entire benchmark loop
    runs inside a single asyncio.run() with manual timing per iteration.
    """
    # Check both LND nodes are reachable.
    if not _check_lnd_available(_ALICE_LND_HOST, _ALICE_LND_PORT):
        return _requires_docker("B9")
    if not _check_lnd_available(_BOB_LND_HOST, _BOB_LND_PORT):
        return _requires_docker("B9")

    # Check credential files exist.
    for path in [_ALICE_MACAROON, _ALICE_TLS_CERT, _BOB_MACAROON, _BOB_TLS_CERT]:
        if not Path(path).exists():
            _bench_logger.warning("B9: credential file missing: %s", path)
            return _requires_docker("B9")

    try:
        from nostr_agent.l402 import L402Verifier  # noqa: PLC0415
        from nostr_agent.lnd_grpc.credentials import (  # noqa: PLC0415
            create_lnd_channel, load_macaroon, load_tls_cert,
        )
        from nostr_agent.lnd_grpc import router_pb2, router_pb2_grpc  # noqa: PLC0415
    except ImportError as exc:
        _bench_logger.warning("B9: cannot import LND modules: %s", exc)
        return _requires_docker("B9")

    import base64 as _b64  # noqa: PLC0415

    # Pre-generate agent keys for signing (used across all iterations).
    root_key = b"b9-benchmark-root-key-32bytes!!"
    sk, pk = _make_bip340_keypair()
    pk_hex = pk.hex()

    total = min(_total_runs, _DOCKER_TOTAL_RUNS)
    warmup_count = min(_warmup, _DOCKER_WARMUP)

    async def _run_all_iterations() -> list[float]:
        """Run all B9 iterations in a single event loop (gRPC requirement)."""
        # Create verifier + alice channel once, reuse across iterations.
        verifier = L402Verifier(
            root_key=root_key,
            lnd_host=_BOB_LND_HOST,
            lnd_port=_BOB_LND_PORT,
            lnd_macaroon_path=_BOB_MACAROON,
            lnd_tls_cert_path=_BOB_TLS_CERT,
        )

        alice_mac_hex = load_macaroon(_ALICE_MACAROON)
        alice_tls = load_tls_cert(_ALICE_TLS_CERT)
        alice_channel = create_lnd_channel(
            _ALICE_LND_HOST, _ALICE_LND_PORT, alice_mac_hex, alice_tls,
        )
        alice_router = router_pb2_grpc.RouterStub(alice_channel)

        results: list[float] = []

        for i in range(total):
            gc.disable()
            t0 = time.perf_counter_ns()

            # Step 1: Create challenge (bob creates invoice + macaroon).
            challenge = await verifier.create_challenge(
                agent_pubkey_hex=pk_hex,
                amount_sat=1,
                caveats=["service = benchmark"],
                memo="B9 benchmark",
            )

            # Step 2: Pay invoice (alice pays bob).
            pay_request = router_pb2.SendPaymentRequest(
                payment_request=challenge.bolt11_invoice,
                timeout_seconds=30,
                fee_limit_sat=10,
                no_inflight_updates=False,
            )
            payment_preimage = None
            async for update in alice_router.SendPaymentV2(pay_request):
                if update.status == 2:  # SUCCEEDED
                    payment_preimage = bytes.fromhex(update.payment_preimage)
                    break
                if update.status == 3:  # FAILED
                    raise RuntimeError(f"Payment failed: {update.failure_reason}")

            if payment_preimage is None:
                raise RuntimeError("No payment preimage received")

            # Step 3: Verify credential.
            macaroon_b64 = _b64.urlsafe_b64encode(challenge.macaroon_bytes).decode()
            timestamp = int(time.time())
            body_hash = sha256(b"")
            payload_bytes = (
                b"GET"
                + b"https://agent.example.com/api/v1/bench"
                + str(timestamp).encode()
                + body_hash
            )
            sign_payload = sha256(payload_bytes)
            sig_bytes = sign_schnorr(sk, sign_payload)

            result = verifier.verify_request(
                method="GET",
                url="https://agent.example.com/api/v1/bench",
                headers={
                    "Authorization": f"L402 {macaroon_b64}:{payment_preimage.hex()}",
                    "X-Nostr-Pubkey": pk_hex,
                    "X-Nostr-Sig": sig_bytes.hex(),
                    "X-Nostr-Timestamp": str(timestamp),
                },
            )

            elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000
            gc.enable()

            assert result.is_valid, f"L402 verification failed: {result.reason_code}"

            if i >= warmup_count:
                results.append(elapsed_ms)

        return results

    # Verify LND connectivity with a single test run.
    try:
        asyncio.run(_run_all_iterations.__wrapped__() if hasattr(_run_all_iterations, '__wrapped__') else _test_b9_connection(root_key, pk_hex, sk))
    except Exception as exc:
        _bench_logger.warning("B9: LND test run failed: %s", exc)
        return _requires_docker("B9")

    # Run all iterations in a single event loop.
    timings = asyncio.run(_run_all_iterations())
    return BenchResult("B9", "l402_full_flow", timings)


async def _test_b9_connection(root_key: bytes, pk_hex: str, sk: bytes) -> None:
    """Quick connectivity test for B9 -- create one invoice and pay it."""
    from nostr_agent.l402 import L402Verifier  # noqa: PLC0415
    from nostr_agent.lnd_grpc.credentials import (  # noqa: PLC0415
        create_lnd_channel, load_macaroon, load_tls_cert,
    )
    from nostr_agent.lnd_grpc import router_pb2, router_pb2_grpc  # noqa: PLC0415

    verifier = L402Verifier(
        root_key=root_key,
        lnd_host=_BOB_LND_HOST,
        lnd_port=_BOB_LND_PORT,
        lnd_macaroon_path=_BOB_MACAROON,
        lnd_tls_cert_path=_BOB_TLS_CERT,
    )
    challenge = await verifier.create_challenge(
        agent_pubkey_hex=pk_hex,
        amount_sat=1,
        caveats=["service = benchmark-test"],
        memo="B9 connectivity test",
    )

    alice_mac_hex = load_macaroon(_ALICE_MACAROON)
    alice_tls = load_tls_cert(_ALICE_TLS_CERT)
    alice_channel = create_lnd_channel(
        _ALICE_LND_HOST, _ALICE_LND_PORT, alice_mac_hex, alice_tls,
    )
    alice_router = router_pb2_grpc.RouterStub(alice_channel)

    pay_request = router_pb2.SendPaymentRequest(
        payment_request=challenge.bolt11_invoice,
        timeout_seconds=30,
        fee_limit_sat=10,
        no_inflight_updates=False,
    )
    async for update in alice_router.SendPaymentV2(pay_request):
        if update.status == 2:
            return
        if update.status == 3:
            raise RuntimeError(f"Payment failed: {update.failure_reason}")
    raise RuntimeError("No payment status received")


# ---------------------------------------------------------------------------
# B10: Macaroon Attenuation Depth
# ---------------------------------------------------------------------------

def bench_b10_macaroon_attenuation(n_caveats: int) -> BenchResult:
    """B10: Macaroon caveat addition (scope attenuation) timing via pymacaroons.

    Measures time to create a base macaroon, add N first-party caveats,
    and serialize the result. Uses the real pymacaroons library.
    """
    import pymacaroons  # type: ignore[import]

    root_key = b"benchmark-root-key-32byteslong!!"

    # Sample caveats representing realistic NostrAgent scope attenuation
    caveat_pool = [
        "service = weather-forecast",
        "capabilities = text-generation",
        "expires_at = 1700100000",
        "max_requests = 100",
        "window_seconds = 3600",
        "actions = read",
        "resources = relay:wss://relay1.example.com",
        "scope = text-generation",
        "agent_pubkey = " + "ab" * 32,
        "delegation_depth = 2",
        "rate_limit = 50/3600",
        "ip_range = 10.0.0.0/8",
        "method = GET",
        "path_prefix = /api/v1/",
        "content_type = application/json",
        "max_tokens = 4096",
        "model = gpt-4",
        "region = eu-west-1",
        "tenant = org-12345",
        "priority = normal",
    ]
    caveats = caveat_pool[:n_caveats]

    def attenuate() -> None:
        m = pymacaroons.Macaroon(
            location="https://agent.example.com",
            identifier="agent-token-bench",
            key=root_key,
        )
        for c in caveats:
            m.add_first_party_caveat(c)
        _ = m.serialize()

    return BenchResult("B10", f"caveats_{n_caveats}", measure_ns(attenuate))


# ---------------------------------------------------------------------------
# B11: Payment Verification Time
# ---------------------------------------------------------------------------

def bench_b11_l402_token_verification() -> BenchResult:
    """B11: L402 token verification via real pymacaroons + real BIP340 sig check.

    Simulates the 5-check verification from L402Verifier.verify_request():
    1. Macaroon deserialization + root key HMAC verification
    2. Caveat satisfaction
    3. Preimage binding (SHA256 check)
    4. Identity binding (pubkey comparison)
    5. BIP340 signature verification on canonical request

    Uses real crypto throughout -- no stubs.
    """
    import pymacaroons  # type: ignore[import]

    # Setup: create a realistic L402 credential
    root_key = b"benchmark-root-key-32byteslong!!"
    sk, pk = _make_bip340_keypair()
    preimage = sha256(b"benchmark-preimage-seed")
    payment_hash = sha256(preimage)

    # Build macaroon with identity-bound identifier
    identifier_hex = (b"\x01" + payment_hash + pk).hex()
    mac = pymacaroons.Macaroon(
        location="nostr-agent",
        identifier=identifier_hex,
        key=root_key.hex(),
    )
    mac.add_first_party_caveat("service = weather-forecast")
    mac.add_first_party_caveat("expires_at = 9999999999")
    token = mac.serialize()

    # Build signed request
    method = "GET"
    url = "https://agent.example.com/api/v1/weather"
    timestamp_str = str(1700000000)
    body_hash = sha256(b"")
    payload = method.encode() + url.encode() + timestamp_str.encode() + body_hash
    sign_payload = sha256(payload)
    request_sig = sign_schnorr(sk, sign_payload)

    def verify_full() -> None:
        # Check 1: Macaroon deserialization + HMAC verification + caveat satisfaction
        dm = pymacaroons.Macaroon.deserialize(token)
        v = pymacaroons.Verifier()
        v.satisfy_exact("service = weather-forecast")
        v.satisfy_exact("expires_at = 9999999999")
        v.verify(dm, root_key.hex())

        # Check 2: Parse identifier -> extract payment_hash + agent_pubkey
        id_raw = bytes.fromhex(dm.identifier)
        _ver = id_raw[0]
        bound_ph = id_raw[1:33]
        bound_pk = id_raw[33:65]

        # Check 3: Preimage binding
        assert sha256(preimage) == bound_ph

        # Check 4: Identity binding
        assert bound_pk == pk

        # Check 5: BIP340 signature verification on canonical request
        assert verify_schnorr(pk, sign_payload, request_sig)

    return BenchResult("B11", "full_5check", measure_ns(verify_full))


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

# Each entry maps a CLI key to a callable returning BenchResult or list[BenchResult].
# Docker-dependent benchmarks are included but will skip at runtime.

ALL_METRICS: dict[str, Callable[[], BenchResult | list[BenchResult]]] = {
    # B1: Auth handshake
    "B1": bench_b1_auth_handshake,

    # B2: Credential verification (3 kind variants)
    "B2": bench_b2_credential_verification,

    # B3: Delegation chain depth (4 depth variants)
    "B3_d1": lambda: bench_b3_delegation_chain(1),
    "B3_d2": lambda: bench_b3_delegation_chain(2),
    "B3_d3": lambda: bench_b3_delegation_chain(3),
    "B3_d4": lambda: bench_b3_delegation_chain(4),

    # B4: Relay discovery (Docker required)
    "B4_r1": lambda: bench_b4_relay_discovery(1),
    "B4_r2": lambda: bench_b4_relay_discovery(2),
    "B4_r3": lambda: bench_b4_relay_discovery(3),

    # B5: Attestation verification
    "B5": bench_b5_attestation_verification,

    # B6: Trust graph query latency (7 size variants)
    "B6_n5":   lambda: bench_b6_trust_graph(5),
    "B6_n10":  lambda: bench_b6_trust_graph(10),
    "B6_n20":  lambda: bench_b6_trust_graph(20),
    "B6_n50":  lambda: bench_b6_trust_graph(50),
    "B6_n100": lambda: bench_b6_trust_graph(100),
    "B6_n200": lambda: bench_b6_trust_graph(200),
    "B6_n500": lambda: bench_b6_trust_graph(500),

    # B6b: Trust graph detailed (TrustResult with path stats)
    "B6b_n50":  lambda: bench_b6b_trust_graph_detailed(50),
    "B6b_n100": lambda: bench_b6b_trust_graph_detailed(100),
    "B6b_n200": lambda: bench_b6b_trust_graph_detailed(200),
    "B6b_n500": lambda: bench_b6b_trust_graph_detailed(500),

    # B6b D_max sweep: max_depth variants at n=50 (ATAM sensitivity)
    "B6b_D2_n50": lambda: bench_b6b_trust_graph_max_depth(50, max_depth=2),
    "B6b_D3_n50": lambda: bench_b6b_trust_graph_max_depth(50, max_depth=3),
    "B6b_D4_n50": lambda: bench_b6b_trust_graph_max_depth(50, max_depth=4),

    # B6b decay sweep: decay variants at n=50 (ATAM sensitivity)
    "B6b_d03_n50": lambda: bench_b6b_trust_graph_decay(50, decay=0.3),
    "B6b_d05_n50": lambda: bench_b6b_trust_graph_decay(50, decay=0.5),
    "B6b_d07_n50": lambda: bench_b6b_trust_graph_decay(50, decay=0.7),

    # B7: Key rotation (Docker required)
    "B7": bench_b7_key_rotation,

    # B8: Revocation propagation (Docker required)
    "B8": bench_b8_revocation_propagation,

    # B9: L402 full flow (Docker required)
    "B9": bench_b9_l402_full_flow,

    # B10: Macaroon attenuation (4 caveat-count variants)
    "B10_c1":  lambda: bench_b10_macaroon_attenuation(1),
    "B10_c5":  lambda: bench_b10_macaroon_attenuation(5),
    "B10_c10": lambda: bench_b10_macaroon_attenuation(10),
    "B10_c20": lambda: bench_b10_macaroon_attenuation(20),

    # B11: L402 token verification (full 5-check)
    "B11": bench_b11_l402_token_verification,
}

# Metric groups for --metrics shorthand (e.g. "B3" expands to B3_d1..B3_d4)
METRIC_GROUPS: dict[str, list[str]] = {
    "B1": ["B1"],
    "B2": ["B2"],
    "B3": ["B3_d1", "B3_d2", "B3_d3", "B3_d4"],
    "B4": ["B4_r1", "B4_r2", "B4_r3"],
    "B5": ["B5"],
    "B6": ["B6_n5", "B6_n10", "B6_n20", "B6_n50", "B6_n100", "B6_n200", "B6_n500"],
    "B6b": ["B6b_n50", "B6b_n100", "B6b_n200", "B6b_n500"],
    "B6b_Dmax": ["B6b_D2_n50", "B6b_D3_n50", "B6b_D4_n50"],
    "B6b_decay": ["B6b_d03_n50", "B6b_d05_n50", "B6b_d07_n50"],
    "B7": ["B7"],
    "B8": ["B8"],
    "B9": ["B9"],
    "B10": ["B10_c1", "B10_c5", "B10_c10", "B10_c20"],
    "B11": ["B11"],
}

# Docker-dependent metric keys (used by run_full_evaluation.py and --paper mode).
DOCKER_METRICS: set[str] = {"B4_r1", "B4_r2", "B4_r3", "B7", "B8", "B9"}


def _expand_metrics(raw: list[str]) -> list[str]:
    """Expand metric group names (e.g. 'B3' -> ['B3_d1', ...]) and individual keys."""
    expanded = []
    for key in raw:
        key_upper = key.upper()
        if key_upper in METRIC_GROUPS:
            expanded.extend(METRIC_GROUPS[key_upper])
        elif key_upper in ALL_METRICS:
            expanded.append(key_upper)
        else:
            # Try as-is for direct keys like B3_d2
            if key in ALL_METRICS:
                expanded.append(key)
            else:
                expanded.append(key)  # will warn later
    return expanded


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

app = typer.Typer(help="NostrAgent benchmark runner (B1-B11).")


@app.command()
def run(
    metrics: str = typer.Option(
        "", "--metrics", "-m",
        help="Comma-separated metric keys (e.g. B1,B3,B6_n100). Groups like B3 expand to all variants.",
    ),
    output: Path = typer.Option(
        OUTPUT_DIR, "--output", "-o",
        help="Output directory for CSV files.",
    ),
    all_metrics: bool = typer.Option(False, "--all", "-a", help="Run all B1-B11 metrics."),
    compare: bool = typer.Option(False, "--compare", "-c", help="Print variant comparison tables."),
    runs: int = typer.Option(RUNS_PER_METRIC, "--runs", "-r", help="Total runs per metric."),
    warmup: int = typer.Option(WARMUP_RUNS, "--warmup", "-w", help="Warm-up runs to discard."),
    paper: bool = typer.Option(
        False, "--paper",
        help="Paper-mode: 1100 runs (100 warmup) offline, 110 runs (10 warmup) Docker. Overrides --runs/--warmup.",
    ),
) -> None:
    """Run selected benchmarks and write CSV results."""
    global _total_runs, _warmup

    if paper:
        # Paper mode: separate run counts for offline and Docker metrics.
        # We set the offline counts here; Docker benchmarks internally cap
        # to _DOCKER_TOTAL_RUNS/_DOCKER_WARMUP via min() in each bench fn.
        _total_runs = _PAPER_OFFLINE_RUNS
        _warmup = _PAPER_OFFLINE_WARMUP
    else:
        _total_runs = runs
        _warmup = warmup

    console = Console()

    # Seed random state for reproducibility
    random.seed(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)

    # Parse comma-separated metrics string
    metric_list = [s.strip() for s in metrics.split(",") if s.strip()] if metrics else []

    # Determine which metrics to run
    if all_metrics:
        selected = list(ALL_METRICS.keys())
    elif metric_list:
        selected = _expand_metrics(metric_list)
    else:
        console.print("[red]Specify --metrics or --all.[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]NostrAgent Benchmark Harness[/bold]")
    console.print(f"  Runs: {_total_runs} (warm-up: {_warmup}, effective: {_total_runs - _warmup})")
    console.print(f"  Seed: {RANDOM_SEED}")
    console.print(f"  Output: {output}/")
    console.print(f"  Metrics: {len(selected)}\n")

    # Capture environment
    env = capture_environment()
    console.print(f"  Python: {env['python_version'].split()[0]}")
    console.print(f"  Platform: {env['platform']}")
    console.print(f"  nostr-sdk: {env['nostr_sdk_version']}")
    console.print(f"  coincurve: {env['coincurve_version']}")
    console.print()

    all_results: list[BenchResult] = []

    for key in selected:
        if key not in ALL_METRICS:
            console.print(f"[yellow]Unknown metric: {key}[/yellow]")
            continue

        console.print(f"Running [bold]{key}[/bold]...", end=" ")
        t_start = time.perf_counter()

        out = ALL_METRICS[key]()

        # Normalize to list
        results_batch: list[BenchResult]
        if isinstance(out, list):
            results_batch = out
        else:
            results_batch = [out]

        elapsed = time.perf_counter() - t_start

        for r in results_batch:
            # Skip docker-required sentinel results
            if r.variant == "docker_required":
                continue
            s = r.stats()
            console.print(
                f"\n  {r.metric}/{r.variant}: "
                f"median={s['median']:.4f}ms  IQR={s['iqr']:.4f}  "
                f"P95={s['p95']:.4f}  P99={s['p99']:.4f}  "
                f"(n={s['n']}, {elapsed:.1f}s total)"
            )
            all_results.append(r)

    # Write CSVs
    real_results = [r for r in all_results if r.variant != "docker_required"]
    if real_results:
        write_csv(real_results, output)
        console.print(f"\n[green]CSVs written to {output}/[/green]")

        # Save environment metadata
        meta_path = output / "environment.json"
        save_metadata(meta_path)
        console.print(f"[green]Environment metadata: {meta_path}[/green]")

    # Summary table
    if real_results:
        summary = Table(title="Benchmark Summary")
        summary.add_column("Metric")
        summary.add_column("Variant")
        summary.add_column("Median (ms)", justify="right")
        summary.add_column("IQR (ms)", justify="right")
        summary.add_column("P95 (ms)", justify="right")
        summary.add_column("P99 (ms)", justify="right")
        summary.add_column("N", justify="right")

        for r in real_results:
            s = r.stats()
            summary.add_row(
                r.metric, r.variant,
                f"{s['median']:.4f}", f"{s['iqr']:.4f}",
                f"{s['p95']:.4f}", f"{s['p99']:.4f}",
                str(s["n"]),
            )
        console.print()
        console.print(summary)

    # Variant comparisons
    if compare and real_results:
        # Group by metric stem for pairwise comparison
        groups: dict[str, list[BenchResult]] = {}
        for r in real_results:
            groups.setdefault(r.metric, []).append(r)

        for metric_name, group in groups.items():
            if len(group) < 2:
                continue
            t = Table(title=f"Variant comparison: {metric_name}")
            t.add_column("A")
            t.add_column("B")
            t.add_column("U-stat", justify="right")
            t.add_column("p-value", justify="right")
            t.add_column("Significant")
            t.add_column("Cliff's delta", justify="right")
            t.add_column("Magnitude")

            for a, b in combinations(group, 2):
                cmp = compare_variants(a, b)
                t.add_row(
                    a.variant, b.variant,
                    f"{cmp['u_stat']:.0f}",
                    f"{cmp['p_value']:.6f}",
                    "yes" if cmp["significant"] else "no",
                    f"{cmp['cliffs_delta']:.4f}",
                    cmp["cliffs_magnitude"],
                )
            console.print(t)


if __name__ == "__main__":
    app()
