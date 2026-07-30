"""Integration test fixtures -- Docker health checks, credential loading, key factories.

Session-scoped ``docker_env`` fixture gates all integration tests: if Docker
containers are not running, relays are not reachable, or LND gRPC is down,
every test in this directory is skipped with a clear message.

Credential paths follow the extraction layout from
``code/src/nostr_agent/lnd_grpc/credentials.py``: certs/ directory relative to
the code/ root, with files named ``lnd-{node}-admin.macaroon`` and
``lnd-{node}-tls.cert``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

try:
    import nostr_sdk as ns
    import websockets

    _DEPS_AVAILABLE = True
except ImportError:
    _DEPS_AVAILABLE = False
    ns = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RELAY_PORTS = (7771, 7772, 7773)
_RELAY_URLS = [f"ws://localhost:{p}" for p in _RELAY_PORTS]

# Expected Docker container name prefixes (from docker-compose.yml).
_EXPECTED_CONTAINERS = [
    "nostragent-bitcoind",
    "nostragent-lnd-alice",
    "nostragent-lnd-bob",
]
# Relay containers may be named relay-1, relay-2, relay-3 or similar.

# Paths relative to code/ directory.
_CODE_DIR = Path(__file__).resolve().parent.parent.parent  # code/
_CREDS_DIR = _CODE_DIR / "infra" / "credentials"


# ---------------------------------------------------------------------------
# LND config dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LNDConfig:
    """LND node connection configuration."""

    host: str
    grpc_port: int
    rest_port: int
    macaroon_path: str
    tls_cert_path: str

    @property
    def grpc_address(self) -> str:
        return f"{self.host}:{self.grpc_port}"


# ---------------------------------------------------------------------------
# Docker availability helpers
# ---------------------------------------------------------------------------

def _docker_daemon_running() -> bool:
    """Check if Docker daemon is reachable."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _containers_up() -> tuple[bool, str]:
    """Check if expected Docker containers are running.

    Returns (ok, detail_message).
    """
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(_CODE_DIR / "infra" / "docker-compose.yml"), "ps", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return False, f"docker compose ps failed: {result.stderr}"

        # Parse container names from JSON output.
        # docker compose ps --format json may return a JSON array or JSON lines.
        running_names: set[str] = set()
        raw = result.stdout.strip()
        try:
            parsed = json.loads(raw)
            items = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            # Fall back to JSON lines
            items = []
            for line in raw.splitlines():
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        for data in items:
            if isinstance(data, dict):
                name = data.get("Name", "")
                state = data.get("State", "")
                if state == "running" and name:
                    running_names.add(name)

        missing = [c for c in _EXPECTED_CONTAINERS if c not in running_names]
        if missing:
            return False, f"Missing containers: {missing}"
        return True, "All expected containers running"

    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, f"docker compose check failed: {e}"


async def _relay_reachable(url: str, timeout: float = 3.0) -> bool:
    """Check if a relay is reachable via WebSocket."""
    try:
        async with websockets.connect(url, close_timeout=timeout, open_timeout=timeout):
            return True
    except Exception:
        return False


async def _lnd_grpc_reachable(config: LNDConfig) -> bool:
    """Check if LND gRPC is reachable via sync GetInfo call."""
    try:
        import grpc
        import os
        os.environ.setdefault("GRPC_SSL_CIPHER_SUITES", "HIGH+ECDSA")

        tls_cert = Path(config.tls_cert_path).read_bytes()
        macaroon_hex = Path(config.macaroon_path).read_bytes().hex()

        creds = grpc.ssl_channel_credentials(tls_cert)
        channel = grpc.secure_channel(f"{config.host}:{config.grpc_port}", creds)

        from nostr_agent.lnd_grpc import lightning_pb2, lightning_pb2_grpc
        stub = lightning_pb2_grpc.LightningStub(channel)
        info = stub.GetInfo(
            lightning_pb2.GetInfoRequest(),
            metadata=[("macaroon", macaroon_hex)],
        )
        channel.close()
        return bool(info.identity_pubkey)
    except Exception:
        return False


async def _full_docker_check() -> tuple[bool, str]:
    """Run all Docker health checks. Returns (available, reason)."""
    if not _DEPS_AVAILABLE:
        return False, "nostr_sdk or websockets not importable"

    if not _docker_daemon_running():
        return False, "Docker daemon not running"

    containers_ok, containers_msg = _containers_up()
    if not containers_ok:
        return False, containers_msg

    # Check at least relay-1 is reachable.
    if not await _relay_reachable(_RELAY_URLS[0]):
        return False, f"Relay {_RELAY_URLS[0]} not reachable via WebSocket"

    # Check LND credentials exist.
    alice_cfg = _build_lnd_config("alice")
    bob_cfg = _build_lnd_config("bob")

    if not Path(alice_cfg.macaroon_path).exists():
        return False, f"Alice macaroon not found at {alice_cfg.macaroon_path}"
    if not Path(bob_cfg.macaroon_path).exists():
        return False, f"Bob macaroon not found at {bob_cfg.macaroon_path}"

    # Check LND gRPC for alice.
    if not await _lnd_grpc_reachable(alice_cfg):
        return False, "LND alice gRPC not reachable"

    return True, "Docker infrastructure available"


def _build_lnd_config(node: str) -> LNDConfig:
    """Build LND config for a node (alice or bob)."""
    grpc_port = 10009 if node == "alice" else 10010
    rest_port = 8080 if node == "alice" else 8081
    return LNDConfig(
        host="localhost",
        grpc_port=grpc_port,
        rest_port=rest_port,
        macaroon_path=str(_CREDS_DIR / node / "admin.macaroon"),
        tls_cert_path=str(_CREDS_DIR / node / "tls.cert"),
    )


# ---------------------------------------------------------------------------
# Session-scoped: Docker environment gate
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def docker_env():
    """Gate fixture: skip all integration tests if Docker infrastructure unavailable.

    Checks: Docker daemon, container status, relay WebSocket, LND gRPC.
    """
    loop = asyncio.new_event_loop()
    try:
        available, reason = loop.run_until_complete(_full_docker_check())
    finally:
        loop.close()

    if not available:
        pytest.skip(f"Docker infrastructure unavailable: {reason}")

    return True


# ---------------------------------------------------------------------------
# Relay URL fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def relay_urls() -> list[str]:
    """All 3 relay WebSocket URLs."""
    return list(_RELAY_URLS)


@pytest.fixture(scope="session")
def relay_url_1() -> str:
    return _RELAY_URLS[0]


@pytest.fixture(scope="session")
def relay_url_2() -> str:
    return _RELAY_URLS[1]


@pytest.fixture(scope="session")
def relay_url_3() -> str:
    return _RELAY_URLS[2]


# ---------------------------------------------------------------------------
# LND configuration fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def lnd_alice_config() -> LNDConfig:
    """Alice's LND connection config (agent node, port 10009)."""
    return _build_lnd_config("alice")


@pytest.fixture(scope="session")
def lnd_bob_config() -> LNDConfig:
    """Bob's LND connection config (service node, port 10010)."""
    return _build_lnd_config("bob")


# ---------------------------------------------------------------------------
# Keypair fixtures -- deterministic operator, factory for fresh agent keys
# ---------------------------------------------------------------------------

_OPERATOR_SEED = hashlib.sha256(b"nostragent-integration-operator-seed").hexdigest()


@pytest.fixture(scope="session")
def operator_keys() -> ns.Keys:
    """Deterministic operator keypair (stable across test runs)."""
    return ns.Keys.parse(_OPERATOR_SEED)


_FRESH_KEY_CTR = 0


@pytest.fixture()
def fresh_agent_keys():
    """Factory fixture: each call returns a deterministic agent keypair.

    Usage: ``keys = fresh_agent_keys()``
    """
    def _factory() -> ns.Keys:
        global _FRESH_KEY_CTR
        _FRESH_KEY_CTR += 1
        seed = hashlib.sha256(f"det-fresh-{_FRESH_KEY_CTR}".encode()).hexdigest()
        return ns.Keys.parse(seed)

    return _factory


@pytest.fixture()
def unique_d_tag(request):
    """Factory fixture: returns a d-tag incorporating the test name for isolation.

    Usage: ``d_tag = unique_d_tag("my-suffix")``
    """
    test_name = request.node.name.replace("[", "-").replace("]", "")

    def _factory(suffix: str = "") -> str:
        ts = int(time.time() * 1000) % 1_000_000
        base = f"t-{test_name}-{ts}"
        if suffix:
            base = f"{base}-{suffix}"
        # Ensure d-tag validity: lowercase, allowed chars, 2-128 chars.
        tag = base[:128].lower().replace("_", "-")
        # Strip any leading/trailing hyphens to satisfy regex anchors.
        tag = tag.strip("-")
        # Ensure at least 2 chars.
        if len(tag) < 2:
            tag = f"d-{tag}0"
        return tag

    return _factory


# ---------------------------------------------------------------------------
# Nostr event loop bootstrap -- session scoped
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def _bootstrap_nostr_event_loop():
    """Ensure nostr_sdk event loop is bootstrapped for async operations."""
    # nostr_sdk requires uniffi_set_event_loop before any async operation.
    # Each async test function will call it with the running loop,
    # but we import here to fail fast if the package is unavailable.
    if not _DEPS_AVAILABLE:
        pytest.skip("nostr_sdk not available")
