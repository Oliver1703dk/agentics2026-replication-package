"""Shared pytest fixtures for the NostrAgent test suite.

Scope decisions:
- Keypairs, scopes, trust policies: function-scoped (cheap, deterministic, no state leak).
- Relay URLs and LND config: session-scoped (constant strings, no I/O).
- Async Client: function-scoped (each test gets a clean connection; avoids cross-test
  subscription bleed). Module-scope would risk relay-side state accumulation.
- Docker check: session-scoped (one subprocess call, gate all integration tests).
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import subprocess
from collections.abc import AsyncGenerator
from dataclasses import dataclass

import pytest

try:
    import nostr_sdk as ns
    from nostr_agent.events import bootstrap
    from nostr_agent.scope import DelegationScope
    from nostr_agent.types import Constraints, RelayUrl, Scope, TrustPolicy
    _NOSTR_AGENT_AVAILABLE = True
except ImportError:
    _NOSTR_AGENT_AVAILABLE = False
    ns = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RANDOM_SEED = 42


@pytest.fixture(autouse=True)
def _seed_rng():
    """Reset random seed before every test for deterministic behaviour."""
    random.seed(RANDOM_SEED)


_RELAY_PORTS = (7771, 7772, 7773)
_LND_ALICE_GRPC = "localhost:10009"
_LND_BOB_GRPC = "localhost:10010"


# ---------------------------------------------------------------------------
# Deterministic key factory (replaces Keys.generate() throughout tests)
# ---------------------------------------------------------------------------

_DETERMINISTIC_KEY_COUNTER = 0


def deterministic_keys() -> "ns.Keys":
    """Return a deterministic keypair using an incrementing counter + SHA256.

    Each call produces a unique but reproducible key (counter resets per test
    via the autouse _seed_rng fixture resetting random.seed, but the counter
    itself is module-global -- callers should use the ``det_keys`` fixture for
    per-test isolation, or call this directly when fixture injection is awkward).
    """
    global _DETERMINISTIC_KEY_COUNTER
    _DETERMINISTIC_KEY_COUNTER += 1
    seed_bytes = hashlib.sha256(
        f"deterministic-test-key-{_DETERMINISTIC_KEY_COUNTER}".encode()
    ).hexdigest()
    return ns.Keys.parse(seed_bytes)


@pytest.fixture(autouse=True)
def _reset_key_counter():
    """Reset deterministic key counter before each test for reproducibility."""
    global _DETERMINISTIC_KEY_COUNTER
    _DETERMINISTIC_KEY_COUNTER = 0


@pytest.fixture()
def det_keys():
    """Fixture returning the deterministic_keys factory function.

    Usage: ``keys = det_keys()`` -- each call returns the next deterministic keypair.
    """
    return deterministic_keys


# Fixed 32-byte seeds for deterministic key derivation (not real secret keys --
# we use these seeds to produce stable hex strings for test identifiers
# and synthetic pubkeys only).
_SEED_OPERATOR = b"\x01" * 32
_SEED_AGENT_A = b"\x02" * 32
_SEED_AGENT_B = b"\x03" * 32
_SEED_AGENT_C = b"\x04" * 32


# ---------------------------------------------------------------------------
# Helper: deterministic hex pubkey-like string from seed (test IDs only)
# ---------------------------------------------------------------------------

def _seed_hex(seed: bytes) -> str:
    """SHA256 of seed as a stable 64-char hex string for test pubkey references."""
    return hashlib.sha256(seed).hexdigest()


# ---------------------------------------------------------------------------
# Docker availability (session-scoped; skips integration tests when absent)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def docker_available() -> bool:
    """Return True if Docker daemon is reachable; session-scoped single check."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


@pytest.fixture(scope="session", autouse=False)
def require_docker(docker_available: bool) -> None:
    """Skip the test if Docker is not running. Apply with @pytest.mark.usefixtures."""
    if not docker_available:
        pytest.skip("Docker not running -- integration test skipped")


@pytest.fixture(scope="session")
def relays_available() -> bool:
    """Return True iff all three strfry relays are reachable at their host ports.

    Checks raw TCP reachability at localhost:_RELAY_PORTS. This is a stricter
    gate than ``docker_available``: it catches the case where the Docker
    daemon is running but the strfry stack from infra/docker-compose.yml has
    not been brought up. Session-scoped single check.
    """
    import socket
    for port in _RELAY_PORTS:
        try:
            with socket.create_connection(("localhost", port), timeout=2):
                pass
        except OSError:
            return False
    return True


@pytest.fixture(scope="session", autouse=False)
def require_relays(relays_available: bool) -> None:
    """Skip the test if the strfry relay stack is not reachable.

    Apply with ``@pytest.mark.usefixtures("require_relays")`` on any test
    that needs an actual relay connection. Produces a clearer skip message
    than the underlying nostr-sdk TypeError that surfaces when relays are
    unreachable.
    """
    if not relays_available:
        pytest.skip(
            "Strfry relays not reachable at localhost:7771-7773. "
            "Bring up the stack: cd code && docker compose -f infra/docker-compose.yml up -d "
            "&& bash infra/scripts/bootstrap.sh"
        )


# ---------------------------------------------------------------------------
# Keypair fixtures -- function-scoped, deterministic via fixed generate() calls
# ---------------------------------------------------------------------------

@pytest.fixture()
def operator_keys() -> ns.Keys:
    """Deterministic operator keypair (seed 0x01*32 → fixed nsec via parse)."""
    # nostr-sdk 0.44.2 does not expose Keys.from_seed(); we use parse(hex_seckey).
    return ns.Keys.parse(_seed_hex(_SEED_OPERATOR))


@pytest.fixture()
def agent_a_keys() -> ns.Keys:
    return ns.Keys.parse(_seed_hex(_SEED_AGENT_A))


@pytest.fixture()
def agent_b_keys() -> ns.Keys:
    return ns.Keys.parse(_seed_hex(_SEED_AGENT_B))


@pytest.fixture()
def agent_c_keys() -> ns.Keys:
    return ns.Keys.parse(_seed_hex(_SEED_AGENT_C))


# ---------------------------------------------------------------------------
# Relay URL fixtures -- session-scoped (pure strings)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def relay_urls() -> list[RelayUrl]:
    return [RelayUrl(f"ws://localhost:{p}") for p in _RELAY_PORTS]


@pytest.fixture(scope="session")
def relay_url_1() -> RelayUrl:
    return RelayUrl(f"ws://localhost:{_RELAY_PORTS[0]}")


@pytest.fixture(scope="session")
def relay_url_2() -> RelayUrl:
    return RelayUrl(f"ws://localhost:{_RELAY_PORTS[1]}")


@pytest.fixture(scope="session")
def relay_url_3() -> RelayUrl:
    return RelayUrl(f"ws://localhost:{_RELAY_PORTS[2]}")


# ---------------------------------------------------------------------------
# LND connection config fixtures -- session-scoped
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LNDConfig:
    host: str
    grpc_port: int
    rest_port: int
    macaroon_path: str  # path relative to Docker volume; resolved by lnd_grpc helpers
    tls_cert_path: str

    @property
    def grpc_address(self) -> str:
        return f"{self.host}:{self.grpc_port}"


@pytest.fixture(scope="session")
def lnd_alice() -> LNDConfig:
    return LNDConfig(
        host="localhost",
        grpc_port=10009,
        rest_port=8080,
        macaroon_path="/tmp/lnd-alice/admin.macaroon",
        tls_cert_path="/tmp/lnd-alice/tls.cert",
    )


@pytest.fixture(scope="session")
def lnd_bob() -> LNDConfig:
    return LNDConfig(
        host="localhost",
        grpc_port=10010,
        rest_port=8081,
        macaroon_path="/tmp/lnd-bob/admin.macaroon",
        tls_cert_path="/tmp/lnd-bob/tls.cert",
    )


# ---------------------------------------------------------------------------
# Scope / Constraints / TrustPolicy fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def scope_read_only() -> DelegationScope:
    """Narrowest useful scope: read access to a single relay resource."""
    return DelegationScope.create(
        capabilities=["relay-read"],
        resources=["wss://relay.example.com"],
        actions=["read"],
    )


@pytest.fixture()
def scope_read_write() -> DelegationScope:
    """Broader scope that scope_read_only correctly attenuates."""
    return DelegationScope.create(
        capabilities=["relay-read", "relay-write"],
        resources=["wss://relay.example.com"],
        actions=["read", "write"],
    )


@pytest.fixture()
def scope_unrestricted() -> DelegationScope:
    """Root scope: all capabilities, unrestricted resources and actions."""
    return DelegationScope.create(
        capabilities=["relay-read", "relay-write", "l402-pay"],
    )


# ---------------------------------------------------------------------------
# Scope fixtures (types.py Scope -- used by unit tests for types module)
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_scope() -> Scope:
    """Scope with single capability, no resources, one action."""
    return Scope(capabilities=("weather-forecast",), resources=(), actions=("read",))


@pytest.fixture()
def sample_scope_broad() -> Scope:
    """Broader scope that sample_scope correctly attenuates."""
    return Scope(
        capabilities=("data-aggregation", "weather-forecast"),
        resources=(),
        actions=("read", "write"),
    )


@pytest.fixture()
def sample_constraints() -> Constraints:
    """Sample Constraints with 24h expiry, depth 3, depth 1."""
    import time as _t
    now = int(_t.time())
    return Constraints(
        expires_at=now + 86400,
        max_chain_depth=3,
        current_depth=1,
        issued_at=now,
    )


@pytest.fixture()
def sample_trust_policy() -> TrustPolicy:
    """Default TrustPolicy (noisy-OR: decay 0.5, max_depth 4, epsilon 0.01)."""
    return TrustPolicy()


@pytest.fixture()
def trust_policy_defaults() -> dict[str, float | int]:
    """Default TrustPolicy parameters (noisy-OR: decay 0.5, max_depth 4, epsilon 0.01)."""
    return {"decay": 0.5, "max_depth": 4, "epsilon": 0.01}


@pytest.fixture()
def trust_policy_strict() -> dict[str, float | int]:
    """Strict policy for adversarial tests: low decay, shallow depth."""
    return {"decay": 0.2, "max_depth": 2, "epsilon": 0.05}


# ---------------------------------------------------------------------------
# Async Client fixture -- function-scoped with cleanup
# ---------------------------------------------------------------------------

@pytest.fixture()
async def nostr_client(relay_urls: list[RelayUrl]) -> AsyncGenerator[ns.Client, None]:
    """Connected ns.Client; disconnects on teardown. Function-scoped to avoid
    cross-test subscription bleed and relay-side state accumulation."""
    loop = asyncio.get_event_loop()
    bootstrap(loop)

    client = ns.Client()
    for url in relay_urls:
        await client.add_relay(url)
    await client.connect()

    yield client

    await client.disconnect()


@pytest.fixture()
async def nostr_client_signed(
    operator_keys: ns.Keys,
    relay_urls: list[RelayUrl],
) -> AsyncGenerator[ns.Client, None]:
    """Connected ns.Client with operator signer; function-scoped."""
    loop = asyncio.get_event_loop()
    bootstrap(loop)

    signer = ns.NostrSigner.keys(operator_keys)
    client = ns.Client(signer)
    for url in relay_urls:
        await client.add_relay(url)
    await client.connect()

    yield client

    await client.disconnect()


# ---------------------------------------------------------------------------
# Event factory fixtures -- Kind 38100 / 38101 / 38102
# ---------------------------------------------------------------------------

@pytest.fixture()
def make_kind_38100(operator_keys: ns.Keys, relay_url_1: RelayUrl):
    """Factory: returns a signed Kind 38100 event. Accepts keyword overrides."""
    from nostr_agent.events import build_and_sign, make_tags_38100

    def _factory(
        agent_id: str = "test-agent-001",
        next_key_hash: str = "a" * 64,
        relay_url: str | None = None,
        keys: ns.Keys | None = None,
    ) -> ns.Event:
        _keys = keys or operator_keys
        tags = make_tags_38100(
            agent_id=agent_id,
            operator_pubkey=_keys.public_key(),
            relay_url=relay_url or relay_url_1,
            schema_version="1",
            next_key_hash=next_key_hash,
        )
        return build_and_sign(
            kind=38100,
            content_dict={"name": agent_id, "version": "0.1.0"},
            tags=tags,
            keys=_keys,
        )

    return _factory


@pytest.fixture()
def make_kind_38101(operator_keys: ns.Keys, agent_a_keys: ns.Keys):
    """Factory: returns a signed Kind 38101 delegation event."""
    from nostr_agent.events import build_and_sign, make_tags_38101

    def _factory(
        delegation_id: str = "test-delegation-001",
        delegator_keys: ns.Keys | None = None,
        delegatee_keys: ns.Keys | None = None,
        scopes: list[str] | None = None,
    ) -> ns.Event:
        _delegator = delegator_keys or operator_keys
        _delegatee = delegatee_keys or agent_a_keys
        tags = make_tags_38101(
            delegation_id=delegation_id,
            delegator_pubkey=_delegator.public_key(),
            delegatee_pubkey=_delegatee.public_key(),
            scopes=scopes or ["relay-read:wss://relay.example.com"],
        )
        return build_and_sign(
            kind=38101,
            content_dict={},
            tags=tags,
            keys=_delegator,
        )

    return _factory


@pytest.fixture()
def make_kind_38102(operator_keys: ns.Keys, agent_a_keys: ns.Keys):
    """Factory: returns a signed Kind 38102 peer attestation event."""
    from nostr_agent.events import build_and_sign, make_tags_38102

    def _factory(
        attestation_id: str = "test-attestation-001",
        attester_keys: ns.Keys | None = None,
        subject_keys: ns.Keys | None = None,
        trust_score: float = 0.8,
    ) -> ns.Event:
        _attester = attester_keys or operator_keys
        _subject = subject_keys or agent_a_keys
        tags = make_tags_38102(
            attestation_id=attestation_id,
            attester_pubkey=_attester.public_key(),
            subject_pubkey=_subject.public_key(),
            trust_score=trust_score,
        )
        return build_and_sign(
            kind=38102,
            content_dict={"confidence": trust_score},
            tags=tags,
            keys=_attester,
        )

    return _factory
