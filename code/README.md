# NostrAgent: Reference Implementation

A Python prototype implementing the NostrAgent decentralized identity and delegation architecture for operator-sovereign agentic systems. Built entirely on Bitcoin-native cryptographic primitives, the architecture provides self-certifying agent identity via BIP340 Schnorr signatures, scoped delegation chains with cryptographic attenuation, federated relay-based discovery, emergent trust through signed peer attestations, and Lightning L402 for unified identity-authorization-payment flows. This prototype covers all five architectural components and serves as the empirical basis for the evaluation reported in the accompanying paper.

## Prerequisites

| Dependency | Version | Notes |
|---|---|---|
| Docker + Docker Compose v2 | Latest stable | Required for relay and Lightning infrastructure |
| Python | 3.11+ | Tested with 3.11.15 |
| `uv` | Latest stable | Astral's Python package manager |
| macOS or Linux | - | Tested on macOS ARM64 (Apple Silicon) |

Verify prerequisites:

```bash
docker --version          # Docker version 27.x+
docker compose version    # Docker Compose version v2.x+
python3 --version         # Python 3.11+
uv --version              # uv 0.6+
```

## Quick Start

From the `code/` directory:

```bash
# 1. Install dependencies
uv sync --python 3.11 --extra dev

# 2. Start Docker infrastructure (3 strfry relays, 2 LND nodes, 1 bitcoind)
docker compose -f infra/docker-compose.yml up -d

# 3. Wait for services to be healthy (bitcoind and LND need chain sync time)
sleep 30

# 4. Create Bitcoin wallet (required for Bitcoin Core v27+)
docker exec nostragent-bitcoind bitcoin-cli -regtest -rpcuser=nostr -rpcpassword=nostr createwallet "default"

# 5. Bootstrap regtest: mine blocks, fund wallets, open Lightning channel
bash infra/scripts/bootstrap.sh

# 6. Verify relays accept custom event kinds
uv run python infra/verify_relays.py

# 7. Run all tests (438 collected items across 5 layers: 254 unit + 51 property + 57 adversarial + 31 integration + 45 top-level integration)
uv run pytest tests/unit/ -v --tb=short
uv run pytest tests/property/ -v --tb=short
uv run pytest tests/adversarial/ -v --tb=short
uv run pytest tests/integration/ -v --tb=short
uv run pytest tests/test_*.py -v --tb=short

# 8. Run benchmarks (B1-B11, 1000 iterations each)
uv run python -m eval.bench --all

# 9. Run 8-step demo (5 agents, full architecture exercise)
uv run python -m nostr_agent.deploy_5agent

# 10. Capture environment metadata
uv run python -c "from eval.env_metadata import save_metadata; save_metadata('eval/results/environment.json')"
```

Or run everything with a single command:

```bash
chmod +x reproduce.sh
./reproduce.sh
```

### Expected Output per Step

| Step | Expected Output |
|---|---|
| 1. Install | Resolves and installs all dependencies into `.venv/` |
| 2. Docker up | 6 containers start: `nostragent-bitcoind`, `nostragent-lnd-alice`, `nostragent-lnd-bob`, `nostragent-relay-1`, `nostragent-relay-2`, `nostragent-relay-3` |
| 3. Wait | Services reach healthy state |
| 4. Create wallet | `"name": "default"` JSON response (or error if wallet already exists -- safe to ignore) |
| 5. Bootstrap | Mines 101+ blocks, funds Alice with 1 BTC, opens 1M sat channel with 500K push to Bob, extracts LND credentials |
| 6. Verify relays | `9/9 passed` -- each of 3 relays accepts kinds 38100, 38101, 38102 |
| 7. Tests | 438 collected items pass across 5 test layers (unit, property, adversarial, integration, top-level integration); adversarial test functions are parametrized, expanding to additional items |
| 8. Benchmarks | CSV files written to `eval/results/` with sub-millisecond timings, statistics table printed |
| 9. Demo | 8-step demo completes: identity creation, delegation chains, peer attestations, trust computation, L402 flow, spoofing rejection, revocation cascade, key rotation |
| 10. Metadata | `eval/results/environment.json` written with Python version, platform, library versions, seed |

## Project Structure

```
code/
├── pyproject.toml                     # Project definition, dependencies, tool config
├── reproduce.sh                       # One-command reproduction script
├── README.md                          # This file
├── src/
│   └── nostr_agent/
│       ├── __init__.py                # Package exports
│       ├── identity.py                # AgentIdentity -- Kind 38100 lifecycle
│       ├── delegation.py              # DelegationManager -- Kind 38101, chain validation
│       ├── discovery.py               # RelayDiscovery -- federated relay-based resolution
│       ├── trust.py                   # TrustManager -- Kind 38102, noisy-OR aggregation
│       ├── l402.py                    # L402Client, L402Verifier -- Lightning payment flow
│       ├── types.py                   # Data classes, exceptions, core types
│       ├── crypto.py                  # BIP340 helpers (SHA256, sign, verify wrappers)
│       ├── validation.py              # Shared validation (tag regex, content size)
│       ├── scope.py                   # DelegationScope -- attenuation logic
│       ├── events.py                  # Event builders for kinds 38100-38102
│       ├── event_builders.py          # Low-level Nostr event construction
│       ├── key_rotation.py            # Pre-rotation protocol (SHA256 commitment of next pubkey)
│       ├── relay_consistency.py       # Multi-relay consistency checks
│       ├── dtag_generation.py         # Deterministic d-tag derivation
│       ├── cli.py                     # Typer CLI entry point
│       ├── deploy_5agent.py           # 5-agent demo deployment
│       ├── l402_test_server.py        # Mock L402 server for testing
│       └── lnd_grpc/                  # LND gRPC stubs and credential helpers
│           ├── __init__.py
│           ├── credentials.py
│           ├── lightning_pb2.py
│           ├── lightning_pb2_grpc.py
│           ├── router_pb2.py
│           └── router_pb2_grpc.py
├── tests/
│   ├── conftest.py                    # Shared fixtures (keypairs, relay URLs, Docker check)
│   ├── unit/                          # 254 fast tests, no Docker required
│   │   ├── test_crypto.py
│   │   ├── test_discovery.py
│   │   ├── test_types.py
│   │   └── test_validation.py
│   ├── property/                      # 51 Hypothesis property-based tests
│   │   ├── strategies.py
│   │   ├── test_attenuation_invariants.py
│   │   ├── test_key_rotation_invariants.py
│   │   └── test_trust_bounds.py
│   ├── adversarial/                   # 57 STRIDE adversarial tests
│   │   ├── conftest.py
│   │   ├── test_clock_skew_fm10.py
│   │   ├── test_replay.py
│   │   ├── test_scope_escalation.py
│   │   ├── test_spoofing.py
│   │   ├── test_sybil.py
│   │   └── test_tampering.py
│   ├── integration/                   # 31 end-to-end tests (require Docker)
│   │   ├── conftest.py
│   │   ├── test_delegation_chain_e2e.py
│   │   ├── test_identity_lifecycle.py
│   │   ├── test_l402_flow_e2e.py
│   │   └── test_trust_graph_e2e.py
│   ├── test_dtag_generation.py        # Top-level integration tests (45 total across these 4 files)
│   ├── test_lnd_grpc_integration.py
│   ├── test_strfry_relay.py
│   └── test_stride_adversarial.py
├── eval/
│   ├── __init__.py
│   ├── __main__.py                    # Entry point for `python -m eval`
│   ├── bench.py                       # B1-B11 benchmark harness
│   ├── benchmark_config.py            # 1000 runs, 100 warmup, seed=42
│   ├── env_metadata.py                # Environment capture for reproducibility
│   ├── stats.py                       # Mann-Whitney U, Cliff's delta
│   ├── synthetic_graphs.py            # Graph generators for B6 trust benchmarks
│   └── results/                       # CSV outputs (gitignored in production)
│       ├── B1_kind_38100.csv
│       ├── B2_kind_*.csv
│       ├── B3_depth_*.csv
│       ├── B6_nodes_*.csv
│       ├── B10_caveats_*.csv
│       ├── B11_full_5check.csv
│       └── environment.json
└── infra/
    ├── docker-compose.yml             # 6 containers: bitcoind, 2x LND, 3x strfry
    ├── verify_relays.py               # 9-check relay verification
    ├── compile_lnd_protos.sh          # Download and compile LND gRPC protos
    ├── bootstrap_lnd_credentials.sh   # Extract LND creds from Docker
    ├── scripts/
    │   └── bootstrap.sh               # Full regtest bootstrap (mine, fund, channel)
    ├── config/
    │   ├── bitcoin.conf
    │   ├── lnd-alice.conf
    │   └── lnd-bob.conf
    │   └── strfry.conf
    └── credentials/                   # Extracted LND macaroons/certs (gitignored)
        ├── alice/
        │   ├── admin.macaroon
        │   └── tls.cert
        └── bob/
            ├── admin.macaroon
            └── tls.cert
```

## Running Individual Components

All commands run from the `code/` directory and use `uv run` to ensure the correct virtual environment.

### Tests

```bash
# Unit tests (fast, no Docker required)
uv run pytest tests/unit/ -v

# Property-based tests (Hypothesis, no Docker required)
uv run pytest tests/property/ -v

# Adversarial tests (STRIDE threat procedures, no Docker required)
uv run pytest tests/adversarial/ -v

# Integration tests (require Docker infrastructure running)
uv run pytest tests/integration/ -v

# All tests at once
uv run pytest tests/ -v

# Specific test file
uv run pytest tests/unit/test_crypto.py -v

# Run with marker filter
uv run pytest -m "unit" -v
uv run pytest -m "property" -v
uv run pytest -m "adversarial" -v
uv run pytest -m "integration" -v
```

### Benchmarks

```bash
# All benchmarks (B1-B11)
uv run python -m eval.bench --all

# Specific metrics
uv run python -m eval.bench --metrics B1,B2,B6

# Custom run count
uv run python -m eval.bench --metrics B6 --runs 500 --warmup 50
```

### Demo

```bash
# 5-agent demo (8 steps: identity, delegation, attestation, trust, L402)
uv run python -m nostr_agent.deploy_5agent

# With relay publishing (requires Docker relays running)
uv run python -m nostr_agent.deploy_5agent --relay ws://localhost:7771

# With pause between steps (seconds)
uv run python -m nostr_agent.deploy_5agent --pause 2
```

### CLI

```bash
# Help
uv run nostr-agent --help

# Identity commands
uv run nostr-agent identity --help

# Delegation commands
uv run nostr-agent delegation --help

# Trust commands
uv run nostr-agent trust --help
```

## Benchmark Results

Benchmarks produce CSV files in `eval/results/` with the following schema:

| Column | Type | Description |
|---|---|---|
| `run_id` | int | Sequential within effective runs (0-899) |
| `metric` | str | Benchmark ID (e.g., `B1`, `B3_depth_2`) |
| `value_ms` | float | Measurement in milliseconds |
| `timestamp` | str | ISO 8601 UTC timestamp |
| `variant` | str | Parameter variant (e.g., `kind_38100`, `depth=3`, `nodes_50`) |

### Benchmark descriptions

| Metric | Description |
|---|---|
| B1 | Kind 38100 identity event creation |
| B2 | Event signature verification (kinds 38100, 38101, 38102) |
| B3 | Delegation chain validation by depth (1-4) |
| B5 | Kind 38102 peer attestation creation |
| B6 | Trust graph computation by graph size (5-500 nodes) |
| B10 | L402 macaroon verification by caveat count (1-20) |
| B11 | Full 5-agent check (identity + delegation + attestation + trust + L402) |

### Statistics

Each benchmark run reports: median, IQR (Q3-Q1), P95, P99, mean, and standard deviation. Variant comparisons use Mann-Whitney U test with Cliff's delta effect size (alpha=0.05).

### Interpreting results

- All crypto operations (B1, B2, B5) should complete in sub-millisecond time
- Delegation chain validation (B3) scales linearly with depth
- Trust computation (B6) scales with graph size (noisy-OR aggregation)
- L402 verification (B10) scales linearly with caveat count
- Timing measurements are inherently non-deterministic; crypto operations and ordering are deterministic with seed=42

## Docker Infrastructure

### Start

```bash
docker compose -f infra/docker-compose.yml up -d
```

This starts 6 containers:

| Container | Service | Host Port | Purpose |
|---|---|---|---|
| `nostragent-bitcoind` | Bitcoin Core v27 (regtest) | 18443 | Regtest RPC |
| `nostragent-lnd-alice` | LND v0.18.4-beta | 10009 (gRPC), 8080 (REST) | Agent Lightning node |
| `nostragent-lnd-bob` | LND v0.18.4-beta | 10010 (gRPC), 8081 (REST) | Service Lightning node |
| `nostragent-relay-1` | strfry | 7771 | Nostr relay |
| `nostragent-relay-2` | strfry | 7772 | Nostr relay |
| `nostragent-relay-3` | strfry | 7773 | Nostr relay |

### Verify health

```bash
# Check all containers are running and healthy
docker compose -f infra/docker-compose.yml ps

# Verify relays accept custom event kinds (9 checks)
uv run python infra/verify_relays.py
```

### Stop

```bash
# Stop containers (preserves volumes)
docker compose -f infra/docker-compose.yml down

# Stop and remove volumes (full reset)
docker compose -f infra/docker-compose.yml down -v
```

### Re-bootstrap after reset

After `down -v`, you need to re-bootstrap the Lightning network:

```bash
docker compose -f infra/docker-compose.yml up -d
sleep 30
docker exec nostragent-bitcoind bitcoin-cli -regtest -rpcuser=nostr -rpcpassword=nostr createwallet "default"
bash infra/scripts/bootstrap.sh
```

## Troubleshooting

### Bitcoin Core v27 wallet error

**Symptom:** `bootstrap.sh` fails with `No wallet is loaded` or `Method not found`.

**Cause:** Bitcoin Core v27+ requires explicit wallet creation; it no longer auto-creates a default wallet.

**Fix:** Create the wallet before running bootstrap:
```bash
docker exec nostragent-bitcoind bitcoin-cli -regtest -rpcuser=nostr -rpcpassword=nostr createwallet "default"
```

If the wallet already exists, this will return an error like `Database already exists` -- this is safe to ignore.

### RelayUrl.parse error

**Symptom:** `TypeError` or `AttributeError` mentioning `RelayUrl.parse` in test fixtures.

**Cause:** `nostr-sdk` 0.44.2 changed how `RelayUrl` is constructed. It uses the constructor directly, not a `.parse()` class method.

**Fix:** Ensure you are using `nostr-sdk==0.44.2` exactly:
```bash
uv sync --python 3.11 --extra dev
```

### LND sync timing

**Symptom:** `bootstrap.sh` fails with `lnd-alice not ready` or `lnd-bob not ready`.

**Cause:** LND needs time to sync with bitcoind. On first start this can take 30-60 seconds.

**Fix:** Wait longer before running bootstrap:
```bash
sleep 60
bash infra/scripts/bootstrap.sh
```

The bootstrap script has its own retry loops (up to 120s per node), but if Docker is slow to start, the initial `docker compose up -d` may need more settling time.

### Docker not running

**Symptom:** Integration tests skip with `Docker not running`.

**Cause:** Docker daemon is not reachable. Unit, property, and adversarial tests do not require Docker and will still pass.

**Fix:** Start Docker Desktop or the Docker daemon, then start infrastructure:
```bash
docker compose -f infra/docker-compose.yml up -d
```

### LND gRPC proto stubs

**Symptom:** `ImportError` for `lightning_pb2` or `router_pb2`.

**Cause:** Pre-compiled gRPC stubs are included in the repository. If they are missing or corrupted:

**Fix:**
```bash
bash infra/compile_lnd_protos.sh
```

This downloads LND v0.18.4-beta proto files and compiles them into `src/nostr_agent/lnd_grpc/`.

### Port conflicts

**Symptom:** Docker containers fail to start with `port already in use`.

**Fix:** Check for conflicting services on ports 7771-7773, 10009-10010, 18443:
```bash
lsof -i :7771 -i :7772 -i :7773 -i :10009 -i :10010 -i :18443
```

Stop conflicting services or adjust port mappings in `infra/docker-compose.yml`.

## Reproducibility Notes

- **Random seed:** All stochastic operations use seed=42 (configured in `eval/benchmark_config.py`)
- **Deterministic keys:** All test keypairs use `Keys.parse(known_hex)`, not `Keys.generate()`
- **Timing variance:** Timing measurements are inherently non-deterministic across runs and machines. Crypto operations and result ordering are deterministic with the fixed seed.
- **Environment metadata:** `eval/results/environment.json` captures Python version, platform, library versions, and timestamp for each benchmark run
- **Pin versions:** All dependencies are pinned in `pyproject.toml` and locked in `uv.lock`

## License

Source code, scripts, and configuration under this directory: MIT.
Data and prose (CSVs, JSON results, READMEs) shipped alongside: CC BY 4.0.
See the top-level [`LICENSE`](../LICENSE) for the full text and the precise scope.

Copyright 2026 Anonymous Authors (names withheld for double-blind review).

## Citation

See the canonical BibTeX entry in the top-level [`README.md`](../README.md#citation).
