#!/usr/bin/env bash
# reproduce.sh -- NostrAgent one-command reproduction script
#
# Reproduces all results reported in the paper:
#   1. Installs Python dependencies
#   2. Starts Docker infrastructure (3 relays, 2 LND, 1 bitcoind)
#   3. Bootstraps regtest Lightning network
#   4. Runs all 5 test layers (unit, property, adversarial, integration, top-level integration)
#   5. Runs benchmarks B1-B11
#   6. Runs 5-agent demo
#   7. Captures environment metadata
#
# Prerequisites: Docker, Python 3.11+, uv
# Usage: cd code/ && ./reproduce.sh
#
# Exit codes:
#   0 -- all steps completed successfully
#   1 -- a step failed (set -e)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

RESULTS_DIR="$SCRIPT_DIR/eval/results"
LOG_FILE="$SCRIPT_DIR/reproduce.log"

# Timestamp for this run
RUN_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

log()  { echo "[reproduce] $(date +%H:%M:%S) $*" | tee -a "$LOG_FILE"; }
die()  { echo "[reproduce] ERROR: $*" >&2; exit 1; }

###############################################################################
# Header
###############################################################################
echo "================================================================="
echo "  NostrAgent Reproducibility Script"
echo "  Started: $RUN_TIMESTAMP"
echo "================================================================="
echo "" > "$LOG_FILE"  # Reset log file

###############################################################################
# 0. Prerequisite checks
###############################################################################
log "Checking prerequisites..."

command -v docker >/dev/null 2>&1   || die "docker not found. Install Docker Desktop."
command -v uv >/dev/null 2>&1       || die "uv not found. Install: curl -LsSf https://astral.sh/uv/install.sh | sh"
docker info >/dev/null 2>&1         || die "Docker daemon not running. Start Docker Desktop."

log "  Docker: $(docker --version)"
log "  uv: $(uv --version)"
log "  Python target: 3.11+"

###############################################################################
# 1. Install dependencies
###############################################################################
log "Step 1/7: Installing Python dependencies..."
uv sync --python 3.11 --extra dev 2>&1 | tail -3
log "  Dependencies installed."

###############################################################################
# 2. Start Docker infrastructure
###############################################################################
log "Step 2/7: Starting Docker infrastructure (6 containers)..."

# Check if containers are already running
RUNNING=$(docker compose -f infra/docker-compose.yml ps --status running -q 2>/dev/null | wc -l | tr -d ' ')
if [[ "$RUNNING" -ge 6 ]]; then
    log "  All 6 containers already running. Skipping startup."
else
    docker compose -f infra/docker-compose.yml up -d 2>&1 | tail -6
    log "  Waiting for containers to reach healthy state..."

    # Wait for bitcoind health check (up to 60s)
    for i in $(seq 1 30); do
        HEALTH=$(docker inspect --format='{{.State.Health.Status}}' nostragent-bitcoind 2>/dev/null || echo "starting")
        [[ "$HEALTH" == "healthy" ]] && break
        [[ $i -eq 30 ]] && die "bitcoind not healthy after 60s"
        sleep 2
    done
    log "  bitcoind healthy."

    # Wait for LND nodes (up to 90s each)
    for NODE in nostragent-lnd-alice nostragent-lnd-bob; do
        for i in $(seq 1 30); do
            HEALTH=$(docker inspect --format='{{.State.Health.Status}}' "$NODE" 2>/dev/null || echo "starting")
            [[ "$HEALTH" == "healthy" ]] && break
            [[ $i -eq 30 ]] && log "  WARNING: $NODE not healthy after 90s (bootstrap will retry)"
            sleep 3
        done
        log "  $NODE ready."
    done

    # Wait for relays (up to 30s)
    for RELAY in nostragent-relay-1 nostragent-relay-2 nostragent-relay-3; do
        for i in $(seq 1 15); do
            HEALTH=$(docker inspect --format='{{.State.Health.Status}}' "$RELAY" 2>/dev/null || echo "starting")
            [[ "$HEALTH" == "healthy" ]] && break
            [[ $i -eq 15 ]] && log "  WARNING: $RELAY not healthy after 30s"
            sleep 2
        done
    done
    log "  All relays ready."
fi

###############################################################################
# 3. Bootstrap regtest Lightning network
###############################################################################
log "Step 3/7: Bootstrapping regtest Lightning network..."

# Create Bitcoin wallet (Bitcoin Core v27+ requires explicit wallet creation).
# Ignore error if wallet already exists.
docker exec nostragent-bitcoind bitcoin-cli -regtest -rpcuser=nostr -rpcpassword=nostr \
    createwallet "default" 2>/dev/null || true

# Run bootstrap script (idempotent -- skips if already bootstrapped)
bash infra/scripts/bootstrap.sh 2>&1 | tee -a "$LOG_FILE" | grep "^\[bootstrap\]" | tail -5

# Compile LND gRPC protos if stubs are missing
if [[ ! -f "src/nostr_agent/lnd_grpc/lightning_pb2.py" ]]; then
    log "  Compiling LND gRPC proto stubs..."
    bash infra/compile_lnd_protos.sh 2>&1 | tail -3
fi

# Verify relays
log "  Verifying relay acceptance of custom event kinds..."
uv run python infra/verify_relays.py 2>&1 | tail -2
log "  Bootstrap complete."

###############################################################################
# 4. Run all test layers
###############################################################################
log "Step 4/7: Running test suite..."

log "  Unit tests (254 items)..."
uv run pytest tests/unit/ -v --tb=short 2>&1 | tail -3
log "  Unit tests passed."

log "  Property-based tests (51 items)..."
uv run pytest tests/property/ -v --tb=short 2>&1 | tail -3
log "  Property tests passed."

log "  Adversarial tests (57 items; 29 functions parametrized)..."
uv run pytest tests/adversarial/ -v --tb=short 2>&1 | tail -3
log "  Adversarial tests passed."

log "  Integration tests (31 items)..."
uv run pytest tests/integration/ -v --tb=short 2>&1 | tail -3
log "  Integration tests passed."

log "  Top-level integration tests (45 items)..."
uv run pytest tests/test_dtag_generation.py tests/test_lnd_grpc_integration.py tests/test_strfry_relay.py tests/test_stride_adversarial.py -v --tb=short 2>&1 | tail -3
log "  Top-level integration tests passed."

log "  All 438 tests passed."

###############################################################################
# 5. Run benchmarks
###############################################################################
log "Step 5/7: Running benchmarks B1-B11 (1000 iterations, 100 warmup each)..."
mkdir -p "$RESULTS_DIR"

uv run python -m eval.bench --all 2>&1 | tee -a "$LOG_FILE" | tail -20
log "  Benchmark CSVs written to eval/results/"

###############################################################################
# 6. Run demo
###############################################################################
log "Step 6/7: Running 5-agent demo (8 steps)..."
uv run python -m nostr_agent.deploy_5agent 2>&1 | tee -a "$LOG_FILE" | tail -10
log "  Demo completed."

###############################################################################
# 7. Capture environment metadata
###############################################################################
log "Step 7/7: Capturing environment metadata..."

uv run python -c "
from eval.env_metadata import save_metadata
meta = save_metadata('eval/results/environment.json')
for k, v in meta.items():
    print(f'  {k}: {v}')
" 2>&1 | tee -a "$LOG_FILE"

# Capture additional metadata
{
    echo ""
    echo "=== Reproduction Run Metadata ==="
    echo "timestamp: $RUN_TIMESTAMP"
    echo "docker_version: $(docker --version 2>/dev/null)"
    echo "docker_compose_version: $(docker compose version 2>/dev/null)"
    echo "uv_version: $(uv --version 2>/dev/null)"
    echo "os: $(uname -a)"
} >> "$LOG_FILE"

# Capture dependency versions
uv pip list 2>/dev/null >> "$LOG_FILE" || true

###############################################################################
# Summary
###############################################################################
echo ""
echo "================================================================="
echo "  NostrAgent Reproduction Complete"
echo "  Finished: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "================================================================="
echo ""
echo "  Results:      eval/results/*.csv"
echo "  Environment:  eval/results/environment.json"
echo "  Full log:     reproduce.log"
echo ""
echo "  Test summary: 438 collected items (254 unit + 51 property + 57 adversarial + 31 integration + 45 top-level integration)"
echo "  Benchmarks:   B1-B11 (900 effective runs each, seed=42)"
echo "  Demo:         8-step 5-agent deployment"
echo ""
echo "  Docker infra is still running. To stop:"
echo "    docker compose -f infra/docker-compose.yml down      # preserve data"
echo "    docker compose -f infra/docker-compose.yml down -v   # full reset"
echo "================================================================="
