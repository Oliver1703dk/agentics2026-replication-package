#!/usr/bin/env bash
# bootstrap_lnd_credentials.sh -- extract LND admin macaroons and TLS certs
# from the running Docker Compose containers into ./credentials/{alice,bob}/.
#
# Run after: docker compose up -d
# Idempotent: overwrites existing files.
#
# The bundled bootstrap.sh already calls these same docker-cp commands as its
# last step, so you only need this standalone script if you tear the stack
# down and want to refresh just the host-side credentials without re-running
# the full mine / fund / channel-open bootstrap.
set -euo pipefail

INFRA_DIR="$(cd "$(dirname "$0")" && pwd)"
CREDS_DIR="$INFRA_DIR/credentials"

ALICE_CTR="nostragent-lnd-alice"
BOB_CTR="nostragent-lnd-bob"

LND_MACAROON_PATH="/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon"
LND_TLS_PATH="/root/.lnd/tls.cert"

log()  { echo "[bootstrap_creds] $*"; }
die()  { echo "[bootstrap_creds] ERROR: $*" >&2; exit 1; }

# 1. Verify containers exist and are running.
for ctr in "$ALICE_CTR" "$BOB_CTR"; do
    if ! docker inspect -f '{{.State.Running}}' "$ctr" 2>/dev/null | grep -q true; then
        die "Container '$ctr' is not running. Start with: docker compose -f $INFRA_DIR/docker-compose.yml up -d"
    fi
done

# 2. Wait briefly for LND inside each container to have generated the macaroon
#    file. Fresh LND takes a few seconds to initialise after bitcoind sync.
for ctr in "$ALICE_CTR" "$BOB_CTR"; do
    log "Waiting for $ctr to have $LND_MACAROON_PATH ..."
    for i in $(seq 1 30); do
        if docker exec "$ctr" test -f "$LND_MACAROON_PATH" 2>/dev/null; then
            break
        fi
        [[ $i -eq 30 ]] && die "$ctr did not produce the admin macaroon within 60s"
        sleep 2
    done
done

# 3. Extract into ./credentials/{alice,bob}/ to match the layout expected by
#    code/src/nostr_agent/lnd_grpc/credentials.py.
mkdir -p "$CREDS_DIR/alice" "$CREDS_DIR/bob"

docker cp "$ALICE_CTR:$LND_TLS_PATH"        "$CREDS_DIR/alice/tls.cert"
docker cp "$ALICE_CTR:$LND_MACAROON_PATH"   "$CREDS_DIR/alice/admin.macaroon"
docker cp "$BOB_CTR:$LND_TLS_PATH"          "$CREDS_DIR/bob/tls.cert"
docker cp "$BOB_CTR:$LND_MACAROON_PATH"     "$CREDS_DIR/bob/admin.macaroon"

log "Extracted credentials:"
log "  $CREDS_DIR/alice/tls.cert"
log "  $CREDS_DIR/alice/admin.macaroon"
log "  $CREDS_DIR/bob/tls.cert"
log "  $CREDS_DIR/bob/admin.macaroon"
log ""
log "These are regtest credentials with zero monetary value. Do not reuse them on any real network."
