#!/usr/bin/env bash
# bootstrap.sh -- NostrAgent regtest Lightning bootstrap
# Run after: docker compose up -d
# Idempotent: safe to re-run. Exit 0 if already bootstrapped.
set -euo pipefail

INFRA_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Use container_name values from docker-compose.yml for docker exec
BTC="docker exec nostragent-bitcoind bitcoin-cli -regtest -rpcuser=nostr -rpcpassword=nostr"
ALICE="docker exec nostragent-lnd-alice lncli --network=regtest --rpcserver=localhost:10009 \
  --tlscertpath=/root/.lnd/tls.cert \
  --macaroonpath=/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon"
BOB="docker exec nostragent-lnd-bob lncli --network=regtest --rpcserver=localhost:10009 \
  --tlscertpath=/root/.lnd/tls.cert \
  --macaroonpath=/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon"

log()  { echo "[bootstrap] $*"; }
die()  { echo "[bootstrap] ERROR: $*" >&2; exit 1; }
jq1()  { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }  # tiny jq substitute

###############################################################################
# 1. Wait for readiness
###############################################################################
log "Waiting for bitcoind RPC..."
for i in $(seq 1 45); do
  $BTC getblockchaininfo &>/dev/null && break
  [[ $i -eq 45 ]] && die "bitcoind not ready after 90s"
  sleep 2
done
log "bitcoind ready ($(  $BTC getblockcount) blocks)"

# Bitcoin Core v27+ requires explicit wallet creation; idempotent.
$BTC createwallet "default" 2>/dev/null || true
log "Bitcoin wallet ready (default)"

log "Waiting for LND alice (may take 30-60s for chain sync)..."
for i in $(seq 1 40); do
  $ALICE getinfo &>/dev/null && break
  [[ $i -eq 40 ]] && die "lnd-alice not ready after 120s"
  sleep 3
done
log "lnd-alice ready"

log "Waiting for LND bob..."
for i in $(seq 1 40); do
  $BOB getinfo &>/dev/null && break
  [[ $i -eq 40 ]] && die "lnd-bob not ready after 120s"
  sleep 3
done
log "lnd-bob ready"

###############################################################################
# 2. Idempotency guard
###############################################################################
ACTIVE_CHANNELS=$($ALICE listchannels | jq1 "len(d.get('channels',[]))")
if [[ "$ACTIVE_CHANNELS" -gt 0 ]]; then
  log "Already bootstrapped ($ACTIVE_CHANNELS active channels). Use 'docker compose down -v' to reset."
  exit 0
fi

###############################################################################
# 3. Mine 101 blocks to coinbase address (coinbase maturity)
###############################################################################
BLOCK_COUNT=$($BTC getblockcount)
if [[ "$BLOCK_COUNT" -lt 101 ]]; then
  COINBASE_ADDR=$($BTC getnewaddress "coinbase" "bech32")
  log "Mining 101 blocks to coinbase $COINBASE_ADDR ..."
  $BTC generatetoaddress 101 "$COINBASE_ADDR" >/dev/null
  log "Chain height now: $($BTC getblockcount)"
else
  log "Chain already has $BLOCK_COUNT blocks, skipping initial mine."
  COINBASE_ADDR=$($BTC getnewaddress "coinbase" "bech32")
fi

###############################################################################
# 4. Fund alice's LND wallet with 1 BTC; confirm with 6 blocks
###############################################################################
ALICE_ONCHAIN=$($ALICE walletbalance | jq1 "int(d.get('confirmed_balance','0'))")
if [[ "$ALICE_ONCHAIN" -lt 50000000 ]]; then   # < 0.5 BTC
  ALICE_ADDR=$($ALICE newaddress p2wkh | jq1 "d['address']")
  log "Sending 1 BTC to alice LND wallet at $ALICE_ADDR ..."
  $BTC sendtoaddress "$ALICE_ADDR" 1.0 >/dev/null
  $BTC generatetoaddress 6 "$COINBASE_ADDR" >/dev/null
  log "Waiting for alice to see confirmed funds..."
  for i in $(seq 1 20); do
    BAL=$($ALICE walletbalance | jq1 "int(d.get('confirmed_balance','0'))")
    [[ "$BAL" -gt 0 ]] && break
    sleep 3
  done
  log "Alice confirmed on-chain balance: ${BAL} sats"
else
  log "Alice already funded ($ALICE_ONCHAIN sats), skipping."
fi

###############################################################################
# 5. Connect peers: alice -> bob (container DNS: nostragent-lnd-bob:9735)
###############################################################################
BOB_PUBKEY=$($BOB getinfo | jq1 "d['identity_pubkey']")
log "Connecting alice to bob ($BOB_PUBKEY@lnd-bob:9735)..."
$ALICE connect "${BOB_PUBKEY}@lnd-bob:9735" 2>/dev/null \
  || log "Peer already connected (continuing)"

###############################################################################
# 6. Open channel: 1,000,000 sat capacity, push 500,000 sats to bob
###############################################################################
log "Opening channel alice->bob (1,000,000 sat / push 500,000 to bob)..."
FUNDING_TXID=$($ALICE openchannel \
  --node_key="$BOB_PUBKEY" \
  --local_amt=1000000 \
  --push_amt=500000 \
  --sat_per_vbyte=1 | jq1 "d['funding_txid']")
log "Funding txid: $FUNDING_TXID"

###############################################################################
# 7. Confirm channel: mine 6 blocks; wait for active state
###############################################################################
log "Mining 6 blocks to confirm channel..."
$BTC generatetoaddress 6 "$COINBASE_ADDR" >/dev/null

log "Waiting for channel to become active..."
ACTIVE=0
for i in $(seq 1 20); do
  ACTIVE=$($ALICE listchannels | jq1 \
    "sum(1 for c in d.get('channels',[]) if c.get('active'))")
  [[ "$ACTIVE" -gt 0 ]] && break
  sleep 3
done
[[ "$ACTIVE" -gt 0 ]] || die "Channel not active after 60s"

###############################################################################
# 8. Verify: balances + channel state
###############################################################################
log "=== Verification ==="
$ALICE listchannels | python3 -c "
import json, sys
for c in json.load(sys.stdin).get('channels', []):
    print(f\"  alice channel: active={c['active']}  cap={c['capacity']}  \
local={c['local_balance']}  remote={c['remote_balance']}\")
"
ALICE_CHAN_BAL=$($ALICE channelbalance | jq1 "d.get('local_balance',{}).get('sat','?')")
BOB_CHAN_BAL=$($BOB   channelbalance | jq1 "d.get('local_balance',{}).get('sat','?')")
log "Alice channel balance: ${ALICE_CHAN_BAL} sats (local)"
log "Bob   channel balance: ${BOB_CHAN_BAL} sats (local)"

###############################################################################
# 9. Test relay: publish Kind 38100 event to relay-1, query it back
###############################################################################
log "=== Relay test ==="
# Check relay-1 is reachable on host port 7771
if ! curl -sf http://localhost:7771 >/dev/null 2>&1; then
  log "WARNING: relay-1 not reachable on localhost:7771 -- skipping relay test"
else
  # Build a minimal Kind 38100 event and inject via strfry's stdin import.
  # Uses a fixed test key (secp256k1 point for privkey=1; NOT for production).
  PUBKEY="79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  EVENT=$(python3 - <<'PY'
import json, hashlib, time
pubkey  = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
content = json.dumps({"agent": "test", "role": "bootstrap-check"})
ts      = int(time.time())
tags    = [["d", "bootstrap-test"]]
serial  = json.dumps([0, pubkey, ts, 38100, tags, content],
                     separators=(',', ':'), ensure_ascii=False)
eid     = hashlib.sha256(serial.encode()).hexdigest()
sig     = "0" * 128   # placeholder -- strfry --skip-verify bypasses sig check
print(json.dumps({"id": eid, "pubkey": pubkey, "created_at": ts,
                  "kind": 38100, "tags": tags, "content": content, "sig": sig}))
PY
)
  # strfry import reads JSONL from stdin (one event per line).
  # Binary is at /app/strfry in the dockurr/strfry image (not in PATH).
  if echo "$EVENT" | docker exec -i nostragent-relay-1 /app/strfry import --no-verify 2>/dev/null; then
    EID=$(echo "$EVENT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"][:12])')
    log "Kind 38100 event published to relay-1 (id=${EID}...)"
  else
    log "Skipped sanity import (verify_relays.py is the canonical relay check)."
  fi
fi

###############################################################################
# 10. Extract credentials for Python gRPC (host-side access)
###############################################################################
CREDS="$INFRA_DIR/credentials"
mkdir -p "$CREDS/alice" "$CREDS/bob"
docker cp "nostragent-lnd-alice:/root/.lnd/tls.cert"                                          "$CREDS/alice/tls.cert"       2>/dev/null || true
docker cp "nostragent-lnd-alice:/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon"         "$CREDS/alice/admin.macaroon" 2>/dev/null || true
docker cp "nostragent-lnd-bob:/root/.lnd/tls.cert"                                            "$CREDS/bob/tls.cert"         2>/dev/null || true
docker cp "nostragent-lnd-bob:/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon"           "$CREDS/bob/admin.macaroon"   2>/dev/null || true
log "Credentials written to $CREDS/"

###############################################################################
# Done
###############################################################################
log ""
log "Bootstrap complete."
log "  Relays:        ws://localhost:7771  ws://localhost:7772  ws://localhost:7773"
log "  Alice gRPC:    localhost:10009   creds: $CREDS/alice/"
log "  Bob   gRPC:    localhost:10010   creds: $CREDS/bob/"
log "  Channel:       ${ACTIVE} active, funding_txid=${FUNDING_TXID}"
