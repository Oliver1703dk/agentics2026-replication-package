#!/usr/bin/env bash
# compile_lnd_protos.sh -- Download and compile LND gRPC proto files.
#
# Produces *_pb2.py and *_pb2_grpc.py stubs in code/src/nostr_agent/lnd_grpc/.
# Idempotent: skips download/compile if stubs already exist.
#
# Requirements: pip install grpcio-tools
# LND version: v0.18.4-beta
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/code/src/nostr_agent/lnd_grpc"
PROTO_WORK_DIR="$SCRIPT_DIR/.proto_build"

LND_VERSION="v0.18.4-beta"
LIGHTNING_PROTO_URL="https://raw.githubusercontent.com/lightningnetwork/lnd/${LND_VERSION}/lnrpc/lightning.proto"
ROUTER_PROTO_URL="https://raw.githubusercontent.com/lightningnetwork/lnd/${LND_VERSION}/lnrpc/routerrpc/router.proto"

# Stubs that should exist after compilation
EXPECTED_STUBS=(
    "$OUTPUT_DIR/lightning_pb2.py"
    "$OUTPUT_DIR/lightning_pb2_grpc.py"
    "$OUTPUT_DIR/router_pb2.py"
    "$OUTPUT_DIR/router_pb2_grpc.py"
)

log()  { echo "[compile_lnd_protos] $*"; }
die()  { echo "[compile_lnd_protos] ERROR: $*" >&2; exit 1; }

###############################################################################
# 1. Idempotency check -- skip if all stubs already exist
###############################################################################
all_exist=true
for stub in "${EXPECTED_STUBS[@]}"; do
    if [[ ! -f "$stub" ]]; then
        all_exist=false
        break
    fi
done

if $all_exist; then
    log "All stubs already exist in $OUTPUT_DIR -- skipping."
    log "  To force recompile: rm ${OUTPUT_DIR}/*_pb2*.py && re-run."
    exit 0
fi

###############################################################################
# 2. Check dependencies
###############################################################################
if ! python3 -c "import grpc_tools.protoc" 2>/dev/null; then
    die "grpcio-tools not installed. Run: pip install grpcio-tools"
fi

###############################################################################
# 3. Download protos into a flat working directory
###############################################################################
mkdir -p "$PROTO_WORK_DIR"
mkdir -p "$OUTPUT_DIR"

log "Downloading lightning.proto (LND ${LND_VERSION})..."
curl -fsSL "$LIGHTNING_PROTO_URL" -o "$PROTO_WORK_DIR/lightning.proto"

log "Downloading router.proto (LND ${LND_VERSION})..."
curl -fsSL "$ROUTER_PROTO_URL" -o "$PROTO_WORK_DIR/router.proto"

###############################################################################
# 4. Patch import paths
#
# router.proto imports "lnrpc/lightning.proto" but we have both protos in a
# flat directory. Rewrite the import to "lightning.proto".
###############################################################################
log "Patching router.proto import path..."
sed -i.bak 's|import "lnrpc/lightning.proto"|import "lightning.proto"|g' \
    "$PROTO_WORK_DIR/router.proto"
rm -f "$PROTO_WORK_DIR/router.proto.bak"

###############################################################################
# 5. Compile with grpcio-tools
###############################################################################
log "Compiling protos -> $OUTPUT_DIR ..."
python3 -m grpc_tools.protoc \
    --proto_path="$PROTO_WORK_DIR" \
    --python_out="$OUTPUT_DIR" \
    --grpc_python_out="$OUTPUT_DIR" \
    lightning.proto router.proto

###############################################################################
# 6. Patch relative imports in generated code
#
# The generated router_pb2.py will have:
#   import lightning_pb2 as lightning__pb2
# This breaks when imported as nostr_agent.lnd_grpc.router_pb2.
# Rewrite to a relative import.
###############################################################################
log "Patching generated imports to use relative imports..."
for pyfile in "$OUTPUT_DIR"/router_pb2.py "$OUTPUT_DIR"/router_pb2_grpc.py; do
    if [[ -f "$pyfile" ]]; then
        sed -i.bak 's/^import lightning_pb2 as/from . import lightning_pb2 as/' "$pyfile"
        sed -i.bak 's/^from lightning_pb2 import/from .lightning_pb2 import/' "$pyfile"
        rm -f "${pyfile}.bak"
    fi
done

###############################################################################
# 7. Clean up working directory
###############################################################################
rm -rf "$PROTO_WORK_DIR"

###############################################################################
# 8. Verify
###############################################################################
missing=()
for stub in "${EXPECTED_STUBS[@]}"; do
    if [[ ! -f "$stub" ]]; then
        missing+=("$stub")
    fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
    die "Compilation failed. Missing stubs: ${missing[*]}"
fi

log "Done. Generated stubs:"
for stub in "${EXPECTED_STUBS[@]}"; do
    log "  $(basename "$stub")"
done
