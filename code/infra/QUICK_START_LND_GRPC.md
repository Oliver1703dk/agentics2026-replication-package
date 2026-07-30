# Quick Start: LND gRPC from Docker

## 1. Start containers
```bash
cd code/infra
docker compose up -d
```

## 2. Extract credentials (one-time)
```bash
python -c "from nostr_agent.lnd_grpc import extract_lnd_credentials_from_docker; \
extract_lnd_credentials_from_docker('alice'); \
extract_lnd_credentials_from_docker('bob')"
```

Files created: `./certs/lnd-{alice,bob}-{tls.cert,admin.macaroon}`

## 3. Use in Python

### Sync (simple):
```python
from nostr_agent.lnd_grpc import load_macaroon, load_tls_cert, create_lnd_channel
from lnrpc import lightning_pb2_grpc
from google.protobuf.empty_pb2 import Empty

macaroon_hex = load_macaroon("./certs/lnd-alice-admin.macaroon")
tls_cert = load_tls_cert("./certs/lnd-alice-tls.cert")
channel = create_lnd_channel("localhost", 10009, macaroon_hex, tls_cert)

stub = lightning_pb2_grpc.LightningStub(channel)
info = stub.GetInfo(Empty())
print(f"Node: {info.alias}, Pubkey: {info.identity_pubkey}")
```

### Async (recommended):
```python
import asyncio
from nostr_agent.lnd_grpc import get_lnd_stub
from google.protobuf.empty_pb2 import Empty

async def main():
    stub, channel = await get_lnd_stub("alice", host="localhost", grpc_port=10009)
    info = await stub.GetInfo(Empty())
    print(f"Node: {info.alias}")
    await channel.close()

asyncio.run(main())
```

## 4. Common RPC examples

```python
# Get node info
info = await stub.GetInfo(Empty())

# List channels
from lnrpc import lightning_pb2
channels = await stub.ListChannels(Empty())

# Create invoice
invoice_request = lightning_pb2.Invoice(
    memo="test",
    value=1000,  # msats
)
invoice = await stub.AddInvoice(invoice_request)
print(invoice.payment_request)  # BOLT11 string

# Pay invoice
pay_request = lightning_pb2.SendRequest(payment_request=bolt11_string)
payment = await stub.SendPaymentSync(pay_request)
```

## Container paths (reference)
- **TLS cert**: `/root/.lnd/tls.cert`
- **Admin macaroon**: `/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon`

## Port mapping
- **Alice gRPC**: 10009 (both container and host)
- **Bob gRPC**: 10009 (container) → 10010 (host)
- **Alice REST**: 8080
- **Bob REST**: 8081

## Test it
```bash
pytest code/tests/test_lnd_grpc_integration.py -v
```

## See also
- `code/infra/LND_GRPC_SETUP.md` -- detailed reference
- `code/src/nostr_agent/lnd_grpc.py` -- source code
- `code/src/nostr_agent/l402.py` -- L402 payment flow (uses LND)
