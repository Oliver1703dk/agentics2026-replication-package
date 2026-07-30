# LND gRPC Setup: Credentials Extraction & Python Integration

## Container Storage Paths

LND stores credentials at:
- **TLS Certificate**: `/root/.lnd/tls.cert`
- **Admin Macaroon**: `/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon`

## Credential Extraction (docker cp)

Once containers are running (`docker compose up -d`), extract credentials:

```bash
# Alice node (gRPC port 10009 in container, 10009 on host)
docker cp lnd-alice:/root/.lnd/tls.cert ./certs/lnd-alice-tls.cert
docker cp lnd-alice:/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon ./certs/lnd-alice-admin.macaroon

# Bob node (gRPC port 10009 in container, 10010 on host)
docker cp lnd-bob:/root/.lnd/tls.cert ./certs/lnd-bob-tls.cert
docker cp lnd-bob:/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon ./certs/lnd-bob-admin.macaroon
```

Or use the helper in Python:
```python
from nostr_agent.lnd_grpc import extract_lnd_credentials_from_docker

extract_lnd_credentials_from_docker("alice")
extract_lnd_credentials_from_docker("bob")
```

## Macaroon Format

- **Storage**: Binary format (21 bytes for typical admin macaroon)
- **For gRPC**: Hex-encoded string passed as `macaroon` metadata header
- **Example**: `b'\x01\x00...'` → `"0100..."`

## TLS Certificate Handling

LND uses **self-signed certificates** on regtest. Python gRPC requires:
1. Load cert as PEM bytes
2. Pass to `grpc.ssl_channel_credentials(root_certificates=...)`
3. Set env var for deprecated cipher support (localhost regtest):
   ```python
   os.environ["GRPC_SSL_CIPHER_SUITES"] = "DEFAULT"
   ```

## Python gRPC Channel Setup

Basic flow (see `lnd_grpc.py` for production-ready code):

```python
import grpc
from nostr_agent.lnd_grpc import load_macaroon, load_tls_cert, create_lnd_channel

# 1. Load credentials
macaroon_hex = load_macaroon("./certs/lnd-alice-admin.macaroon")
tls_cert = load_tls_cert("./certs/lnd-alice-tls.cert")

# 2. Create channel with TLS + macaroon auth
channel = create_lnd_channel(
    host="localhost",
    port=10009,  # alice
    macaroon_hex=macaroon_hex,
    tls_cert_bytes=tls_cert,
)

# 3. Use stub
from lnrpc import lightning_pb2_grpc
from google.protobuf.empty_pb2 import Empty

stub = lightning_pb2_grpc.LightningStub(channel)
info = stub.GetInfo(Empty())
print(info)
```

## Async Usage (Recommended)

```python
import asyncio
from nostr_agent.lnd_grpc import get_lnd_stub
from google.protobuf.empty_pb2 import Empty

async def get_node_info():
    stub, channel = await get_lnd_stub("alice", host="localhost", grpc_port=10009)
    try:
        info = await stub.GetInfo(Empty())
        print(f"Node alias: {info.alias}")
    finally:
        await channel.close()

asyncio.run(get_node_info())
```

## Port Mappings (docker-compose.yml)

| Node | Container gRPC | Host gRPC | REST |
|------|----------------|----------|------|
| alice | 10009 | 10009 | 8080 |
| bob | 10009 | 10010 | 8081 |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `FileNotFoundError: admin.macaroon` | Run `docker cp` to extract; verify container is healthy |
| `SSL certificate problem` | Ensure `GRPC_SSL_CIPHER_SUITES="DEFAULT"` is set before channel creation |
| `No module named 'lnrpc'` | Install: `pip install lnd-grpc-py` |
| `permission denied` on macOS | Ensure docker daemon is running; use full paths in docker cp |
| gRPC channel timeout | Check container health: `docker compose ps` |

## Dependencies

```bash
pip install grpc protobuf lnd-grpc-py
```

## References

The LND gRPC stubs in `code/src/nostr_agent/lnd_grpc/` are pre-compiled from
the LND `lightning.proto` and `routerrpc/router.proto` files at version
`v0.18.4-beta`. To regenerate the stubs from upstream, see
`compile_lnd_protos.sh` in this directory.
