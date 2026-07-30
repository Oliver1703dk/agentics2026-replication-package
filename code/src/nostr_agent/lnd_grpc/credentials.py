"""LND gRPC credential extraction and channel setup (TB3 trust boundary).

Handles:
1. Extracting admin.macaroon + tls.cert from LND Docker containers
2. Loading and hex-encoding macaroon for gRPC metadata
3. Building authenticated gRPC channels with TLS + macaroon auth
4. Helper to return configured stub for lnrpc.Lightning service

Storage paths in LND container:
  /root/.lnd/tls.cert                                  (TLS certificate)
  /root/.lnd/data/chain/bitcoin/regtest/admin.macaroon (admin capability macaroon)

Extraction:
  docker cp lnd-alice:/root/.lnd/tls.cert ./certs/lnd-alice-tls.cert
  docker cp lnd-alice:/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon ./certs/lnd-alice-admin.macaroon
  docker cp lnd-bob:/root/.lnd/tls.cert ./certs/lnd-bob-tls.cert
  docker cp lnd-bob:/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon ./certs/lnd-bob-admin.macaroon
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path

import grpc
from google.protobuf.empty_pb2 import Empty


class LNDCredentialError(Exception):
    """Raised when LND credentials cannot be loaded."""


def load_macaroon(macaroon_path: str) -> str:
    """Load admin.macaroon and return as hex string for gRPC metadata.

    Args:
        macaroon_path: Path to admin.macaroon file.

    Returns:
        Hex-encoded macaroon string.

    Raises:
        LNDCredentialError if file not found or unreadable.
    """
    try:
        with open(macaroon_path, "rb") as f:
            macaroon_bytes = f.read()
        return macaroon_bytes.hex()
    except FileNotFoundError:
        raise LNDCredentialError(
            f"admin.macaroon not found at {macaroon_path}. "
            "Run: docker cp lnd-alice:/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon {macaroon_path}"
        )
    except Exception as e:
        raise LNDCredentialError(f"Failed to load macaroon: {e}")


def load_tls_cert(tls_cert_path: str) -> bytes:
    """Load TLS certificate.

    Args:
        tls_cert_path: Path to tls.cert file.

    Returns:
        PEM-encoded certificate bytes.

    Raises:
        LNDCredentialError if file not found or unreadable.
    """
    try:
        with open(tls_cert_path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        raise LNDCredentialError(
            f"tls.cert not found at {tls_cert_path}. "
            f"Run: docker cp lnd-alice:/root/.lnd/tls.cert {tls_cert_path}"
        )
    except Exception as e:
        raise LNDCredentialError(f"Failed to load TLS cert: {e}")


def create_lnd_channel(
    host: str,
    port: int,
    macaroon_hex: str,
    tls_cert_bytes: bytes,
) -> grpc.aio.Channel:
    """Create a gRPC channel with macaroon auth + TLS for LND.

    Args:
        host: LND host (e.g. "localhost").
        port: gRPC port (10009 for alice, 10010 for bob on host).
        macaroon_hex: Hex-encoded admin macaroon.
        tls_cert_bytes: PEM-encoded TLS certificate.

    Returns:
        Authenticated aio.Channel configured for LND gRPC.

    Notes:
        - For localhost with self-signed cert, sets GRPC_SSL_CIPHER_SUITES env var
        - Adds macaroon as metadata interceptor (all RPC calls)
        - Channel is non-blocking (async-capable)
    """
    # For regtest localhost with self-signed cert, allow deprecated TLS ciphers
    os.environ["GRPC_SSL_CIPHER_SUITES"] = "DEFAULT"

    # Create SSL credentials from certificate
    ssl_creds = grpc.ssl_channel_credentials(
        root_certificates=tls_cert_bytes,
        private_key=None,
        certificate_chain=None,
    )

    # Macaroon metadata callback: injects macaroon into every RPC call
    def _macaroon_plugin(context, callback):
        """gRPC auth plugin that attaches the macaroon metadata."""
        callback([("macaroon", macaroon_hex)], None)

    macaroon_creds = grpc.metadata_call_credentials(_macaroon_plugin)

    # Build composite credentials: SSL + macaroon metadata
    composite = grpc.composite_channel_credentials(ssl_creds, macaroon_creds)

    # Create channel with TLS
    target = f"{host}:{port}"
    channel = grpc.aio.secure_channel(
        target,
        composite,
        options=[
            ("grpc.max_receive_message_length", 1024 * 1024 * 10),  # 10MB
        ],
    )

    return channel


async def get_lnd_stub(
    node_name: str,
    host: str = "localhost",
    grpc_port: int = 10009,
    certs_dir: str | None = None,
) -> tuple:
    """Extract credentials and return configured LND stub + channel.

    Args:
        node_name: "alice" or "bob" (determines cert filenames and port mappings).
        host: gRPC host (default "localhost").
        grpc_port: gRPC port override (default 10009 for alice, 10010 for bob).
        certs_dir: Directory containing extracted certs. Defaults to ./certs/.

    Returns:
        Tuple of (lnrpc.Lightning stub, channel).
        Stub is ready for async RPC calls.

    Raises:
        LNDCredentialError if credentials not found or invalid.

    Example:
        stub, channel = await get_lnd_stub("alice")
        info = await stub.GetInfo(Empty())
        await channel.close()
    """
    if certs_dir is None:
        certs_dir = "./certs"

    # Adjust port for bob (10010 on host = 10009 in container)
    if node_name == "bob" and grpc_port == 10009:
        grpc_port = 10010

    # Load credentials
    macaroon_path = f"{certs_dir}/lnd-{node_name}-admin.macaroon"
    tls_cert_path = f"{certs_dir}/lnd-{node_name}-tls.cert"

    macaroon_hex = load_macaroon(macaroon_path)
    tls_cert_bytes = load_tls_cert(tls_cert_path)

    # Create channel
    channel = create_lnd_channel(host, grpc_port, macaroon_hex, tls_cert_bytes)

    # Import compiled LND gRPC stubs (generated by code/infra/compile_lnd_protos.sh)
    try:
        from nostr_agent.lnd_grpc import lightning_pb2_grpc  # type: ignore[import]
    except ImportError:
        raise LNDCredentialError(
            "LND gRPC stubs not found. Run: bash code/infra/compile_lnd_protos.sh"
        )

    stub = lightning_pb2_grpc.LightningStub(channel)
    return stub, channel


# Quick-start extraction script (run manually or in bootstrap)
def extract_lnd_credentials_from_docker(
    node_name: str,
    container_name: str = None,
    output_dir: str = "./certs",
) -> None:
    """Extract LND credentials from Docker container via docker cp.

    Args:
        node_name: "alice" or "bob".
        container_name: Docker container name. Defaults to f"lnd-{node_name}".
        output_dir: Where to save certs (default ./certs/).

    Raises:
        LNDCredentialError if docker cp fails.

    Example:
        extract_lnd_credentials_from_docker("alice")
        extract_lnd_credentials_from_docker("bob")
    """
    import subprocess

    if container_name is None:
        container_name = f"lnd-{node_name}"

    Path(output_dir).mkdir(exist_ok=True)

    # Macaroon extraction
    macaroon_src = (
        f"{container_name}:/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon"
    )
    macaroon_dst = f"{output_dir}/lnd-{node_name}-admin.macaroon"

    try:
        subprocess.run(["docker", "cp", macaroon_src, macaroon_dst], check=True)
        print(f"Extracted macaroon -> {macaroon_dst}")
    except subprocess.CalledProcessError as e:
        raise LNDCredentialError(f"Failed to extract macaroon: {e}")

    # TLS cert extraction
    tls_src = f"{container_name}:/root/.lnd/tls.cert"
    tls_dst = f"{output_dir}/lnd-{node_name}-tls.cert"

    try:
        subprocess.run(["docker", "cp", tls_src, tls_dst], check=True)
        print(f"Extracted TLS cert -> {tls_dst}")
    except subprocess.CalledProcessError as e:
        raise LNDCredentialError(f"Failed to extract TLS cert: {e}")


if __name__ == "__main__":
    # Bootstrap: extract credentials from running containers
    print("Extracting LND credentials from Docker containers...")
    extract_lnd_credentials_from_docker("alice")
    extract_lnd_credentials_from_docker("bob")
    print("Done. Use get_lnd_stub('alice') or get_lnd_stub('bob') in your code.")
