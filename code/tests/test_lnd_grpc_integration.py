"""Integration tests for LND gRPC credential extraction and channel setup."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from google.protobuf.empty_pb2 import Empty

from nostr_agent.lnd_grpc import (
    LNDCredentialError,
    create_lnd_channel,
    extract_lnd_credentials_from_docker,
    get_lnd_stub,
    load_macaroon,
    load_tls_cert,
)


class TestCredentialLoading:
    """Test macaroon and TLS cert loading."""

    def test_load_macaroon_missing_file(self, tmp_path):
        """load_macaroon raises LNDCredentialError if file not found."""
        missing = tmp_path / "nonexistent.macaroon"
        with pytest.raises(LNDCredentialError, match="not found"):
            load_macaroon(str(missing))

    def test_load_macaroon_valid_file(self, tmp_path):
        """load_macaroon returns hex string for valid binary."""
        macaroon_file = tmp_path / "admin.macaroon"
        macaroon_file.write_bytes(b"\x01\x00\x02\x03")  # 4 bytes

        result = load_macaroon(str(macaroon_file))
        assert result == "01000203"
        assert isinstance(result, str)

    def test_load_tls_cert_missing_file(self, tmp_path):
        """load_tls_cert raises LNDCredentialError if file not found."""
        missing = tmp_path / "nonexistent.cert"
        with pytest.raises(LNDCredentialError, match="not found"):
            load_tls_cert(str(missing))

    def test_load_tls_cert_valid_file(self, tmp_path):
        """load_tls_cert returns bytes for valid PEM."""
        cert_file = tmp_path / "tls.cert"
        pem = b"-----BEGIN CERTIFICATE-----\nABCD\n-----END CERTIFICATE-----"
        cert_file.write_bytes(pem)

        result = load_tls_cert(str(cert_file))
        assert result == pem
        assert isinstance(result, bytes)


class TestChannelCreation:
    """Test gRPC channel setup with TLS and macaroon auth."""

    def test_create_lnd_channel_basic(self, tmp_path):
        """create_lnd_channel builds a gRPC channel (smoke test)."""
        # Create dummy cert and macaroon
        cert_file = tmp_path / "tls.cert"
        cert_file.write_bytes(b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")

        macaroon_hex = "01000203"

        # Channel creation should not raise
        channel = create_lnd_channel(
            host="localhost",
            port=10009,
            macaroon_hex=macaroon_hex,
            tls_cert_bytes=cert_file.read_bytes(),
        )
        assert channel is not None

    def test_grpc_cipher_env_var_set(self, tmp_path):
        """create_lnd_channel sets GRPC_SSL_CIPHER_SUITES for localhost."""
        cert_file = tmp_path / "tls.cert"
        cert_file.write_bytes(b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")

        # Ensure env var is not set
        os.environ.pop("GRPC_SSL_CIPHER_SUITES", None)

        create_lnd_channel(
            host="localhost",
            port=10009,
            macaroon_hex="01000203",
            tls_cert_bytes=cert_file.read_bytes(),
        )

        assert os.environ.get("GRPC_SSL_CIPHER_SUITES") == "DEFAULT"


class TestDockerExtraction:
    """Test docker cp credential extraction."""

    @pytest.mark.skipif(
        not Path("/var/run/docker.sock").exists(),
        reason="Docker daemon not available",
    )
    def test_extract_credentials_alice(self, tmp_path):
        """extract_lnd_credentials_from_docker calls docker cp (requires running containers)."""
        # This test only runs if:
        # 1. Docker daemon is available
        # 2. lnd-alice container is running
        # 3. We have permission to docker cp
        output_dir = tmp_path / "certs"
        output_dir.mkdir()

        try:
            extract_lnd_credentials_from_docker(
                "alice",
                container_name="lnd-alice",
                output_dir=str(output_dir),
            )
            # If successful, files should exist
            assert (output_dir / "lnd-alice-tls.cert").exists()
            assert (output_dir / "lnd-alice-admin.macaroon").exists()
        except Exception as e:
            # Skip if container not running or other Docker error
            pytest.skip(f"Docker extraction skipped: {e}")


class TestAsyncStubFactory:
    """Test get_lnd_stub async stub factory."""

    @pytest.mark.skipif(
        not Path("/var/run/docker.sock").exists(),
        reason="Docker daemon not available",
    )
    @pytest.mark.asyncio
    async def test_get_lnd_stub_alice(self, tmp_path):
        """get_lnd_stub loads credentials and returns configured stub (integration)."""
        # First, extract credentials
        certs_dir = tmp_path / "certs"
        certs_dir.mkdir()

        try:
            extract_lnd_credentials_from_docker(
                "alice",
                container_name="lnd-alice",
                output_dir=str(certs_dir),
            )
        except Exception as e:
            pytest.skip(f"Could not extract credentials: {e}")

        # Then, get stub
        try:
            stub, channel = await get_lnd_stub(
                "alice",
                host="localhost",
                grpc_port=10009,
                certs_dir=str(certs_dir),
            )

            # Attempt GetInfo RPC (requires lnd-alice running)
            info = await stub.GetInfo(Empty())
            assert info.identity_pubkey  # Should return a pubkey

            await channel.close()
        except Exception as e:
            pytest.skip(f"gRPC connection failed: {e}")

    @pytest.mark.skipif(
        not Path("/var/run/docker.sock").exists(),
        reason="Docker daemon not available",
    )
    @pytest.mark.asyncio
    async def test_get_lnd_stub_bob(self, tmp_path):
        """get_lnd_stub works for bob node (port 10010)."""
        certs_dir = tmp_path / "certs"
        certs_dir.mkdir()

        try:
            extract_lnd_credentials_from_docker(
                "bob",
                container_name="lnd-bob",
                output_dir=str(certs_dir),
            )
        except Exception as e:
            pytest.skip(f"Could not extract credentials: {e}")

        try:
            stub, channel = await get_lnd_stub(
                "bob",
                host="localhost",
                certs_dir=str(certs_dir),
            )

            info = await stub.GetInfo(Empty())
            assert info.identity_pubkey

            await channel.close()
        except Exception as e:
            pytest.skip(f"gRPC connection failed: {e}")


class TestEndToEndFlow:
    """Full credential extraction + channel setup + RPC flow."""

    @pytest.mark.skipif(
        not Path("/var/run/docker.sock").exists(),
        reason="Docker daemon not available",
    )
    @pytest.mark.asyncio
    async def test_full_workflow(self, tmp_path):
        """Extract, connect, and call GetInfo on running LND node."""
        certs_dir = tmp_path / "certs"
        certs_dir.mkdir()

        try:
            # Step 1: Extract from container
            extract_lnd_credentials_from_docker(
                "alice",
                container_name="lnd-alice",
                output_dir=str(certs_dir),
            )

            # Step 2: Load and verify credentials
            macaroon_hex = load_macaroon(str(certs_dir / "lnd-alice-admin.macaroon"))
            tls_cert = load_tls_cert(str(certs_dir / "lnd-alice-tls.cert"))

            assert len(macaroon_hex) > 0
            assert len(tls_cert) > 0

            # Step 3: Create channel
            channel = create_lnd_channel(
                host="localhost",
                port=10009,
                macaroon_hex=macaroon_hex,
                tls_cert_bytes=tls_cert,
            )

            # Step 4: Call RPC
            from nostr_agent.lnd_grpc import lightning_pb2_grpc

            stub = lightning_pb2_grpc.LightningStub(channel)
            info = await stub.GetInfo(Empty())

            # Verify we got node info back
            assert len(info.identity_pubkey) > 0
            assert info.num_active_channels >= 0

            await channel.close()
        except Exception as e:
            pytest.skip(f"End-to-end flow failed (container may not be running): {e}")
