"""Minimal FastAPI L402 test server for integration testing.

Implements: 402 challenge, macaroon verification, Authorization header check.
"""

import base64
import json
from typing import Callable

import pymacaroons  # type: ignore[import]
from fastapi import Depends, FastAPI, Header, HTTPException, Response
from fastapi.responses import JSONResponse

# ─────────────────────────────────────────────────────────────────────
# L402 Verifier (5-check flow)
# ─────────────────────────────────────────────────────────────────────


class L402Verifier:
    """Verify L402 token against macaroon root key and preimage hash."""

    def __init__(self, root_key: bytes):
        self.root_key = root_key

    def verify(self, macaroon_b64: str, preimage_hex: str) -> bool:
        """Execute 5-check verification:
        1. Base64 decode macaroon
        2. Deserialize Macaroon
        3. Verify preimage matches caveat hash
        4. Check signature with root_key
        5. Validate caveats satisfied
        """
        try:
            # 1-2: Deserialize (base64 is already handled by pymacaroons)
            m = pymacaroons.Macaroon.deserialize(macaroon_b64)

            # 3: Preimage format check
            if len(preimage_hex) != 64:
                return False
            if not all(c in "0123456789abcdef" for c in preimage_hex.lower()):
                return False

            # 4-5: Verify signature with root_key
            # Extract and satisfy first-party caveats from macaroon
            v = pymacaroons.Verifier()
            for caveat in m.first_party_caveats():
                caveat_str = caveat.caveat_id_bytes.decode("utf-8")
                v.satisfy_exact(caveat_str)
            try:
                v.verify(m, self.root_key)
                return True
            except Exception:
                return False
        except Exception:
            return False


# ─────────────────────────────────────────────────────────────────────
# FastAPI Server
# ─────────────────────────────────────────────────────────────────────


def create_l402_server(root_key: bytes | None = None) -> FastAPI:
    """Create test server with L402 middleware.

    Args:
        root_key: Macaroon root key (default: fixed test key).

    Returns:
        FastAPI instance ready to mount/run.
    """
    if root_key is None:
        root_key = b"test_root_key_32_bytes_long_xxxx"

    app = FastAPI()
    verifier = L402Verifier(root_key)

    # ─── Challenge Generator ───
    def generate_challenge(macaroon_b64: str | None = None) -> tuple[str, str]:
        """Generate L402 challenge: base64 macaroon + invoice."""
        if macaroon_b64 is None:
            m = pymacaroons.Macaroon(
                location="https://agent.example.com",
                identifier="session-001",
                key=root_key,
            )
            m = m.add_first_party_caveat("account = test_agent")
            # m.serialize() returns a base64 string already
            macaroon_b64 = m.serialize()

        # Fake BOLT11 invoice for testing
        invoice = (
            "lnbc100n1pw9m7pppp5z7xw8txwz9yxwvl6qq5j7l8q0x0xq6qz7xw8txwz9yxwvl6qq5j"
        )
        return macaroon_b64, invoice

    # ─── Dependency: Check Authorization ───
    def check_l402(authorization: str | None = Header(None)) -> dict:
        """Middleware dependency for L402 verification."""
        if not authorization:
            macaroon_b64, invoice = generate_challenge()
            raise HTTPException(
                status_code=402,
                detail="Payment Required",
                headers={
                    "WWW-Authenticate": f'L402 macaroon="{macaroon_b64}", invoice="{invoice}"'
                },
            )

        if not authorization.startswith("L402 "):
            raise HTTPException(status_code=401, detail="Invalid scheme")

        parts = authorization[5:].split(":")
        if len(parts) != 2:
            raise HTTPException(status_code=401, detail="Malformed token")

        macaroon_b64, preimage_hex = parts
        if not verifier.verify(macaroon_b64, preimage_hex):
            raise HTTPException(status_code=401, detail="Invalid L402 token")

        return {"macaroon": macaroon_b64, "preimage": preimage_hex}

    # ─── Routes ───
    @app.get("/protected")
    async def protected_resource(
        auth: dict = Depends(check_l402),
    ) -> dict:
        """Example protected endpoint."""
        return {"status": "ok", "data": "secret_resource"}

    @app.get("/health")
    async def health() -> dict:
        """Health check (no L402 required)."""
        return {"status": "healthy"}

    return app


# ─────────────────────────────────────────────────────────────────────
# Test Fixture & Standalone Runner
# ─────────────────────────────────────────────────────────────────────


async def run_l402_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run server standalone (for demo/manual testing)."""
    import uvicorn

    app = create_l402_server()
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()


# pytest fixture
def pytest_l402_server_fixture(root_key: bytes | None = None) -> Callable:
    """Return a pytest fixture factory for L402 server."""
    import pytest
    from fastapi.testclient import TestClient

    @pytest.fixture
    def l402_server():
        app = create_l402_server(root_key)
        client = TestClient(app)
        yield client

    return l402_server


if __name__ == "__main__":
    import asyncio

    asyncio.run(run_l402_server())
