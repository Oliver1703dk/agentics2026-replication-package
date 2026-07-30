"""Unit tests for nostr_agent.discovery.

Covers the no-network surface of the discovery module: RelayDiscovery
construction (URL validation), property accessors, and the _dedup_by_d_tag
helper that drives multi-relay replaceable-event resolution.

Tests requiring a live relay are in tests/integration/ and tests/test_strfry_relay.py.
"""

from __future__ import annotations

import pytest

from nostr_agent.discovery import RelayDiscovery, _dedup_by_d_tag
from nostr_agent.types import AgentInfo, TrustPolicy


# ============================================================================
# RelayDiscovery construction
# ============================================================================


class TestRelayDiscoveryConstruction:
    def test_valid_ws_urls_accepted(self) -> None:
        rd = RelayDiscovery(["ws://localhost:7771", "ws://localhost:7772"])
        assert rd.relay_urls == ["ws://localhost:7771", "ws://localhost:7772"]
        assert rd.timeout_seconds == 10.0
        assert rd.is_connected is False

    def test_wss_urls_accepted(self) -> None:
        rd = RelayDiscovery(["wss://relay.example.com"])
        assert rd.relay_urls == ["wss://relay.example.com"]

    def test_custom_timeout_accepted(self) -> None:
        rd = RelayDiscovery(["ws://localhost:7771"], timeout_seconds=30.0)
        assert rd.timeout_seconds == 30.0

    def test_empty_relay_list_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid relay_urls"):
            RelayDiscovery([])

    def test_invalid_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid relay_urls"):
            RelayDiscovery(["http://localhost:7771"])

    def test_too_many_relays_rejected(self) -> None:
        """Validator caps the pool at 10 relays."""
        with pytest.raises(ValueError, match="Invalid relay_urls"):
            RelayDiscovery([f"ws://relay{i}.example.com" for i in range(11)])

    def test_relay_urls_property_returns_copy(self) -> None:
        """Mutating the list returned by the property must not affect internal state."""
        rd = RelayDiscovery(["ws://localhost:7771"])
        returned = rd.relay_urls
        returned.append("ws://injected.example.com")
        assert rd.relay_urls == ["ws://localhost:7771"]


# ============================================================================
# _dedup_by_d_tag
# ============================================================================


def _make_agent_info(pubkey: str, d_tag: str, created_at: int) -> AgentInfo:
    """Minimal AgentInfo factory for dedup tests."""
    return AgentInfo(
        pubkey=pubkey,
        d_tag=d_tag,
        name=f"agent-{d_tag}",
        description="",
        capabilities=(),
        relay_urls=(),
        status="active",
        created_at=created_at,
        operator_pubkey=pubkey,
        endpoints={},
        trust_policy=TrustPolicy(),
    )


class TestDedupByDTag:
    def test_empty_list_returns_empty(self) -> None:
        assert _dedup_by_d_tag([]) == []

    def test_single_agent_passes_through(self) -> None:
        info = _make_agent_info("pk1", "agent1", 1000)
        result = _dedup_by_d_tag([info])
        assert result == [info]

    def test_distinct_d_tags_all_kept(self) -> None:
        a = _make_agent_info("pk1", "agent1", 1000)
        b = _make_agent_info("pk1", "agent2", 1000)
        result = _dedup_by_d_tag([a, b])
        assert len(result) == 2

    def test_same_d_tag_keeps_latest_by_created_at(self) -> None:
        old = _make_agent_info("pk1", "agent1", 1000)
        new = _make_agent_info("pk1", "agent1", 2000)
        result = _dedup_by_d_tag([old, new])
        assert len(result) == 1
        assert result[0].created_at == 2000

    def test_same_d_tag_order_independent(self) -> None:
        """Result depends on created_at, not input order."""
        a = _make_agent_info("pk1", "agent1", 1000)
        b = _make_agent_info("pk1", "agent1", 2000)
        assert _dedup_by_d_tag([a, b])[0].created_at == 2000
        assert _dedup_by_d_tag([b, a])[0].created_at == 2000

    def test_different_pubkey_same_d_tag_both_kept(self) -> None:
        """Dedup key is (pubkey, d_tag); different pubkeys are distinct entries."""
        a = _make_agent_info("pk1", "agent1", 1000)
        b = _make_agent_info("pk2", "agent1", 1000)
        result = _dedup_by_d_tag([a, b])
        assert len(result) == 2
