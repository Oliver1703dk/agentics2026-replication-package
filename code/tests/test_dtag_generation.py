"""Tests for deterministic d-tag generation (Kind 38101).

Verifies:
(1) Canonical JSON serialization with sorted keys/arrays
(2) SHA256(scope_json) produces consistent scope_hash
(3) Deterministic d-tag: SHA256(pk || pk || hash || ts)[:16]
(4) Same inputs → same d-tag across multiple calls
(5) Edge cases: empty arrays, single capability, complex resources
"""

import pytest
from nostr_agent.dtag_generation import compute_d_tag, compute_scope_hash, verify_d_tag_determinism


class TestScopeHash:
    """Verify canonical scope JSON serialization."""

    def test_scope_hash_determinism(self):
        """Same scope always produces same hash."""
        scope = {
            "capabilities": ["read", "write"],
            "resources": ["res-1", "res-2"],
            "actions": ["query", "mutate"],
        }
        h1 = compute_scope_hash(scope)
        h2 = compute_scope_hash(scope)
        assert h1 == h2
        assert len(h1) == 64, "SHA256 hex must be 64 chars"

    def test_scope_hash_array_order_independent(self):
        """Different array orders produce same hash (sorting)."""
        scope_a = {
            "capabilities": ["z", "a"],
            "resources": ["res-2", "res-1"],
            "actions": ["write", "read"],
        }
        scope_b = {
            "capabilities": ["a", "z"],
            "resources": ["res-1", "res-2"],
            "actions": ["read", "write"],
        }
        assert compute_scope_hash(scope_a) == compute_scope_hash(scope_b)

    def test_scope_hash_different_scopes_different_hash(self):
        """Different scopes produce different hashes."""
        scope1 = {"capabilities": ["read"], "resources": [], "actions": []}
        scope2 = {"capabilities": ["write"], "resources": [], "actions": []}
        assert compute_scope_hash(scope1) != compute_scope_hash(scope2)

    def test_empty_arrays(self):
        """Empty arrays are handled correctly."""
        scope = {"capabilities": ["x"], "resources": [], "actions": []}
        h = compute_scope_hash(scope)
        assert len(h) == 64


class TestDTagGeneration:
    """Verify d-tag generation algorithm."""

    def test_dtag_format(self):
        """d-tag is exactly 16 lowercase hex chars."""
        scope = {
            "capabilities": ["read"],
            "resources": ["res"],
            "actions": ["query"],
        }
        pk1 = "a" * 64
        pk2 = "b" * 64
        d = compute_d_tag(pk1, pk2, scope, 1234567890)
        assert len(d) == 16
        assert all(c in "0123456789abcdef" for c in d)

    def test_dtag_determinism(self):
        """Same inputs always produce same d-tag."""
        scope = {
            "capabilities": ["weather-query"],
            "resources": ["https://api.weather.example/v1"],
            "actions": ["read"],
        }
        pk1 = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
        pk2 = "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4"
        ts = 1746268800

        d1 = compute_d_tag(pk1, pk2, scope, ts)
        d2 = compute_d_tag(pk1, pk2, scope, ts)
        d3 = compute_d_tag(pk1, pk2, scope, ts)

        assert d1 == d2 == d3

    def test_dtag_changes_with_different_pubkeys(self):
        """Different pubkeys → different d-tag."""
        scope = {
            "capabilities": ["read"],
            "resources": [],
            "actions": [],
        }
        pk1_a = "a" * 64
        pk1_b = "b" * 64
        pk2 = "c" * 64

        d_a = compute_d_tag(pk1_a, pk2, scope, 1000)
        d_b = compute_d_tag(pk1_b, pk2, scope, 1000)
        assert d_a != d_b

    def test_dtag_changes_with_different_timestamp(self):
        """Different timestamp → different d-tag."""
        scope = {
            "capabilities": ["read"],
            "resources": [],
            "actions": [],
        }
        pk1 = "a" * 64
        pk2 = "b" * 64

        d_1000 = compute_d_tag(pk1, pk2, scope, 1000)
        d_2000 = compute_d_tag(pk1, pk2, scope, 2000)
        assert d_1000 != d_2000

    def test_dtag_changes_with_different_scope(self):
        """Different scope → different d-tag."""
        pk1 = "a" * 64
        pk2 = "b" * 64
        ts = 1234567890

        scope1 = {
            "capabilities": ["read"],
            "resources": [],
            "actions": [],
        }
        scope2 = {
            "capabilities": ["write"],
            "resources": [],
            "actions": [],
        }

        d1 = compute_d_tag(pk1, pk2, scope1, ts)
        d2 = compute_d_tag(pk1, pk2, scope2, ts)
        assert d1 != d2

    def test_verify_dtag_determinism_helper(self):
        """verify_d_tag_determinism correctly validates."""
        scope = {
            "capabilities": ["read"],
            "resources": ["res"],
            "actions": [],
        }
        pk1 = "a" * 64
        pk2 = "b" * 64
        ts = 9999

        d = compute_d_tag(pk1, pk2, scope, ts)
        assert verify_d_tag_determinism(pk1, pk2, scope, ts, d)
        assert not verify_d_tag_determinism(pk1, pk2, scope, ts, "0000000000000000")


class TestEdgeCases:
    """Verify edge cases: empty arrays, single items, complex resources."""

    def test_empty_resources_and_actions(self):
        """Unrestricted scope (empty resources/actions)."""
        scope = {
            "capabilities": ["single-cap"],
            "resources": [],
            "actions": [],
        }
        pk1 = "a" * 64
        pk2 = "b" * 64
        d = compute_d_tag(pk1, pk2, scope, 1234567890)
        assert len(d) == 16

    def test_single_capability(self):
        """Minimal scope with one capability."""
        scope = {
            "capabilities": ["x"],
            "resources": [],
            "actions": [],
        }
        pk1 = "a" * 64
        pk2 = "b" * 64
        d = compute_d_tag(pk1, pk2, scope, 1234567890)
        assert len(d) == 16

    def test_complex_resources(self):
        """Many resources with varied format."""
        scope = {
            "capabilities": ["read-data"],
            "resources": [
                "https://api.example.com/v1/users",
                "https://api.example.com/v1/posts",
                "local:cache:1",
                "local:cache:2",
            ],
            "actions": ["read", "list"],
        }
        pk1 = "a" * 64
        pk2 = "b" * 64
        d = compute_d_tag(pk1, pk2, scope, 1234567890)
        assert len(d) == 16

    def test_many_capabilities_and_actions(self):
        """Large scope with many items."""
        scope = {
            "capabilities": [f"cap-{i}" for i in range(10)],
            "resources": [f"res-{i}" for i in range(5)],
            "actions": [f"act-{i}" for i in range(8)],
        }
        pk1 = "a" * 64
        pk2 = "b" * 64
        d = compute_d_tag(pk1, pk2, scope, 1234567890)
        assert len(d) == 16

    def test_special_characters_in_resources(self):
        """Resources with special characters."""
        scope = {
            "capabilities": ["api-access"],
            "resources": [
                "https://api.example.com:8080/v1/path?query=1",
                "wss://relay.example.com/",
                "nostr:nip:42",
            ],
            "actions": ["read"],
        }
        pk1 = "a" * 64
        pk2 = "b" * 64
        d = compute_d_tag(pk1, pk2, scope, 1234567890)
        assert len(d) == 16

    def test_canonical_json_key_order(self):
        """Canonical JSON always has keys in order: actions, capabilities, resources."""
        scope = {
            "resources": ["first"],  # Input in different order
            "actions": ["query"],
            "capabilities": ["read"],
        }
        h = compute_scope_hash(scope)
        # Hash should be stable regardless of input order
        assert len(h) == 64
        # Verify by computing again with different input order
        scope_reordered = {
            "capabilities": ["read"],
            "resources": ["first"],
            "actions": ["query"],
        }
        assert compute_scope_hash(scope_reordered) == h
