"""Unit tests for nostr_agent.validation -- structural validators.

Covers: validate_d_tag, validate_capability, validate_capabilities,
validate_version, validate_name, validate_description, validate_relay_urls,
validate_pubkey_hex, validate_timestamp, validate_confidence,
validate_content_size, validate_tag_count, validate_url.

All individual validators return bool (never raise).
"""

from __future__ import annotations

import time

import pytest

from nostr_agent.validation import (
    validate_capability,
    validate_capabilities,
    validate_confidence,
    validate_content_size,
    validate_d_tag,
    validate_description,
    validate_name,
    validate_pubkey_hex,
    validate_relay_urls,
    validate_tag_count,
    validate_timestamp,
    validate_url,
    validate_version,
)


# ===========================================================================
# validate_d_tag
# ===========================================================================


class TestValidateDTag:
    """d-tag: lowercase alphanumeric/dot/dash/underscore, 2-128 chars."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "d_tag",
        [
            "weather-v1",
            "a1",
            "my.agent-name_v2",
            "ab",                          # minimum length (2)
            "x" * 128,                     # maximum length (128)
            "agent-001",
            "data.aggregation",
            "foo_bar",
            "0a",
        ],
    )
    def test_valid(self, d_tag: str):
        assert validate_d_tag(d_tag) is True

    @pytest.mark.unit
    def test_too_short_single_char(self):
        assert validate_d_tag("a") is False

    @pytest.mark.unit
    def test_empty_string(self):
        assert validate_d_tag("") is False

    @pytest.mark.unit
    def test_too_long(self):
        assert validate_d_tag("x" * 129) is False

    @pytest.mark.unit
    def test_uppercase_rejected(self):
        assert validate_d_tag("WeatherAgent") is False

    @pytest.mark.unit
    def test_starts_with_dash(self):
        assert validate_d_tag("-start") is False

    @pytest.mark.unit
    def test_ends_with_dash(self):
        assert validate_d_tag("end-") is False

    @pytest.mark.unit
    def test_starts_with_dot(self):
        assert validate_d_tag(".start") is False

    @pytest.mark.unit
    def test_ends_with_dot(self):
        assert validate_d_tag("end.") is False

    @pytest.mark.unit
    def test_starts_with_underscore(self):
        assert validate_d_tag("_start") is False

    @pytest.mark.unit
    def test_ends_with_underscore(self):
        assert validate_d_tag("end_") is False

    @pytest.mark.unit
    def test_spaces_rejected(self):
        assert validate_d_tag("has space") is False

    @pytest.mark.unit
    def test_special_chars_rejected(self):
        assert validate_d_tag("no!excl") is False

    @pytest.mark.unit
    def test_non_string_rejected(self):
        assert validate_d_tag(123) is False  # type: ignore[arg-type]

    @pytest.mark.unit
    def test_none_rejected(self):
        assert validate_d_tag(None) is False  # type: ignore[arg-type]


# ===========================================================================
# validate_capability
# ===========================================================================


class TestValidateCapability:
    """Single capability label: [a-z0-9-]{1,64}."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "cap",
        [
            "weather-forecast",
            "a",
            "data-aggregation",
            "x" * 64,           # maximum length
            "a-b-c",
            "123",
            "tool-use",
        ],
    )
    def test_valid(self, cap: str):
        assert validate_capability(cap) is True

    @pytest.mark.unit
    def test_empty_string(self):
        assert validate_capability("") is False

    @pytest.mark.unit
    def test_uppercase_rejected(self):
        assert validate_capability("UPPER") is False

    @pytest.mark.unit
    def test_mixed_case_rejected(self):
        assert validate_capability("Mixed") is False

    @pytest.mark.unit
    def test_space_rejected(self):
        assert validate_capability("with space") is False

    @pytest.mark.unit
    def test_too_long(self):
        assert validate_capability("x" * 65) is False

    @pytest.mark.unit
    def test_special_char_rejected(self):
        assert validate_capability("special!char") is False

    @pytest.mark.unit
    def test_underscore_rejected(self):
        """Capability regex is [a-z0-9-] -- underscore not allowed."""
        assert validate_capability("has_underscore") is False

    @pytest.mark.unit
    def test_dot_rejected(self):
        assert validate_capability("has.dot") is False


# ===========================================================================
# validate_capabilities
# ===========================================================================


class TestValidateCapabilities:
    """List of capabilities: at least 1, all pass regex."""

    @pytest.mark.unit
    def test_valid_single(self):
        assert validate_capabilities(["weather-forecast"]) is True

    @pytest.mark.unit
    def test_valid_multiple(self):
        assert validate_capabilities(["a", "b", "c"]) is True

    @pytest.mark.unit
    def test_empty_list_fails(self):
        assert validate_capabilities([]) is False

    @pytest.mark.unit
    def test_one_invalid_in_list_fails(self):
        assert validate_capabilities(["valid", "INVALID"]) is False

    @pytest.mark.unit
    def test_non_list_fails(self):
        assert validate_capabilities("not-a-list") is False  # type: ignore[arg-type]

    @pytest.mark.unit
    def test_none_fails(self):
        assert validate_capabilities(None) is False  # type: ignore[arg-type]


# ===========================================================================
# validate_version
# ===========================================================================


class TestValidateVersion:
    """Semantic version: major.minor.patch (strict, no pre-release)."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "version",
        ["1.0.0", "0.1.0", "99.99.99", "0.0.0", "10.20.30"],
    )
    def test_valid(self, version: str):
        assert validate_version(version) is True

    @pytest.mark.unit
    def test_two_parts_invalid(self):
        assert validate_version("1.0") is False

    @pytest.mark.unit
    def test_prefix_v_invalid(self):
        assert validate_version("v1.0.0") is False

    @pytest.mark.unit
    def test_prerelease_invalid(self):
        assert validate_version("1.0.0-beta") is False

    @pytest.mark.unit
    def test_build_metadata_invalid(self):
        assert validate_version("1.0.0+build") is False

    @pytest.mark.unit
    def test_empty_invalid(self):
        assert validate_version("") is False

    @pytest.mark.unit
    def test_four_parts_invalid(self):
        assert validate_version("1.2.3.4") is False


# ===========================================================================
# validate_name
# ===========================================================================


class TestValidateName:
    """Agent name: 1-128 chars, non-empty after stripping."""

    @pytest.mark.unit
    def test_valid_simple(self):
        assert validate_name("WeatherAgent") is True

    @pytest.mark.unit
    def test_valid_single_char(self):
        assert validate_name("a") is True

    @pytest.mark.unit
    def test_valid_max_length(self):
        assert validate_name("x" * 128) is True

    @pytest.mark.unit
    def test_empty_fails(self):
        assert validate_name("") is False

    @pytest.mark.unit
    def test_whitespace_only_fails(self):
        assert validate_name("   ") is False

    @pytest.mark.unit
    def test_too_long(self):
        assert validate_name("x" * 129) is False

    @pytest.mark.unit
    def test_strips_whitespace(self):
        """Name with leading/trailing spaces is valid if core is 1-128."""
        assert validate_name("  agent  ") is True


# ===========================================================================
# validate_description
# ===========================================================================


class TestValidateDescription:
    """Agent description: 1-512 chars."""

    @pytest.mark.unit
    def test_valid(self):
        assert validate_description("A weather forecasting agent.") is True

    @pytest.mark.unit
    def test_valid_max_length(self):
        assert validate_description("x" * 512) is True

    @pytest.mark.unit
    def test_empty_fails(self):
        assert validate_description("") is False

    @pytest.mark.unit
    def test_too_long(self):
        assert validate_description("x" * 513) is False

    @pytest.mark.unit
    def test_whitespace_only_fails(self):
        assert validate_description("   ") is False


# ===========================================================================
# validate_relay_urls
# ===========================================================================


class TestValidateRelayUrls:
    """Relay URL list: 1-10 URLs, all match wss?:// pattern."""

    @pytest.mark.unit
    def test_valid_single_wss(self):
        assert validate_relay_urls(["wss://relay.example.com"]) is True

    @pytest.mark.unit
    def test_valid_single_ws(self):
        assert validate_relay_urls(["ws://localhost:7771"]) is True

    @pytest.mark.unit
    def test_valid_multiple(self):
        urls = [f"wss://relay{i}.example.com" for i in range(10)]
        assert validate_relay_urls(urls) is True

    @pytest.mark.unit
    def test_empty_list_fails(self):
        assert validate_relay_urls([]) is False

    @pytest.mark.unit
    def test_11_urls_fails(self):
        urls = [f"wss://relay{i}.example.com" for i in range(11)]
        assert validate_relay_urls(urls) is False

    @pytest.mark.unit
    def test_non_ws_url_fails(self):
        assert validate_relay_urls(["https://relay.example.com"]) is False

    @pytest.mark.unit
    def test_http_url_fails(self):
        assert validate_relay_urls(["http://relay.example.com"]) is False

    @pytest.mark.unit
    def test_mixed_valid_and_invalid_fails(self):
        assert validate_relay_urls(["wss://good.com", "http://bad.com"]) is False

    @pytest.mark.unit
    def test_non_list_fails(self):
        assert validate_relay_urls("wss://relay.example.com") is False  # type: ignore[arg-type]


# ===========================================================================
# validate_pubkey_hex
# ===========================================================================


class TestValidatePubkeyHex:
    """64-char lowercase hex public key."""

    @pytest.mark.unit
    def test_valid_64_lowercase_hex(self):
        pk = "a" * 64
        assert validate_pubkey_hex(pk) is True

    @pytest.mark.unit
    def test_valid_mixed_hex(self):
        pk = "0123456789abcdef" * 4
        assert validate_pubkey_hex(pk) is True

    @pytest.mark.unit
    def test_wrong_length_63(self):
        assert validate_pubkey_hex("a" * 63) is False

    @pytest.mark.unit
    def test_wrong_length_65(self):
        assert validate_pubkey_hex("a" * 65) is False

    @pytest.mark.unit
    def test_uppercase_rejected(self):
        assert validate_pubkey_hex("A" * 64) is False

    @pytest.mark.unit
    def test_mixed_case_rejected(self):
        pk = "aAbBcCdD" * 8
        assert validate_pubkey_hex(pk) is False

    @pytest.mark.unit
    def test_non_hex_rejected(self):
        pk = "g" * 64
        assert validate_pubkey_hex(pk) is False

    @pytest.mark.unit
    def test_empty_rejected(self):
        assert validate_pubkey_hex("") is False


# ===========================================================================
# validate_timestamp
# ===========================================================================


class TestValidateTimestamp:
    """Timestamp: positive, not before 2024-01-01, not >300s in the future."""

    @pytest.mark.unit
    def test_valid_recent(self):
        ts = int(time.time()) - 60  # 1 minute ago
        assert validate_timestamp(ts) is True

    @pytest.mark.unit
    def test_valid_now(self):
        ts = int(time.time())
        assert validate_timestamp(ts) is True

    @pytest.mark.unit
    def test_valid_5_min_future(self):
        """Exactly 300s in the future should pass (boundary)."""
        ts = int(time.time()) + 300
        assert validate_timestamp(ts) is True

    @pytest.mark.unit
    def test_invalid_far_future(self):
        """301s in the future should fail."""
        ts = int(time.time()) + 301
        assert validate_timestamp(ts) is False

    @pytest.mark.unit
    def test_invalid_before_2024(self):
        """2023-12-31 should fail (< 1704067200)."""
        assert validate_timestamp(1704067199) is False

    @pytest.mark.unit
    def test_valid_exactly_2024_start(self):
        """2024-01-01T00:00:00Z should pass."""
        assert validate_timestamp(1704067200) is True

    @pytest.mark.unit
    def test_invalid_zero(self):
        assert validate_timestamp(0) is False

    @pytest.mark.unit
    def test_invalid_negative(self):
        assert validate_timestamp(-1) is False

    @pytest.mark.unit
    def test_non_int_fails(self):
        assert validate_timestamp(1704067200.5) is False  # type: ignore[arg-type]

    @pytest.mark.unit
    def test_string_fails(self):
        assert validate_timestamp("1704067200") is False  # type: ignore[arg-type]


# ===========================================================================
# validate_confidence
# ===========================================================================


class TestValidateConfidence:
    """Confidence score: float in [0.0, 1.0]."""

    @pytest.mark.unit
    def test_valid_zero(self):
        assert validate_confidence(0.0) is True

    @pytest.mark.unit
    def test_valid_one(self):
        assert validate_confidence(1.0) is True

    @pytest.mark.unit
    def test_valid_half(self):
        assert validate_confidence(0.5) is True

    @pytest.mark.unit
    def test_invalid_negative(self):
        assert validate_confidence(-0.1) is False

    @pytest.mark.unit
    def test_invalid_above_one(self):
        assert validate_confidence(1.1) is False

    @pytest.mark.unit
    def test_int_zero_valid(self):
        """Integer 0 should be accepted (isinstance check allows int)."""
        assert validate_confidence(0) is True

    @pytest.mark.unit
    def test_int_one_valid(self):
        assert validate_confidence(1) is True

    @pytest.mark.unit
    def test_string_fails(self):
        assert validate_confidence("0.5") is False  # type: ignore[arg-type]

    @pytest.mark.unit
    def test_none_fails(self):
        assert validate_confidence(None) is False  # type: ignore[arg-type]


# ===========================================================================
# validate_content_size
# ===========================================================================


class TestValidateContentSize:
    """Event content size: default limit 8192 bytes."""

    @pytest.mark.unit
    def test_under_limit_passes(self):
        content = "x" * 8000
        assert validate_content_size(content) is True

    @pytest.mark.unit
    def test_exactly_at_limit_passes(self):
        content = "x" * 8192
        assert validate_content_size(content) is True

    @pytest.mark.unit
    def test_over_limit_fails(self):
        content = "x" * 8193
        assert validate_content_size(content) is False

    @pytest.mark.unit
    def test_empty_content_passes(self):
        assert validate_content_size("") is True

    @pytest.mark.unit
    def test_custom_limit(self):
        content = "x" * 100
        assert validate_content_size(content, max_bytes=50) is False
        assert validate_content_size(content, max_bytes=200) is True

    @pytest.mark.unit
    def test_utf8_multibyte_chars(self):
        """Multi-byte UTF-8 characters count correctly."""
        # Each emoji is ~4 bytes in UTF-8
        content = "\U0001f600" * 2048  # 2048 * 4 = 8192 bytes
        assert validate_content_size(content) is True
        content_over = "\U0001f600" * 2049  # 2049 * 4 = 8196 bytes
        assert validate_content_size(content_over) is False

    @pytest.mark.unit
    def test_non_string_fails(self):
        assert validate_content_size(12345) is False  # type: ignore[arg-type]


# ===========================================================================
# validate_tag_count
# ===========================================================================


class TestValidateTagCount:
    """Event tag count: default limit 50."""

    @pytest.mark.unit
    def test_50_passes(self):
        tags = [["t", f"tag{i}"] for i in range(50)]
        assert validate_tag_count(tags) is True

    @pytest.mark.unit
    def test_51_fails(self):
        tags = [["t", f"tag{i}"] for i in range(51)]
        assert validate_tag_count(tags) is False

    @pytest.mark.unit
    def test_empty_list_passes(self):
        assert validate_tag_count([]) is True

    @pytest.mark.unit
    def test_custom_limit(self):
        tags = [["t"]] * 10
        assert validate_tag_count(tags, max_tags=5) is False
        assert validate_tag_count(tags, max_tags=10) is True

    @pytest.mark.unit
    def test_non_list_fails(self):
        assert validate_tag_count("not a list") is False  # type: ignore[arg-type]


# ===========================================================================
# validate_url
# ===========================================================================


class TestValidateUrl:
    """Endpoint URL: http(s) or ws(s) scheme."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "url",
        [
            "https://api.example.com/v1",
            "http://localhost:8080",
            "wss://relay.example.com",
            "ws://localhost:7771",
        ],
    )
    def test_valid(self, url: str):
        assert validate_url(url) is True

    @pytest.mark.unit
    def test_ftp_rejected(self):
        assert validate_url("ftp://files.example.com") is False

    @pytest.mark.unit
    def test_empty_rejected(self):
        assert validate_url("") is False

    @pytest.mark.unit
    def test_bare_domain_rejected(self):
        assert validate_url("example.com") is False

    @pytest.mark.unit
    def test_non_string_rejected(self):
        assert validate_url(None) is False  # type: ignore[arg-type]
