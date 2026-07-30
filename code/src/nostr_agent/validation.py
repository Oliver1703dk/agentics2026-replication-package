"""Structural validation for events and delegation chain invariants.

Provides: (1) compiled regex patterns for d-tag, capability labels, hex strings, semver;
(2) content size, tag count, timestamp, and URL validators; (3) validate_event_structure()
for comprehensive event validation; (4) validate_chain() for delegation chain invariants.

All individual validators return bool (never raise) for composability.
Higher-level validators (validate_event_structure, validate_chain) raise ValidationError
with descriptive messages.
"""

from __future__ import annotations

import re
import time
from typing import Any

from nostr_agent.types import DelegationChain, DelegationLink


class ValidationError(Exception):
    """Raised when an event or chain fails structural validation."""


# =============================================================================
# COMPILED REGEX PATTERNS
# =============================================================================

# d-tag: lowercase alphanumeric, dot, dash, underscore. Length 2-128, not starting/ending with special.
PATTERN_D_TAG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,126}[a-z0-9]$")

# Capability label: lowercase alphanumeric + dash, 1-64 chars
PATTERN_CAPABILITY = re.compile(r"^[a-z0-9-]{1,64}$")

# Hex string (64 chars): SHA256 or public key hex representation (lowercase only)
PATTERN_HEX_64 = re.compile(r"^[0-9a-f]{64}$")

# Semantic version: major.minor.patch (strict, no pre-release/build metadata per plan)
PATTERN_SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")

# Relay URL: wss:// or ws:// followed by non-whitespace
PATTERN_RELAY_URL = re.compile(
    r"^wss?://[^\s]+$"
)

# General URL: http(s) or ws(s)
PATTERN_URL = re.compile(r"^(https?|wss?)://[^\s]+$")

# Earliest valid timestamp: 2024-01-01T00:00:00Z
_MIN_TIMESTAMP = 1704067200


# =============================================================================
# INDIVIDUAL VALIDATORS (all return bool, never raise)
# =============================================================================

def validate_d_tag(d_tag: str) -> bool:
    """Validate d-tag format: lowercase alphanumeric/dot/dash/underscore, 2-128 chars."""
    if not isinstance(d_tag, str) or not d_tag:
        return False
    if len(d_tag) < 2 or len(d_tag) > 128:
        return False
    return PATTERN_D_TAG.match(d_tag) is not None


def validate_capability(cap: str) -> bool:
    """Validate a single capability label: lowercase alphanumeric + dash, 1-64 chars."""
    if not isinstance(cap, str) or not cap:
        return False
    return PATTERN_CAPABILITY.match(cap) is not None


def validate_capabilities(caps: list[str]) -> bool:
    """Validate a list of capabilities: at least 1, all pass regex."""
    if not isinstance(caps, list) or len(caps) == 0:
        return False
    return all(validate_capability(c) for c in caps)


def validate_version(version: str) -> bool:
    """Validate semantic version string (major.minor.patch)."""
    if not isinstance(version, str) or not version:
        return False
    return PATTERN_SEMVER.match(version) is not None


def validate_name(name: str) -> bool:
    """Validate agent name: 1-128 chars, non-empty after stripping."""
    if not isinstance(name, str):
        return False
    stripped = name.strip()
    return 1 <= len(stripped) <= 128


def validate_description(desc: str) -> bool:
    """Validate agent description: 1-512 chars."""
    if not isinstance(desc, str):
        return False
    stripped = desc.strip()
    return 1 <= len(stripped) <= 512


def validate_relay_urls(urls: list[str]) -> bool:
    """Validate relay URL list: 1-10 URLs, all match wss?:// pattern."""
    if not isinstance(urls, list) or not (1 <= len(urls) <= 10):
        return False
    return all(
        isinstance(u, str) and PATTERN_RELAY_URL.match(u) is not None
        for u in urls
    )


def validate_pubkey_hex(pk: str) -> bool:
    """Validate 64-char lowercase hex public key."""
    if not isinstance(pk, str) or len(pk) != 64:
        return False
    return PATTERN_HEX_64.match(pk) is not None


def validate_content_size(content: str, max_bytes: int = 8192) -> bool:
    """Validate event content does not exceed size limit (default 8 KB)."""
    if not isinstance(content, (str, bytes)):
        return False
    size = len(content.encode("utf-8") if isinstance(content, str) else content)
    return size <= max_bytes


def validate_tag_count(tags: list, max_tags: int = 50) -> bool:
    """Validate event tag count does not exceed limit (default 50)."""
    if not isinstance(tags, list):
        return False
    return len(tags) <= max_tags


def validate_timestamp(ts: int) -> bool:
    """Validate timestamp: positive, not before 2024-01-01, not >300s in the future."""
    if not isinstance(ts, int) or ts <= 0:
        return False
    if ts < _MIN_TIMESTAMP:
        return False
    now = int(time.time())
    if ts > now + 300:
        return False
    return True


def validate_confidence(confidence: float) -> bool:
    """Validate confidence score: float in [0.0, 1.0]."""
    if not isinstance(confidence, (int, float)):
        return False
    return 0.0 <= float(confidence) <= 1.0


def validate_url(url: str) -> bool:
    """Validate endpoint URL: http(s) or ws(s) scheme."""
    if not isinstance(url, str) or not url:
        return False
    return PATTERN_URL.match(url) is not None


# =============================================================================
# COMPREHENSIVE EVENT VALIDATION (raises ValidationError)
# =============================================================================

def validate_event_structure(event_dict: dict[str, Any]) -> None:
    """Validate common NostrAgent event structure.

    Checks: kind, pubkey hex, content size, tag count, timestamp future-bound.

    Raises ValidationError on failure.
    """
    # Required fields
    for field_name in ("kind", "pubkey", "content", "tags", "created_at"):
        if field_name not in event_dict:
            raise ValidationError(f"Event missing required field: '{field_name}'")

    kind = event_dict["kind"]
    if not isinstance(kind, int) or kind < 0:
        raise ValidationError(f"kind must be non-negative int, got {kind!r}")

    # Validate pubkey is 64-char lowercase hex
    if not validate_pubkey_hex(event_dict["pubkey"]):
        raise ValidationError(
            f"Invalid pubkey: must be 64 lowercase hex chars, got {event_dict['pubkey']!r}"
        )

    # Validate content size
    if not validate_content_size(event_dict["content"]):
        size = len(event_dict["content"].encode("utf-8") if isinstance(event_dict["content"], str) else event_dict["content"])
        raise ValidationError(f"Content size {size} bytes exceeds limit 8192")

    # Validate tag count
    if not validate_tag_count(event_dict["tags"]):
        raise ValidationError(f"Tag count {len(event_dict['tags'])} exceeds limit 50")

    # Validate timestamp
    if not validate_timestamp(event_dict["created_at"]):
        ts = event_dict["created_at"]
        now = int(time.time())
        if isinstance(ts, int) and ts < _MIN_TIMESTAMP:
            raise ValidationError(f"Timestamp {ts} is before 2024-01-01")
        elif isinstance(ts, int) and ts > now + 300:
            delta = ts - now
            raise ValidationError(f"Timestamp {delta}s in future exceeds tolerance 300s")
        else:
            raise ValidationError(f"Invalid timestamp: {ts!r}")


# =============================================================================
# DELEGATION CHAIN VALIDATION (raises ValidationError)
# =============================================================================

def validate_chain(chain: DelegationChain) -> None:
    """Validate a delegation chain end-to-end.

    Checks:
    - At least one link
    - Each link's delegatee matches next link's delegator (continuity)
    - Each link's scopes attenuate the previous link's scopes (attenuation invariant)

    Raises ValidationError on failure.
    """
    if not chain.links:
        raise ValidationError("Delegation chain must contain at least one link")

    for i, link in enumerate(chain.links[1:], start=1):
        prev = chain.links[i - 1]
        if link.delegator_pubkey != prev.delegatee_pubkey:
            raise ValidationError(
                f"Chain continuity broken at link {i}: "
                f"delegator {link.delegator_pubkey!r} != "
                f"previous delegatee {prev.delegatee_pubkey!r}"
            )
        _validate_scope_attenuation(prev, link, i)


def _validate_scope_attenuation(
    parent_link: DelegationLink, child_link: DelegationLink, index: int
) -> None:
    """Assert each child scope attenuates a matching parent scope."""
    parent_scopes = {s.resource: s for s in parent_link.scopes}
    for child_scope in child_link.scopes:
        parent_scope = parent_scopes.get(child_scope.resource)
        if parent_scope is None:
            raise ValidationError(
                f"Link {index}: child scope resource {child_scope.resource!r} "
                "not present in parent scopes"
            )
        if not child_scope.attenuates(parent_scope):
            raise ValidationError(
                f"Link {index}: child scope actions {child_scope.actions} "
                f"are not a subset of parent actions {parent_scope.actions}"
            )
