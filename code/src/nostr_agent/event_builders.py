"""JSON content builders for Kind 38100, 38101, 38102 with deterministic serialization.

Each builder returns a dict. Use json.dumps(dict, sort_keys=True, separators=(',', ':'))
for canonical JSON matching Nostr event spec. This module has no external dependencies
beyond Python stdlib to avoid circular imports.
"""

from typing import Optional, Dict, List, Any
import json as _json_module


def build_kind_38100_content(
    name: str,
    version: str,
    description: str,
    status: str,
    capabilities: List[str],
    operator: str,
    created: int,
    endpoints: Optional[Dict[str, str]] = None,
    trust_policy: Optional[Dict[str, Any]] = None,
    rotation_proof: Optional[str] = None,
) -> Dict[str, Any]:
    """Kind 38100 -- Agent Identity Declaration content.

    Args:
        name: Human-readable agent name (1-128 chars)
        version: Semantic version (X.Y.Z)
        description: Agent purpose (1-512 chars)
        status: "active" | "rotated" | "decommissioned"
        capabilities: List of capability labels (sorted, non-empty)
        operator: Operator pubkey (64-char hex, must match p tag)
        created: Unix timestamp (must match event created_at)
        endpoints: Optional dict of protocol endpoints {protocol: url}
        trust_policy: Optional dict {min_attestation_count, trust_decay_per_hop, max_trust_depth, require_l402}
        rotation_proof: BIP340 sig (128-char hex, required on rotation only)

    Returns:
        Dict with all required/optional fields. Omits None fields.
    """
    content = {
        "name": name,
        "version": version,
        "description": description,
        "status": status,
        "capabilities": sorted(capabilities),  # Deterministic ordering
        "operator": operator,
        "created": created,
    }

    if endpoints is not None:
        content["endpoints"] = endpoints
    if trust_policy is not None:
        content["trust_policy"] = trust_policy
    if rotation_proof is not None:
        content["rotation_proof"] = rotation_proof

    return content


def build_kind_38101_content(
    scope_capabilities: List[str],
    scope_resources: List[str],
    scope_actions: List[str],
    expires_at: int,
    max_chain_depth: int,
    current_depth: int,
    issued_at: int,
    parent_delegation: Optional[str] = None,
    revocation_status: str = "active",
    reason: Optional[str] = None,
    rate_limit_hint: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Kind 38101 -- Delegation Chain Event content.

    Args:
        scope_capabilities: Delegated capabilities (sorted, non-empty)
        scope_resources: Delegated resources (sorted, may be empty = unrestricted)
        scope_actions: Delegated actions (sorted, may be empty = unrestricted)
        expires_at: Delegation expiration (Unix ts, > issued_at)
        max_chain_depth: Max permitted chain depth (>= 1)
        current_depth: This delegation's depth (1 for root, >= parent+1 for sub)
        issued_at: Issuance timestamp (>= parent issued_at)
        parent_delegation: Parent coordinate string (null for root, coord for sub)
        revocation_status: "active" | "revoked"
        reason: "routine" | "compromise" | "decommission" | null
        rate_limit_hint: Optional {"max_requests": int, "window_seconds": int}

    Returns:
        Dict with canonical scope/constraints nesting.
    """
    content = {
        "schema_version": "1.0",
        "scope": {
            "capabilities": sorted(scope_capabilities),
            "resources": sorted(scope_resources),
            "actions": sorted(scope_actions),
        },
        "constraints": {
            "expires_at": expires_at,
            "max_chain_depth": max_chain_depth,
            "current_depth": current_depth,
        },
        "parent_delegation": parent_delegation,
        "issued_at": issued_at,
        "revocation_status": revocation_status,
        "reason": reason,
    }

    if rate_limit_hint is not None:
        content["constraints"]["rate_limit_hint"] = rate_limit_hint
    else:
        content["constraints"]["rate_limit_hint"] = None

    return content


def build_kind_38102_content(
    attestee: str,
    capability: str,
    confidence: float,
    issued_at: int,
    evidence: Optional[Dict[str, Any]] = None,
    context: Optional[str] = None,
) -> Dict[str, Any]:
    """Kind 38102 -- Peer Attestation Event content.

    Args:
        attestee: Attestee pubkey (64-char hex, must match p tag)
        capability: Capability label (must match t tag)
        confidence: Trust edge weight (0.0-1.0, float)
        issued_at: Issuance timestamp (Unix ts)
        evidence: Optional {"interaction_count", "success_rate", "first_interaction", "last_interaction"}
        context: Optional human-readable context (max 1024 chars)

    Returns:
        Dict with canonical field ordering. Confidence is preserved as-is (no rounding).
    """
    content = {
        "attestee": attestee,
        "capability": capability,
        "confidence": confidence,  # Preserved as float with full precision
        "issued_at": issued_at,
    }

    if evidence is not None:
        content["evidence"] = evidence
    if context is not None:
        content["context"] = context

    return content


def serialize_event_content(content: Dict[str, Any]) -> str:
    """Canonical JSON serialization for Nostr event content.

    Args:
        content: Event content dict (from builder functions)

    Returns:
        Canonical JSON string: sorted keys, compact separators, UTF-8, no trailing whitespace.
        This is deterministic: same dict always produces identical bytes (suitable for hashing/signing).
    """
    return _json_module.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


