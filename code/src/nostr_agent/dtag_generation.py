"""Deterministic d-tag generation for Kind 38101 delegation events.

Algorithm: SHA256(delegator_pk || delegatee_pk || scope_hash || created_at)[:16]
where scope_hash = SHA256(canonical_json(scope)).

Canonical JSON: keys sorted ("actions", "capabilities", "resources"), arrays
lexicographically sorted, compact (separators=(",",":")), ensure_ascii=True.
"""

import hashlib
import json
from typing import Any


def compute_scope_hash(scope: dict[str, Any]) -> str:
    """Generate SHA256 hash of canonical scope JSON.

    Keys always in order: actions, capabilities, resources.
    Arrays internally sorted lexicographically.
    Output: 64-char lowercase hex.
    """
    canonical = json.dumps(
        {
            "actions": sorted(scope.get("actions", [])),
            "capabilities": sorted(scope.get("capabilities", [])),
            "resources": sorted(scope.get("resources", [])),
        },
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_d_tag(
    delegator_pubkey: str,
    delegatee_pubkey: str,
    scope: dict[str, Any],
    created_at: int,
) -> str:
    """Generate 16-char deterministic d-tag for Kind 38101.

    Args:
        delegator_pubkey: Delegator's hex pubkey (64 chars).
        delegatee_pubkey: Delegatee's hex pubkey (64 chars).
        scope: Dict with "actions", "capabilities", "resources" arrays.
        created_at: Event creation timestamp (Unix seconds).

    Returns:
        16-char lowercase hex string. Deterministic and collision-resistant.
    """
    scope_hash = compute_scope_hash(scope)
    preimage = f"{delegator_pubkey}{delegatee_pubkey}{scope_hash}{created_at}"
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()[:16]


def verify_d_tag_determinism(
    delegator_pk: str,
    delegatee_pk: str,
    scope: dict[str, Any],
    created_at: int,
    expected_d_tag: str,
) -> bool:
    """Verify that same inputs always produce expected d-tag."""
    return compute_d_tag(delegator_pk, delegatee_pk, scope, created_at) == expected_d_tag


