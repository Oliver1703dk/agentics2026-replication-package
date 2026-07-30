"""Delegation scope: three-dimensional capability/resource/action model.

Implements the scope type used in Kind 38101 delegation chain events.
Each dimension uses empty-set-as-unrestricted semantics for resources and actions;
capabilities always require explicit subset containment.

Canonical hash is SHA256 of compact JSON with sorted keys and sorted arrays,
suitable for the Kind 38101 'd' tag deduplication.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

_CAP_RE = re.compile(r"^[a-z0-9-]{1,64}$")
_ACTION_RE = re.compile(r"^[a-z0-9_\-\.]{1,64}$")
_RESOURCE_MAX = 256


class ScopeValidationError(ValueError):
    """Raised when a scope field fails format constraints."""


def _validate_capability(cap: str) -> None:
    if not _CAP_RE.match(cap):
        raise ScopeValidationError(
            f"Invalid capability {cap!r}: must match ^[a-z0-9-]{{1,64}}$"
        )


def _validate_resource(res: str) -> None:
    if len(res) > _RESOURCE_MAX:
        raise ScopeValidationError(
            f"Resource {res!r} exceeds {_RESOURCE_MAX} characters"
        )


def _validate_action(act: str) -> None:
    if not _ACTION_RE.match(act):
        raise ScopeValidationError(
            f"Invalid action {act!r}: must match ^[a-z0-9_\\-\\.]{{1,64}}$"
        )


@dataclass(frozen=True)
class DelegationScope:
    """Immutable, lexicographically-sorted three-dimensional scope.

    Fields are stored as sorted tuples (no duplicates) to guarantee a
    canonical in-memory representation and stable hash output.

    Empty tuple == unrestricted for resources and actions.
    Capabilities must always be explicitly listed (empty = no capabilities).
    """

    capabilities: tuple[str, ...]
    resources: tuple[str, ...]
    actions: tuple[str, ...]

    @staticmethod
    def create(
        capabilities: list[str] | tuple[str, ...] | None = None,
        resources: list[str] | tuple[str, ...] | None = None,
        actions: list[str] | tuple[str, ...] | None = None,
    ) -> "DelegationScope":
        """Validate inputs and return an immutable DelegationScope.

        Duplicates are detected and rejected (not silently deduplicated) to
        surface authoring bugs early.
        """
        caps = list(capabilities or [])
        ress = list(resources or [])
        acts = list(actions or [])

        for cap in caps:
            _validate_capability(cap)
        for res in ress:
            _validate_resource(res)
        for act in acts:
            _validate_action(act)

        for label, lst in (("capabilities", caps), ("resources", ress), ("actions", acts)):
            seen: set[str] = set()
            for item in lst:
                if item in seen:
                    raise ScopeValidationError(
                        f"Duplicate {label} entry: {item!r}"
                    )
                seen.add(item)

        return DelegationScope(
            capabilities=tuple(sorted(caps)),
            resources=tuple(sorted(ress)),
            actions=tuple(sorted(acts)),
        )

    # ------------------------------------------------------------------
    # Attenuation
    # ------------------------------------------------------------------

    def attenuates(self, parent: "DelegationScope") -> bool:
        """Return True iff self is a valid attenuation of parent.

        Rules:
        - capabilities: set(child) ⊆ set(parent), no empty-set bypass.
        - resources: empty parent = unrestricted; non-empty parent requires
          set(child) ⊆ set(parent).
        - actions: same empty-set semantics as resources.
        """
        if not set(self.capabilities) <= set(parent.capabilities):
            return False
        if parent.resources and not set(self.resources) <= set(parent.resources):
            return False
        if parent.actions and not set(self.actions) <= set(parent.actions):
            return False
        return True

    # ------------------------------------------------------------------
    # Canonical hash (d-tag)
    # ------------------------------------------------------------------

    def canonical_json(self) -> str:
        """Compact JSON with sorted keys and sorted arrays -- no whitespace."""
        return json.dumps(
            {
                "actions": list(self.actions),
                "capabilities": list(self.capabilities),
                "resources": list(self.resources),
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    def scope_hash(self) -> str:
        """SHA256 hex digest of the canonical JSON serialization."""
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()

    # ------------------------------------------------------------------
    # Intersection
    # ------------------------------------------------------------------

    def intersect(self, other: "DelegationScope") -> "DelegationScope":
        """Return the intersection of two scopes (most restrictive combination).

        For resources and actions, empty means unrestricted:
        - unrestricted ∩ X  = X
        - X ∩ unrestricted  = X
        - X ∩ Y             = X ∩ Y  (set intersection)
        """
        caps = tuple(sorted(set(self.capabilities) & set(other.capabilities)))

        if not self.resources:
            ress = other.resources
        elif not other.resources:
            ress = self.resources
        else:
            ress = tuple(sorted(set(self.resources) & set(other.resources)))

        if not self.actions:
            acts = other.actions
        elif not other.actions:
            acts = self.actions
        else:
            acts = tuple(sorted(set(self.actions) & set(other.actions)))

        return DelegationScope(capabilities=caps, resources=ress, actions=acts)

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def __str__(self) -> str:
        """Human-readable representation for CLI output."""
        parts = []
        parts.append(
            "capabilities: "
            + (", ".join(self.capabilities) if self.capabilities else "(none)")
        )
        parts.append(
            "resources: "
            + (", ".join(self.resources) if self.resources else "(unrestricted)")
        )
        parts.append(
            "actions: "
            + (", ".join(self.actions) if self.actions else "(unrestricted)")
        )
        return "  " + "\n  ".join(parts)
