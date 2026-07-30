"""Kind 38101 delegation chain -- build helpers, full chain verification, and DelegationManager.

verify_chain() implements the 7-condition attenuation invariant (INV-1..INV-7)
from delegation_chain_formal.md and the chain walk algorithm from
event_spec_kind38101.md §6.

DelegationManager is the high-level class interface from prototype_specification.md §1.2,
wrapping the low-level functions with proper types and relay I/O.

Key design choices:
- All verification logic is synchronous over already-fetched events; relay I/O is
  isolated in the async fetch layer so the core algorithm is pure and testable.
- Fail-fast: the first violated invariant returns a typed ChainViolation immediately.
- Cycle detection uses event coordinates (kind:pubkey:d-tag) as the visited set.
- Empty set semantics (INV-2, INV-3): empty parent resources/actions = unrestricted;
  only non-empty parents require subset containment.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum, auto
from typing import TYPE_CHECKING, Awaitable, Callable

import nostr_sdk  # type: ignore[import]
import nostr_sdk as ns  # alias used by events.py patterns

from nostr_agent.crypto import compute_scope_hash, verify_event
from nostr_agent.types import (
    AttenuationError,
    ChainVerificationResult,
    Constraints,
    DelegationChain,
    DelegationLink,
    DepthExceededError,
    PublicKey,
    PublishError,
    PublishResult,
    Scope,
    SelfDelegationError,
    Signature,
)
from nostr_agent.validation import validate_chain

if TYPE_CHECKING:
    from nostr_agent.identity import AgentIdentity

logger = logging.getLogger(__name__)

KIND_IDENTITY = 38100
KIND_DELEGATION = 38101

# Clock skew tolerance for INV-5 (issued_at comparison), in seconds.
# A child issued_at may lag its parent by up to this many seconds (ADR clock-skew note).
CLOCK_SKEW_TOLERANCE: int = 60

# Guards against unbounded walks on pathologically malformed events.
MAX_CHAIN_DEPTH_HARD_CAP: int = 16


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class ViolationKind(Enum):
    INV_1_CAPABILITIES = auto()   # child capabilities not ⊆ parent
    INV_2_RESOURCES = auto()      # child resources not ⊆ parent (non-empty parent)
    INV_3_ACTIONS = auto()        # child actions not ⊆ parent (non-empty parent)
    INV_4_EXPIRY = auto()         # child expires_at > parent expires_at
    INV_5_ISSUED_AT = auto()      # child issued_at < parent issued_at − tolerance
    INV_6_DEPTH = auto()          # depth counter wrong or exceeds max_chain_depth
    INV_7_SIGNATURE = auto()      # BIP340 verify failed or delegator ≠ parent delegatee
    REVOKED = auto()              # revocation_status != "active" (cascade revocation)
    CYCLE = auto()                # event coordinate already in visited set
    RESOLUTION_FAILURE = auto()   # relay fetch returned None
    MALFORMED = auto()            # JSON parse error or missing required field
    ROOT_MISMATCH = auto()        # root anchor validation failed


@dataclass(frozen=True)
class ChainViolation:
    kind: ViolationKind
    depth: int     # hop index where violation was detected (0 = leaf)
    detail: str


@dataclass(frozen=True)
class VerifyResult:
    valid: bool
    violation: ChainViolation | None = None

    @classmethod
    def ok(cls) -> "VerifyResult":
        return cls(valid=True)

    @classmethod
    def fail(cls, kind: ViolationKind, depth: int, detail: str) -> "VerifyResult":
        return cls(valid=False, violation=ChainViolation(kind, depth, detail))


# ---------------------------------------------------------------------------
# Relay fetch type alias
# ---------------------------------------------------------------------------

# Async callable: a_tag_coordinate → nostr_sdk.Event | None.
# The coordinate is the raw "a" tag value, e.g. "38101:<pubkey>:<d-tag>".
EventFetcher = Callable[[str], Awaitable[nostr_sdk.Event | None]]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_tag(event: nostr_sdk.Event, name: str) -> str | None:
    """Return the first value of a named tag, or None if absent."""
    for tag in event.tags().to_vec():
        items = tag.as_vec()
        if items and items[0] == name and len(items) > 1:
            return items[1]
    return None


def _coordinate(event: nostr_sdk.Event) -> str:
    """Produce the NIP-01 parameterized replaceable event coordinate."""
    d = _get_tag(event, "d") or ""
    return f"{event.kind().as_u16()}:{event.author().to_hex()}:{d}"


def _parse_content(event: nostr_sdk.Event, depth: int) -> tuple[dict, VerifyResult | None]:
    try:
        return json.loads(event.content()), None
    except json.JSONDecodeError as exc:
        return {}, VerifyResult.fail(ViolationKind.MALFORMED, depth, f"JSON parse error: {exc}")


def _scoped_subset(child: list[str], parent: list[str]) -> bool:
    """Subset check with empty-set semantics: empty parent = unrestricted (always True)."""
    if not parent:
        return True
    return set(child) <= set(parent)


# ---------------------------------------------------------------------------
# Per-hop condition checks
# ---------------------------------------------------------------------------


def _check_7_conditions(
    child_content: dict,
    parent_content: dict,
    parent_p_tag: str,
    child_pubkey: str,
    depth: int,
) -> VerifyResult | None:
    """Check INV-1..INV-7 for a Kind-38101 → Kind-38101 hop.

    Returns the first failing VerifyResult, or None if all conditions pass.
    """
    c_scope = child_content.get("scope", {})
    p_scope = parent_content.get("scope", {})
    c_con = child_content.get("constraints", {})
    p_con = parent_content.get("constraints", {})

    # INV-1: capability subset (no empty-set exemption -- capabilities are always required)
    if not set(c_scope.get("capabilities", [])) <= set(p_scope.get("capabilities", [])):
        return VerifyResult.fail(
            ViolationKind.INV_1_CAPABILITIES, depth,
            f"child caps {c_scope.get('capabilities')} ⊄ parent {p_scope.get('capabilities')}",
        )

    # INV-2: resource subset (empty parent = unrestricted)
    if not _scoped_subset(c_scope.get("resources", []), p_scope.get("resources", [])):
        return VerifyResult.fail(
            ViolationKind.INV_2_RESOURCES, depth,
            f"child resources {c_scope.get('resources')} ⊄ parent {p_scope.get('resources')}",
        )

    # INV-3: action subset (empty parent = unrestricted)
    if not _scoped_subset(c_scope.get("actions", []), p_scope.get("actions", [])):
        return VerifyResult.fail(
            ViolationKind.INV_3_ACTIONS, depth,
            f"child actions {c_scope.get('actions')} ⊄ parent {p_scope.get('actions')}",
        )

    # INV-4: expiry narrows or stays equal
    if c_con.get("expires_at", 0) > p_con.get("expires_at", 0):
        return VerifyResult.fail(
            ViolationKind.INV_4_EXPIRY, depth,
            f"child expires_at {c_con.get('expires_at')} > parent {p_con.get('expires_at')}",
        )

    # INV-5: anti-backdating with clock skew tolerance
    child_iss = child_content.get("issued_at", 0)
    parent_iss = parent_content.get("issued_at", 0)
    if child_iss < parent_iss - CLOCK_SKEW_TOLERANCE:
        return VerifyResult.fail(
            ViolationKind.INV_5_ISSUED_AT, depth,
            f"child issued_at {child_iss} < parent {parent_iss} − {CLOCK_SKEW_TOLERANCE}s",
        )

    # INV-6: depth tracking (three sub-conditions)
    expected_depth = p_con.get("current_depth", 0) + 1
    c_depth = c_con.get("current_depth", -1)
    c_max = c_con.get("max_chain_depth", 0)
    p_max = p_con.get("max_chain_depth", 0)
    if c_depth != expected_depth:
        return VerifyResult.fail(
            ViolationKind.INV_6_DEPTH, depth,
            f"current_depth {c_depth} != expected {expected_depth}",
        )
    if c_depth > c_max:
        return VerifyResult.fail(
            ViolationKind.INV_6_DEPTH, depth,
            f"current_depth {c_depth} exceeds max_chain_depth {c_max}",
        )
    if c_max > p_max:
        return VerifyResult.fail(
            ViolationKind.INV_6_DEPTH, depth,
            f"child max_chain_depth {c_max} > parent max_chain_depth {p_max}",
        )

    # INV-7: cryptographic binding -- delegator must be parent's delegatee
    if child_pubkey != parent_p_tag:
        return VerifyResult.fail(
            ViolationKind.INV_7_SIGNATURE, depth,
            f"child pubkey {child_pubkey[:16]}… ≠ parent p-tag {parent_p_tag[:16]}…",
        )

    return None  # all conditions passed


def _check_root_anchor(
    child_content: dict,
    root_event: nostr_sdk.Event,
    child_pubkey: str,
    depth: int,
) -> VerifyResult | None:
    """Validate a root delegation (current_depth == 1) against its Kind 38100 anchor.

    Root-level rules differ from sub-delegation:
    - delegator pubkey must equal the operator identity pubkey
    - capabilities must be subset of identity's declared capabilities
    - current_depth must be 1
    - identity status must be "active"
    """
    try:
        root_content = json.loads(root_event.content())
    except json.JSONDecodeError as exc:
        return VerifyResult.fail(ViolationKind.MALFORMED, depth, f"root identity parse: {exc}")

    c_scope = child_content.get("scope", {})
    c_con = child_content.get("constraints", {})

    # Root identity must be active (decommissioned / rotated = reject)
    if root_content.get("status") != "active":
        return VerifyResult.fail(
            ViolationKind.REVOKED, depth,
            f"root identity status '{root_content.get('status')}' (not active)",
        )

    # Capability subset: root delegation cannot exceed identity's declared capabilities
    root_caps = root_content.get("capabilities", [])
    if not set(c_scope.get("capabilities", [])) <= set(root_caps):
        return VerifyResult.fail(
            ViolationKind.ROOT_MISMATCH, depth,
            f"root delegation caps {c_scope.get('capabilities')} ⊄ identity {root_caps}",
        )

    # Root delegation must be at depth 1
    if c_con.get("current_depth", -1) != 1:
        return VerifyResult.fail(
            ViolationKind.INV_6_DEPTH, depth,
            f"root delegation current_depth {c_con.get('current_depth')} != 1",
        )

    # INV-5 vs identity: issued_at >= identity created_at (with tolerance)
    c_con = child_content.get("constraints", {})
    root_created = root_content.get("created", root_event.created_at().as_secs())
    child_issued = c_con.get("issued_at", child_content.get("issued_at", 0))
    if child_issued < root_created - CLOCK_SKEW_TOLERANCE:
        return VerifyResult.fail(
            ViolationKind.INV_5_ISSUED_AT, depth,
            f"root delegation issued_at {child_issued} < identity created {root_created}",
        )

    # INV-4 vs identity: expires_at must not exceed identity's expiration tag (if present)
    root_exp_tag = _get_tag(root_event, "expiration")
    if root_exp_tag is not None:
        if c_con.get("expires_at", 0) > int(root_exp_tag):
            return VerifyResult.fail(
                ViolationKind.INV_4_EXPIRY, depth,
                f"root delegation expires_at {c_con.get('expires_at')} > identity expiration {root_exp_tag}",
            )

    # INV-7 for root: delegator pubkey must be the operator (root identity's pubkey)
    root_pubkey = root_event.author().to_hex()
    if child_pubkey != root_pubkey:
        return VerifyResult.fail(
            ViolationKind.ROOT_MISMATCH, depth,
            f"root delegation pubkey {child_pubkey[:16]}… ≠ operator {root_pubkey[:16]}…",
        )

    return None  # root anchor valid


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def verify_chain(
    leaf_event: nostr_sdk.Event,
    fetch_event: EventFetcher,
) -> VerifyResult:
    """Verify a Kind 38101 delegation chain from leaf to root Kind 38100 anchor.

    Enforces all properties from delegation_chain_formal.md:
    - INV-1..INV-7 at every hop (7-condition attenuation invariant)
    - Cascade revocation: any ancestor with revocation_status != "active" fails the chain
    - Cycle detection: repeated event coordinate → immediate failure
    - Root anchor validation: different rules for the Kind 38100 terminus

    Args:
        leaf_event: The Kind 38101 delegation being exercised (the leaf of the chain).
        fetch_event: Async callable resolving an a-tag coordinate to a nostr_sdk.Event,
                     or None if relay resolution fails.

    Returns:
        VerifyResult.ok() if all conditions pass.
        VerifyResult.fail(violation) with the specific invariant, depth, and detail
        on the first failure encountered (fail-fast semantics).
    """
    current = leaf_event
    visited: set[str] = set()
    depth = 0

    while True:
        # ── Kind guard ──────────────────────────────────────────────────────
        if current.kind().as_u16() != KIND_DELEGATION:
            return VerifyResult.fail(
                ViolationKind.MALFORMED, depth,
                f"expected kind {KIND_DELEGATION}, got {current.kind().as_u16()}",
            )

        # ── INV-7 (own signature) ───────────────────────────────────────────
        if not verify_event(current):
            return VerifyResult.fail(
                ViolationKind.INV_7_SIGNATURE, depth,
                f"BIP340 signature invalid at depth {depth}",
            )

        # ── Parse content ───────────────────────────────────────────────────
        content, err = _parse_content(current, depth)
        if err:
            return err

        # ── Cascade revocation ──────────────────────────────────────────────
        if content.get("revocation_status") != "active":
            return VerifyResult.fail(
                ViolationKind.REVOKED, depth,
                f"revocation_status = '{content.get('revocation_status')}' at depth {depth}",
            )

        # ── Cycle detection ─────────────────────────────────────────────────
        coord = _coordinate(current)
        if coord in visited:
            return VerifyResult.fail(ViolationKind.CYCLE, depth, f"cycle at {coord}")
        visited.add(coord)

        # ── Depth hard cap ──────────────────────────────────────────────────
        if depth >= MAX_CHAIN_DEPTH_HARD_CAP:
            return VerifyResult.fail(
                ViolationKind.INV_6_DEPTH, depth,
                f"chain exceeds hard cap of {MAX_CHAIN_DEPTH_HARD_CAP} hops",
            )

        # ── Fetch parent ────────────────────────────────────────────────────
        a_tag = _get_tag(current, "a")
        if not a_tag:
            return VerifyResult.fail(ViolationKind.MALFORMED, depth, "missing a-tag")

        parent = await fetch_event(a_tag)
        if parent is None:
            return VerifyResult.fail(
                ViolationKind.RESOLUTION_FAILURE, depth,
                f"relay resolution failed for {a_tag}",
            )

        # ── Parent signature ────────────────────────────────────────────────
        if not verify_event(parent):
            return VerifyResult.fail(
                ViolationKind.INV_7_SIGNATURE, depth,
                f"parent BIP340 signature invalid (parent of depth {depth})",
            )

        parent_kind = parent.kind().as_u16()
        child_pubkey = current.author().to_hex()

        # ── Root anchor branch (Kind 38100) ─────────────────────────────────
        if parent_kind == KIND_IDENTITY:
            err = _check_root_anchor(content, parent, child_pubkey, depth)
            if err:
                return err
            return VerifyResult.ok()

        # ── Sub-delegation branch (Kind 38101) ──────────────────────────────
        if parent_kind == KIND_DELEGATION:
            parent_content, err = _parse_content(parent, depth + 1)
            if err:
                return err

            # Cascade revocation: ancestor must also be active
            if parent_content.get("revocation_status") != "active":
                return VerifyResult.fail(
                    ViolationKind.REVOKED, depth + 1,
                    f"ancestor at depth {depth + 1} is revoked",
                )

            parent_p_tag = _get_tag(parent, "p") or ""
            err = _check_7_conditions(content, parent_content, parent_p_tag, child_pubkey, depth)
            if err:
                return err

            current = parent
            depth += 1

        else:
            return VerifyResult.fail(
                ViolationKind.MALFORMED, depth,
                f"unexpected parent kind {parent_kind}",
            )


# Module-level alias: DelegationManager.verify_chain (a staticmethod) shadows the
# top-level verify_chain function.  This alias lets the method call the original.
_verify_chain_core = verify_chain


# ---------------------------------------------------------------------------
# Legacy build helpers (retained for compatibility with validation.py)
# ---------------------------------------------------------------------------


def build_delegation_event(
    delegator_keys: nostr_sdk.Keys,
    delegatee_pubkey: PublicKey,
    scopes: list[Scope],
    expires_at: int | None = None,
) -> nostr_sdk.Event:
    """Build and sign a Kind 38101 delegation event (legacy tag format)."""
    tags = [
        nostr_sdk.Tag.parse(["delegatee", delegatee_pubkey]),
        *[
            nostr_sdk.Tag.parse(["scope", s.resource, *sorted(s.actions)])
            for s in scopes
        ],
    ]
    if expires_at is not None:
        tags.append(nostr_sdk.Tag.parse(["expiration", str(expires_at)]))

    builder = nostr_sdk.EventBuilder(nostr_sdk.Kind(KIND_DELEGATION), "").tags(tags)
    return builder.sign_with_keys(delegator_keys)


def parse_delegation_link(event: nostr_sdk.Event) -> DelegationLink:
    """Parse a Kind 38101 event into a DelegationLink (legacy format)."""
    tags_by_name: dict[str, list[list[str]]] = {}
    for tag in event.tags().to_vec():
        parts = tag.as_vec()
        if parts:
            tags_by_name.setdefault(parts[0], []).append(parts)

    delegatee_tag = tags_by_name.get("delegatee", [[]])[0]
    delegatee_pubkey = PublicKey(delegatee_tag[1]) if len(delegatee_tag) > 1 else PublicKey("")

    parsed_scopes = [
        Scope(resource=t[1], actions=frozenset(t[2:]))
        for t in tags_by_name.get("scope", [])
        if len(t) > 1
    ]

    expiry_tag = tags_by_name.get("expiration", [[]])[0]
    expires_at = int(expiry_tag[1]) if len(expiry_tag) > 1 else None

    return DelegationLink(
        delegator_pubkey=PublicKey(event.author().to_hex()),
        delegatee_pubkey=delegatee_pubkey,
        scopes=parsed_scopes,
        signature=Signature(event.signature().to_hex()),
        event_id=event.id().to_hex(),  # type: ignore[arg-type]
        expires_at=expires_at,
    )


def build_chain(links: list[DelegationLink]) -> DelegationChain:
    """Assemble and validate a DelegationChain from a list of parsed links."""
    chain = DelegationChain(links=links)
    validate_chain(chain)
    return chain


# ---------------------------------------------------------------------------
# Default relay query timeout
# ---------------------------------------------------------------------------

_RELAY_TIMEOUT = timedelta(seconds=10)


# ===========================================================================
# DelegationManager -- prototype_specification.md §1.2
# ===========================================================================


class DelegationManager:
    """Kind 38101 Delegation Chain lifecycle.

    Handles operator-to-agent and agent-to-agent delegation with scoped,
    time-bound, depth-limited authorization. Enforces the 7-condition
    attenuation invariant (INV-1 through INV-7) at both issuance and
    verification time.
    """

    def __init__(self, identity: AgentIdentity) -> None:
        """Initialize with the delegator's identity.

        Args:
            identity: The AgentIdentity of the delegating agent/operator.
        """
        self._identity = identity

    # ------------------------------------------------------------------
    # compute_d_tag -- deterministic d-tag generation
    # ------------------------------------------------------------------

    @staticmethod
    def compute_d_tag(
        delegator_pubkey: str,
        delegatee_pubkey: str,
        scope: Scope,
        created_at: int,
    ) -> str:
        """Deterministic d-tag generation for Kind 38101.

        SHA256(delegator_pk + delegatee_pk + scope_hash + created_at)[:16].

        Args:
            delegator_pubkey: Hex delegator public key.
            delegatee_pubkey: Hex delegatee public key.
            scope: Scope object.
            created_at: Event timestamp.

        Returns:
            16-char lowercase hex d-tag.
        """
        scope_hash = compute_scope_hash(
            scope.capabilities, scope.resources, scope.actions,
        )
        preimage = (
            delegator_pubkey + delegatee_pubkey + scope_hash + str(created_at)
        )
        digest = hashlib.sha256(preimage.encode("utf-8")).hexdigest()
        return digest[:16]

    # ------------------------------------------------------------------
    # validate_attenuation -- INV-1/2/3 subset check
    # ------------------------------------------------------------------

    @staticmethod
    def validate_attenuation(child_scope: Scope, parent_scope: Scope) -> bool:
        """Check that child scope is a subset of parent scope.

        Enforces INV-1 (capabilities), INV-2 (resources), INV-3 (actions)
        with empty-set semantics (empty parent = unrestricted).

        Returns:
            True if child_scope is properly attenuated relative to parent_scope.
        """
        return child_scope.attenuates(parent_scope)

    # ------------------------------------------------------------------
    # delegate -- create and publish Kind 38101
    # ------------------------------------------------------------------

    async def delegate(
        self,
        delegatee_pubkey: str,
        scope: Scope,
        constraints: Constraints,
        parent_event: ns.Event | None = None,
        relay_urls: list[str] | None = None,
    ) -> PublishResult:
        """Create and publish a Kind 38101 delegation event.

        For root delegations (operator -> agent): parent_event is None, a-tag
        references the Kind 38100 identity coordinate, current_depth=1.

        For sub-delegations (agent A -> agent B): parent_event is the Kind 38101
        event that authorized agent A. Scope MUST attenuate parent scope.

        Args:
            delegatee_pubkey: Hex public key of the agent receiving the delegation.
            scope: Scope object with capabilities, resources, actions.
            constraints: Constraints with expires_at, max_chain_depth, current_depth,
                issued_at, optional rate_limit_hint.
            parent_event: The parent Kind 38101 event for sub-delegations. None for root.
            relay_urls: Override relay set.

        Returns:
            PublishResult with event_id and per-relay status.

        Raises:
            SelfDelegationError: If delegatee_pubkey == delegator pubkey.
            AttenuationError: If child scope is not a subset of parent scope.
            DepthExceededError: If current_depth > max_chain_depth.
            ValueError: If scope or constraints fail validation.
            PublishError: If zero relays accepted the event.
        """
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        delegator_hex = self._identity.pubkey_hex

        # --- Input validation ---
        if delegatee_pubkey == delegator_hex:
            raise SelfDelegationError("Cannot delegate to self")

        if not scope.capabilities:
            raise ValueError("scope.capabilities must be non-empty")

        if constraints.current_depth < 1:
            raise ValueError(
                f"constraints.current_depth must be >= 1, got {constraints.current_depth}"
            )
        if constraints.current_depth > constraints.max_chain_depth:
            raise DepthExceededError(
                f"current_depth {constraints.current_depth} > "
                f"max_chain_depth {constraints.max_chain_depth}"
            )
        if constraints.expires_at <= constraints.issued_at:
            raise ValueError(
                f"expires_at ({constraints.expires_at}) must be > "
                f"issued_at ({constraints.issued_at})"
            )

        # --- Determine parent coordinate and validate attenuation ---
        if parent_event is None:
            # Root delegation: a-tag references Kind 38100 identity.
            parent_coord = (
                f"{KIND_IDENTITY}:{delegator_hex}:{self._identity.d_tag}"
            )
            delegation_type = "root"
            if constraints.current_depth != 1:
                raise ValueError(
                    f"Root delegation must have current_depth=1, got {constraints.current_depth}"
                )
        else:
            # Sub-delegation: validate attenuation against parent.
            parent_content_raw, parse_err = _parse_content(parent_event, 0)
            if parse_err:
                raise ValueError(f"Cannot parse parent event content: {parse_err.violation}")

            parent_scope_dict = parent_content_raw.get("scope", {})
            parent_scope = Scope(
                capabilities=tuple(sorted(parent_scope_dict.get("capabilities", []))),
                resources=tuple(sorted(parent_scope_dict.get("resources", []))),
                actions=tuple(sorted(parent_scope_dict.get("actions", []))),
            )

            if not self.validate_attenuation(scope, parent_scope):
                raise AttenuationError(
                    f"Child scope {scope} is not a valid attenuation of parent {parent_scope}"
                )

            parent_con = parent_content_raw.get("constraints", {})

            # Depth consistency.
            expected_depth = parent_con.get("current_depth", 0) + 1
            if constraints.current_depth != expected_depth:
                raise ValueError(
                    f"current_depth must be {expected_depth} (parent + 1), "
                    f"got {constraints.current_depth}"
                )

            # max_chain_depth narrows.
            parent_max = parent_con.get("max_chain_depth", 0)
            if constraints.max_chain_depth > parent_max:
                raise DepthExceededError(
                    f"max_chain_depth {constraints.max_chain_depth} > "
                    f"parent max_chain_depth {parent_max}"
                )

            # Temporal narrowing.
            parent_expires = parent_con.get("expires_at", 0)
            if constraints.expires_at > parent_expires:
                raise ValueError(
                    f"expires_at {constraints.expires_at} > "
                    f"parent expires_at {parent_expires}"
                )

            # Build parent coordinate from parent event.
            parent_d = _get_tag(parent_event, "d") or ""
            parent_author = parent_event.author().to_hex()
            parent_coord = f"{KIND_DELEGATION}:{parent_author}:{parent_d}"
            delegation_type = "sub"

        # --- Compute deterministic d-tag ---
        d_tag = self.compute_d_tag(
            delegator_hex, delegatee_pubkey, scope, constraints.issued_at,
        )

        # --- Build content JSON ---
        content: dict = {
            "scope": {
                "capabilities": sorted(scope.capabilities),
                "resources": sorted(scope.resources),
                "actions": sorted(scope.actions),
            },
            "constraints": {
                "expires_at": constraints.expires_at,
                "max_chain_depth": constraints.max_chain_depth,
                "current_depth": constraints.current_depth,
                "issued_at": constraints.issued_at,
            },
            "revocation_status": "active",
            "delegation_type": delegation_type,
        }
        if constraints.rate_limit_hint is not None:
            content["constraints"]["rate_limit_hint"] = {
                "max_requests": constraints.rate_limit_hint.max_requests,
                "window_seconds": constraints.rate_limit_hint.window_seconds,
            }

        content_json = json.dumps(content, separators=(",", ":"), ensure_ascii=True)

        # --- Build tags ---
        delegatee_pk = ns.PublicKey.parse(delegatee_pubkey)

        tags: list[ns.Tag] = [
            # d-tag (NIP-33 identifier)
            ns.Tag.identifier(d_tag),
            # p-tag (delegatee)
            ns.Tag.public_key(delegatee_pk),
            # a-tag (parent reference)
            ns.Tag.custom(ns.TagKind.UNKNOWN("a"), [parent_coord]),
            # alt tag
            ns.Tag.alt("Kind 38101: NostrAgent Delegation Chain Event"),
            # schema_version
            ns.Tag.custom(ns.TagKind.UNKNOWN("schema_version"), ["1.0"]),
            # expiration tag
            ns.Tag.expiration(ns.Timestamp.from_secs(constraints.expires_at)),
        ]

        # t-tags for each capability (relay-level #t filtering)
        for cap in sorted(scope.capabilities):
            tags.append(ns.Tag.hashtag(cap))

        # --- Build, sign, and publish ---
        builder = ns.EventBuilder(ns.Kind(KIND_DELEGATION), content_json).tags(tags)

        all_relays = list(self._identity.relay_urls)
        if relay_urls:
            for url in relay_urls:
                if url not in all_relays:
                    all_relays.append(url)

        signer = ns.NostrSigner.keys(self._identity.keys)
        client = ns.Client(signer)
        try:
            for url in all_relays:
                await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
            await client.connect()
            output = await client.send_event_builder(builder)
        finally:
            await client.disconnect()

        succeeded = [str(r) for r in output.success]
        failed = {str(k): str(v) for k, v in output.failed.items()}

        if not succeeded:
            raise PublishError(f"Zero relays accepted delegation. Failures: {failed}")

        event_id = output.id.to_hex()

        result = PublishResult(
            event_id=event_id,
            succeeded=tuple(succeeded),
            failed=failed,
        )
        logger.info(
            "Published Kind 38101 (d=%s, type=%s, delegatee=%s) to %d/%d relays, id=%s",
            d_tag,
            delegation_type,
            delegatee_pubkey[:16],
            len(succeeded),
            len(all_relays),
            event_id[:16],
        )
        return result

    # ------------------------------------------------------------------
    # verify_chain -- walk leaf to root, return ChainVerificationResult
    # ------------------------------------------------------------------

    @staticmethod
    async def verify_chain(
        leaf_event: ns.Event,
        relay_urls: list[str],
    ) -> ChainVerificationResult:
        """Walk delegation chain from leaf to root, verifying every hop.

        Wraps the low-level verify_chain() function with relay I/O and
        returns the typed ChainVerificationResult.

        Args:
            leaf_event: The Kind 38101 event being exercised.
            relay_urls: Relays to fetch parent events from.

        Returns:
            ChainVerificationResult with is_valid, chain_depth,
            root_identity_pubkey, violated_invariant, errors.
        """
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        # Build an EventFetcher that queries the relay set.
        async def _fetch_event(a_tag_coord: str) -> ns.Event | None:
            """Resolve an a-tag coordinate to an event from relays."""
            parts = a_tag_coord.split(":")
            if len(parts) < 3:
                return None

            kind_num, author_hex, d_tag_val = int(parts[0]), parts[1], parts[2]

            client = ns.Client()
            try:
                for url in relay_urls:
                    await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
                await client.connect()

                f = (
                    ns.Filter()
                    .kind(ns.Kind(kind_num))
                    .author(ns.PublicKey.parse(author_hex))
                    .identifier(d_tag_val)
                )
                events_output = await client.fetch_events(f, _RELAY_TIMEOUT)
                events = events_output.to_vec()
            finally:
                await client.disconnect()

            if not events:
                return None

            # Parameterized replaceable: latest created_at wins.
            return max(events, key=lambda e: e.created_at().as_secs())

        # Run the low-level verify_chain.
        low_result = await _verify_chain_core(leaf_event, _fetch_event)

        # Walk the chain again to determine depth and root pubkey on success.
        # (The low-level function doesn't return these, so we reconstruct.)
        if low_result.valid:
            # Walk from leaf to count depth and find root.
            depth = 0
            current = leaf_event
            root_pubkey = ""
            while True:
                a_tag = _get_tag(current, "a")
                if not a_tag:
                    break
                parent = await _fetch_event(a_tag)
                if parent is None:
                    break
                depth += 1
                if parent.kind().as_u16() == KIND_IDENTITY:
                    root_pubkey = parent.author().to_hex()
                    break
                current = parent

            return ChainVerificationResult(
                is_valid=True,
                chain_depth=depth,
                root_identity_pubkey=root_pubkey,
            )
        else:
            violation = low_result.violation
            inv_name = violation.kind.name if violation else None
            detail = violation.detail if violation else "unknown"
            depth = violation.depth if violation else 0

            return ChainVerificationResult(
                is_valid=False,
                chain_depth=depth,
                violated_invariant=inv_name,
                errors=(detail,),
            )

    # ------------------------------------------------------------------
    # revoke -- publish revocation replacement event
    # ------------------------------------------------------------------

    async def revoke(
        self,
        delegation_d_tag: str,
        reason: str = "routine",
        relay_urls: list[str] | None = None,
    ) -> PublishResult:
        """Revoke a delegation by publishing a replacement event.

        Publishes a Kind 38101 event with same d-tag, higher created_at,
        revocation_status="revoked". Cascade semantics: all descendant
        delegations referencing this event via a-tag are implicitly
        invalidated.

        Args:
            delegation_d_tag: The d-tag of the delegation to revoke.
            reason: One of "routine", "compromise", "decommission".
            relay_urls: Override relay set.

        Returns:
            PublishResult with event_id and per-relay status.

        Raises:
            PublishError: If zero relays accepted the event.
        """
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        content = json.dumps(
            {
                "revocation_status": "revoked",
                "revocation_reason": reason,
            },
            separators=(",", ":"),
            ensure_ascii=True,
        )

        tags: list[ns.Tag] = [
            ns.Tag.identifier(delegation_d_tag),
            ns.Tag.alt("Kind 38101: NostrAgent Delegation [REVOKED]"),
            ns.Tag.custom(ns.TagKind.UNKNOWN("schema_version"), ["1.0"]),
        ]

        all_relays = list(self._identity.relay_urls)
        if relay_urls:
            for url in relay_urls:
                if url not in all_relays:
                    all_relays.append(url)

        # For parameterized replaceable events, the revocation must have a
        # strictly greater created_at than the existing event on the relay.
        # Fetch existing to determine the minimum timestamp.
        existing_ts = 0
        try:
            client_q = ns.Client()
            for url in all_relays:
                await client_q.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
            await client_q.connect()
            f = (
                ns.Filter()
                .kind(ns.Kind(KIND_DELEGATION))
                .author(ns.PublicKey.parse(self._identity.pubkey_hex))
                .identifier(delegation_d_tag)
            )
            events_output = await client_q.fetch_events(f, _RELAY_TIMEOUT)
            for ev in events_output.to_vec():
                ts = ev.created_at().as_secs()
                if ts > existing_ts:
                    existing_ts = ts
            await client_q.disconnect()
        except Exception:
            pass  # Best effort; fall back to current time.

        revoke_ts = max(int(time.time()), existing_ts + 1)

        builder = ns.EventBuilder(ns.Kind(KIND_DELEGATION), content).tags(tags)
        builder = builder.custom_created_at(ns.Timestamp.from_secs(revoke_ts))

        signer = ns.NostrSigner.keys(self._identity.keys)
        client = ns.Client(signer)
        try:
            for url in all_relays:
                await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
            await client.connect()
            output = await client.send_event_builder(builder)
        finally:
            await client.disconnect()

        succeeded = [str(r) for r in output.success]
        failed = {str(k): str(v) for k, v in output.failed.items()}

        if not succeeded:
            raise PublishError(f"Zero relays accepted revocation. Failures: {failed}")

        event_id = output.id.to_hex()

        result = PublishResult(
            event_id=event_id,
            succeeded=tuple(succeeded),
            failed=failed,
        )
        logger.info(
            "Revoked Kind 38101 (d=%s, reason=%s) to %d/%d relays, id=%s",
            delegation_d_tag,
            reason,
            len(succeeded),
            len(all_relays),
            event_id[:16],
        )
        return result

    # ------------------------------------------------------------------
    # list_active -- query delegations by author
    # ------------------------------------------------------------------

    @staticmethod
    async def list_active(
        delegator_pubkey: str,
        relay_urls: list[str],
    ) -> list[ns.Event]:
        """List all active (non-revoked, non-expired) delegations by a delegator.

        Queries relays for Kind 38101 events authored by delegator_pubkey.
        Filters client-side for revocation_status=="active" and unexpired.
        Deduplicates by d-tag (latest created_at wins).

        Args:
            delegator_pubkey: Hex public key of the delegator.
            relay_urls: Relays to query.

        Returns:
            List of active Kind 38101 events.
        """
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        client = ns.Client()
        try:
            for url in relay_urls:
                await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
            await client.connect()

            f = (
                ns.Filter()
                .kind(ns.Kind(KIND_DELEGATION))
                .author(ns.PublicKey.parse(delegator_pubkey))
            )
            events_output = await client.fetch_events(f, _RELAY_TIMEOUT)
            events = events_output.to_vec()
        finally:
            await client.disconnect()

        return _filter_active_delegations(events)

    # ------------------------------------------------------------------
    # list_received -- query delegations by p-tag
    # ------------------------------------------------------------------

    @staticmethod
    async def list_received(
        delegatee_pubkey: str,
        relay_urls: list[str],
    ) -> list[ns.Event]:
        """List all active delegations TO a delegatee.

        Queries relays for Kind 38101 events with p-tag matching
        delegatee_pubkey.

        Args:
            delegatee_pubkey: Hex public key of the delegatee.
            relay_urls: Relays to query.

        Returns:
            List of active Kind 38101 events delegated to this agent.
        """
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        client = ns.Client()
        try:
            for url in relay_urls:
                await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
            await client.connect()

            f = (
                ns.Filter()
                .kind(ns.Kind(KIND_DELEGATION))
                .custom_tag(
                    ns.SingleLetterTag.lowercase(ns.Alphabet.P),
                    delegatee_pubkey,
                )
            )
            events_output = await client.fetch_events(f, _RELAY_TIMEOUT)
            events = events_output.to_vec()
        finally:
            await client.disconnect()

        return _filter_active_delegations(events)


# ---------------------------------------------------------------------------
# Shared helpers for list_active / list_received
# ---------------------------------------------------------------------------


def _filter_active_delegations(events: list[ns.Event]) -> list[ns.Event]:
    """Filter and deduplicate Kind 38101 events to active, unexpired ones.

    Deduplicates by d-tag (latest created_at wins -- parameterized replaceable).
    Then filters for revocation_status == "active" and not expired.
    """
    now = int(time.time())

    # Deduplicate: group by d-tag, keep latest.
    by_d_tag: dict[str, ns.Event] = {}
    for event in events:
        d = _get_tag(event, "d") or ""
        existing = by_d_tag.get(d)
        if existing is None or event.created_at().as_secs() > existing.created_at().as_secs():
            by_d_tag[d] = event

    active: list[ns.Event] = []
    for event in by_d_tag.values():
        try:
            content = json.loads(event.content())
        except json.JSONDecodeError:
            continue

        if content.get("revocation_status") != "active":
            continue

        # Check expiry.
        expires_at = content.get("constraints", {}).get("expires_at", 0)
        if expires_at and expires_at <= now:
            continue

        active.append(event)

    return active
