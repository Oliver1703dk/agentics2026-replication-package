"""Core domain types for NostrAgent.

All frozen dataclasses use tuple for immutable sequences, matching the
immutability of published Nostr events. Implements the data model behind
the architecture described in the paper Section 4.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, NewType

# ---------------------------------------------------------------------------
# Primitive NewTypes
# ---------------------------------------------------------------------------

# Hex-encoded secp256k1 public key (32 bytes = 64 hex chars for x-only BIP340)
PublicKey = NewType("PublicKey", str)

# Hex-encoded BIP340 Schnorr signature (64 bytes = 128 hex chars)
Signature = NewType("Signature", str)

# Nostr event id (SHA256 of canonical serialization, hex)
EventId = NewType("EventId", str)

# Relay websocket URL
RelayUrl = NewType("RelayUrl", str)


# ---------------------------------------------------------------------------
# Scope and Constraints (Kind 38101)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Scope:
    """Delegation scope -- capabilities, resources, and actions.

    All arrays sorted lexicographically. Empty tuple = unrestricted for
    resources and actions. capabilities must be non-empty.

    Migration note: the previous interface had ``resource: str`` and
    ``actions: frozenset[str]``. Those are preserved as deprecated
    properties for backward compatibility. New code should use
    ``capabilities``, ``resources``, and ``actions`` directly.
    """

    capabilities: tuple[str, ...] = ()  # Non-empty. Each ^[a-z0-9-]{1,64}$.
    resources: tuple[str, ...] = ()     # Empty = unrestricted. Each max 256 chars.
    actions: tuple[str, ...] = ()       # Empty = unrestricted. Each ^[a-z0-9-]{1,64}$.

    # --- Deprecated backward-compat properties ---
    # Old code used Scope(resource="...", actions=frozenset({...})).
    # These properties let old read-paths (scope.resource, scope.actions as
    # frozenset) continue to work while we migrate call-sites.

    @property
    def resource(self) -> str:  # noqa: D401 -- deprecated compat shim
        """[DEPRECATED] First resource string, for legacy call-sites."""
        return self.resources[0] if self.resources else ""

    def attenuates(self, parent: Scope) -> bool:
        """Return True if *self* is a valid attenuation of *parent*.

        Attenuation rules (spec INV-1 through INV-3):
        - capabilities must be a subset of parent capabilities
        - resources must be a subset of parent resources (empty = unrestricted)
        - actions must be a subset of parent actions (empty = unrestricted)
        """
        child_caps = set(self.capabilities)
        parent_caps = set(parent.capabilities)
        if not child_caps <= parent_caps:
            return False

        # Empty parent tuple means unrestricted -- any child is a subset.
        if parent.resources and not set(self.resources) <= set(parent.resources):
            return False

        if parent.actions and not set(self.actions) <= set(parent.actions):
            return False

        return True


@dataclass(frozen=True)
class RateLimitHint:
    """Advisory rate limit (NOT cryptographically enforced)."""

    max_requests: int
    window_seconds: int


@dataclass(frozen=True)
class Constraints:
    """Delegation constraints -- temporal bounds, depth limits, rate hints."""

    expires_at: int        # Unix timestamp. > issued_at. <= parent.expires_at.
    max_chain_depth: int   # >= 1. <= parent.max_chain_depth.
    current_depth: int     # >= 1. == parent.current_depth + 1 (or 1 for root).
    issued_at: int         # Unix timestamp. >= parent.issued_at.
    rate_limit_hint: RateLimitHint | None = None


# ---------------------------------------------------------------------------
# Trust Policy (Kind 38100 content.trust_policy)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TrustPolicy:
    """Trust evaluation parameters from Kind 38100 content."""

    min_attestation_count: int = 1    # 0-1000
    trust_decay_per_hop: float = 0.5  # (0.0, 1.0]
    max_trust_depth: int = 4          # 1-10
    require_l402: bool = False


# ---------------------------------------------------------------------------
# Publish Results
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PublishResult:
    """Result of publishing an event to relays."""

    event_id: str                                       # Hex event ID.
    succeeded: tuple[str, ...] = ()                     # Relay URLs that accepted.
    failed: dict[str, str] = field(default_factory=dict)  # URL -> error reason.

    @property
    def success_count(self) -> int:
        return len(self.succeeded)

    @property
    def is_published(self) -> bool:
        return self.success_count > 0


# ---------------------------------------------------------------------------
# Rotation / Decommission Results
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RotationResult:
    """Result of a key rotation."""

    old_pubkey: str            # Hex pubkey of the rotated key.
    new_pubkey: str            # Hex pubkey of the new active key.
    rotation_timestamp: int    # Unix timestamp of the rotation.
    delegations_reissued: int  # Number of delegations re-issued under new key.
    grace_period: int          # Seconds old delegations remain valid.
    old_event_id: str = ""     # Event ID of the "rotated" status event.
    new_event_id: str = ""     # Event ID of the new "active" identity event.


@dataclass(frozen=True)
class DecommissionResult:
    """Result of decommissioning an identity."""

    pubkey: str        # Hex pubkey of the decommissioned key.
    timestamp: int     # Unix timestamp.
    event_id: str = ""  # Event ID of the decommission event.


# ---------------------------------------------------------------------------
# Verification Results
# ---------------------------------------------------------------------------

class VerificationStatus(Enum):
    """Status codes for identity and chain verification."""

    VALID = "valid"
    INVALID_SIGNATURE = "invalid_signature"
    INVALID_SCHEMA = "invalid_schema"
    CHAIN_BROKEN = "chain_broken"
    REVOKED = "revoked"
    DECOMMISSIONED = "decommissioned"
    EXPIRED = "expired"
    NOT_FOUND = "not_found"
    ROTATION_IN_PROGRESS = "rotation_in_progress"


@dataclass(frozen=True)
class VerificationResult:
    """Result of verifying a Kind 38100 identity event."""

    is_valid: bool
    status: VerificationStatus
    chain_depth: int = 0            # Number of rotation hops (0 = genesis).
    errors: tuple[str, ...] = ()    # Human-readable error descriptions.


@dataclass(frozen=True)
class ChainVerificationResult:
    """Result of verifying a Kind 38101 delegation chain."""

    is_valid: bool
    chain_depth: int = 0                    # Number of delegation hops.
    root_identity_pubkey: str = ""          # Hex pubkey of the Kind 38100 root.
    violated_invariant: str | None = None   # E.g., "INV-1" if capability widened.
    errors: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Discovery Types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AgentInfo:
    """Summary of a discovered agent identity (Kind 38100)."""

    pubkey: str                  # Hex pubkey.
    d_tag: str                   # Agent identifier.
    name: str                    # Human-readable name.
    description: str             # Agent description.
    capabilities: tuple[str, ...]  # Capability labels.
    relay_urls: tuple[str, ...]  # Preferred relays.
    status: str                  # "active", "rotated", "decommissioned".
    created_at: int              # Event timestamp.
    operator_pubkey: str         # Hex operator pubkey.
    endpoints: dict[str, str] = field(default_factory=dict)
    trust_policy: TrustPolicy = field(default_factory=TrustPolicy)


# ---------------------------------------------------------------------------
# Legacy Identity (backward-compat -- kept for existing imports)
# ---------------------------------------------------------------------------

@dataclass
class AgentIdentity:
    """Kind 38100 Agent Identity Declaration.

    Holds the resolved state of an agent's identity, not the raw event.

    Migration note: this mutable dataclass predates the frozen AgentInfo.
    New discovery code should prefer AgentInfo. This class is retained for
    backward compatibility with identity.py and other existing modules.
    """

    pubkey: PublicKey
    operator_pubkey: PublicKey
    relay_urls: list[RelayUrl]
    scopes: list[Scope]
    next_key_hash: str  # SHA256 of next rotation key (pre-rotation)
    event_id: EventId | str = ""
    created_at: int = 0  # Unix timestamp


# ---------------------------------------------------------------------------
# Legacy Delegation / Attestation types (backward-compat)
# ---------------------------------------------------------------------------

@dataclass
class DelegationLink:
    """A single link in a Kind 38101 delegation chain."""

    delegator_pubkey: PublicKey
    delegatee_pubkey: PublicKey
    scopes: list[Scope]
    signature: Signature
    event_id: EventId | str = ""
    expires_at: int | None = None  # Unix timestamp, None = no expiry


@dataclass
class DelegationChain:
    """An ordered sequence of delegation links from operator to agent.

    Invariant: each link's scopes must attenuate the previous link's scopes.
    The chain root must be signed by the operator key.
    """

    links: list[DelegationLink]

    @property
    def root_pubkey(self) -> PublicKey:
        return self.links[0].delegator_pubkey

    @property
    def leaf_pubkey(self) -> PublicKey:
        return self.links[-1].delegatee_pubkey

    @property
    def effective_scopes(self) -> list[Scope]:
        return self.links[-1].scopes


@dataclass
class Attestation:
    """Kind 38102 Peer Attestation event."""

    attester_pubkey: PublicKey
    subject_pubkey: PublicKey
    trust_value: float  # [0.0, 1.0]
    tags: list[str]
    signature: Signature
    event_id: EventId | str = ""
    created_at: int = 0


# Used in trust graph calculations (bounded-sum / noisy-OR aggregation)
TrustScore = NewType("TrustScore", float)


# ---------------------------------------------------------------------------
# Trust Graph Types
# ---------------------------------------------------------------------------

@dataclass
class TrustGraph:
    """Capability-scoped trust graph (adjacency list).

    Nodes are agent pubkeys (hex). Edges are attestation confidence values.
    One graph instance per capability. Mutable -- edges are added as
    attestation events are discovered.
    """

    capability: str
    adjacency: dict[str, list[tuple[str, float]]] = field(default_factory=dict)
    # adjacency[attester_pubkey] = [(attestee_pubkey, confidence), ...]

    def add_edge(self, attester: str, attestee: str, confidence: float) -> None:
        """Add an attestation edge to the graph."""
        if attester not in self.adjacency:
            self.adjacency[attester] = []
        self.adjacency[attester].append((attestee, confidence))

    @property
    def node_count(self) -> int:
        """Number of unique nodes in the graph."""
        nodes: set[str] = set(self.adjacency.keys())
        for edges in self.adjacency.values():
            for attestee, _ in edges:
                nodes.add(attestee)
        return len(nodes)

    @property
    def edge_count(self) -> int:
        """Total number of attestation edges."""
        return sum(len(edges) for edges in self.adjacency.values())


@dataclass(frozen=True)
class TrustResult:
    """Result of a trust computation."""

    score: float       # Trust score in [0.0, 1.0].
    paths_found: int   # Number of simple paths found.
    paths_pruned: int  # Number of paths pruned by epsilon.


# ---------------------------------------------------------------------------
# L402 Types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class L402Challenge:
    """L402 challenge from service (HTTP 402 response)."""

    macaroon_bytes: bytes    # Raw macaroon bytes.
    bolt11_invoice: str      # BOLT11 invoice string.
    payment_hash: bytes      # 32-byte payment hash (from identifier).
    amount_sat: int          # Invoice amount in satoshis.
    agent_pubkey: bytes      # 32-byte agent pubkey bound in identifier.


@dataclass(frozen=True)
class PaymentResult:
    """Result of a Lightning payment."""

    preimage: bytes      # 32-byte payment preimage.
    payment_hash: bytes  # 32-byte payment hash.
    amount_sat: int      # Amount paid.
    fee_sat: int         # Routing fee paid.
    status: str          # "SUCCEEDED", "FAILED", "IN_FLIGHT".


@dataclass(frozen=True)
class L402VerificationResult:
    """Result of L402 request verification."""

    is_valid: bool
    reason_code: str       # "OK", "PREIMAGE_MISMATCH", "PUBKEY_MISMATCH",
                           # "SIGNATURE_INVALID", "TIMESTAMP_STALE", "CAVEAT_VIOLATION".
    agent_pubkey: str = ""  # Hex pubkey of the verified agent.


# ---------------------------------------------------------------------------
# Exception Hierarchy
# ---------------------------------------------------------------------------

class NostrAgentError(Exception):
    """Base exception for all NostrAgent errors."""


class PublishError(NostrAgentError):
    """Zero relays accepted the event."""


class RotationError(NostrAgentError):
    """Key rotation precondition or publication failure."""


class AttenuationError(NostrAgentError):
    """Child scope is not a subset of parent scope."""


class DepthExceededError(NostrAgentError):
    """Delegation chain depth exceeds max_chain_depth."""


class SelfDelegationError(NostrAgentError):
    """Cannot delegate to self."""


class SelfAttestationError(NostrAgentError):
    """Cannot attest own capabilities."""


class L402PaymentError(NostrAgentError):
    """Lightning payment failed."""


class L402VerificationError(NostrAgentError):
    """Service rejected L402 credential."""


class L402AmountExceededError(NostrAgentError):
    """Invoice amount exceeds maximum auto-pay threshold."""


class L402ParseError(NostrAgentError):
    """Malformed L402 challenge header."""


class LndConnectionError(NostrAgentError):
    """Cannot connect to LND node."""
