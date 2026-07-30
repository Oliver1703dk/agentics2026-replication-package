"""NostrAgent: Decentralized Identity and Delegation Architecture for Sovereign Agentic Systems."""

from nostr_agent.types import (
    AgentIdentity,
    Attestation,
    DelegationChain,
    Scope,
    TrustScore,
)
from nostr_agent.delegation import DelegationManager
from nostr_agent.relay_consistency import (
    QueryResult,
    multi_relay_query,
    publish_with_confirmation,
    wait_revocation_propagated,
    verify_rotation_consistency,
)

__all__ = [
    "AgentIdentity",
    "Attestation",
    "DelegationChain",
    "DelegationManager",
    "Scope",
    "TrustScore",
    "QueryResult",
    "multi_relay_query",
    "publish_with_confirmation",
    "wait_revocation_propagated",
    "verify_rotation_consistency",
]
