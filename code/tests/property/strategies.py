"""Custom Hypothesis strategies for NostrAgent property-based tests.

Strategies generate valid domain objects (Scope, Constraints, TrustGraph,
delegation chains) suitable for testing algebraic invariants. All generated
objects satisfy the type contracts from nostr_agent.types.

References:
- paper Section 4 (delegation chain attenuation invariants)
- paper Section 4 (trust model: noisy-OR aggregation with multiplicative decay
  d = 0.5 and depth limit 4)
"""

from __future__ import annotations

import hashlib
from typing import Any

from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy, composite

from nostr_agent.types import Constraints, Scope, TrustGraph as TrustGraphType

# ---------------------------------------------------------------------------
# Primitive strategies
# ---------------------------------------------------------------------------

# Capability label: ^[a-z0-9-]{1,64}$ (validation.py PATTERN_CAPABILITY).
# Use sampled_from for speed; from_regex is slow and produces many rejects.
_CAPABILITY_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-"

capability_st: SearchStrategy[str] = st.text(
    alphabet=_CAPABILITY_ALPHABET, min_size=1, max_size=16
)

# Resource string: arbitrary non-empty text, max 256 chars.
resource_st: SearchStrategy[str] = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789/._-:", min_size=1, max_size=64
)

# Action string: same format as capability.
action_st: SearchStrategy[str] = capability_st

# Hex pubkey-like string (64 hex chars). Not real keys -- used for graph nodes.
pubkey_st: SearchStrategy[str] = st.binary(min_size=32, max_size=32).map(
    lambda b: hashlib.sha256(b).hexdigest()
)


# ---------------------------------------------------------------------------
# Scope strategies
# ---------------------------------------------------------------------------


@composite
def scope_st(draw: Any) -> Scope:
    """Generate a valid Scope with sorted, deduplicated tuples."""
    caps = draw(
        st.lists(capability_st, min_size=1, max_size=8, unique=True)
    )
    resources = draw(
        st.lists(resource_st, min_size=0, max_size=5, unique=True)
    )
    actions = draw(
        st.lists(action_st, min_size=0, max_size=5, unique=True)
    )
    return Scope(
        capabilities=tuple(sorted(caps)),
        resources=tuple(sorted(resources)),
        actions=tuple(sorted(actions)),
    )


@composite
def subscope_st(draw: Any, parent: Scope) -> Scope:
    """Generate a child Scope that is a valid attenuation of *parent*.

    - capabilities: non-empty subset of parent capabilities
    - resources: subset of parent resources (or empty if parent empty)
    - actions: subset of parent actions (or empty if parent empty)
    """
    # Capabilities: draw a non-empty subset of parent's capabilities.
    caps_list = list(parent.capabilities)
    # st.lists with sampled_from, at least 1, at most len(parent.capabilities)
    child_caps = draw(
        st.lists(
            st.sampled_from(caps_list),
            min_size=1,
            max_size=len(caps_list),
            unique=True,
        )
    )

    # Resources: subset (or empty if parent is empty/unrestricted).
    if parent.resources:
        child_resources = draw(
            st.lists(
                st.sampled_from(list(parent.resources)),
                min_size=0,
                max_size=len(parent.resources),
                unique=True,
            )
        )
    else:
        # Parent unrestricted: child can have any resources or empty.
        child_resources = draw(
            st.lists(resource_st, min_size=0, max_size=3, unique=True)
        )

    # Actions: subset (or empty if parent is empty/unrestricted).
    if parent.actions:
        child_actions = draw(
            st.lists(
                st.sampled_from(list(parent.actions)),
                min_size=0,
                max_size=len(parent.actions),
                unique=True,
            )
        )
    else:
        child_actions = draw(
            st.lists(action_st, min_size=0, max_size=3, unique=True)
        )

    return Scope(
        capabilities=tuple(sorted(child_caps)),
        resources=tuple(sorted(child_resources)),
        actions=tuple(sorted(child_actions)),
    )


# ---------------------------------------------------------------------------
# Constraints strategies
# ---------------------------------------------------------------------------

# Timestamp range: 2024-01-01 to 2030-01-01.
_MIN_TS = 1704067200
_MAX_TS = 1893456000


@composite
def constraints_st(draw: Any) -> Constraints:
    """Generate valid Constraints with proper temporal ordering and depth bounds."""
    issued_at = draw(st.integers(min_value=_MIN_TS, max_value=_MAX_TS - 60))
    expires_at = issued_at + draw(st.integers(min_value=60, max_value=86400 * 365))
    max_chain_depth = draw(st.integers(min_value=1, max_value=10))
    current_depth = draw(st.integers(min_value=1, max_value=max_chain_depth))
    return Constraints(
        expires_at=expires_at,
        max_chain_depth=max_chain_depth,
        current_depth=current_depth,
        issued_at=issued_at,
    )


@composite
def subconstraints_st(draw: Any, parent: Constraints) -> Constraints:
    """Generate child Constraints satisfying INV-4 through INV-6.

    - expires_at <= parent.expires_at (INV-4)
    - max_chain_depth <= parent.max_chain_depth (INV-6a)
    - current_depth == parent.current_depth + 1 (INV-6b)
    - current_depth <= max_chain_depth (INV-6c)
    - issued_at >= parent.issued_at (INV-5)
    """
    child_depth = parent.current_depth + 1

    # max_chain_depth must be >= child_depth AND <= parent.max_chain_depth.
    if child_depth > parent.max_chain_depth:
        # Cannot create a valid child: depth would exceed max. This is
        # checked by callers (chain_st filters this case).
        raise ValueError("parent depth exhausted -- cannot sub-delegate")

    max_chain_depth = draw(
        st.integers(min_value=child_depth, max_value=parent.max_chain_depth)
    )

    # issued_at >= parent.issued_at, but not beyond a reasonable future.
    issued_at = draw(
        st.integers(
            min_value=parent.issued_at,
            max_value=min(parent.issued_at + 86400, _MAX_TS),
        )
    )

    # expires_at <= parent.expires_at, but > issued_at.
    min_exp = issued_at + 60
    max_exp = parent.expires_at
    if min_exp > max_exp:
        # Edge case: parent expires too soon after child issued_at.
        expires_at = max_exp
    else:
        expires_at = draw(st.integers(min_value=min_exp, max_value=max_exp))

    return Constraints(
        expires_at=expires_at,
        max_chain_depth=max_chain_depth,
        current_depth=child_depth,
        issued_at=issued_at,
    )


# ---------------------------------------------------------------------------
# TrustGraph strategy
# ---------------------------------------------------------------------------


@composite
def trust_graph_st(
    draw: Any,
    min_nodes: int = 3,
    max_nodes: int = 15,
    edge_density: float = 0.3,
) -> TrustGraphType:
    """Generate a random TrustGraph with configurable node count and edge density.

    Nodes are synthetic hex pubkeys. Edges have confidence in (0.01, 1.0].
    """
    n_nodes = draw(st.integers(min_value=min_nodes, max_value=max_nodes))
    nodes = [f"node{i:04d}" for i in range(n_nodes)]

    graph = TrustGraphType(capability="test-cap")
    for i in range(n_nodes):
        for j in range(n_nodes):
            if i == j:
                continue
            add_edge = draw(st.floats(min_value=0.0, max_value=1.0))
            if add_edge < edge_density:
                confidence = draw(
                    st.floats(min_value=0.01, max_value=1.0, allow_nan=False)
                )
                graph.add_edge(nodes[i], nodes[j], confidence)

    return graph


# ---------------------------------------------------------------------------
# Delegation chain strategy
# ---------------------------------------------------------------------------


@composite
def chain_st(draw: Any, max_depth: int = 4) -> list[tuple[Scope, Constraints]]:
    """Generate a valid delegation chain as list of (Scope, Constraints) pairs.

    The chain starts with a root (current_depth=1) and attenuates at each hop.
    Each hop narrows scope and constraints per INV-1 through INV-6.
    """
    # Root scope and constraints.
    root_scope = draw(scope_st())

    # Root constraints: current_depth=1, max_chain_depth >= 1.
    root_issued = draw(st.integers(min_value=_MIN_TS, max_value=_MAX_TS - 86400))
    root_expires = root_issued + draw(st.integers(min_value=3600, max_value=86400 * 365))
    root_max_depth = draw(st.integers(min_value=1, max_value=max_depth))
    root_constraints = Constraints(
        expires_at=root_expires,
        max_chain_depth=root_max_depth,
        current_depth=1,
        issued_at=root_issued,
    )

    chain: list[tuple[Scope, Constraints]] = [(root_scope, root_constraints)]

    # Generate subsequent hops up to max_chain_depth.
    remaining = draw(
        st.integers(min_value=0, max_value=root_max_depth - 1)
    )
    current_scope = root_scope
    current_constraints = root_constraints

    for _ in range(remaining):
        if current_constraints.current_depth >= current_constraints.max_chain_depth:
            break  # Cannot sub-delegate further.

        child_scope = draw(subscope_st(current_scope))
        child_constraints = draw(subconstraints_st(current_constraints))
        chain.append((child_scope, child_constraints))
        current_scope = child_scope
        current_constraints = child_constraints

    return chain
