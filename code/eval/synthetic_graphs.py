"""Synthetic trust graph generation for B6b benchmark (scalability to 500+ nodes).

Provides six topology generators + confidence sampling for benchmarking trust computation
at scale (100-500+ nodes). All use fixed random seeds for reproducibility.

Six topologies:
  1. Erdos-Renyi: Random directed graph, edge_prob=0.15, weights uniform [0.5, 1.0]
  2. Ring: Directed cycle 0->1->...->n-1->0, uniform weight
  3. Star: Hub (0) + n-1 leaves, bidirectional edges, uniform weight
  4. Chain: Linear path 0->1->...->n-1, uniform weight
  5. Sybil: k honest nodes (full mesh 0.9) + N Sybil (full mesh 0.95) + m bridge edges (0.3)
  6. Confidence variants: Same graph, different weight distributions (uniform, beta)

Example usage in benchmarks:
  >>> from nostr_agent.trust import compute_trust
  >>> from eval.synthetic_graphs import synthetic_suite, confidence_variants
  >>>
  >>> # Generate all topologies at n=500
  >>> graphs = synthetic_suite(sizes=[500])
  >>> for name, g in graphs:
  >>>     t = compute_trust(g, "0", "250")
  >>>     print(f"{name}: {t:.4f}")
  >>>
  >>> # Test confidence distribution effects
  >>> dists = confidence_variants(n=500)
  >>> for dist_name, g in dists.items():
  >>>     t = compute_trust(g, "0", "250")
  >>>     print(f"{dist_name}: {t:.4f}")

Expected stats for n=500:
  - Erdos-Renyi (p=0.15): ~37k edges, many short paths
  - Ring: 500 edges, longest path 500 hops (mostly pruned by max_depth=4)
  - Star: 998 edges, hub-mediated paths, typically 2-3 hops
  - Chain: 499 edges, linear path (mostly pruned by max_depth=4)
  - Sybil: 400*399 + 100*99 + 10 ≈ 168k edges, high internal trust
"""

import random
from nostr_agent.trust import TrustGraph


def make_random_graph(n: int, edge_prob: float = 0.15, seed: int = 42) -> TrustGraph:
    """Erdos-Renyi directed graph. See nostr_agent.trust for implementation."""
    rng = random.Random(seed)
    graph: TrustGraph = {str(i): [] for i in range(n)}
    for i in range(n):
        for j in range(n):
            if i != j and rng.random() < edge_prob:
                w = rng.uniform(0.5, 1.0)
                graph[str(i)].append((str(j), w))
    return graph


def make_ring_graph(n: int, weight: float = 0.8) -> TrustGraph:
    """Ring topology: 0->1->2->...->n-1->0."""
    nodes = [str(i) for i in range(n)]
    graph: TrustGraph = {}
    for i in range(n):
        graph[nodes[i]] = [(nodes[(i + 1) % n], weight)]
    return graph


def make_star_graph(n: int, weight: float = 0.8) -> TrustGraph:
    """Star: hub (0) with n-1 leaves, bidirectional."""
    hub = "0"
    graph: TrustGraph = {hub: []}
    for i in range(1, n):
        leaf = str(i)
        graph[hub].append((leaf, weight))
        graph[leaf] = [(hub, weight)]
    return graph


def make_chain_graph(n: int, weight: float = 0.8) -> TrustGraph:
    """Chain: 0->1->2->...->n-1."""
    graph: TrustGraph = {}
    for i in range(n - 1):
        graph[str(i)] = [(str(i + 1), weight)]
    graph[str(n - 1)] = []
    return graph


def make_sybil_graph(
    n_honest: int,
    n_sybil: int,
    n_bridges: int = 3,
    seed: int = 42,
) -> TrustGraph:
    """Sybil cluster: honest full mesh (0.9) + Sybil full mesh (0.95) + bridges (0.3)."""
    rng = random.Random(seed)
    graph: TrustGraph = {}
    total = n_honest + n_sybil

    for i in range(total):
        graph[str(i)] = []

    # Honest clique
    for i in range(n_honest):
        for j in range(n_honest):
            if i != j:
                graph[str(i)].append((str(j), 0.9))

    # Sybil clique
    for i in range(n_honest, total):
        for j in range(n_honest, total):
            if i != j:
                graph[str(i)].append((str(j), 0.95))

    # Bridges: honest -> sybil (0.3)
    for _ in range(n_bridges):
        h = rng.randint(0, n_honest - 1)
        s = rng.randint(n_honest, total - 1)
        if (str(s), 0.3) not in graph[str(h)]:
            graph[str(h)].append((str(s), 0.3))

    return graph


def sample_confidences(
    graph: TrustGraph,
    seed: int = 42,
    dist: str = "uniform",
    alpha: float = 2.0,
    beta: float = 5.0,
) -> TrustGraph:
    """Resample edge weights from distribution (uniform or beta)."""
    rng = random.Random(seed)
    new_graph: TrustGraph = {}

    for node, edges in graph.items():
        new_graph[node] = []
        for neighbor, _ in edges:
            if dist == "uniform":
                w = rng.uniform(0.5, 1.0)
            elif dist == "beta":
                w = rng.betavariate(alpha, beta)
                w = max(0.0, min(1.0, w))
            else:
                raise ValueError(f"Unknown distribution: {dist}")
            new_graph[node].append((neighbor, w))

    return new_graph


def synthetic_suite(
    sizes: list[int] | None = None,
    seed: int = 42,
) -> list[tuple[str, TrustGraph]]:
    """Generate all 6 topologies across multiple scales.

    Args:
        sizes:  Node counts (default [100, 250, 500]).
        seed:   Random seed.

    Returns:
        List of (name, graph) tuples.
    """
    if sizes is None:
        sizes = [100, 250, 500]

    results: list[tuple[str, TrustGraph]] = []

    for n in sizes:
        results.append((f"erdos_renyi_n{n}", make_random_graph(n, edge_prob=0.15, seed=seed)))
        results.append((f"ring_n{n}", make_ring_graph(n, weight=0.8)))
        results.append((f"star_n{n}", make_star_graph(n, weight=0.8)))
        results.append((f"chain_n{n}", make_chain_graph(n, weight=0.8)))

        n_honest = int(0.8 * n)
        n_sybil = n - n_honest
        results.append((f"sybil_n{n}", make_sybil_graph(n_honest, n_sybil, n_bridges=10, seed=seed)))

    return results


def confidence_variants(
    n: int = 500,
    seed: int = 42,
) -> dict[str, TrustGraph]:
    """Same Erdos-Renyi graph with different confidence distributions.

    Returns:
        Dict mapping name -> TrustGraph.
    """
    base = make_random_graph(n, edge_prob=0.15, seed=seed)

    return {
        "uniform_[0.5,1.0]": base,
        "beta_alpha2_beta5": sample_confidences(base, seed=seed, dist="beta", alpha=2.0, beta=5.0),
        "beta_alpha5_beta2": sample_confidences(base, seed=seed, dist="beta", alpha=5.0, beta=2.0),
    }
