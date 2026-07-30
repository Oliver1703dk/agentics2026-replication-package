# Synthetic Trust Graph Generation (B6b Benchmark)

## Overview

Pure Python synthetic trust graph generators for benchmarking trust computation at scale (100-500+ nodes). All generators use fixed random seeds for reproducibility.

## Six Topologies

| Topology | Function | Use Case | Expected Edges (n=500) |
|----------|----------|----------|--------------------------|
| **Erdos-Renyi** | `make_random_graph(n, edge_prob=0.15, seed=42)` | Random sparse graph | ~37,500 |
| **Ring** | `make_ring_graph(n, weight=0.8)` | Cycle: 0→1→...→n-1→0 | 500 |
| **Star** | `make_star_graph(n, weight=0.8)` | Hub + leaves, bidirectional | 998 |
| **Chain** | `make_chain_graph(n, weight=0.8)` | Linear path: 0→1→...→n-1 | 499 |
| **Sybil** | `make_sybil_graph(n_honest, n_sybil, n_bridges=10, seed=42)` | Attack scenario | ~168,000 (at 400+100 split) |
| **Confidence** | `sample_confidences(graph, dist="uniform"|"beta", ...)` | Distribution variants | Same edges, resampled weights |

## API

### Core Functions

```python
from nostr_agent.trust import (
    make_random_graph,
    make_ring_graph,
    make_star_graph,
    make_chain_graph,
    make_sybil_graph,
    sample_confidences,
)

# Single graph
g = make_random_graph(n=500, edge_prob=0.15, seed=42)

# Sybil topology: 400 honest (0.9 internal), 100 Sybil (0.95 internal), 10 bridges
g = make_sybil_graph(n_honest=400, n_sybil=100, n_bridges=10, seed=42)

# Resample confidences from beta distribution
g_resampled = sample_confidences(g, dist="beta", alpha=2.0, beta=5.0, seed=42)
```

### Benchmark Suite

```python
from eval.synthetic_graphs import synthetic_suite, confidence_variants
from nostr_agent.trust import compute_trust

# All 6 topologies at multiple scales
graphs = synthetic_suite(sizes=[100, 250, 500], seed=42)
for name, g in graphs:
    t = compute_trust(g, "0", "250")
    print(f"{name}: {len(g)} nodes, trust={t:.4f}")

# Same Erdos-Renyi graph with different confidence distributions
dists = confidence_variants(n=500, seed=42)
for dist_name, g in dists.items():
    t = compute_trust(g, "0", "250")
    print(f"{dist_name}: trust={t:.4f}")
```

## Implementation Details

### Node IDs
- String indices: `"0"`, `"1"`, ..., `"n-1"`
- Compatible with `compute_trust(graph, source, target)` pubkey argument

### Confidence Values
- **Uniform**: `U[0.5, 1.0]` (default, represents high-confidence attestations)
- **Beta**: `Beta(α, β)` clamped to `[0, 1]`
  - `α=2, β=5`: Biased toward low values (skeptical attestations)
  - `α=5, β=2`: Biased toward high values (optimistic attestations)

### Sybil Topology Structure
```
Honest nodes (0..n_h-1):  Full mesh, weight=0.9
Sybil nodes (n_h..n-1):   Full mesh, weight=0.95
Bridges:                   Random honest→Sybil edges, weight=0.3
```

This models an attacker creating a cohesive Sybil cluster (high internal trust) with limited
connections to the honest network.

### Reproducibility
- All generators accept `seed` parameter for deterministic output
- Uses Python's `random.Random(seed)` for isolation from global RNG state
- Benchmarks should report seed and graph name (e.g., `erdos_renyi_n500_seed42`)

## Performance Characteristics

Generation time (seed=42, Python 3.11 on Apple Silicon M3):

| Topology | n=100 | n=250 | n=500 |
|----------|-------|-------|-------|
| Erdos-Renyi | <1ms | ~5ms | ~20ms |
| Ring | <1ms | <1ms | <1ms |
| Star | <1ms | ~1ms | ~3ms |
| Chain | <1ms | <1ms | <1ms |
| Sybil (80/20 split) | ~5ms | ~30ms | ~120ms |
| sample_confidences | <1ms | ~2ms | ~10ms |

**Note:** Sybil graph is O(n²) due to full-mesh cliques. For n=500, Sybil generation
involves ~158k edges. This is acceptable for benchmarks; don't generate Sybil graphs
much larger than n=500 for tight timing constraints.

## Integration with Benchmarks

### B6b: Scalability (Trust Computation Latency)

```python
# Measure latency as n grows
import time
from nostr_agent.trust import compute_trust
from eval.synthetic_graphs import synthetic_suite

results = []
for name, g in synthetic_suite(sizes=[100, 250, 500]):
    start = time.perf_counter()
    for _ in range(100):  # Warm-up
        compute_trust(g, "0", "250")
    
    start = time.perf_counter()
    for _ in range(1000):
        compute_trust(g, "0", "250")
    elapsed = time.perf_counter() - start
    
    print(f"{name}: {elapsed/1000*1e6:.2f} µs/call")
```

### B7: Confidence Distribution Effects

```python
from eval.synthetic_graphs import confidence_variants

dists = confidence_variants(n=500, seed=42)
for dist_name, g in dists.items():
    # Run trust computation, measure sensitivity to distribution shape
    ...
```

## Files

- `../src/nostr_agent/trust.py` -- Core generators + trust computation (lines 204-288)
- `./synthetic_graphs.py` -- Benchmark suite + convenience functions
- This README -- Integration guide

## Testing

Quick sanity check:

```bash
python3.11 << 'EOF'
import sys
sys.path.insert(0, 'code/src')
sys.path.insert(0, 'code/eval')

from synthetic_graphs import synthetic_suite
from nostr_agent.trust import compute_trust

graphs = synthetic_suite(sizes=[50])
print(f"Generated {len(graphs)} graphs")

# Spot check a few
for name, g in graphs[:2]:
    nodes = len(g)
    edges = sum(len(v) for v in g.values())
    t = compute_trust(g, "0", str(nodes // 2))
    print(f"  {name}: {nodes} nodes, {edges} edges, trust={t:.4f}")
EOF
```

Expected output:
```
Generated 5 graphs
  erdos_renyi_n50: 50 nodes, 369 edges, trust=0.XXXX
  ring_n50: 50 nodes, 50 edges, trust=0.0000
```

## References

- **Trust computation**: Noisy-OR aggregation, decay parameter d=0.5, max_depth=4 (see `../src/nostr_agent/trust.py`)
- **B6b** (Scalability benchmark): Measure latency as n → 500+
- **FM-7** (Sybil deterrence): Peer attestation (Kind 38102) with L402-backed cost floor
