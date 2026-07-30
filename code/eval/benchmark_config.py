"""Benchmark configuration matching prototype spec section 5.2.

Central configuration for NostrAgent B1-B11 benchmarks. All harness code
imports from here to ensure consistent parameters across runs.
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Core parameters
# ---------------------------------------------------------------------------

RUNS_PER_METRIC: int = 1000
WARMUP_RUNS: int = 100
EFFECTIVE_RUNS: int = RUNS_PER_METRIC - WARMUP_RUNS  # 900
RANDOM_SEED: int = 42
OUTPUT_DIR: Path = Path(__file__).resolve().parent / "results"

# ---------------------------------------------------------------------------
# CSV schema
# ---------------------------------------------------------------------------

CSV_COLUMNS: list[str] = [
    "run_id",       # int: sequential within effective runs
    "metric",       # str: e.g. "B1", "B3_depth_2"
    "value_ms",     # float: measurement in milliseconds
    "timestamp",    # str: ISO 8601 UTC
    "variant",      # str: parameter variant (e.g. "depth=3", "graph_size=50")
]

# ---------------------------------------------------------------------------
# Statistics to compute per metric
# ---------------------------------------------------------------------------

STATISTICS: list[str] = [
    "median",
    "iqr",     # Q3 - Q1
    "p95",
    "p99",
    "mean",
    "std",
]

# ---------------------------------------------------------------------------
# Comparative statistics (within NostrAgent variants)
# ---------------------------------------------------------------------------

COMPARATIVE_TEST: str = "mann_whitney_u"
COMPARATIVE_EFFECT_SIZE: str = "cliffs_delta"
COMPARATIVE_ALPHA: float = 0.05

# ---------------------------------------------------------------------------
# Bundled dict form (for code that expects the spec's dict shape)
# ---------------------------------------------------------------------------

BENCHMARK_CONFIG: dict = {
    "runs_per_metric": RUNS_PER_METRIC,
    "warmup_runs": WARMUP_RUNS,
    "effective_runs": EFFECTIVE_RUNS,
    "random_seed": RANDOM_SEED,
    "output_format": "csv",
    "output_dir": str(OUTPUT_DIR),
    "csv_columns": CSV_COLUMNS,
    "statistics": STATISTICS,
    "comparative": {
        "test": COMPARATIVE_TEST,
        "effect_size": COMPARATIVE_EFFECT_SIZE,
        "alpha": COMPARATIVE_ALPHA,
    },
}
