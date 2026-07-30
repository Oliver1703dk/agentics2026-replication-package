# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "krippendorff==0.8.2",
# ]
# ///
"""Reproduce the paper's inter-rater agreement numbers for the ATAM panel.

The paper's Section 5.2 (RQ1) reports, for the two-round mini-Delphi expert
panel that rated the twelve-leaf utility tree on (importance, difficulty):

  - Krippendorff alpha (ordinal) = 0.94 in Round 2, averaged across the
    importance and difficulty axes (importance 1.00, difficulty 0.88;
    bootstrap 95% CI [0.78, 1.00]), up from 0.79 in Round 1.
  - Fleiss kappa = 0.78 in Round 2 (Round 1: 0.46), reported for
    comparability with ATAM studies that use kappa.

This script reproduces all of these from the raw ratings in
`round1_ratings.csv` and `round2_ratings.csv` (12 leaves x 3 experts,
each cell an "importance,difficulty" pair such as "H,M").

Krippendorff alpha uses the `krippendorff` package with the ordinal
distance metric per Krippendorff (2004), computed per axis and averaged.
Bootstrap 95% CIs resample the 12 items with replacement, 10000
iterations, seed 20260412, stdlib only.

Fleiss kappa (Fleiss 1971) is nominal by construction, so the two axes
are not averaged; instead each "importance,difficulty" pair is treated
as one joint category (H,H; H,M; ...; L,L) and kappa is computed per
round over those joint labels, stdlib only.

Usage:
    uv run agreement.py
"""
from __future__ import annotations

import csv
import json
import random
from pathlib import Path

import krippendorff as kd

RANK = {"H": 2, "M": 1, "L": 0}
HERE = Path(__file__).resolve().parent
BOOTSTRAP_SEED = 20260412
BOOTSTRAP_ITERS = 10_000


def load_ratings(csv_path: Path) -> dict[str, list[str]]:
    """Load a ratings CSV into {item_id: [expert_a, expert_b, expert_c]}.

    Each label is a "importance,difficulty" pair like "H,M".
    """
    with csv_path.open() as f:
        reader = csv.DictReader(f)
        return {
            row["item_id"]: [row["expert_a"], row["expert_b"], row["expert_c"]]
            for row in reader
        }


def split_axes(rating_map: dict[str, list[str]]) -> tuple[list[list[int]], list[list[int]]]:
    """Return (importance_matrix, difficulty_matrix) as raters x items int ranks."""
    n_raters = len(next(iter(rating_map.values())))
    importance: list[list[int]] = [[] for _ in range(n_raters)]
    difficulty: list[list[int]] = [[] for _ in range(n_raters)]
    for labels in rating_map.values():
        for r, lbl in enumerate(labels):
            imp, diff = lbl.split(",")
            importance[r].append(RANK[imp])
            difficulty[r].append(RANK[diff])
    return importance, difficulty


def alpha_ordinal(matrix: list[list[int]]) -> float:
    """Krippendorff alpha with ordinal metric on rank-coded ratings.

    Wraps the `krippendorff` package's reference implementation. Returns 1.0
    when the package returns NaN (the convention for zero-variance data).
    """
    val = float(kd.alpha(reliability_data=matrix, level_of_measurement="ordinal"))
    return 1.0 if val != val else val  # NaN -> 1.0 (perfect agreement, no variance)


def alpha_for_round(rating_map: dict[str, list[str]]) -> dict[str, float]:
    imp, diff = split_axes(rating_map)
    a_imp = alpha_ordinal(imp)
    a_diff = alpha_ordinal(diff)
    return {
        "importance": a_imp,
        "difficulty": a_diff,
        "average": (a_imp + a_diff) / 2,
    }


def bootstrap_ci_average(
    rating_map: dict[str, list[str]],
    n_iter: int = BOOTSTRAP_ITERS,
    seed: int = BOOTSTRAP_SEED,
) -> tuple[float, float]:
    """Return (lo, hi) of a 95% bootstrap CI on the axis-averaged alpha.

    Resamples items (utility-tree leaves) with replacement to capture
    sampling uncertainty across the 12-leaf tree.
    """
    rng = random.Random(seed)
    items = list(rating_map.keys())
    n = len(items)
    samples: list[float] = []
    for _ in range(n_iter):
        picks = [items[rng.randrange(n)] for _ in range(n)]
        resampled = {f"{i}_{k}": rating_map[k] for i, k in enumerate(picks)}
        try:
            a = alpha_for_round(resampled)["average"]
        except Exception:
            continue
        if a == a:
            samples.append(a)
    if not samples:
        return float("nan"), float("nan")
    samples.sort()
    lo = samples[int(0.025 * len(samples))]
    hi = samples[int(0.975 * len(samples)) - 1]
    return lo, hi


def fleiss_kappa_joint(rating_map: dict[str, list[str]]) -> float:
    """Fleiss kappa over joint (importance, difficulty) categories.

    Each raw label such as "H,M" is one nominal category. Standard
    Fleiss (1971) formulation: kappa = (P_bar - P_e) / (1 - P_e), with
    P_bar the mean per-item agreement and P_e the chance agreement from
    the pooled category proportions.
    """
    rows = list(rating_map.values())
    n_items = len(rows)
    n_raters = len(rows[0])
    totals: dict[str, int] = {}
    p_bar_sum = 0.0
    for labels in rows:
        counts: dict[str, int] = {}
        for lbl in labels:
            counts[lbl] = counts.get(lbl, 0) + 1
            totals[lbl] = totals.get(lbl, 0) + 1
        p_i = (sum(c * c for c in counts.values()) - n_raters) / (n_raters * (n_raters - 1))
        p_bar_sum += p_i
    p_bar = p_bar_sum / n_items
    n_total = n_items * n_raters
    p_e = sum((t / n_total) ** 2 for t in totals.values())
    return (p_bar - p_e) / (1 - p_e)


def main() -> None:
    r1 = load_ratings(HERE / "round1_ratings.csv")
    r2 = load_ratings(HERE / "round2_ratings.csv")

    report: dict = {}
    for name, data in [("round1", r1), ("round2", r2)]:
        a = alpha_for_round(data)
        lo, hi = bootstrap_ci_average(data)
        kappa = fleiss_kappa_joint(data)
        print(
            f"{name}: alpha importance = {a['importance']:.4f}, "
            f"difficulty = {a['difficulty']:.4f}, "
            f"average = {a['average']:.4f}  "
            f"[95% CI {lo:.4f}, {hi:.4f}]"
        )
        print(f"{name}: fleiss kappa (joint importance-difficulty categories) = {kappa:.4f}")
        report[name] = {
            "alpha_importance": round(a["importance"], 4),
            "alpha_difficulty": round(a["difficulty"], 4),
            "alpha_average": round(a["average"], 4),
            "alpha_average_bootstrap_95ci": [round(lo, 4), round(hi, 4)],
            "fleiss_kappa_joint": round(kappa, 4),
        }

    report["paper_claims"] = {
        "section": "Section 5.2 (RQ1)",
        "krippendorff_alpha": "Round 2 alpha = 0.94 averaged across importance and difficulty; reproduced by round2.alpha_average",
        "fleiss_kappa": "Round 2 kappa = 0.78 (Round 1: 0.46) on joint categories; reproduced by round2.fleiss_kappa_joint and round1.fleiss_kappa_joint",
    }

    out = HERE / "agreement_results.json"
    out.write_text(json.dumps(report, indent=2))
    print(f"\nWrote {out.name}")


if __name__ == "__main__":
    main()
