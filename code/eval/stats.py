"""Statistical comparison utilities for benchmark analysis (spec section 5.5).

Provides Mann-Whitney U test and Cliff's delta effect size with Romano et al.
(2006) thresholds for interpreting effect magnitude. Used to compare variants
within the same benchmark (e.g. delegation chain depth 1 vs 2, graph sizes).
"""

from __future__ import annotations

from scipy.stats import mannwhitneyu  # type: ignore[import]


def mann_whitney_test(
    sample_a: list[float],
    sample_b: list[float],
    alpha: float = 0.05,
) -> dict:
    """Mann-Whitney U test for comparing two independent samples.

    Non-parametric test appropriate for benchmark timing distributions which
    are typically right-skewed (not normally distributed).

    Args:
        sample_a: First sample of timing measurements (ms).
        sample_b: Second sample of timing measurements (ms).
        alpha: Significance level (default 0.05).

    Returns:
        Dict with U_statistic, p_value, significant (bool).
    """
    stat, p_value = mannwhitneyu(sample_a, sample_b, alternative="two-sided")
    return {
        "U_statistic": float(stat),
        "p_value": float(p_value),
        "significant": p_value < alpha,
    }


def cliffs_delta(sample_a: list[float], sample_b: list[float]) -> dict:
    """Cliff's delta effect size with Romano et al. (2006) thresholds.

    Measures the probability that a randomly selected value from sample_a
    is larger than a randomly selected value from sample_b, minus the
    reverse probability. Range: [-1, 1].

    Romano thresholds:
      |delta| < 0.147 -> negligible
      |delta| < 0.33  -> small
      |delta| < 0.474 -> medium
      |delta| >= 0.474 -> large

    Args:
        sample_a: First sample of timing measurements (ms).
        sample_b: Second sample of timing measurements (ms).

    Returns:
        Dict with delta (float) and magnitude (str).
    """
    n_a, n_b = len(sample_a), len(sample_b)
    dominance = sum(
        (1 if a > b else -1 if a < b else 0)
        for a in sample_a
        for b in sample_b
    )
    delta = dominance / (n_a * n_b)

    abs_delta = abs(delta)
    if abs_delta < 0.147:
        magnitude = "negligible"
    elif abs_delta < 0.33:
        magnitude = "small"
    elif abs_delta < 0.474:
        magnitude = "medium"
    else:
        magnitude = "large"

    return {"delta": delta, "magnitude": magnitude}
