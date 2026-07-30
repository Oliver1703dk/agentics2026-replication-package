"""Publication-quality matplotlib figures for NostrAgent benchmarks.

Targets Springer LNCS column width (8.25 cm / 3.25 in).
Fonts: Computer Modern (LaTeX-compatible) via pgf/text.usetex or fallback.
Grayscale-safe: fills use gray shades, distinguished by hatch patterns.

Usage:
    python -m eval.plot_figures [--out-dir <output directory>]

Outputs (all PDF):
    fig_bench_overview.pdf  -- grouped bar chart B1-B5, B10, B11
    fig_b6_trust_scaling.pdf -- log-log line plot trust query vs nodes
    fig_b3_depth.pdf        -- B3 delegation depth bars + linear regression
    fig_docker_benchmarks.pdf -- Docker infra benchmarks B4, B7, B8, B9
"""

from __future__ import annotations

import csv
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("pdf")  # non-interactive, no display required

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from scipy import stats as scipy_stats
import typer

# ---------------------------------------------------------------------------
# LNCS rcParams -- Computer Modern, 8pt body, 6pt minimum
# ---------------------------------------------------------------------------

LNCS_RCPARAMS: dict = {
    # Computer Modern via LaTeX (requires a working LaTeX installation)
    # Fall back gracefully if LaTeX is unavailable.
    "text.usetex": False,       # set True if LaTeX available on build system
    "font.family": "serif",
    "font.serif": ["Computer Modern Roman", "Times New Roman", "DejaVu Serif"],
    "font.size": 8,
    "axes.titlesize": 8,
    "axes.labelsize": 8,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "legend.fontsize": 7,
    "figure.dpi": 300,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.02,
    "pdf.fonttype": 42,         # embed fonts as Type 42 (TrueType) for PDF/A compliance
    "ps.fonttype": 42,
    "axes.linewidth": 0.5,
    "xtick.major.width": 0.5,
    "ytick.major.width": 0.5,
    "lines.linewidth": 0.8,
}

# LNCS text column width in inches
COL_W = 3.25  # 8.25 cm

# Grayscale fills (light to dark) + matching hatch patterns
GRAYS = ["0.85", "0.65", "0.45", "0.25", "0.15", "0.60", "0.35"]
HATCHES = ["", "///", "...", "xxx", "---", "\\\\\\", "|||"]


# ---------------------------------------------------------------------------
# Data loading helpers
# ---------------------------------------------------------------------------

def load_csv(path: Path) -> list[float]:
    """Return list of value_ms floats from a benchmark CSV."""
    with path.open() as f:
        return [float(row["value_ms"]) for row in csv.DictReader(f)]


def stats_from_csv(path: Path) -> dict[str, float]:
    """Return median, iqr (Q1-Q3), p25, p75, err_lo, err_hi from a CSV file."""
    vals = load_csv(path)
    arr = np.array(vals)
    q25, q75 = float(np.percentile(arr, 25)), float(np.percentile(arr, 75))
    median = float(np.median(arr))
    return {
        "median": median,
        "iqr": q75 - q25,
        "q25": q25,
        "q75": q75,
        "err_lo": median - q25,
        "err_hi": q75 - median,
        "n": len(vals),
    }


# ---------------------------------------------------------------------------
# Figure 1: Grouped bar chart -- B1, B2 (38100), B3 (depth-1), B5, B10, B11
# ---------------------------------------------------------------------------

def plot_bench_overview(results_dir: Path, out_path: Path) -> None:
    """Grouped bar: B1, B2(38100), B5, B10(1-cav), B10(5-cav), B11.

    Single-group bars (each benchmark is one bar). Asymmetric IQR error bars
    (Q25 below, Q75 above median). Grayscale + hatching for accessibility.
    """
    benchmarks = [
        ("B1",    "B1\nAuth",       results_dir / "B1_kind_38100.csv"),
        ("B2",    "B2\nSig",        results_dir / "B2_kind_38100.csv"),
        ("B5",    "B5\nAttest",     results_dir / "B5_kind_38102.csv"),
        ("B10-1", "B10\n1 cav",     results_dir / "B10_caveats_1.csv"),
        ("B10-5", "B10\n5 cav",     results_dir / "B10_caveats_5.csv"),
        ("B10-20","B10\n20 cav",    results_dir / "B10_caveats_20.csv"),
        ("B11",   "B11\nL402",      results_dir / "B11_full_5check.csv"),
    ]

    labels = [b[1] for b in benchmarks]
    medians, errs_lo, errs_hi = [], [], []
    for _, _, path in benchmarks:
        s = stats_from_csv(path)
        medians.append(s["median"])
        errs_lo.append(s["err_lo"])
        errs_hi.append(s["err_hi"])

    x = np.arange(len(labels))
    fig, ax = plt.subplots(figsize=(COL_W, 1.9))

    for i, (med, elo, ehi) in enumerate(zip(medians, errs_lo, errs_hi)):
        ax.bar(
            x[i], med,
            color=GRAYS[i % len(GRAYS)],
            hatch=HATCHES[i % len(HATCHES)],
            edgecolor="black",
            linewidth=0.5,
            width=0.65,
            yerr=[[elo], [ehi]],
            capsize=2.5,
            error_kw={"elinewidth": 0.6, "capthick": 0.6, "ecolor": "black"},
        )

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7, linespacing=1.1)
    ax.set_ylabel("Latency (ms)", fontsize=7)
    ax.set_title("Crypto/Attestation/L402 Benchmarks (B1, B2, B5, B10, B11)", fontsize=7)
    ax.yaxis.grid(True, linewidth=0.3, linestyle="--", alpha=0.7)
    ax.set_axisbelow(True)
    ax.tick_params(axis="both", which="both", length=2)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    fig.tight_layout(pad=0.3)
    fig.savefig(out_path)
    plt.close(fig)
    print(f"  Saved: {out_path}")


# ---------------------------------------------------------------------------
# Figure 2: Log-log plot -- B6 trust query latency vs. graph size
# All data measured at the default decay d=0.5. Power-law fit overlaid as a
# visual guide. Decay sensitivity is reported separately via SP-5 in Section 5.1.
# ---------------------------------------------------------------------------

def plot_b6_trust_scaling(results_dir: Path, out_path: Path) -> None:
    """Log-log: trust query latency vs. graph size (d=0.5 measured)."""
    node_counts = [5, 10, 20, 50, 100, 200, 500]
    file_map = {
        5:   "B6_nodes_5.csv",
        10:  "B6_nodes_10.csv",
        20:  "B6_nodes_20.csv",
        50:  "B6_nodes_50.csv",
        100: "B6_nodes_100.csv",
        200: "B6_nodes_200.csv",
        500: "B6_nodes_500.csv",
    }

    measured_medians = []
    measured_errs_lo = []
    measured_errs_hi = []
    for n in node_counts:
        s = stats_from_csv(results_dir / file_map[n])
        measured_medians.append(s["median"])
        measured_errs_lo.append(s["err_lo"])
        measured_errs_hi.append(s["err_hi"])

    measured_arr = np.array(measured_medians)
    nodes_arr = np.array(node_counts, dtype=float)

    # Power-law fit to the measured d=0.5 data as a visual guide.
    # log(T) = alpha * log(N) + c  => fit in log space.
    log_n = np.log(nodes_arr)
    log_t = np.log(measured_arr)
    alpha, log_c = np.polyfit(log_n, log_t, 1)
    c = np.exp(log_c)
    n_smooth = np.logspace(np.log10(5), np.log10(500), 100)
    fit_curve = c * n_smooth**alpha

    fig, ax = plt.subplots(figsize=(COL_W, 1.9))

    # Measured points with asymmetric IQR error bars
    ax.errorbar(
        nodes_arr, measured_arr,
        yerr=[measured_errs_lo, measured_errs_hi],
        fmt="s",
        color="0.2",
        markersize=3,
        linewidth=0,
        elinewidth=0.6,
        capsize=2,
        capthick=0.6,
        label="Measured (IQR)",
        zorder=5,
    )
    ax.plot(
        n_smooth, fit_curve,
        color="0.2", linestyle="-", linewidth=0.9,
        label=f"Power-law fit ($T \\propto N^{{{alpha:.2f}}}$)",
    )

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Graph nodes", fontsize=7)
    ax.set_ylabel("Query latency (ms)", fontsize=7)
    ax.set_title("B6: Trust Graph Query Scaling (noisy-OR, depth\u22644)", fontsize=7)
    ax.legend(fontsize=6, framealpha=0.85, edgecolor="0.7", handlelength=1.5)
    ax.tick_params(axis="both", which="both", length=2)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(True, which="major", linewidth=0.3, linestyle="--", alpha=0.6)
    ax.grid(True, which="minor", linewidth=0.15, linestyle=":", alpha=0.4)

    fig.tight_layout(pad=0.3)
    fig.savefig(out_path)
    plt.close(fig)
    print(f"  Saved: {out_path}")


# ---------------------------------------------------------------------------
# Figure 3: B3 delegation depth -- bars + OLS linear regression overlay
# ---------------------------------------------------------------------------

def plot_b3_depth(results_dir: Path, out_path: Path) -> None:
    """Bar chart: B3 delegation chain verification latency vs. chain depth.

    Overlays an OLS linear regression line to demonstrate O(depth) scaling.
    """
    depths = [1, 2, 3, 4]
    file_map = {
        1: "B3_depth_1.csv",
        2: "B3_depth_2.csv",
        3: "B3_depth_3.csv",
        4: "B3_depth_4.csv",
    }

    medians, errs_lo, errs_hi = [], [], []
    for d in depths:
        s = stats_from_csv(results_dir / file_map[d])
        medians.append(s["median"])
        errs_lo.append(s["err_lo"])
        errs_hi.append(s["err_hi"])

    depths_arr = np.array(depths, dtype=float)
    medians_arr = np.array(medians)

    # OLS linear regression
    slope, intercept, r_value, p_value, se = scipy_stats.linregress(depths_arr, medians_arr)
    fit_x = np.linspace(0.5, 4.5, 100)
    fit_y = slope * fit_x + intercept

    fig, ax = plt.subplots(figsize=(COL_W, 1.9))

    bar_width = 0.55
    for i, (d, med, elo, ehi) in enumerate(zip(depths, medians, errs_lo, errs_hi)):
        ax.bar(
            d, med,
            width=bar_width,
            color=GRAYS[i],
            hatch=HATCHES[i],
            edgecolor="black",
            linewidth=0.5,
            yerr=[[elo], [ehi]],
            capsize=3,
            error_kw={"elinewidth": 0.6, "capthick": 0.6, "ecolor": "black"},
        )

    # Regression line
    ax.plot(
        fit_x, fit_y,
        color="0.1",
        linestyle="--",
        linewidth=0.9,
        label=f"OLS fit (R²={r_value**2:.3f})",
        zorder=5,
    )

    ax.set_xticks(depths)
    ax.set_xticklabels([f"depth {d}" for d in depths], fontsize=7)
    ax.set_ylabel("Verify latency (ms)", fontsize=7)
    ax.set_title("B3: Delegation Chain Depth vs. Verification Latency", fontsize=7)
    ax.legend(fontsize=6, framealpha=0.85, edgecolor="0.7")
    ax.yaxis.grid(True, linewidth=0.3, linestyle="--", alpha=0.7)
    ax.set_axisbelow(True)
    ax.tick_params(axis="both", which="both", length=2)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.set_xlim(0.5, 4.5)

    fig.tight_layout(pad=0.3)
    fig.savefig(out_path)
    plt.close(fig)
    print(f"  Saved: {out_path}")


# ---------------------------------------------------------------------------
# Figure 4: Docker infrastructure benchmarks -- B4, B7, B8, B9
# ---------------------------------------------------------------------------

def plot_docker_benchmarks(results_dir: Path, out_path: Path) -> None:
    """Bar chart: Docker-dependent benchmarks B4, B7, B8, B9 on log scale.

    Uses log Y-axis because latencies span two orders of magnitude
    (~2 ms for relay discovery vs ~337 ms for revocation propagation).
    Asymmetric IQR error bars (Q25 below, Q75 above median).
    """
    benchmarks = [
        ("B4", "B4\n3 relays",    results_dir / "B4_relays_3.csv"),
        ("B7", "B7\nRotation",    results_dir / "B7_key_rotation.csv"),
        ("B8", "B8\nRevocation",  results_dir / "B8_revocation_propagation.csv"),
        ("B9", "B9\nL402",        results_dir / "B9_l402_full_flow.csv"),
    ]

    labels = [b[1] for b in benchmarks]
    medians, errs_lo, errs_hi = [], [], []
    for _, _, path in benchmarks:
        s = stats_from_csv(path)
        medians.append(s["median"])
        errs_lo.append(s["err_lo"])
        errs_hi.append(s["err_hi"])

    x = np.arange(len(labels))
    fig, ax = plt.subplots(figsize=(COL_W, 1.9))

    for i, (med, elo, ehi) in enumerate(zip(medians, errs_lo, errs_hi)):
        ax.bar(
            x[i], med,
            color=GRAYS[i % len(GRAYS)],
            hatch=HATCHES[i % len(HATCHES)],
            edgecolor="black",
            linewidth=0.5,
            width=0.65,
            yerr=[[elo], [ehi]],
            capsize=2.5,
            error_kw={"elinewidth": 0.6, "capthick": 0.6, "ecolor": "black"},
        )

    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7, linespacing=1.1)
    ax.set_ylabel("Latency (ms, log scale)", fontsize=7)
    ax.set_title("Docker Infrastructure Benchmarks", fontsize=7)
    ax.yaxis.grid(True, which="major", linewidth=0.3, linestyle="--", alpha=0.7)
    ax.yaxis.grid(True, which="minor", linewidth=0.15, linestyle=":", alpha=0.4)
    ax.set_axisbelow(True)
    ax.tick_params(axis="both", which="both", length=2)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    fig.tight_layout(pad=0.3)
    fig.savefig(out_path)
    plt.close(fig)
    print(f"  Saved: {out_path}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

app = typer.Typer(help="Generate publication-quality figures for NostrAgent paper.")


@app.command()
def main(
    results_dir: Path = typer.Option(
        Path(__file__).parent / "results",
        "--results", "-r",
        help="Directory containing benchmark CSV files.",
    ),
    out_dir: Path = typer.Option(
        Path(__file__).parent.parent.parent / "paper" / "figures",
        "--out-dir", "-o",
        help="Output directory for PDF figures.",
    ),
    usetex: bool = typer.Option(
        False, "--usetex",
        help="Enable text.usetex (requires LaTeX + dvipng/dvisvgm on PATH).",
    ),
) -> None:
    """Generate all four paper figures and save as PDF."""
    # If results_dir doesn't contain CSVs directly, look for latest timestamped run
    if not (results_dir / "B1_kind_38100.csv").exists():
        # Try to find latest timestamped subdirectory
        candidates = sorted(results_dir.glob("*/benchmarks/B1_kind_38100.csv"))
        if candidates:
            results_dir = candidates[-1].parent  # Use the benchmarks/ dir of latest run

    out_dir.mkdir(parents=True, exist_ok=True)

    # Apply LNCS rcParams
    rc = dict(LNCS_RCPARAMS)
    rc["text.usetex"] = usetex
    plt.rcParams.update(rc)

    print(f"Results dir : {results_dir}")
    print(f"Output dir  : {out_dir}")
    print(f"usetex      : {usetex}")
    print()

    plot_bench_overview(results_dir, out_dir / "fig_bench_overview.pdf")
    plot_b6_trust_scaling(results_dir, out_dir / "fig_b6_trust_scaling.pdf")
    plot_b3_depth(results_dir, out_dir / "fig_b3_depth.pdf")
    plot_docker_benchmarks(results_dir, out_dir / "fig_docker_benchmarks.pdf")

    print("\nAll figures saved.")


if __name__ == "__main__":
    app()
