"""Generate all paper-ready artifacts from benchmark CSVs.

Single entry point: reads eval/results/*.csv and writes .tex tables and
.pdf figures (the artifacts the paper imports as figures and tables),
plus a summary JSON.

Usage:
    python -m eval.generate_paper_artifacts
    python -m eval.generate_paper_artifacts --results eval/results --tables ./tables --figures ./figures
    python -m eval.generate_paper_artifacts --usetex  # requires LaTeX on PATH

Design rationale: kept as one script (not a pipeline of many) because:
- All outputs share the same loaded data; splitting adds no reuse benefit.
- The paper is single-author; a Makefile-style pipeline is over-engineering here.
- Figures and tables must stay consistent; one call guarantees that.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import NamedTuple

import matplotlib
matplotlib.use("pdf")

import matplotlib.pyplot as plt
import numpy as np
import typer
from rich.console import Console
from rich.table import Table as RichTable

from eval.benchmark_config import COMPARATIVE_ALPHA
from eval.plot_figures import LNCS_RCPARAMS, plot_b3_depth, plot_b6_trust_scaling, plot_bench_overview
from eval.stats import cliffs_delta, mann_whitney_test

console = Console()

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_csv(path: Path) -> list[float]:
    """Return value_ms floats from a benchmark CSV (all rows)."""
    with path.open() as f:
        return [float(row["value_ms"]) for row in csv.DictReader(f)]


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

class BenchStats(NamedTuple):
    median: float
    iqr: float      # Q3 - Q1
    p95: float
    p99: float
    n: int


def compute_statistics(values: list[float]) -> BenchStats:
    """Compute paper-required statistics for a single metric sample.

    Args:
        values: Raw timing measurements in ms (warm-up already excluded by bench.py).

    Returns:
        BenchStats with median, IQR, P95, P99, and sample count.
    """
    arr = np.array(values)
    q25, q75 = float(np.percentile(arr, 25)), float(np.percentile(arr, 75))
    return BenchStats(
        median=float(np.median(arr)),
        iqr=q75 - q25,
        p95=float(np.percentile(arr, 95)),
        p99=float(np.percentile(arr, 99)),
        n=len(values),
    )


def compare_variants(
    variants: dict[str, list[float]],
) -> list[dict]:
    """Run Mann-Whitney U + Cliff's delta for all ordered variant pairs.

    Args:
        variants: Mapping of variant label → raw values.

    Returns:
        List of comparison dicts, one per pair.
    """
    labels = list(variants.keys())
    results = []
    for i in range(len(labels)):
        for j in range(i + 1, len(labels)):
            a_label, b_label = labels[i], labels[j]
            a_vals, b_vals = variants[a_label], variants[b_label]
            mw = mann_whitney_test(a_vals, b_vals, alpha=COMPARATIVE_ALPHA)
            cd = cliffs_delta(a_vals, b_vals)
            results.append({
                "a": a_label,
                "b": b_label,
                "U": mw["U_statistic"],
                "p_value": mw["p_value"],
                "significant": mw["significant"],
                "cliffs_delta": cd["delta"],
                "magnitude": cd["magnitude"],
            })
    return results


# ---------------------------------------------------------------------------
# LaTeX table generation (booktabs)
# ---------------------------------------------------------------------------

# Benchmark groups: (benchmark_id, display_name, {variant_label: csv_filename})
BENCHMARK_GROUPS: list[tuple[str, str, dict[str, str]]] = [
    ("B1",  "Identity publish (Kind 38100)",     {"kind\\_38100": "B1_kind_38100.csv"}),
    ("B2",  "Sig verify (all kinds)",            {
        "kind\\_38100": "B2_kind_38100.csv",
        "kind\\_38101": "B2_kind_38101.csv",
        "kind\\_38102": "B2_kind_38102.csv",
    }),
    ("B3",  "Delegation chain verify",           {
        "depth=1": "B3_depth_1.csv",
        "depth=2": "B3_depth_2.csv",
        "depth=3": "B3_depth_3.csv",
        "depth=4": "B3_depth_4.csv",
    }),
    ("B5",  "Peer attestation (Kind 38102)",     {"kind\\_38102": "B5_kind_38102.csv"}),
    ("B6",  "Trust graph query (noisy-OR)",      {
        "n=5":   "B6_nodes_5.csv",
        "n=10":  "B6_nodes_10.csv",
        "n=20":  "B6_nodes_20.csv",
        "n=50":  "B6_nodes_50.csv",
        "n=100": "B6_nodes_100.csv",
        "n=200": "B6_nodes_200.csv",
        "n=500": "B6_nodes_500.csv",
    }),
    ("B10", "L402 macaroon verify",             {
        "caveats=1":  "B10_caveats_1.csv",
        "caveats=5":  "B10_caveats_5.csv",
        "caveats=10": "B10_caveats_10.csv",
        "caveats=20": "B10_caveats_20.csv",
    }),
    ("B11", "L402 full flow (5 checks)",        {"full\\_5check": "B11_full_5check.csv"}),
]


def _fmt(val: float, decimals: int = 3) -> str:
    return f"{val:.{decimals}f}"


def generate_latex_table(
    groups: list[tuple[str, str, dict[str, str]]],
    results_dir: Path,
    caption: str,
    label: str,
) -> str:
    """Build a booktabs LaTeX table: Benchmark | Variant | n | Median | IQR | P95 | P99 (ms).

    Args:
        groups: BENCHMARK_GROUPS or a subset.
        results_dir: Directory containing CSV files.
        caption: LaTeX \\caption text.
        label: LaTeX \\label key.

    Returns:
        Complete LaTeX table string.
    """
    rows: list[tuple[str, str, BenchStats]] = []
    for bench_id, bench_name, variants in groups:
        first = True
        for variant_label, csv_file in variants.items():
            path = results_dir / csv_file
            if not path.exists():
                console.print(f"  [yellow]Skip (missing): {csv_file}[/yellow]")
                continue
            stats = compute_statistics(load_csv(path))
            display_id = f"\\textbf{{{bench_id}}}" if first else ""
            first = False
            rows.append((display_id, variant_label, stats))

    lines = [
        "\\begin{table}[t]",
        "\\centering",
        "\\small",
        f"\\caption{{{caption}}}",
        f"\\label{{{label}}}",
        "\\begin{tabular}{@{}llrrrrl@{}}",
        "\\toprule",
        "Benchmark & Variant & $n$ & Median (ms) & IQR (ms) & P95 (ms) & P99 (ms) \\\\",
        "\\midrule",
    ]

    prev_id = ""
    for display_id, variant, stats in rows:
        if display_id and prev_id:
            lines.append("\\midrule")  # separate benchmark groups
        if display_id:
            prev_id = display_id
        lines.append(
            f"{display_id} & {variant} & {stats.n} & "
            f"{_fmt(stats.median)} & {_fmt(stats.iqr)} & "
            f"{_fmt(stats.p95)} & {_fmt(stats.p99)} \\\\"
        )

    lines += [
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ]
    return "\n".join(lines)


def generate_comparison_table(
    groups: list[tuple[str, str, dict[str, str]]],
    results_dir: Path,
    caption: str,
    label: str,
) -> str:
    """Build a booktabs LaTeX table for Mann-Whitney + Cliff's delta comparisons.

    Only emits rows for benchmark groups that have ≥2 variants.
    """
    lines = [
        "\\begin{table}[t]",
        "\\centering",
        "\\small",
        f"\\caption{{{caption}}}",
        f"\\label{{{label}}}",
        "\\begin{tabular}{@{}llllrrl@{}}",
        "\\toprule",
        "Bench & Variant A & Variant B & $p$-value & $\\delta$ (Cliff's) & Magnitude & Sig. \\\\",
        "\\midrule",
    ]

    first_group = True
    for bench_id, _bench_name, variants in groups:
        valid = {
            lbl: load_csv(results_dir / fname)
            for lbl, fname in variants.items()
            if (results_dir / fname).exists()
        }
        if len(valid) < 2:
            continue

        if not first_group:
            lines.append("\\midrule")
        first_group = False

        comparisons = compare_variants(valid)
        for i, comp in enumerate(comparisons):
            bench_col = f"\\textbf{{{bench_id}}}" if i == 0 else ""
            sig_marker = "$\\bullet$" if comp["significant"] else ""
            lines.append(
                f"{bench_col} & {comp['a']} & {comp['b']} & "
                f"{comp['p_value']:.3e} & {comp['cliffs_delta']:+.3f} & "
                f"{comp['magnitude']} & {sig_marker} \\\\"
            )

    lines += [
        "\\bottomrule",
        "\\multicolumn{7}{l}{\\footnotesize $\\bullet$ = $p < 0.05$, Mann-Whitney U two-sided.} \\\\",
        "\\end{tabular}",
        "\\end{table}",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Summary JSON
# ---------------------------------------------------------------------------

def build_summary_json(
    groups: list[tuple[str, str, dict[str, str]]],
    results_dir: Path,
) -> dict:
    """Build a summary dict suitable for serialising to summary.json.

    Structure: {benchmark_id: {variant: {median, iqr, p95, p99, n}}}
    Plus top-level comparisons list.
    """
    summary: dict = {"benchmarks": {}, "comparisons": []}

    for bench_id, bench_name, variants in groups:
        summary["benchmarks"][bench_id] = {"name": bench_name, "variants": {}}
        variant_data: dict[str, list[float]] = {}

        for variant_label, csv_file in variants.items():
            path = results_dir / csv_file
            if not path.exists():
                continue
            vals = load_csv(path)
            stats = compute_statistics(vals)
            summary["benchmarks"][bench_id]["variants"][variant_label] = {
                "median_ms": stats.median,
                "iqr_ms":    stats.iqr,
                "p95_ms":    stats.p95,
                "p99_ms":    stats.p99,
                "n":         stats.n,
            }
            variant_data[variant_label] = vals

        if len(variant_data) >= 2:
            for comp in compare_variants(variant_data):
                summary["comparisons"].append({"benchmark": bench_id, **comp})

    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

app = typer.Typer(help="Generate paper tables, figures, and summary JSON from benchmark CSVs.")


@app.command()
def main(
    results: Path = typer.Option(
        Path(__file__).parent / "results",
        "--results", "-r",
        help="Directory containing benchmark CSV files.",
    ),
    tables: Path = typer.Option(
        Path(__file__).parent.parent.parent / "paper" / "tables",
        "--tables",
        help="Output directory for LaTeX .tex table files.",
    ),
    figures: Path = typer.Option(
        Path(__file__).parent.parent.parent / "paper" / "figures",
        "--figures",
        help="Output directory for PDF figure files.",
    ),
    usetex: bool = typer.Option(
        False, "--usetex",
        help="Enable text.usetex for LaTeX-rendered fonts (requires LaTeX on PATH).",
    ),
) -> None:
    """Full pipeline: CSVs → LaTeX tables + PDF figures + summary.json."""
    tables.mkdir(parents=True, exist_ok=True)
    figures.mkdir(parents=True, exist_ok=True)

    console.rule("[bold]NostrAgent paper artifact generation[/bold]")
    console.print(f"  Results : {results}")
    console.print(f"  Tables  : {tables}")
    console.print(f"  Figures : {figures}")

    # --- LaTeX tables ---
    console.rule("Tables")

    bench_tex = generate_latex_table(
        BENCHMARK_GROUPS, results,
        caption="NostrAgent benchmark results (median, IQR, P95, P99; 900 effective runs each).",
        label="tab:benchmarks",
    )
    (tables / "benchmark_results.tex").write_text(bench_tex)
    console.print("  Saved: benchmark_results.tex")

    cmp_tex = generate_comparison_table(
        BENCHMARK_GROUPS, results,
        caption="Variant comparisons: Mann-Whitney U and Cliff's delta effect size.",
        label="tab:comparisons",
    )
    (tables / "comparison_stats.tex").write_text(cmp_tex)
    console.print("  Saved: comparison_stats.tex")

    # --- Summary JSON ---
    console.rule("Summary JSON")
    summary = build_summary_json(BENCHMARK_GROUPS, results)
    summary_path = results / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, default=bool))
    console.print(f"  Saved: {summary_path}")

    # --- Rich preview table ---
    rich_t = RichTable(title="Statistics preview", show_header=True, header_style="bold")
    for col in ["Benchmark", "Variant", "n", "Median (ms)", "IQR", "P95", "P99"]:
        rich_t.add_column(col, justify="right" if col not in ("Benchmark", "Variant") else "left")
    for bench_id, bench_data in summary["benchmarks"].items():
        for variant, s in bench_data["variants"].items():
            rich_t.add_row(
                bench_id, variant, str(s["n"]),
                f"{s['median_ms']:.4f}", f"{s['iqr_ms']:.4f}",
                f"{s['p95_ms']:.4f}", f"{s['p99_ms']:.4f}",
            )
    console.print(rich_t)

    # --- Figures ---
    console.rule("Figures")
    rc = dict(LNCS_RCPARAMS)
    rc["text.usetex"] = usetex
    plt.rcParams.update(rc)

    plot_bench_overview(results, figures / "fig_bench_overview.pdf")
    plot_b6_trust_scaling(results, figures / "fig_b6_trust_scaling.pdf")
    plot_b3_depth(results, figures / "fig_b3_depth.pdf")

    console.rule("[green]Done[/green]")


if __name__ == "__main__":
    app()
