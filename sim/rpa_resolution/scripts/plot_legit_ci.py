#!/usr/bin/env python3
"""Plot headline legitimate-resolution seed points and 95% confidence intervals.

This script mirrors the manuscript figure style used by
``docs/m6-journal-submission/scripts/redraw_problem_figures.py`` so rerunning it
does not overwrite Fig. 17 with an older raster-first style.
"""

from __future__ import annotations

import csv
import math
import os
import statistics
import tempfile
from collections import defaultdict
from pathlib import Path

os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "mplconfig"))
os.environ.setdefault("XDG_CACHE_HOME", str(Path(tempfile.gettempdir()) / "fontconfig-cache"))
os.environ.setdefault("FC_CACHEDIR", str(Path(tempfile.gettempdir()) / "fontconfig-cache"))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[3]
INPUT = ROOT / "sim/rpa_resolution/results/m10_statistical_extension/combined_summary.csv"
OUT_DIR = ROOT / "docs/m6-journal-submission/figures"
METHODS = ["BudgetDoS", "AdaptiveRateLimit", "P3-NoPersist", "P3-Persist"]
METHOD_LABELS = ["Budget", "Adaptive", "NoPersist", "Persist"]
SCENARIOS = [("medium_flood", "Medium flood"), ("heavy_flood", "Heavy flood")]
COLORS = {
    "BudgetDoS": "#D55E00",
    "AdaptiveRateLimit": "#CC79A7",
    "P3-NoPersist": "#0072B2",
    "P3-Persist": "#009E73",
}
T_CRIT_95 = {
    4: 2.776,
    19: 2.093,
}


def load_rows() -> list[dict[str, str]]:
    with INPUT.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def grouped_legit_rates(rows: list[dict[str, str]]) -> dict[tuple[str, str], list[float]]:
    grouped: dict[tuple[str, str], list[float]] = defaultdict(list)
    for row in rows:
        if row["m10_experiment"] != "main":
            continue
        if row["method"] not in METHODS:
            continue
        grouped[(row["m10_scenario"], row["method"])].append(float(row["legit_resolution_rate"]))
    return grouped


def ci95(values: list[float]) -> tuple[float, float]:
    mean = statistics.mean(values)
    if len(values) <= 1:
        return mean, 0.0
    half = T_CRIT_95.get(len(values) - 1, 1.96) * statistics.stdev(values) / math.sqrt(len(values))
    return mean, half


def main() -> None:
    rows = load_rows()
    grouped = grouped_legit_rates(rows)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 8.8,
            "axes.labelsize": 9.2,
            "axes.titlesize": 9.8,
            "xtick.labelsize": 8.2,
            "ytick.labelsize": 8.2,
            "legend.fontsize": 8.1,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.linewidth": 0.8,
            "grid.color": "#D8DEE9",
            "grid.linewidth": 0.45,
            "grid.alpha": 0.55,
            "figure.dpi": 160,
            "savefig.dpi": 600,
            "svg.fonttype": "none",
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.2), sharey=True)

    for ax, (scenario, title) in zip(axes, SCENARIOS):
        for idx, method in enumerate(METHODS):
            values = grouped[(scenario, method)]
            mean, half = ci95(values)
            x = idx + 1
            jitter = [x + (offset - (len(values) - 1) / 2) * 0.018 for offset in range(len(values))]
            ax.scatter(jitter, values, s=12, alpha=0.55, color=COLORS[method], edgecolor="white", linewidth=0.25)
            ax.errorbar(
                [x],
                [mean],
                yerr=[[half], [half]],
                fmt="o",
                color=COLORS[method],
                capsize=3.5,
                elinewidth=1.15,
                markersize=4.6,
            )
        ax.set_title(title)
        ax.set_xticks(range(1, len(METHODS) + 1))
        ax.set_xticklabels(METHOD_LABELS, rotation=15, ha="right")
        ax.set_ylim(0.50, 1.0)
        ax.grid(axis="y")

    axes[0].set_ylabel("Legitimate resolution rate")
    fig.tight_layout()
    for suffix in ("pdf", "svg", "png"):
        output = OUT_DIR / f"fig13_legit_rate_ci.{suffix}"
        fig.savefig(output, bbox_inches="tight", dpi=600)
        if suffix == "svg":
            output.write_text(
                "\n".join(line.rstrip() for line in output.read_text(encoding="utf-8").splitlines()) + "\n",
                encoding="utf-8",
            )


if __name__ == "__main__":
    main()
