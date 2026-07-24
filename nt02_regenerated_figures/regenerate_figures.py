#!/usr/bin/env python3
"""Regenerate manuscript Figures 9, 15, and 17 with print-readable fonts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
import os
import statistics
import tempfile
from collections import defaultdict
from pathlib import Path

os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "mplconfig-btky-nt02"))
os.environ.setdefault("XDG_CACHE_HOME", str(Path(tempfile.gettempdir()) / "fontconfig-btky-nt02"))
os.environ.setdefault("FC_CACHEDIR", str(Path(tempfile.gettempdir()) / "fontconfig-btky-nt02"))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from PIL import Image


REPO = Path(__file__).resolve().parents[4]
DATA_ROOT = REPO
DATA_M10 = DATA_ROOT / "sim/rpa_resolution/figures/m10_statistical_extension"
RESULTS_M10 = DATA_ROOT / "sim/rpa_resolution/results/m10_statistical_extension/combined_summary.csv"
OUT = Path(__file__).resolve().parent

COLORS = {
    "Random-RL": "#8DA0CB",
    "BudgetDoS": "#D55E00",
    "AdaptiveRateLimit": "#CC79A7",
    "P3-NoPersist": "#0072B2",
    "P3-Persist": "#009E73",
}
T_CRIT_95 = {4: 2.776, 19: 2.093}


def set_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 11.0,
            "axes.labelsize": 12.0,
            "axes.titlesize": 12.2,
            "xtick.labelsize": 10.5,
            "ytick.labelsize": 10.5,
            "legend.fontsize": 10.5,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.linewidth": 0.9,
            "grid.color": "#D8DEE9",
            "grid.linewidth": 0.55,
            "grid.alpha": 0.60,
            "figure.dpi": 180,
            "savefig.dpi": 600,
            "savefig.facecolor": "white",
            "svg.fonttype": "none",
            "svg.hashsalt": "btky-nt02",
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-root",
        type=Path,
        default=REPO,
        help="Directory containing sim/rpa_resolution (default: repository root).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Directory for generated figures and figure_manifest.csv.",
    )
    return parser.parse_args()


def configure_paths(data_root: Path, output_dir: Path) -> None:
    global DATA_ROOT, DATA_M10, RESULTS_M10, OUT
    DATA_ROOT = data_root.resolve()
    DATA_M10 = DATA_ROOT / "sim/rpa_resolution/figures/m10_statistical_extension"
    RESULTS_M10 = DATA_ROOT / "sim/rpa_resolution/results/m10_statistical_extension/combined_summary.csv"
    OUT = output_dir.resolve()
    required = [DATA_M10 / "table_m10_headline_stats.csv", RESULTS_M10]
    missing = [path for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError("Missing packaged M10 input(s): " + ", ".join(str(path) for path in missing))
    OUT.mkdir(parents=True, exist_ok=True)


def portable_path(path: Path) -> str:
    try:
        return str(path.relative_to(DATA_ROOT))
    except ValueError:
        return str(path)


def pad_png_to_aspect(path: Path, target_aspect: float) -> None:
    with Image.open(path) as source:
        width, height = source.size
        current_aspect = width / height
        if abs(current_aspect - target_aspect) < 0.001:
            return
        if current_aspect < target_aspect:
            canvas_width = math.ceil(height * target_aspect)
            canvas_height = height
        else:
            canvas_width = width
            canvas_height = math.ceil(width / target_aspect)
        canvas = Image.new("RGB", (canvas_width, canvas_height), "white")
        canvas.paste(source.convert("RGB"), ((canvas_width - width) // 2, (canvas_height - height) // 2))
        canvas.save(path, dpi=(600, 600))


def save(fig: plt.Figure, stem: str, target_png_aspect: float) -> None:
    for ext in ("pdf", "svg", "png"):
        path = OUT / f"{stem}.{ext}"
        metadata: dict[str, object] | None = None
        if ext == "pdf":
            metadata = {
                "Creator": "btky NT-02 reproducible figure generator",
                "CreationDate": None,
                "ModDate": None,
            }
        elif ext == "svg":
            metadata = {"Creator": "btky NT-02 reproducible figure generator", "Date": None}
        fig.savefig(path, bbox_inches="tight", dpi=600, metadata=metadata)
        if ext == "svg":
            path.write_text(
                "\n".join(line.rstrip() for line in path.read_text(encoding="utf-8").splitlines()) + "\n",
                encoding="utf-8",
            )
        elif ext == "png":
            pad_png_to_aspect(path, target_png_aspect)
    plt.close(fig)


def figure9() -> None:
    rows = [
        row
        for row in read_csv(DATA_M10 / "table_m10_headline_stats.csv")
        if row["m10_experiment"] == "main" and row["m10_scenario"] == "heavy_flood"
    ]
    methods = ["Random-RL", "BudgetDoS", "AdaptiveRateLimit", "P3-NoPersist", "P3-Persist"]
    labels = methods
    selected = {row["method"]: row for row in rows if row["method"] in methods}
    y = list(range(len(methods)))
    colors = [COLORS[method] for method in methods]

    attack = [float(selected[m]["attack_aes_amplification_mean"]) for m in methods]
    attack_low = [float(selected[m]["attack_aes_amplification_ci95_low"]) for m in methods]
    attack_high = [float(selected[m]["attack_aes_amplification_ci95_high"]) for m in methods]
    attack_yerr = [
        [value - low for value, low in zip(attack, attack_low)],
        [high - value for value, high in zip(attack, attack_high)],
    ]
    legit = [float(selected[m]["legit_resolution_rate_mean"]) * 100 for m in methods]
    legit_low = [float(selected[m]["legit_resolution_rate_ci95_low"]) * 100 for m in methods]
    legit_high = [float(selected[m]["legit_resolution_rate_ci95_high"]) * 100 for m in methods]
    legit_yerr = [
        [value - low for value, low in zip(legit, legit_low)],
        [high - value for value, high in zip(legit, legit_high)],
    ]

    fig, (ax_attack, ax_service) = plt.subplots(1, 2, figsize=(8.0, 4.35))
    ax_attack.barh(y, attack, color=colors, edgecolor="white", linewidth=0.6, height=0.72, zorder=3)
    ax_attack.errorbar(attack, y, xerr=attack_yerr, fmt="none", ecolor="#2B2B2B", elinewidth=0.9, capsize=2.6, zorder=4)
    ax_attack.set_xscale("log")
    ax_attack.set_title("Attack work under heavy flood", pad=7)
    ax_attack.set_xlabel("Attack amplification (AES/min)")
    ax_attack.set_yticks(y)
    ax_attack.set_yticklabels(labels)
    ax_attack.grid(True, axis="x", which="major")
    ax_attack.grid(True, axis="x", which="minor", alpha=0.16)
    ax_attack.axvspan(4.40e4, 4.70e4, color="#EAF6EF", alpha=0.55, zorder=0)
    ax_attack.text(6.0e4, 2.5, "bounded methods\nsame band", ha="left", va="center", fontsize=10.0, color="#26734D")

    ax_service.barh(y, legit, color=colors, edgecolor="white", linewidth=0.6, height=0.72, zorder=3)
    ax_service.errorbar(legit, y, xerr=legit_yerr, fmt="none", ecolor="#2B2B2B", elinewidth=0.9, capsize=2.6, zorder=4)
    ax_service.set_title("Legitimate service, same runs", pad=7)
    ax_service.set_xlabel("Legitimate resolution (%)")
    ax_service.set_yticks(y)
    ax_service.set_yticklabels(labels)
    ax_service.set_xlim(0, 105)
    ax_service.grid(True, axis="x")
    ax_service.annotate(
        "reserve recovery",
        xy=(legit[-1], y[-1]),
        xytext=(69.0, y[-1] - 0.55),
        ha="left",
        va="center",
        fontsize=10.0,
        color=COLORS["P3-Persist"],
        arrowprops=dict(arrowstyle="-", color=COLORS["P3-Persist"], linewidth=0.9, shrinkA=3, shrinkB=3),
    )
    ax_attack.invert_yaxis()
    ax_service.invert_yaxis()
    fig.text(0.50, 0.975, "M10 main heavy flood, 10000 attack RPAs/min, 20 seeds", ha="center", va="top", fontsize=10.5, color="#384252")
    fig.subplots_adjust(left=0.16, right=0.985, bottom=0.15, top=0.82, wspace=0.46)
    save(fig, "figure09_large_font", 4442 / 1963)


def row_for(rows: list[dict[str, str]], experiment: str, **criteria: str) -> dict[str, str]:
    return next(
        row
        for row in rows
        if row["m10_experiment"] == experiment
        and row["method"] == "P3-Persist"
        and all(str(row[key]) == str(value) for key, value in criteria.items())
    )


def figure15() -> None:
    rows = read_csv(DATA_M10 / "table_m10_headline_stats.csv")
    panels = [
        (
            "(a) Reserve size R",
            ["50", "100", "200", "400"],
            [row_for(rows, "reserve_sensitivity", persist_reserve=v, persist_k="1") for v in ["50", "100", "200", "400"]],
        ),
        (
            "(b) Persistence threshold k",
            ["1", "2", "3"],
            [row_for(rows, "threshold_sensitivity", persist_reserve="200", persist_k=v) for v in ["1", "2", "3"]],
        ),
        (
            "(c) Duplicate-filter boundary",
            ["unique\nstress", "repeated\nno filter", "repeated\n60 s filter"],
            [
                row_for(rows, "attacker_dilemma", unique_attack_rpa="True", duplicate_filter_window_s="0"),
                row_for(rows, "attacker_dilemma", unique_attack_rpa="False", duplicate_filter_window_s="0"),
                row_for(rows, "attacker_dilemma", unique_attack_rpa="False", duplicate_filter_window_s="60"),
            ],
        ),
        (
            "(d) Repeated-address rate pressure",
            ["10k/min", "20k/min"],
            [
                row_for(rows, "rate_independence", attack_rpa_rate_per_min="10000.0"),
                row_for(rows, "rate_independence", attack_rpa_rate_per_min="20000.0"),
            ],
        ),
    ]

    fig, axes = plt.subplots(2, 2, figsize=(8.0, 5.75), sharey=True)
    for ax, (title, labels, selected) in zip(axes.flatten(), panels):
        values = [float(row["legit_resolution_rate_mean"]) * 100 for row in selected]
        attack = [float(row["attack_aes_amplification_mean"]) / 1000 for row in selected]
        colors = [COLORS["P3-Persist"] if i == 0 or "200" in labels[i] or "unique" in labels[i] else "#A9B4C2" for i in range(len(labels))]
        ax.bar(range(len(labels)), values, color=colors, edgecolor="white", linewidth=0.5, width=0.66)
        ax.set_title(title, pad=7)
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, linespacing=0.9)
        ax.set_ylim(55, 104)
        ax.grid(True, axis="y")
        if len(labels) <= 3:
            for x, value, atk in zip(range(len(labels)), values, attack):
                ax.text(x, value + 1.2, f"{atk:.0f}k AES/min", ha="center", va="bottom", fontsize=10.0, color="#384252")
    axes[0, 0].set_ylabel("Legitimate resolution (%)")
    axes[1, 0].set_ylabel("Legitimate resolution (%)")
    fig.legend(
        handles=[
            Patch(facecolor=COLORS["P3-Persist"], label="P3-Persist setting"),
            Patch(facecolor="#A9B4C2", label="Sensitivity point"),
        ],
        loc="upper center",
        bbox_to_anchor=(0.5, 1.0),
        ncol=2,
        frameon=False,
    )
    fig.subplots_adjust(left=0.10, right=0.985, bottom=0.11, top=0.84, hspace=0.50, wspace=0.27)
    save(fig, "figure15_large_font", 4384 / 2862)


def ci95(values: list[float]) -> tuple[float, float]:
    mean = statistics.mean(values)
    if len(values) <= 1:
        return mean, 0.0
    half = T_CRIT_95.get(len(values) - 1, 1.96) * statistics.stdev(values) / math.sqrt(len(values))
    return mean, half


def figure17() -> None:
    grouped: dict[tuple[str, str], list[float]] = defaultdict(list)
    for row in read_csv(RESULTS_M10):
        if row["m10_experiment"] == "main" and row["method"] in COLORS and row["method"] != "Random-RL":
            grouped[(row["m10_scenario"], row["method"])].append(float(row["legit_resolution_rate"]))

    methods = ["BudgetDoS", "AdaptiveRateLimit", "P3-NoPersist", "P3-Persist"]
    labels = methods
    scenarios = [("medium_flood", "Medium flood"), ("heavy_flood", "Heavy flood")]
    fig, axes = plt.subplots(1, 2, figsize=(8.0, 4.15), sharey=True)
    for ax, (scenario, title) in zip(axes, scenarios):
        for idx, method in enumerate(methods):
            values = grouped[(scenario, method)]
            mean, half = ci95(values)
            y = idx + 1
            jitter = [y + (offset - (len(values) - 1) / 2) * 0.020 for offset in range(len(values))]
            ax.scatter(values, jitter, s=20, alpha=0.58, color=COLORS[method], edgecolor="white", linewidth=0.3)
            ax.errorbar([mean], [y], xerr=[[half], [half]], fmt="o", color=COLORS[method], capsize=4.2, elinewidth=1.4, markersize=6.0)
        ax.set_title(title, pad=7)
        ax.set_yticks(range(1, len(methods) + 1))
        ax.set_yticklabels(labels)
        ax.set_xlim(0.50, 1.0)
        ax.set_xlabel("Legitimate resolution rate")
        ax.grid(True, axis="x")
        ax.invert_yaxis()
    fig.subplots_adjust(left=0.18, right=0.985, bottom=0.16, top=0.88, wspace=0.18)
    save(fig, "figure17_large_font", 4283 / 1881)


def write_manifest() -> None:
    source_files = [
        DATA_M10 / "table_m10_headline_stats.csv",
        RESULTS_M10,
    ]
    output_files = sorted(path for path in OUT.glob("figure*_large_font.*") if path.suffix in {".png", ".pdf", ".svg"})
    with (OUT / "figure_manifest.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["role", "file", "sha256"], lineterminator="\n")
        writer.writeheader()
        for path in source_files:
            writer.writerow({"role": "source_data", "file": portable_path(path), "sha256": sha256(path)})
        for path in output_files:
            writer.writerow({"role": "generated_figure", "file": path.name, "sha256": sha256(path)})


def main() -> None:
    args = parse_args()
    configure_paths(args.data_root, args.output_dir)
    set_style()
    figure9()
    figure15()
    figure17()
    write_manifest()
    print(f"Generated Figures 9, 15, and 17 in {OUT}")


if __name__ == "__main__":
    main()
