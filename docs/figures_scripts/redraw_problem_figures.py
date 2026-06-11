#!/usr/bin/env python3
"""Redraw the manuscript figures with a consistent SCI journal style.

The script produces PDF/SVG vector figures plus 600 dpi PNG fallbacks. The PDF
files are intended for the LaTeX/PDF master chain; PNG exists only for DOCX
compatibility.
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
from matplotlib.lines import Line2D
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Patch, Rectangle


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "figures_out"
DATA_M3 = ROOT / "sim/rpa_resolution/figures/m3_paper"
DATA_M4 = ROOT / "sim/rpa_resolution/figures/m4_paper"
DATA_M6 = ROOT / "sim/rpa_resolution/figures/m6_review_closure"
DATA_M10 = ROOT / "sim/rpa_resolution/figures/m10_statistical_extension"
RESULTS_M10 = ROOT / "sim/rpa_resolution/results/m10_statistical_extension/combined_summary.csv"

T_CRIT_95 = {4: 2.776, 19: 2.093}

COLORS = {
    "StaticRL": "#4D4D4D",
    "ZephyrCache": "#56B4E9",
    "BudgetDoS": "#D55E00",
    "AdaptiveRateLimit": "#CC79A7",
    "P3-NoPersist": "#0072B2",
    "P3-Persist": "#009E73",
    "P3-NoBudget": "#A6761D",
    "P3-NoCache": "#E69F00",
    "P3-NoTrust": "#7F7F7F",
    "P3-NoRL": "#6A3D9A",
    "Random-RL": "#8DA0CB",
}

FILL = {
    "neutral": "#F6F7F9",
    "blue": "#EAF3FA",
    "green": "#EAF6EF",
    "orange": "#FFF3E6",
    "red": "#FCECEC",
    "violet": "#F2EDF8",
}

NO_RESERVE_LABEL = "P3-NoPersist"

EDGE = {
    "neutral": "#697386",
    "blue": "#2F6F9F",
    "green": "#26734D",
    "orange": "#B65F00",
    "red": "#B42318",
    "violet": "#6A3D9A",
}


def set_style() -> None:
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
            "lines.linewidth": 1.75,
            "patch.linewidth": 0.9,
            "figure.dpi": 160,
            "savefig.dpi": 600,
            "savefig.facecolor": "white",
            "svg.fonttype": "none",
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )


def save(fig: plt.Figure, stem: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "svg", "png"):
        path = OUT / f"{stem}.{ext}"
        fig.savefig(path, bbox_inches="tight", dpi=600)
        if ext == "svg":
            path.write_text(
                "\n".join(line.rstrip() for line in path.read_text(encoding="utf-8").splitlines()) + "\n",
                encoding="utf-8",
            )
    plt.close(fig)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def box(
    ax,
    xy: tuple[float, float],
    text: str,
    kind: str = "neutral",
    width: float = 0.17,
    height: float = 0.11,
    fontsize: float = 7.8,
    weight: str = "normal",
):
    x, y = xy
    patch = FancyBboxPatch(
        (x - width / 2, y - height / 2),
        width,
        height,
        boxstyle="round,pad=0.010,rounding_size=0.010",
        facecolor=FILL[kind],
        edgecolor=EDGE[kind],
        linewidth=0.8,
    )
    ax.add_patch(patch)
    ax.text(x, y, text, ha="center", va="center", fontsize=fontsize, weight=weight, linespacing=1.12)
    return patch


def arrow(
    ax,
    start: tuple[float, float],
    end: tuple[float, float],
    label: str | None = None,
    color: str = "#2B2B2B",
    rad: float = 0.0,
    label_offset: tuple[float, float] = (0.0, 0.022),
    lw: float = 0.9,
):
    patch = FancyArrowPatch(
        start,
        end,
        arrowstyle="-|>",
        mutation_scale=9,
        linewidth=lw,
        color=color,
        connectionstyle=f"arc3,rad={rad}",
        shrinkA=2,
        shrinkB=2,
    )
    ax.add_patch(patch)
    if label:
        mx = (start[0] + end[0]) / 2 + label_offset[0]
        my = (start[1] + end[1]) / 2 + label_offset[1]
        ax.text(mx, my, label, ha="center", va="center", fontsize=7.5, color=color)


def elbow_arrow(
    ax,
    points: list[tuple[float, float]],
    label: str | None = None,
    color: str = "#2B2B2B",
    lw: float = 0.8,
    label_xy: tuple[float, float] | None = None,
):
    """Draw a segmented connector whose final segment carries the arrow head."""
    if len(points) < 2:
        return
    xs, ys = zip(*points[:-1])
    ax.plot(xs, ys, color=color, linewidth=lw, solid_capstyle="round", zorder=1)
    patch = FancyArrowPatch(
        points[-2],
        points[-1],
        arrowstyle="-|>",
        mutation_scale=8.5,
        linewidth=lw,
        color=color,
        shrinkA=0,
        shrinkB=0,
        zorder=1,
    )
    ax.add_patch(patch)
    if label:
        if label_xy is None:
            a, b = points[-2], points[-1]
            label_xy = ((a[0] + b[0]) / 2, (a[1] + b[1]) / 2 + 0.026)
        ax.text(*label_xy, label, ha="center", va="center", fontsize=7.4, color=color)


def init_diagram(figsize=(7.0, 3.2)):
    fig, ax = plt.subplots(figsize=figsize)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    return fig, ax


def fig01_system_overview() -> None:
    # Two-row layout. Top band = the shared resolution data path (the problem);
    # bottom band = the P3 scheduler that bounds it (the mechanism). Every
    # connector starts and ends on a box's *visual* edge -- nominal +/- (half +
    # PAD), where PAD is the FancyBboxPatch padding -- so arrowheads touch the
    # border exactly without crossing into it, and boxes keep a clear gap.
    fig, ax = init_diagram((7.6, 4.6))

    PAD = 0.010
    boxes = {}

    def place(name, cx, cy, w, h, kind, text, fs, weight="normal"):
        box(ax, (cx, cy), text, kind, w, h, fontsize=fs, weight=weight)
        boxes[name] = (cx, cy, w, h)

    def left(n):
        cx, _, w, _ = boxes[n]
        return cx - w / 2 - PAD

    def right(n):
        cx, _, w, _ = boxes[n]
        return cx + w / 2 + PAD

    def top(n):
        _, cy, _, h = boxes[n]
        return cy + h / 2 + PAD

    def bottom(n):
        _, cy, _, h = boxes[n]
        return cy - h / 2 - PAD

    def cx_(n):
        return boxes[n][0]

    def cy_(n):
        return boxes[n][1]

    ax.text(0.090, 0.955, "Inputs", ha="center", fontsize=8.0, weight="bold", color="#273449")
    ax.text(0.300, 0.955, "Boundary", ha="center", fontsize=8.0, weight="bold", color="#273449")
    ax.text(0.640, 0.955, "Resolving", ha="center", fontsize=8.0, weight="bold", color="#273449")
    ax.text(0.527, 0.360, "P3 scheduler", ha="center", fontsize=8.0, weight="bold", color="#273449")
    ax.text(0.880, 0.360, "Outcome", ha="center", fontsize=8.0, weight="bold", color="#273449")

    # --- top band: inputs -> queue -> (privacy boundary) -> cache -> hit/miss -> host scan ---
    place("leg", 0.090, 0.855, 0.150, 0.090, "green", "Legitimate\nbonded RPA", 7.4)
    place("ben", 0.090, 0.720, 0.150, 0.090, "neutral", "Benign\nunknown RPA", 7.4)
    place("flo", 0.090, 0.585, 0.150, 0.090, "red", "Flooded\nunknown RPA", 7.4)
    place("queue", 0.260, 0.720, 0.090, 0.360, "neutral", "RPA event\nqueue", 7.2)

    boundary_x = 0.350
    ax.plot([boundary_x, boundary_x], [0.530, 0.910], color="#788698", linewidth=0.9, linestyle=(0, (3, 3)), zorder=0)
    ax.text(boundary_x, 0.512, "no pre-resolution\nidentity oracle", ha="center", va="top", fontsize=7.0, color="#384252")

    place("cache", 0.455, 0.720, 0.120, 0.100, "blue", "cache / RL\nlookup", 7.4)
    place("known", 0.660, 0.855, 0.130, 0.090, "green", "Known fast\npath", 7.4)
    place("miss", 0.655, 0.585, 0.115, 0.085, "orange", "unknown\nmiss", 7.4)
    place("host", 0.835, 0.585, 0.130, 0.095, "red", "Host IRK scan\nsurface", 7.2)
    ax.text(0.760, 0.495, "N - C work if unbounded", ha="center", va="center", fontsize=7.2, color=EDGE["red"])

    # --- bottom band: P3 scheduler -> admit/defer ---
    place("budget", 0.430, 0.235, 0.140, 0.095, "blue", "Budget gate\nB per window", 7.2)
    place("persist", 0.625, 0.235, 0.140, 0.095, "green", "Persistence\nreserve R", 7.2)
    place("admit", 0.895, 0.235, 0.105, 0.120, "green", "Admit /\ndefer", 7.6, weight="bold")

    # --- connectors: every endpoint sits on a visual edge ---
    elbow_arrow(ax, [(right("leg"), cy_("leg")), (left("queue"), cy_("leg"))], lw=0.72)
    elbow_arrow(ax, [(right("ben"), cy_("ben")), (left("queue"), cy_("ben"))], lw=0.72)
    elbow_arrow(ax, [(right("flo"), cy_("flo")), (left("queue"), cy_("flo"))], lw=0.72)
    elbow_arrow(ax, [(right("queue"), cy_("queue")), (left("cache"), cy_("queue"))], lw=0.72)

    elbow_arrow(ax, [(right("cache"), 0.755), (0.640, 0.755), (0.640, bottom("known"))], lw=0.72,
                label="hit", label_xy=(0.590, 0.772))
    elbow_arrow(ax, [(right("cache"), 0.685), (0.640, 0.685), (0.640, top("miss"))], lw=0.72,
                label="miss", label_xy=(0.590, 0.702))
    elbow_arrow(ax, [(right("miss"), cy_("miss")), (left("host"), cy_("miss"))], lw=0.72)

    # post-miss host work is the only thing that reaches the scheduler
    elbow_arrow(ax, [(0.885, bottom("host")), (0.885, 0.435), (cx_("budget"), 0.435), (cx_("budget"), top("budget"))],
                lw=0.72, label="post-miss only", label_xy=(0.560, 0.453))

    elbow_arrow(ax, [(right("budget"), cy_("budget")), (left("persist"), cy_("persist"))], lw=0.72)
    elbow_arrow(ax, [(right("persist"), cy_("persist")), (left("admit"), cy_("admit"))], lw=0.72)

    # cache/RL hits are admitted directly, bypassing the host-scan bottleneck
    elbow_arrow(ax, [(right("known"), cy_("known")), (0.935, cy_("known")), (0.935, top("admit"))], lw=0.72)

    save(fig, "fig01_system_overview")


def fig02_privacy_boundary() -> None:
    fig, ax = init_diagram((7.0, 3.25))

    ax.add_patch(Rectangle((0.04, 0.13), 0.42, 0.74, facecolor="#FFF8F8", edgecolor="#D9A1A1", linewidth=0.75))
    ax.add_patch(Rectangle((0.54, 0.13), 0.42, 0.74, facecolor="#F5FBF7", edgecolor="#93BFA4", linewidth=0.75))
    ax.plot([0.50, 0.50], [0.10, 0.90], color="#3F4652", linewidth=1.0)
    ax.text(0.50, 0.92, "privacy boundary", ha="center", va="center", fontsize=7.8, color="#3F4652")

    ax.text(0.25, 0.82, "Forbidden before resolving", ha="center", fontsize=8.1, weight="bold", color=EDGE["red"])
    ax.text(0.75, 0.82, "Admissible inputs", ha="center", fontsize=8.1, weight="bold", color=EDGE["green"])

    forbidden = [
        (0.25, 0.65, "Bonded-membership\npredicate"),
        (0.25, 0.49, "Per-address\naccept/reject response"),
        (0.25, 0.33, "Bloom/prefilter\nidentity shortcut"),
    ]
    allowed = [
        (0.75, 0.67, "Cache/RL\nstate"),
        (0.75, 0.51, "Budget\nwindow"),
        (0.75, 0.35, "Repeated visible\nRPA value after denial"),
        (0.75, 0.20, "Aggregate load\nor RSSI defer hint"),
    ]
    for x, y, text in forbidden:
        box(ax, (x, y), text, "red", 0.25, 0.092, fontsize=7.5)
        ax.text(x - 0.145, y, "x", ha="center", va="center", fontsize=8.6, weight="bold", color=EDGE["red"])
    for x, y, text in allowed:
        box(ax, (x, y), text, "green", 0.25, 0.092, fontsize=7.5)

    save(fig, "fig02_privacy_boundary")


def fig03_related_work_positioning() -> None:
    fig, ax = plt.subplots(figsize=(6.8, 4.1))
    ax.set_xlim(-0.05, 1.05)
    ax.set_ylim(-0.05, 1.05)
    ax.set_xlabel("Privacy-admissible use of RPA stream structure")
    ax.set_ylabel("Post-miss resolving-work control")
    ax.grid(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    points = [
        ("Privacy / traceability\nstudies", 0.18, 0.18, "#9AA3AF"),
        ("BLE DoS / stack\nhardening", 0.23, 0.35, "#9AA3AF"),
        ("Open-stack cache\nand fixed RL", 0.38, 0.44, COLORS["ZephyrCache"]),
        ("Generic rate\nlimiting", 0.48, 0.72, COLORS["BudgetDoS"]),
        ("P3-Persist", 0.82, 0.82, COLORS["P3-Persist"]),
    ]
    for label, x, y, color in points:
        size = 220 if label == "P3-Persist" else 150
        ax.scatter([x], [y], s=size, color=color, edgecolor="white", linewidth=0.9, zorder=3)
        ax.annotate(label, (x, y), xytext=(7, 6), textcoords="offset points", fontsize=8.0, color="#1F2937")

    ax.axhspan(0.66, 1.02, xmin=0.62, xmax=1.0, color="#EAF6EF", alpha=0.55, zorder=0)
    ax.text(0.83, 0.96, "target gap", ha="center", va="center", fontsize=8.3, color=EDGE["green"])
    ax.set_xticks([0, 0.5, 1.0])
    ax.set_xticklabels(["none", "generic", "RPA-specific"])
    ax.set_yticks([0, 0.5, 1.0])
    ax.set_yticklabels(["none", "partial", "bounded"])
    fig.tight_layout()
    save(fig, "fig03_related_work_positioning")


def fig04_algorithm_flow() -> None:
    # Same P3-Persist logic as before, redrawn with the Fig. 1 edge-aware
    # connector method so arrows touch box borders without crossing text.
    fig, ax = init_diagram((7.6, 4.4))

    PAD = 0.010
    boxes = {}

    def place(name, cx, cy, w, h, kind, text, fs, weight="normal"):
        box(ax, (cx, cy), text, kind, w, h, fontsize=fs, weight=weight)
        boxes[name] = (cx, cy, w, h)

    def left(n):
        cx, _, w, _ = boxes[n]
        return cx - w / 2 - PAD

    def right(n):
        cx, _, w, _ = boxes[n]
        return cx + w / 2 + PAD

    def top(n):
        _, cy, _, h = boxes[n]
        return cy + h / 2 + PAD

    def bottom(n):
        _, cy, _, h = boxes[n]
        return cy - h / 2 - PAD

    def cx_(n):
        return boxes[n][0]

    def cy_(n):
        return boxes[n][1]

    def edge_arrow(start, end, color="#2B2B2B", lw=0.72):
        patch = FancyArrowPatch(
            start,
            end,
            arrowstyle="-|>",
            mutation_scale=8.5,
            linewidth=lw,
            color=color,
            shrinkA=0,
            shrinkB=0,
            zorder=1,
        )
        ax.add_patch(patch)

    ax.text(0.090, 0.945, "Input", ha="center", fontsize=8.0, weight="bold", color="#273449")
    ax.text(0.285, 0.945, "Fast path", ha="center", fontsize=8.0, weight="bold", color="#273449")
    ax.text(0.535, 0.945, "Post-miss admission", ha="center", fontsize=8.0, weight="bold", color="#273449")
    ax.text(0.780, 0.945, "Host work", ha="center", fontsize=8.0, weight="bold", color="#273449")
    ax.text(0.925, 0.945, "Outcome", ha="center", fontsize=8.0, weight="bold", color="#273449")

    boundary_x = 0.405
    ax.plot([boundary_x, boundary_x], [0.250, 0.850], color="#788698", linewidth=0.9, linestyle=(0, (3, 3)), zorder=0)
    ax.text(boundary_x, 0.875, "post-miss\nwork only", ha="center", va="bottom", fontsize=6.8, color="#384252", linespacing=1.05)

    place("rpa", 0.090, 0.705, 0.140, 0.090, "blue", "RPA\nadvertisement", 7.4)
    place("nonrpa", 0.090, 0.375, 0.130, 0.085, "neutral", "Non-RPA\nbypass", 7.3)
    place("lookup", 0.285, 0.705, 0.145, 0.095, "green", "Cache / RL\nlookup", 7.4)
    place("fast", 0.285, 0.375, 0.135, 0.085, "green", "Resolved\nfast path", 7.3)

    place("budget", 0.535, 0.750, 0.150, 0.090, "orange", "Budget\navailable?", 7.4)
    place("persist", 0.535, 0.520, 0.190, 0.095, "green", "Persistence gate\nD[rv] >= k, r < R", 7.2)
    place("defer", 0.535, 0.270, 0.140, 0.085, "red", "Defer /\nbudget skip", 7.3)

    place("host", 0.765, 0.635, 0.125, 0.090, "blue", "Host IRK\nscan", 7.4)
    place("match", 0.930, 0.770, 0.110, 0.090, "green", "Match:\ncache + RL", 7.2)
    place("miss", 0.930, 0.500, 0.110, 0.090, "orange", "Miss:\ncharge state", 7.2)

    elbow_arrow(ax, [(cx_("rpa"), bottom("rpa")), (cx_("rpa"), top("nonrpa"))], lw=0.72,
                label="no", label_xy=(0.060, 0.545))
    elbow_arrow(ax, [(right("rpa"), cy_("rpa")), (left("lookup"), cy_("lookup"))], lw=0.72,
                label="yes", label_xy=(0.188, 0.730))
    elbow_arrow(ax, [(cx_("lookup"), bottom("lookup")), (cx_("lookup"), top("fast"))], lw=0.72,
                label="hit", label_xy=(0.252, 0.545))
    elbow_arrow(ax, [(right("lookup"), cy_("lookup")), (0.420, cy_("lookup")), (0.420, cy_("budget")), (left("budget"), cy_("budget"))],
                lw=0.72, label="miss", label_xy=(0.388, 0.733))

    edge_arrow((right("budget"), cy_("budget")), (left("host"), 0.670))
    ax.text(0.650, 0.755, "yes", ha="center", va="center", fontsize=7.2, color="#2B2B2B")
    elbow_arrow(ax, [(cx_("budget"), bottom("budget")), (cx_("budget"), top("persist"))],
                lw=0.72, label="no", label_xy=(0.502, 0.635))
    edge_arrow((right("persist"), cy_("persist")), (left("host"), 0.600), color=EDGE["green"])
    ax.text(
        0.650,
        0.625,
        "grant",
        ha="center",
        va="center",
        fontsize=7.2,
        color=EDGE["green"],
        bbox={"facecolor": "white", "edgecolor": "none", "pad": 0.3},
    )
    elbow_arrow(ax, [(cx_("persist"), bottom("persist")), (cx_("persist"), top("defer"))],
                lw=0.72, label="no", label_xy=(0.502, 0.395))

    edge_arrow((right("host"), 0.665), (left("match"), cy_("match")))
    edge_arrow((right("host"), 0.605), (left("miss"), cy_("miss")))

    ax.text(
        0.535,
        0.130,
        "P3-Persist observes only packet type, cache/RL state, budget window, and repeated visible RPA value before host resolving.",
        ha="center",
        va="center",
        fontsize=6.8,
        color="#4B5563",
    )
    save(fig, "fig04_algorithm_flow")


def fig05_running_example_timeline() -> None:
    fig, ax = init_diagram((7.6, 4.25))

    PAD = 0.010
    timeline_y = 0.505
    event_y = 0.745
    state_y = 0.220
    event_h = 0.105
    state_h = 0.085
    event_w = 0.092
    state_w = 0.096

    def bottom_of(y, h):
        return y - h / 2 - PAD

    def top_of(y, h):
        return y + h / 2 + PAD

    ax.text(0.075, 0.930, "Incoming events", ha="left", va="center", fontsize=8.2, weight="bold", color="#273449")
    ax.text(0.075, 0.075, "Budget / reserve state", ha="left", va="center", fontsize=8.2, weight="bold", color="#273449")

    ax.add_patch(Rectangle((0.072, 0.135), 0.856, 0.175, facecolor="#FFFFFF", edgecolor="#D7DEE8", linewidth=0.65, zorder=-3))
    ax.plot([0.075, 0.925], [timeline_y, timeline_y], color="#2B2B2B", linewidth=0.78, zorder=1)

    events = [
        (0.105, "Unique\nflood", "orange", "B used"),
        (0.240, "Unique\nflood", "orange", "B used"),
        (0.375, "Budget\nexhausted", "neutral", "u = B"),
        (0.510, "Legit L\nfirst miss", "red", "D[L] = 1"),
        (0.645, "Same L\nreappears", "green", "reserve scan"),
        (0.780, "Same L", "blue", "cache hit"),
        (0.915, "Same L", "blue", "cache hit"),
    ]

    for x, label, kind, state in events:
        ax.plot([x, x], [timeline_y - 0.030, timeline_y + 0.030], color="#2B2B2B", linewidth=0.70, zorder=2)
        ax.plot([x, x], [timeline_y + 0.030, bottom_of(event_y, event_h)], color=EDGE[kind], linewidth=0.68, zorder=0)
        ax.plot([x, x], [top_of(state_y, state_h), timeline_y - 0.030], color=EDGE[kind], linewidth=0.52, alpha=0.55, zorder=0)
        box(ax, (x, event_y), label, kind, event_w, event_h, fontsize=7.15)
        box(ax, (x, state_y), state, kind, state_w, state_h, fontsize=7.1)

    reserve_x0 = 0.510
    reserve_x1 = 0.645
    reserve_y = 0.575
    ax.plot([reserve_x0, reserve_x1], [reserve_y, reserve_y], color=EDGE["green"], linewidth=0.72, zorder=1)
    ax.plot([reserve_x0, reserve_x0], [reserve_y - 0.020, reserve_y + 0.020], color=EDGE["green"], linewidth=0.72, zorder=1)
    ax.plot([reserve_x1, reserve_x1], [reserve_y - 0.020, reserve_y + 0.020], color=EDGE["green"], linewidth=0.72, zorder=1)
    ax.text(
        (reserve_x0 + reserve_x1) / 2,
        reserve_y + 0.038,
        "reserve admits repeated visible RPA",
        ha="center",
        va="center",
        fontsize=7.2,
        color=EDGE["green"],
        bbox={"facecolor": "white", "edgecolor": "none", "pad": 0.25},
    )

    save(fig, "fig05_running_example_timeline")


def fig06_proposition_evidence_roadmap() -> None:
    fig, ax = init_diagram((7.6, 4.55))

    PAD = 0.010
    cols = [
        ("Claim", 0.135, 0.155, "green"),
        ("Question", 0.365, 0.175, "blue"),
        ("Metric", 0.590, 0.160, "orange"),
        ("Evidence", 0.825, 0.185, "violet"),
    ]
    headers = [c[0] for c in cols]
    xs = [c[1] for c in cols]
    widths = [c[2] for c in cols]
    kinds = [c[3] for c in cols]
    row_h = 0.086

    def left(cx, w):
        return cx - w / 2 - PAD

    def right(cx, w):
        return cx + w / 2 + PAD

    def edge_arrow(start, end, color="#2B2B2B", lw=0.58):
        patch = FancyArrowPatch(
            start,
            end,
            arrowstyle="-|>",
            mutation_scale=7.6,
            linewidth=lw,
            color=color,
            shrinkA=0,
            shrinkB=0,
            zorder=1,
        )
        ax.add_patch(patch)

    for header, x in zip(headers, xs):
        ax.text(x, 0.935, header, ha="center", va="center", fontsize=8.2, weight="bold", color="#273449")
    rows = [
        ("Prop. 0\nprivacy boundary", "Can P3 avoid\nmembership oracle?", "Allowed input\nsurface", "Figure 2,\nTable 8"),
        ("Prop. 1-2\nwork bounds", "Does flood work\nstay bounded?", "Attack AES/min", "Figure 9,\nTables 13, 16, 17"),
        ("Prop. 3\nservice recovery", "Does reserve recover\nlegitimate RPAs?", "Legit rate,\nfalse defer", "Figure 17,\nTable 16"),
        ("Prop. 4\nadaptive boundary", "Can repeats pressure\nreserve?", "B+R cap,\nDelta filter", "Table 17"),
        ("P1 capacity\nallocation", "Does C change the\nboundary?", "C, N, legit rate", "Figs. 11-13,\nTable 18"),
    ]
    y0 = 0.805
    for i, row in enumerate(rows):
        y = y0 - i * 0.145
        if i % 2 == 0:
            ax.add_patch(
                Rectangle(
                    (0.055, y - 0.061),
                    0.890,
                    0.122,
                    facecolor="#FAFBFC",
                    edgecolor="none",
                    zorder=-4,
                )
            )
        for x, w, text, kind in zip(xs, widths, row, kinds):
            box(ax, (x, y), text, kind, w, row_h, fontsize=6.95)
        for j in range(len(xs) - 1):
            edge_arrow((right(xs[j], widths[j]), y), (left(xs[j + 1], widths[j + 1]), y), lw=0.58)
    save(fig, "fig06_proposition_evidence_roadmap")


def fig07_budgetdos_vs_p3() -> None:
    rows = read_csv(DATA_M10 / "table_m10_headline_stats.csv")
    scenarios = [("medium_flood", "Medium flood"), ("heavy_flood", "Heavy flood")]
    methods = ["BudgetDoS", "P3-NoPersist", "P3-Persist"]
    panels = [
        ("legit_resolution_rate_mean", "(a) Legitimate resolution", "Legitimate resolution (%)", 100.0, (45, 101)),
        ("false_defer_legit_rate_mean", "(b) False defer", "False defer (%)", 100.0, (0, 50)),
        ("attack_aes_amplification_mean", "(c) Attack amplification", "Attack amplification (×10³ AES/min)", 1 / 1000, (42, 47)),
    ]
    fig, axes = plt.subplots(1, 3, figsize=(7.3, 3.1))
    width = 0.22
    for ax, (metric, title, ylabel, scale, ylim) in zip(axes, panels):
        for idx, method in enumerate(methods):
            xs = [i + (idx - 1) * width for i in range(len(scenarios))]
            vals = []
            for scenario, _label in scenarios:
                row = next(
                    r
                    for r in rows
                    if r["m10_experiment"] == "main"
                    and r["m10_scenario"] == scenario
                    and r["method"] == method
                )
                vals.append(float(row[metric]) * scale)
            ax.bar(
                xs,
                vals,
                width=width * 0.9,
                color=COLORS[method],
                edgecolor="white",
                linewidth=0.45,
                label=method,
            )
        ax.set_xticks(range(len(scenarios)))
        ax.set_xticklabels([label for _scenario, label in scenarios])
        ax.set_title(title, pad=6)
        ax.set_ylabel(ylabel)
        ax.set_ylim(*ylim)
        ax.grid(True, axis="y")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 0.99), ncol=3, frameon=False)
    fig.subplots_adjust(left=0.075, right=0.985, bottom=0.19, top=0.75, wspace=0.32)
    save(fig, "fig09_budgetdos_vs_p3")


def fig08_experiment_roadmap() -> None:
    fig, ax = init_diagram((7.6, 4.6))

    PAD = 0.010
    cols = [
        ("Experiment family", 0.155, 0.220, "blue"),
        ("Generator / data", 0.500, 0.220, "neutral"),
        ("Evidence role", 0.835, 0.220, "green"),
    ]
    headers = [c[0] for c in cols]
    xs = [c[1] for c in cols]
    widths = [c[2] for c in cols]
    kinds = [c[3] for c in cols]
    row_h = 0.080

    def left(cx, w):
        return cx - w / 2 - PAD

    def right(cx, w):
        return cx + w / 2 + PAD

    def edge_arrow(start, end, color="#2B2B2B", lw=0.58):
        patch = FancyArrowPatch(
            start,
            end,
            arrowstyle="-|>",
            mutation_scale=7.6,
            linewidth=lw,
            color=color,
            shrinkA=0,
            shrinkB=0,
            zorder=1,
        )
        ax.add_patch(patch)

    for x, title in zip(xs, headers):
        ax.text(x, 0.935, title, ha="center", va="center", fontsize=8.2, weight="bold", color="#273449")

    rows = [
        ("Main matrix\n420 runs", "run_m3_matrix.py\n3360 rows", "RQ1/RQ2\nscale and flood bound"),
        ("Sensitivity +\nablation", "m3 sweeps\nmodule-disabled runs", "robustness and\ncomponent separation"),
        ("Long-window +\nbudget frontier", "run_m4_*.py\n1800-second checks", "duration continuity\nand tunability"),
        ("Persistence stats\n20 seeds", "run_m10_*.py\nCI and paired tests", "service recovery\nat same bound"),
        ("Adaptive adversary\n480 runs", "run_m11_*.py\n(m,r,p), Delta", "reserve-pressure\nboundary"),
        ("nRF5340 DK\nauxiliary", "hardware record\nno power claim", "stack context only"),
    ]
    for idx, row in enumerate(rows):
        y = 0.805 - idx * 0.112
        if idx % 2 == 0:
            ax.add_patch(
                Rectangle(
                    (0.050, y - 0.055),
                    0.900,
                    0.110,
                    facecolor="#FAFBFC",
                    edgecolor="none",
                    zorder=-4,
                )
            )
        for x, w, text, kind in zip(xs, widths, row, kinds):
            box(ax, (x, y), text, kind, w, row_h, fontsize=6.95)
        edge_arrow((right(xs[0], widths[0]), y), (left(xs[1], widths[1]), y), lw=0.58)
        edge_arrow((right(xs[1], widths[1]), y), (left(xs[2], widths[2]), y), lw=0.58)
    save(fig, "fig_exp_campaign_roadmap")


def fig09_attack_aes() -> None:
    rows = [
        r
        for r in read_csv(DATA_M10 / "table_m10_headline_stats.csv")
        if r["m10_experiment"] == "main" and r["m10_scenario"] == "heavy_flood"
    ]
    methods = ["Random-RL", "BudgetDoS", "AdaptiveRateLimit", "P3-NoPersist", "P3-Persist"]
    labels = ["Random-RL", "BudgetDoS", "AdaptRL", "NoPersist", "P3-Persist"]
    colors = [COLORS[m] for m in methods]
    x = list(range(len(methods)))
    selected = {r["method"]: r for r in rows if r["method"] in methods}

    attack = [float(selected[m]["attack_aes_amplification_mean"]) for m in methods]
    attack_low = [float(selected[m]["attack_aes_amplification_ci95_low"]) for m in methods]
    attack_high = [float(selected[m]["attack_aes_amplification_ci95_high"]) for m in methods]
    attack_yerr = [[a - lo for a, lo in zip(attack, attack_low)], [hi - a for a, hi in zip(attack, attack_high)]]

    legit = [float(selected[m]["legit_resolution_rate_mean"]) * 100 for m in methods]
    legit_low = [float(selected[m]["legit_resolution_rate_ci95_low"]) * 100 for m in methods]
    legit_high = [float(selected[m]["legit_resolution_rate_ci95_high"]) * 100 for m in methods]
    legit_yerr = [[y - lo for y, lo in zip(legit, legit_low)], [hi - y for y, hi in zip(legit, legit_high)]]

    fig, axes = plt.subplots(1, 2, figsize=(7.4, 3.55))
    ax_attack, ax_service = axes

    ax_attack.bar(x, attack, color=colors, edgecolor="white", linewidth=0.55, width=0.72, zorder=3)
    ax_attack.errorbar(x, attack, yerr=attack_yerr, fmt="none", ecolor="#2B2B2B", elinewidth=0.75, capsize=2.2, zorder=4)
    ax_attack.set_yscale("log")
    ax_attack.set_title("Attack work under heavy flood", pad=6)
    ax_attack.set_ylabel("Attack amplification (AES/min)")
    ax_attack.set_xticks(x)
    ax_attack.set_xticklabels(labels, rotation=24, ha="right")
    ax_attack.grid(True, axis="y", which="major")
    ax_attack.grid(True, axis="y", which="minor", alpha=0.14)
    ax_attack.axhspan(4.40e4, 4.70e4, color="#EAF6EF", alpha=0.50, zorder=0)
    ax_attack.text(1.45, 6.20e4, "bounded methods\nsame band", ha="left", va="center", fontsize=7.2, color=EDGE["green"])

    ax_service.bar(x, legit, color=colors, edgecolor="white", linewidth=0.55, width=0.72, zorder=3)
    ax_service.errorbar(x, legit, yerr=legit_yerr, fmt="none", ecolor="#2B2B2B", elinewidth=0.75, capsize=2.2, zorder=4)
    ax_service.set_title("Legitimate service, same runs", pad=6)
    ax_service.set_ylabel("Legitimate resolution (%)")
    ax_service.set_xticks(x)
    ax_service.set_xticklabels(labels, rotation=24, ha="right")
    ax_service.set_ylim(0, 105)
    ax_service.grid(True, axis="y")
    ax_service.annotate(
        "reserve\nrecovery",
        xy=(x[-1], legit[-1]),
        xytext=(x[-1] - 0.95, 90.0),
        textcoords="data",
        ha="right",
        va="center",
        fontsize=7.1,
        color=COLORS["P3-Persist"],
        arrowprops=dict(arrowstyle="-", color=COLORS["P3-Persist"], linewidth=0.70, shrinkA=3, shrinkB=3),
    )

    for ax in axes:
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
    fig.text(0.50, 0.985, "M10 main heavy flood, 10000 attack RPAs/min, 20 seeds", ha="center", va="top", fontsize=8.0, color="#384252")
    fig.subplots_adjust(left=0.075, right=0.985, bottom=0.25, top=0.80, wspace=0.34)
    save(fig, "fig04_attack_aes")


def fig10_budget_frontier() -> None:
    rows = read_csv(DATA_M4 / "table_budget_sensitivity.csv")
    scenarios = [("medium_flood", "Medium flood"), ("heavy_flood", "Heavy flood")]
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.2), sharey=True)
    for ax, (scenario, title) in zip(axes, scenarios):
        selected = [r for r in rows if r["m4_scenario"] == scenario]
        selected.sort(key=lambda r: float(r["budget_per_window"]))
        x = [float(r["relative_reduction"]) * 100 for r in selected]
        y = [float(r["p3_legit_resolution_rate_mean"]) * 100 for r in selected]
        budgets = [int(float(r["budget_per_window"])) for r in selected]
        ax.plot(x, y, color=COLORS["P3-NoPersist"], marker="o", markersize=4.5)
        for xi, yi, budget in zip(x, y, budgets):
            if budget in {100, 500, 5000}:
                dx = -24 if budget == 5000 and scenario == "medium_flood" else 4
                dy = -12 if budget == 100 else 5
                ax.annotate(f"B={budget}", (xi, yi), xytext=(dx, dy), textcoords="offset points", fontsize=7.5)
        ax.set_title(title)
        ax.set_xlabel("Attack-work reduction vs StaticRL (%)")
        ax.set_xlim(-4, 103)
        ax.set_ylim(50, 101.5)
        ax.grid(True)
    axes[0].set_ylabel("Legitimate resolution (%)")
    fig.tight_layout()
    save(fig, "fig11_budget_frontier")


def fig11_bonded_scale() -> None:
    rows = read_csv(DATA_M3 / "fig_bonded_scale.csv") + read_csv(DATA_M3 / "fig_bonded_scale_p3_persist.csv")
    methods = ["StaticRL", "ZephyrCache", "BudgetDoS", "P3-NoPersist", "P3-Persist"]
    fig, axes = plt.subplots(1, 2, figsize=(7.55, 3.55), gridspec_kw={"width_ratios": [1.28, 1.12]})
    baseline_by_n = {}
    for row in rows:
        if row["method"] == "StaticRL":
            baseline_by_n[int(row["num_bonded"])] = float(row["aes_attempts_total_mean"])
    label_map = {
        "StaticRL": "StaticRL",
        "ZephyrCache": "ZephyrCache",
        "BudgetDoS": "BudgetDoS",
        "P3-NoPersist": NO_RESERVE_LABEL,
        "P3-Persist": "P3-Persist",
    }
    marker_map = {"StaticRL": "o", "ZephyrCache": "^", "BudgetDoS": "s", "P3-NoPersist": "D", "P3-Persist": "P"}
    markerface_map = {
        "StaticRL": COLORS["StaticRL"],
        "ZephyrCache": "#BDE3F7",
        "BudgetDoS": "#F2A45C",
        "P3-NoPersist": "white",
        "P3-Persist": COLORS["P3-Persist"],
    }
    linestyle_map = {
        "StaticRL": "-",
        "ZephyrCache": (0, (5, 2)),
        "BudgetDoS": (0, (3, 1.5)),
        "P3-NoPersist": "-",
        "P3-Persist": "-",
    }
    alpha_map = {"StaticRL": 0.92, "ZephyrCache": 0.82, "BudgetDoS": 0.92, "P3-NoPersist": 1.0, "P3-Persist": 1.0}
    x_shift_map = {"StaticRL": 0.970, "ZephyrCache": 0.985, "BudgetDoS": 1.000, "P3-NoPersist": 1.015, "P3-Persist": 1.030}
    for method in methods:
        selected = [r for r in rows if r["method"] == method]
        selected.sort(key=lambda r: int(r["num_bonded"]))
        x = [int(r["num_bonded"]) for r in selected]
        x_plot = [xi * x_shift_map[method] for xi in x]
        y = [float(r["aes_attempts_total_mean"]) / 1000 for r in selected]
        axes[0].plot(
            x_plot,
            y,
            marker=marker_map[method],
            markersize=4.4,
            markerfacecolor=markerface_map[method],
            markeredgewidth=1.15 if method in {"P3-NoPersist", "P3-Persist"} else 0.9,
            linewidth=2.08 if method in {"StaticRL", "P3-NoPersist", "P3-Persist"} else 1.65,
            linestyle=linestyle_map[method],
            alpha=alpha_map[method],
            color=COLORS[method],
            label=label_map[method],
            zorder=5 if method == "P3-Persist" else 4 if method == "P3-NoPersist" else 3,
        )
        ratio = [float(r["aes_attempts_total_mean"]) / baseline_by_n[int(r["num_bonded"])] * 100 for r in selected]
        axes[1].plot(
            x_plot,
            ratio,
            marker=marker_map[method],
            markersize=4.4,
            markerfacecolor=markerface_map[method],
            markeredgewidth=1.15 if method in {"P3-NoPersist", "P3-Persist"} else 0.9,
            linewidth=2.0 if method in {"StaticRL", "P3-NoPersist", "P3-Persist"} else 1.65,
            linestyle=linestyle_map[method],
            alpha=alpha_map[method],
            color=COLORS[method],
            label=label_map[method],
            zorder=5 if method == "P3-Persist" else 4 if method in {"StaticRL", "P3-NoPersist"} else 3,
        )
        if method in {"BudgetDoS", "P3-NoPersist", "P3-Persist"}:
            label_y = {"BudgetDoS": 50.4, "P3-NoPersist": 48.2, "P3-Persist": 54.1}[method]
            axes[1].text(
                1135,
                label_y,
                label_map[method],
                fontsize=6.55,
                color=COLORS[method],
                ha="left",
                va="center",
            )
    for ax in axes:
        ax.set_xscale("log", base=2)
        ax.set_xlim(14, 1360)
        ax.set_xticks([16, 64, 256, 1024])
        ax.set_xticklabels(["16", "64", "256", "1024"])
        ax.grid(True, which="major")
        ax.grid(True, which="minor", alpha=0.14)
        ax.set_xlabel("Bonded identities N")
    axes[0].set_yscale("log")
    axes[0].set_title("Absolute resolving work")
    axes[0].set_ylabel("Total AES-equivalent attempts (×10³)")
    axes[1].set_title("Work relative to StaticRL")
    axes[1].set_ylabel("StaticRL-normalized work (%)")
    axes[1].set_ylim(47, 101.5)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 1.01), ncol=5, frameon=False)
    fig.subplots_adjust(left=0.085, right=0.985, bottom=0.18, top=0.74, wspace=0.32)
    save(fig, "fig05_bonded_scale")


def fig12_rl_capacity() -> None:
    rows = read_csv(DATA_M3 / "fig_rl_capacity.csv") + read_csv(DATA_M3 / "fig_rl_capacity_p3_persist.csv")
    methods = ["StaticRL", "ZephyrCache", "BudgetDoS", "P3-NoPersist", "P3-Persist"]
    bounded_methods = ["BudgetDoS", "P3-NoPersist", "P3-Persist"]
    capacities = [8, 16, 32]
    fig, axes = plt.subplots(
        2,
        2,
        figsize=(7.55, 4.55),
        gridspec_kw={"height_ratios": [1.45, 1.0], "hspace": 0.34, "wspace": 0.25},
    )
    scenarios = [(128, 1000, "N=128, medium flood"), (512, 1000, "N=512, medium flood")]
    label_map = {
        "StaticRL": "StaticRL",
        "ZephyrCache": "ZephyrCache",
        "BudgetDoS": "BudgetDoS",
        "P3-NoPersist": NO_RESERVE_LABEL,
        "P3-Persist": "P3-Persist",
    }
    hatch_map = {
        "StaticRL": "",
        "ZephyrCache": "",
        "BudgetDoS": "",
        "P3-NoPersist": "//",
        "P3-Persist": "..",
    }
    all_width = 0.145
    all_offsets = [(idx - (len(methods) - 1) / 2) * all_width for idx in range(len(methods))]
    zoom_width = 0.215
    zoom_offsets = [(idx - (len(bounded_methods) - 1) / 2) * zoom_width for idx in range(len(bounded_methods))]

    def values_for(num_bonded: int, attack_rate: int, method: str) -> list[float]:
        vals = []
        for cap in capacities:
            row = next(
                r
                for r in rows
                if int(r["num_bonded"]) == num_bonded
                and int(r["rl_capacity"]) == cap
                and int(float(r["attack_rpa_rate_per_min"])) == attack_rate
                and r["method"] == method
            )
            vals.append(float(row["aes_attempts_total_mean"]) / 1000)
        return vals

    for col, (num_bonded, attack_rate, title) in enumerate(scenarios):
        ax = axes[0, col]
        for idx, method in enumerate(methods):
            vals = values_for(num_bonded, attack_rate, method)
            x = [i + all_offsets[idx] for i in range(len(capacities))]
            ax.bar(
                x,
                vals,
                width=all_width * 0.92,
                color=COLORS[method],
                edgecolor="#FFFFFF" if method not in {"P3-NoPersist", "P3-Persist"} else COLORS[method],
                linewidth=0.55 if method not in {"P3-NoPersist", "P3-Persist"} else 0.85,
                hatch=hatch_map[method],
                label=label_map[method],
                zorder=5 if method == "P3-Persist" else 4 if method == "P3-NoPersist" else 3,
            )
        ax.set_xticks(range(len(capacities)))
        ax.set_xticklabels([])
        ax.set_title(title, pad=5)
        ax.set_yscale("log")
        ax.grid(True, axis="y", which="major")
        ax.grid(True, axis="y", which="minor", alpha=0.14)
        ax.set_axisbelow(True)
        ax.text(0.06, 0.91, "all methods", transform=ax.transAxes, fontsize=7.0, color="#384252", ha="left", va="center")

        ax_zoom = axes[1, col]
        for idx, method in enumerate(bounded_methods):
            vals = values_for(num_bonded, attack_rate, method)
            x = [i + zoom_offsets[idx] for i in range(len(capacities))]
            bars = ax_zoom.bar(
                x,
                vals,
                width=zoom_width * 0.90,
                color=COLORS[method],
                edgecolor="#FFFFFF" if method == "BudgetDoS" else COLORS[method],
                linewidth=0.55 if method == "BudgetDoS" else 0.85,
                hatch=hatch_map[method],
                label=label_map[method],
                zorder=5 if method == "P3-Persist" else 4,
            )
            if method == "P3-Persist":
                for bar, val in zip(bars, vals):
                    ax_zoom.text(
                        bar.get_x() + bar.get_width() / 2,
                        val + (1.1 if num_bonded == 128 else 4.0),
                        f"{val:.0f}",
                        ha="center",
                        va="bottom",
                        fontsize=6.5,
                        color=COLORS["P3-Persist"],
                    )
        ax_zoom.set_xticks(range(len(capacities)))
        ax_zoom.set_xticklabels([str(c) for c in capacities])
        ax_zoom.set_xlabel("Resolving-list capacity C")
        ax_zoom.grid(True, axis="y")
        ax_zoom.set_axisbelow(True)
        ax_zoom.text(0.06, 0.88, "bounded-method zoom", transform=ax_zoom.transAxes, fontsize=7.0, color=EDGE["green"], ha="left", va="center")

        if num_bonded == 128:
            ax.set_ylim(25, 850)
            ax_zoom.set_ylim(32, 55)
        else:
            ax.set_ylim(120, 3200)
            ax_zoom.set_ylim(180, 225)

    axes[0, 0].set_ylabel("Total AES-equivalent attempts (×10³)")
    axes[1, 0].set_ylabel("Zoomed AES-equivalent attempts (×10³)")
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 1.005), ncol=5, frameon=False)
    fig.text(
        0.50,
        0.035,
        "attack = 1000 RPA/min, five seeds; P3-Persist uses R=200, k=1; green labels show P3-Persist AES-equivalent attempts (×10³)",
        ha="center",
        va="center",
        fontsize=7.0,
        color="#4B5563",
    )
    fig.subplots_adjust(left=0.085, right=0.985, bottom=0.15, top=0.82)
    save(fig, "fig06_rl_capacity")


def fig13_capacity_frontier() -> None:
    rows = read_csv(DATA_M6 / "table_m6_review_closure_summary.csv")
    selected = [
        r
        for r in rows
        if r["m6_review_scenario"] == "capacity_direct_expansion" and r["method"] == "P3-NoPersist"
    ]
    selected.sort(key=lambda r: int(r["rl_capacity"]))
    capacities = [int(r["rl_capacity"]) for r in selected]
    legit = [float(r["legit_resolution_rate_mean"]) * 100 for r in selected]
    attack = [float(r["attack_aes_amplification_mean"]) / 1000 for r in selected]

    p3_rows = read_csv(DATA_M10 / "table_m10_headline_stats.csv")
    p3_medium = next(
        r
        for r in p3_rows
        if r["m10_experiment"] == "main" and r["m10_scenario"] == "medium_flood" and r["method"] == "P3-Persist"
    )
    p3_legit = float(p3_medium["legit_resolution_rate_mean"]) * 100
    p3_attack = float(p3_medium["attack_aes_amplification_mean"]) / 1000

    x = list(range(len(capacities)))
    fig, axes = plt.subplots(1, 2, figsize=(7.45, 3.35), sharex=True)
    for ax in axes:
        ax.axvspan(-0.35, 3.35, color="#F6F7F9", zorder=0)
        ax.axvspan(3.65, 4.35, color="#FCECEC", alpha=0.36, zorder=0)
    axes[0].plot(x, legit, marker="o", color=COLORS["P3-NoPersist"], label="Direct C expansion")
    axes[0].axhline(p3_legit, color=COLORS["P3-Persist"], linestyle="--", linewidth=1.6, label="P3-Persist @ C=8")
    axes[0].set_ylabel("Legitimate resolution (%)")
    axes[0].set_ylim(72, 102)
    axes[0].grid(True, axis="y")
    axes[0].set_title("Service recovery")
    axes[0].annotate("commodity\nlow C", (x[0], legit[0]), xytext=(7, -10), textcoords="offset points", fontsize=7.2)
    axes[0].annotate("moderate C\nstill below P3-Persist", (x[3], legit[3]), xytext=(-56, -30), textcoords="offset points", fontsize=7.2)

    axes[1].plot(x, attack, marker="s", color=COLORS["StaticRL"], linestyle="-", label="Direct C expansion")
    axes[1].axhline(p3_attack, color=COLORS["P3-Persist"], linestyle="--", linewidth=1.6, label="P3-Persist @ C=8")
    axes[1].set_ylabel("Attack amplification (k AES/min)")
    axes[1].set_ylim(-2, max(attack) * 1.20)
    axes[1].grid(True, axis="y")
    axes[1].set_title("Attack-work boundary")
    axes[1].annotate("theoretical\nupper bound C=N", (x[-1], attack[-1]), xytext=(-54, 24), textcoords="offset points", fontsize=7.2)
    axes[1].text(1.5, axes[1].get_ylim()[1] * 0.90, "practical low-capacity regime", ha="center", va="center", fontsize=7.1, color="#384252")

    for ax in axes:
        ax.set_xticks(x)
        ax.set_xticklabels([str(c) for c in capacities])
        ax.set_xlabel("Resolving-list capacity C")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 0.995), ncol=2, frameon=False)
    fig.subplots_adjust(left=0.085, right=0.985, bottom=0.17, top=0.75, wspace=0.30)
    save(fig, "fig12_capacity_frontier")


def fig14_ablation() -> None:
    rows = read_csv(DATA_M3 / "fig_ablation.csv")
    m10_rows = read_csv(DATA_M10 / "table_m10_headline_stats.csv")
    fig, axes = plt.subplots(1, 2, figsize=(7.45, 3.45), gridspec_kw={"width_ratios": [1.05, 1.20]})

    methods = ["P3-NoPersist", "P3-NoBudget", "P3-NoCache", "P3-NoTrust", "P3-NoRL", "ZephyrCache"]
    labels = ["P3-\nNoPersist", "No\nBudget", "No\nCache", "No\nTrust", "No\nRL", "Cache\nonly"]
    rate = 10000
    vals = []
    for method in methods:
        row = next(r for r in rows if int(float(r["attack_rpa_rate_per_min"])) == rate and r["method"] == method)
        vals.append(float(row["attack_aes_amplification_mean"]))
    colors = [COLORS["P3-NoPersist"], COLORS["P3-NoBudget"], "#9AA3AF", "#B8BFC8", "#A9B4C2", COLORS["ZephyrCache"]]
    axes[0].bar(range(len(methods)), vals, color=colors, edgecolor="white", linewidth=0.45, width=0.70)
    axes[0].set_yscale("log")
    axes[0].set_xticks(range(len(methods)))
    axes[0].set_xticklabels(labels)
    axes[0].set_xlabel("Pre-persistence method / ablation variant")
    axes[0].set_ylabel("Attack amplification (AES/min)")
    axes[0].set_title("Budget module bounds work")
    axes[0].grid(True, axis="y", which="both")

    scenarios = [("medium_flood", "Medium"), ("heavy_flood", "Heavy")]
    persist_methods = ["BudgetDoS", "P3-NoPersist", "P3-Persist"]
    width = 0.22
    for idx, method in enumerate(persist_methods):
        xs = [i + (idx - 1) * width for i in range(len(scenarios))]
        y = []
        for scenario, _label in scenarios:
            row = next(
                r
                for r in m10_rows
                if r["m10_experiment"] == "main" and r["m10_scenario"] == scenario and r["method"] == method
            )
            y.append(float(row["legit_resolution_rate_mean"]) * 100)
        axes[1].bar(xs, y, width=width * 0.90, color=COLORS[method], edgecolor="white", linewidth=0.45, label=method)
    axes[1].set_xticks(range(len(scenarios)))
    axes[1].set_xticklabels([label for _scenario, label in scenarios])
    axes[1].set_xlabel("Flood scenario")
    axes[1].set_ylabel("Legitimate resolution (%)")
    axes[1].set_ylim(45, 102)
    axes[1].set_title("P3-Persist adds service recovery", pad=6)
    axes[1].grid(True, axis="y")
    axes[1].legend(loc="upper left", bbox_to_anchor=(0.01, 0.995), ncol=1, frameon=False, fontsize=7.0, borderaxespad=0)
    axes[1].annotate(
        "core method",
        xy=(0.22, 95.7),
        xytext=(0.48, 88),
        textcoords="data",
        fontsize=7.1,
        color=EDGE["green"],
        arrowprops=dict(arrowstyle="-", color=EDGE["green"], linewidth=0.7, shrinkA=2, shrinkB=2),
    )
    fig.subplots_adjust(left=0.085, right=0.985, bottom=0.21, top=0.80, wspace=0.34)
    save(fig, "fig07_ablation")


def _p3_rows_for_sweep(rows: list[dict[str, str]], selector) -> list[dict[str, str]]:
    selected = [r for r in rows if r["method"] == "P3-NoPersist" and selector(r)]
    seen: set[tuple[float, float, float, float]] = set()
    unique = []
    for row in selected:
        key = (
            float(row["background_rpa_rate_per_min"]),
            float(row["active_skew"]),
            float(row["rpa_rotation_interval_min"]),
            float(row["rssi_noise_db"]),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    return unique


def fig15_sensitivity() -> None:
    rows = read_csv(DATA_M10 / "table_m10_headline_stats.csv")

    def row_for(exp: str, **criteria) -> dict[str, str]:
        return next(
            r
            for r in rows
            if r["m10_experiment"] == exp
            and r["method"] == "P3-Persist"
            and all(str(r[key]) == str(value) for key, value in criteria.items())
        )

    panels = [
        (
            "(a) Reserve size R",
            ["50", "100", "200", "400"],
            [row_for("reserve_sensitivity", persist_reserve=v, persist_k="1") for v in ["50", "100", "200", "400"]],
        ),
        (
            "(b) Persistence threshold k",
            ["1", "2", "3"],
            [row_for("threshold_sensitivity", persist_reserve="200", persist_k=v) for v in ["1", "2", "3"]],
        ),
        (
            "(c) Duplicate-filter boundary",
            ["unique\nstress", "repeated\nno filter", "repeated\n60-second filter"],
            [
                row_for("attacker_dilemma", unique_attack_rpa="True", duplicate_filter_window_s="0"),
                row_for("attacker_dilemma", unique_attack_rpa="False", duplicate_filter_window_s="0"),
                row_for("attacker_dilemma", unique_attack_rpa="False", duplicate_filter_window_s="60"),
            ],
        ),
        (
            "(d) Repeated-address rate pressure",
            ["10k/min", "20k/min"],
            [
                row_for("rate_independence", attack_rpa_rate_per_min="10000.0"),
                row_for("rate_independence", attack_rpa_rate_per_min="20000.0"),
            ],
        ),
    ]

    fig, axes = plt.subplots(2, 2, figsize=(7.35, 4.85), sharey=True)
    for ax, (title, labels, selected) in zip(axes.flatten(), panels):
        values = [float(r["legit_resolution_rate_mean"]) * 100 for r in selected]
        attack = [float(r["attack_aes_amplification_mean"]) / 1000 for r in selected]
        colors = [COLORS["P3-Persist"] if i == 0 or "200" in labels[i] or "unique" in labels[i] else "#A9B4C2" for i in range(len(labels))]
        ax.bar(range(len(labels)), values, color=colors, edgecolor="white", linewidth=0.45, width=0.66)
        ax.set_title(title)
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels)
        ax.set_ylim(55, 101)
        ax.grid(True, axis="y")
        for x, val, atk in zip(range(len(labels)), values, attack):
            if len(labels) <= 3:
                ax.text(x, val + 1.1, f"{atk:.0f}k", ha="center", va="bottom", fontsize=7.1, color="#384252")
    axes[0, 0].set_ylabel("Legitimate resolution (%)")
    axes[1, 0].set_ylabel("Legitimate resolution (%)")
    fig.legend(
        handles=[Patch(facecolor=COLORS["P3-Persist"], label="P3-Persist setting"), Patch(facecolor="#A9B4C2", label="Sensitivity point")],
        loc="upper center",
        bbox_to_anchor=(0.5, 1.005),
        ncol=2,
        frameon=False,
    )
    fig.subplots_adjust(left=0.085, right=0.985, bottom=0.12, top=0.84, hspace=0.48, wspace=0.25)
    save(fig, "fig08_sensitivity")


def fig16_legit_path_mix() -> None:
    rows = read_csv(DATA_M3 / "table_q_sched_actual.csv")
    picks = [
        ("m3p0_nb128_rl8_atk1000_s20260530", "Benign reuse\nN=128"),
        ("m3p0_nb1024_rl8_atk10000_s20260603", "Heavy flood\nN=1024"),
    ]
    methods = ["StaticRL", "ZephyrCache", "BudgetDoS", "P3-NoPersist"]
    categories = [
        ("rl_hit_legit_rate", "RL hit", "#4D4D4D"),
        ("cache_hit_legit_rate", "Cache hit", COLORS["ZephyrCache"]),
        ("host_scan_legit_rate", "Host scan", "#E69F00"),
        ("budget_skip_legit_rate", "Budget skip", "#BDBDBD"),
        ("defer_legit_rate", "Defer", COLORS["BudgetDoS"]),
    ]
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.45), sharey=True)
    for panel_idx, (ax, (run_id, title)) in enumerate(zip(axes, picks)):
        selected = [r for r in rows if r["sample_run_id"] == run_id and r["method"] in methods]
        x = list(range(len(methods)))
        bottom = [0.0] * len(methods)
        for col, label, color in categories:
            vals = [float(next(r for r in selected if r["method"] == method).get(col, "0") or 0) for method in methods]
            ax.bar(x, vals, bottom=bottom, color=color, label=label if panel_idx == 0 else None, width=0.68)
            bottom = [a + b for a, b in zip(bottom, vals)]
        ax.set_xticks(x)
        ax.set_xticklabels(["Static", "Cache", "Budget", "P3"], rotation=0)
        ax.set_title(title, pad=10)
        ax.set_ylim(0, 1.02)
        ax.grid(True, axis="y")
    axes[0].set_ylabel("Fraction of legitimate RPA events")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 0.985), ncol=5, frameon=False)
    fig.subplots_adjust(left=0.09, right=0.985, bottom=0.16, top=0.76, wspace=0.22)
    save(fig, "fig10_legit_path_mix")


def grouped_legit_rates() -> dict[tuple[str, str], list[float]]:
    rows = read_csv(RESULTS_M10)
    grouped: dict[tuple[str, str], list[float]] = defaultdict(list)
    for row in rows:
        if row["m10_experiment"] != "main":
            continue
        if row["method"] not in {"BudgetDoS", "AdaptiveRateLimit", "P3-NoPersist", "P3-Persist"}:
            continue
        grouped[(row["m10_scenario"], row["method"])].append(float(row["legit_resolution_rate"]))
    return grouped


def ci95(values: list[float]) -> tuple[float, float]:
    mean = statistics.mean(values)
    if len(values) <= 1:
        return mean, 0.0
    half = T_CRIT_95.get(len(values) - 1, 1.96) * statistics.stdev(values) / math.sqrt(len(values))
    return mean, half


def fig17_legit_rate_ci() -> None:
    grouped = grouped_legit_rates()
    methods = ["BudgetDoS", "AdaptiveRateLimit", "P3-NoPersist", "P3-Persist"]
    scenarios = [("medium_flood", "Medium flood"), ("heavy_flood", "Heavy flood")]
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.2), sharey=True)
    for ax, (scenario, title) in zip(axes, scenarios):
        for idx, method in enumerate(methods):
            values = grouped[(scenario, method)]
            mean, half = ci95(values)
            x = idx + 1
            jitter = [x + (offset - (len(values) - 1) / 2) * 0.018 for offset in range(len(values))]
            ax.scatter(jitter, values, s=12, alpha=0.55, color=COLORS[method], edgecolor="white", linewidth=0.25)
            ax.errorbar([x], [mean], yerr=[[half], [half]], fmt="o", color=COLORS[method], capsize=3.5, elinewidth=1.15, markersize=4.6)
        ax.set_title(title)
        ax.set_xticks(range(1, len(methods) + 1))
        ax.set_xticklabels(["Budget", "Adaptive", "NoPersist", "Persist"], rotation=15, ha="right")
        ax.set_ylim(0.50, 1.0)
        ax.grid(True, axis="y")
    axes[0].set_ylabel("Legitimate resolution rate")
    fig.tight_layout()
    save(fig, "fig13_legit_rate_ci")


def main() -> None:
    set_style()
    fig01_system_overview()
    fig02_privacy_boundary()
    fig03_related_work_positioning()
    fig04_algorithm_flow()
    fig05_running_example_timeline()
    fig06_proposition_evidence_roadmap()
    fig07_budgetdos_vs_p3()
    fig08_experiment_roadmap()
    fig09_attack_aes()
    fig10_budget_frontier()
    fig11_bonded_scale()
    fig12_rl_capacity()
    fig13_capacity_frontier()
    fig14_ablation()
    fig15_sensitivity()
    fig16_legit_path_mix()
    fig17_legit_rate_ci()
    print(f"redrew 17 PDF/SVG/PNG figure sets in {OUT}")


if __name__ == "__main__":
    main()
