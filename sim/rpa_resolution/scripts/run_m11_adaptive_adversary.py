#!/usr/bin/env python3
"""Run the M11 adaptive-adversary strategy-space sweep."""

from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent / "src"
sys.path.insert(0, str(SRC_DIR))

from rpa_sim import run  # noqa: E402
from run_m8_algorithm_novelty_experiments import base_config  # noqa: E402


SEEDS = list(range(20260610, 20260630))
METHODS = ["BudgetDoS", "P3-Persist"]
ATTACK_COST = 512 - 8
MAX_WORKERS = 4


def strategy_grid() -> list[dict[str, Any]]:
    strategies: list[dict[str, Any]] = [
        {
            "attack_strategy": "unique",
            "unique_attack_rpa": True,
            "attack_addr_pool_size": 0,
            "attack_repeats_per_addr": 1,
            "attack_repeat_interval_s": 0.0,
        },
        {
            "attack_strategy": "legacy_repeated",
            "unique_attack_rpa": False,
            "attack_addr_pool_size": 0,
            "attack_repeats_per_addr": 1,
            "attack_repeat_interval_s": 0.0,
        },
    ]
    for pool_size, repeats, interval_s in [
        (1, 1, 15.0),
        (1, 4, 15.0),
        (4, 1, 15.0),
        (4, 4, 15.0),
        (16, 1, 60.0),
        (16, 4, 60.0),
        (64, 1, 60.0),
        (64, 4, 60.0),
        (256, 1, 120.0),
        (256, 4, 120.0),
    ]:
        strategies.append(
            {
                "attack_strategy": f"pool{pool_size}_r{repeats}_p{int(interval_s)}",
                "unique_attack_rpa": False,
                "attack_addr_pool_size": pool_size,
                "attack_repeats_per_addr": repeats,
                "attack_repeat_interval_s": interval_s,
            }
        )
    return strategies


def configs() -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for strategy in strategy_grid():
        for duplicate_filter_window_s in [0, 60]:
            for seed in SEEDS:
                output.append(
                    base_config(
                        f"m11_{strategy['attack_strategy']}_dup{duplicate_filter_window_s}_s{seed}",
                        seed,
                        METHODS,
                        m11_experiment="adaptive_adversary",
                        m11_scenario="heavy_flood",
                        background_rpa_rate_per_min=1000.0,
                        attack_rpa_rate_per_min=10000.0,
                        duplicate_filter_window_s=duplicate_filter_window_s,
                        persist_reserve=200,
                        persist_k=1,
                        **strategy,
                    )
                )
    return output


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def read_summary(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def metric_values(rows: list[dict[str, str]], metric: str) -> list[float]:
    return [float(row[metric]) for row in rows]


def summarize(rows: list[dict[str, str]], keys: list[str], metrics: list[str]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[tuple(row.get(key, "") for key in keys)].append(row)

    output: list[dict[str, Any]] = []
    for values, group_rows in sorted(grouped.items()):
        item: dict[str, Any] = {key: value for key, value in zip(keys, values)}
        item["n"] = len(group_rows)
        for metric in metrics:
            vals = metric_values(group_rows, metric)
            item[f"{metric}_mean"] = round(mean(vals), 6)
            item[f"{metric}_sd"] = round(stdev(vals), 6) if len(vals) > 1 else 0.0
        item["dup_removable_fraction_mean"] = round(mean(float(row["dup_removable_fraction"]) for row in group_rows), 6)
        item["dup_removable_fraction_sd"] = round(
            stdev(float(row["dup_removable_fraction"]) for row in group_rows) if len(group_rows) > 1 else 0.0,
            6,
        )
        output.append(item)
    return output


def add_derived_metrics(row: dict[str, str]) -> None:
    measurement_min = float(row["summary_measurement_s"]) / 60.0
    admitted_attack = float(row["attack_aes_amplification"]) * measurement_min / ATTACK_COST
    duplicate_attack = float(row["duplicate_filter_attack_count"])
    skipped_attack = float(row["budget_skip_attack_count"])
    attack_events = admitted_attack + duplicate_attack + skipped_attack
    row["estimated_attack_event_count"] = str(round(attack_events, 6))
    row["dup_removable_fraction"] = str(round(duplicate_attack / attack_events, 6) if attack_events else 0.0)


def decorate_rows(config: dict[str, Any], run_dir: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for row in read_summary(run_dir / "summary.csv"):
        row.update(
            {
                "suite": "m11_adaptive_adversary",
                "m11_experiment": str(config["m11_experiment"]),
                "m11_scenario": str(config["m11_scenario"]),
                "duration_s": str(config["duration_s"]),
                "num_bonded": str(config["num_bonded"]),
                "rl_capacity": str(config["rl_capacity"]),
                "background_rpa_rate_per_min": str(config["background_rpa_rate_per_min"]),
                "attack_rpa_rate_per_min": str(config["attack_rpa_rate_per_min"]),
                "unique_attack_rpa": str(config.get("unique_attack_rpa", True)),
                "duplicate_filter_window_s": str(config.get("duplicate_filter_window_s", 0)),
                "attack_strategy": str(config["attack_strategy"]),
                "attack_addr_pool_size": str(config.get("attack_addr_pool_size", 0)),
                "attack_repeats_per_addr": str(config.get("attack_repeats_per_addr", 1)),
                "attack_repeat_interval_s": str(config.get("attack_repeat_interval_s", 0.0)),
                "attack_rotation_s": str(config.get("attack_rotation_s", "")),
                "persist_reserve": str(config.get("persist_reserve", "")),
                "persist_k": str(config.get("persist_k", "")),
                "seed": str(config["seed"]),
            }
        )
        add_derived_metrics(row)
        rows.append(row)
    return rows


def run_configs_subprocess(all_configs: list[dict[str, Any]], out: Path, config_dir: Path) -> list[dict[str, str]]:
    combined: list[dict[str, str]] = []
    pending = list(all_configs)
    active: list[tuple[subprocess.Popen[bytes], dict[str, Any], Path]] = []
    completed = 0
    while pending or active:
        while pending and len(active) < MAX_WORKERS:
            config = pending.pop(0)
            config_path = config_dir / f"{config['run_id']}.json"
            run_dir = out / config["run_id"]
            write_json(config_path, config)
            proc = subprocess.Popen(
                [
                    sys.executable,
                    str(SRC_DIR / "rpa_sim.py"),
                    "--config",
                    str(config_path),
                    "--out",
                    str(run_dir),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            active.append((proc, config, run_dir))

        still_active: list[tuple[subprocess.Popen[bytes], dict[str, Any], Path]] = []
        for proc, config, run_dir in active:
            status = proc.poll()
            if status is None:
                still_active.append((proc, config, run_dir))
                continue
            stderr = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
            if status != 0:
                raise RuntimeError(f"{config['run_id']} failed with status {status}:\n{stderr}")
            combined.extend(decorate_rows(config, run_dir))
            completed += 1
            if completed % 20 == 0 or completed == len(all_configs):
                print(f"m11: completed {completed}/{len(all_configs)} runs", flush=True)
        active = still_active
        if active:
            time.sleep(0.2)
    return combined


def best_response_rows(summary_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in summary_rows:
        grouped[(row["duplicate_filter_window_s"], row["method"])].append(row)

    output: list[dict[str, Any]] = []
    for (delta, method), rows in sorted(grouped.items()):
        best = max(rows, key=lambda row: float(row["attack_aes_amplification_mean"]))
        output.append(
            {
                "duplicate_filter_window_s": delta,
                "method": method,
                "best_attack_strategy": best["attack_strategy"],
                "attack_addr_pool_size": best["attack_addr_pool_size"],
                "attack_repeats_per_addr": best["attack_repeats_per_addr"],
                "attack_repeat_interval_s": best["attack_repeat_interval_s"],
                "attack_aes_amplification_mean": best["attack_aes_amplification_mean"],
                "attack_aes_amplification_sd": best["attack_aes_amplification_sd"],
                "legit_resolution_rate_mean": best["legit_resolution_rate_mean"],
                "false_defer_legit_rate_mean": best["false_defer_legit_rate_mean"],
                "reserve_grant_attack_count_mean": best["reserve_grant_attack_count_mean"],
                "duplicate_filter_attack_count_mean": best["duplicate_filter_attack_count_mean"],
                "dup_removable_fraction_mean": best["dup_removable_fraction_mean"],
            }
        )
    return output


def paired_delta_rows(summary_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for row in summary_rows:
        by_key[(row["method"], row["attack_strategy"], row["duplicate_filter_window_s"])] = row

    output: list[dict[str, Any]] = []
    for (method, strategy, delta), off_row in sorted(by_key.items()):
        if delta != "0":
            continue
        on_row = by_key.get((method, strategy, "60"))
        if on_row is None:
            continue
        output.append(
            {
                "method": method,
                "attack_strategy": strategy,
                "amp_dup_off_mean": off_row["attack_aes_amplification_mean"],
                "amp_dup_on_mean": on_row["attack_aes_amplification_mean"],
                "amp_on_over_off": round(
                    float(on_row["attack_aes_amplification_mean"]) / max(1.0, float(off_row["attack_aes_amplification_mean"])),
                    6,
                ),
                "dup_removable_fraction_on": on_row["dup_removable_fraction_mean"],
                "legit_rate_dup_on_mean": on_row["legit_resolution_rate_mean"],
            }
        )
    return output


def maybe_plot(paired_rows: list[dict[str, Any]], out_dir: Path) -> None:
    try:
        os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "matplotlib-p3repro"))
        import matplotlib.pyplot as plt
    except BaseException:
        return

    p3_rows = [row for row in paired_rows if row["method"] == "P3-Persist"]
    if not p3_rows:
        return
    xs = [float(row["amp_dup_off_mean"]) for row in p3_rows]
    ys = [float(row["amp_dup_on_mean"]) for row in p3_rows]
    colors = [float(row["dup_removable_fraction_on"]) for row in p3_rows]
    fig, ax = plt.subplots(figsize=(6.2, 4.2), dpi=180)
    scatter = ax.scatter(xs, ys, c=colors, cmap="viridis", s=30, edgecolors="none")
    ax.axhline(45765.22, color="#444444", linestyle="--", linewidth=1.0, label="unique-flood P3-Persist")
    ax.axline((0, 0), slope=1, color="#999999", linestyle=":", linewidth=1.0, label="no duplicate-filter effect")
    ax.set_xlabel("Attack amplification with duplicate filter off (AES-equiv/min)")
    ax.set_ylabel("Attack amplification with duplicate filter on (AES-equiv/min)")
    ax.set_title("Adaptive-address strategies under duplicate filtering")
    ax.legend(loc="upper left", fontsize=7)
    cbar = fig.colorbar(scatter, ax=ax)
    cbar.set_label("duplicate-filtered attack fraction")
    fig.tight_layout()
    out_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_dir / "fig_m11_adaptive_adversary.png")
    plt.close(fig)


def main() -> None:
    out = Path("sim/rpa_resolution/results/m11_adaptive_adversary")
    config_dir = Path("sim/rpa_resolution/configs/m11/adaptive_adversary")
    figure_dir = Path("sim/rpa_resolution/figures/m11_adaptive_adversary")
    out.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)
    figure_dir.mkdir(parents=True, exist_ok=True)

    all_configs = configs()
    combined = run_configs_subprocess(all_configs, out, config_dir)

    fieldnames = [
        "suite",
        "m11_experiment",
        "m11_scenario",
        "run_id",
        "duration_s",
        "num_bonded",
        "rl_capacity",
        "background_rpa_rate_per_min",
        "attack_rpa_rate_per_min",
        "unique_attack_rpa",
        "duplicate_filter_window_s",
        "attack_strategy",
        "attack_addr_pool_size",
        "attack_repeats_per_addr",
        "attack_repeat_interval_s",
        "attack_rotation_s",
        "persist_reserve",
        "persist_k",
        "seed",
        "method",
        "summary_warmup_applied",
        "summary_warmup_s",
        "summary_measurement_s",
        "aes_attempts_total",
        "aes_attempts_per_legit_resolved",
        "legit_resolution_rate",
        "p50_resolution_delay_ms",
        "p95_resolution_delay_ms",
        "p99_resolution_delay_ms",
        "attack_aes_amplification",
        "false_defer_legit_rate",
        "reserve_grant_legit_count",
        "reserve_grant_attack_count",
        "duplicate_filter_legit_count",
        "duplicate_filter_attack_count",
        "cache_hit_legit_count",
        "host_scan_legit_count",
        "budget_skip_legit_count",
        "budget_skip_attack_count",
        "estimated_attack_event_count",
        "dup_removable_fraction",
        "estimated_energy_uJ",
        "sram_bytes",
    ]
    combined_path = out / "combined_summary.csv"
    with combined_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(combined)

    metrics = [
        "attack_aes_amplification",
        "legit_resolution_rate",
        "false_defer_legit_rate",
        "reserve_grant_attack_count",
        "duplicate_filter_attack_count",
    ]
    summary = summarize(
        combined,
        [
            "m11_experiment",
            "m11_scenario",
            "attack_strategy",
            "attack_addr_pool_size",
            "attack_repeats_per_addr",
            "attack_repeat_interval_s",
            "duplicate_filter_window_s",
            "method",
        ],
        metrics,
    )
    write_csv(figure_dir / "table_m11_strategy_summary.csv", summary)
    best_rows = best_response_rows(summary)
    paired_rows = paired_delta_rows(summary)
    write_csv(figure_dir / "table_m11_best_response.csv", best_rows)
    write_csv(figure_dir / "table_m11_paired_duplicate_filter.csv", paired_rows)
    write_json(
        out / "matrix_manifest.json",
        {
            "suite": "m11_adaptive_adversary",
            "run_count": len(all_configs),
            "summary_rows": len(combined),
            "seeds": SEEDS,
            "strategy_count": len(strategy_grid()),
            "combined_summary": str(combined_path),
            "strategy_summary": str(figure_dir / "table_m11_strategy_summary.csv"),
            "best_response_table": str(figure_dir / "table_m11_best_response.csv"),
            "paired_duplicate_filter_table": str(figure_dir / "table_m11_paired_duplicate_filter.csv"),
        },
    )
    maybe_plot(paired_rows, figure_dir)


if __name__ == "__main__":
    main()
