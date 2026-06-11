#!/usr/bin/env python3
"""Run the 20-seed statistical extension for the persistence claims."""

from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent / "src"
sys.path.insert(0, str(SRC_DIR))

from rpa_sim import run  # noqa: E402
from run_m8_algorithm_novelty_experiments import MAIN_METHODS, base_config  # noqa: E402


SEEDS = list(range(20260610, 20260630))


def configs() -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    scenario_overrides = {
        "medium_flood": {"background_rpa_rate_per_min": 100.0, "attack_rpa_rate_per_min": 1000.0},
        "heavy_flood": {"background_rpa_rate_per_min": 1000.0, "attack_rpa_rate_per_min": 10000.0},
    }

    for scenario, overrides in scenario_overrides.items():
        for seed in SEEDS:
            output.append(
                base_config(
                    f"m10_main_{scenario}_s{seed}",
                    seed,
                    MAIN_METHODS,
                    m10_experiment="main",
                    m10_scenario=scenario,
                    **overrides,
                )
            )

    for reserve in [50, 100, 200, 400]:
        for seed in SEEDS:
            output.append(
                base_config(
                    f"m10_reserve_r{reserve}_s{seed}",
                    seed,
                    ["P3-Persist"],
                    m10_experiment="reserve_sensitivity",
                    m10_scenario="heavy_flood",
                    background_rpa_rate_per_min=1000.0,
                    attack_rpa_rate_per_min=10000.0,
                    persist_reserve=reserve,
                    persist_k=1,
                )
            )

    for threshold in [1, 2, 3]:
        for seed in SEEDS:
            output.append(
                base_config(
                    f"m10_threshold_k{threshold}_s{seed}",
                    seed,
                    ["P3-Persist"],
                    m10_experiment="threshold_sensitivity",
                    m10_scenario="heavy_flood",
                    background_rpa_rate_per_min=1000.0,
                    attack_rpa_rate_per_min=10000.0,
                    persist_reserve=200,
                    persist_k=threshold,
                )
            )

    dilemma_cases = [
        ("unique", True, 0),
        ("repeated", False, 0),
        ("repeated_dup60", False, 60),
    ]
    for label, unique, duplicate_filter_window_s in dilemma_cases:
        for seed in SEEDS:
            output.append(
                base_config(
                    f"m10_dilemma_{label}_s{seed}",
                    seed,
                    ["BudgetDoS", "P3-Persist"],
                    m10_experiment="attacker_dilemma",
                    m10_scenario="heavy_flood",
                    background_rpa_rate_per_min=1000.0,
                    attack_rpa_rate_per_min=10000.0,
                    unique_attack_rpa=unique,
                    duplicate_filter_window_s=duplicate_filter_window_s,
                    persist_reserve=200,
                    persist_k=1,
                )
            )

    for attack_rate in [10000.0, 20000.0]:
        for seed in SEEDS:
            output.append(
                base_config(
                    f"m10_rate_repeated_atk{int(attack_rate)}_s{seed}",
                    seed,
                    ["P3-Persist"],
                    m10_experiment="rate_independence",
                    m10_scenario="heavy_flood",
                    background_rpa_rate_per_min=1000.0,
                    attack_rpa_rate_per_min=attack_rate,
                    unique_attack_rpa=False,
                    duplicate_filter_window_s=0,
                    persist_reserve=200,
                    persist_k=1,
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


def summarize(rows: list[dict[str, str]], keys: list[str], metrics: list[str]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[tuple(row.get(key, "") for key in keys)].append(row)

    output: list[dict[str, Any]] = []
    for values, group_rows in sorted(grouped.items()):
        item: dict[str, Any] = {key: value for key, value in zip(keys, values)}
        item["n"] = len(group_rows)
        for metric in metrics:
            vals = [float(row[metric]) for row in group_rows]
            item[f"{metric}_mean"] = round(mean(vals), 6)
            item[f"{metric}_sd"] = round(stdev(vals), 6) if len(vals) > 1 else 0.0
        output.append(item)
    return output


def main() -> None:
    out = Path("sim/rpa_resolution/results/m10_statistical_extension")
    config_dir = Path("sim/rpa_resolution/configs/m10/statistical_extension")
    figure_dir = Path("sim/rpa_resolution/figures/m10_statistical_extension")
    out.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)
    figure_dir.mkdir(parents=True, exist_ok=True)

    combined: list[dict[str, str]] = []
    all_configs = configs()
    for idx, config in enumerate(all_configs, 1):
        write_json(config_dir / f"{config['run_id']}.json", config)
        run_dir = out / config["run_id"]
        run(config, run_dir)
        for row in read_summary(run_dir / "summary.csv"):
            row.update(
                {
                    "suite": "m10_statistical_extension",
                    "m10_experiment": str(config["m10_experiment"]),
                    "m10_scenario": str(config["m10_scenario"]),
                    "duration_s": str(config["duration_s"]),
                    "num_bonded": str(config["num_bonded"]),
                    "rl_capacity": str(config["rl_capacity"]),
                    "background_rpa_rate_per_min": str(config["background_rpa_rate_per_min"]),
                    "attack_rpa_rate_per_min": str(config["attack_rpa_rate_per_min"]),
                    "unique_attack_rpa": str(config.get("unique_attack_rpa", True)),
                    "duplicate_filter_window_s": str(config.get("duplicate_filter_window_s", 0)),
                    "persist_reserve": str(config.get("persist_reserve", "")),
                    "persist_k": str(config.get("persist_k", "")),
                    "seed": str(config["seed"]),
                }
            )
            combined.append(row)
        if idx % 25 == 0:
            print(f"m10: completed {idx}/{len(all_configs)} runs")

    fieldnames = [
        "suite",
        "m10_experiment",
        "m10_scenario",
        "run_id",
        "duration_s",
        "num_bonded",
        "rl_capacity",
        "background_rpa_rate_per_min",
        "attack_rpa_rate_per_min",
        "unique_attack_rpa",
        "duplicate_filter_window_s",
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
        "estimated_energy_uJ",
        "sram_bytes",
    ]
    combined_path = out / "combined_summary.csv"
    with combined_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(combined)

    metrics = [
        "aes_attempts_total",
        "attack_aes_amplification",
        "legit_resolution_rate",
        "false_defer_legit_rate",
        "sram_bytes",
    ]
    summary = summarize(
        combined,
        [
            "m10_experiment",
            "m10_scenario",
            "attack_rpa_rate_per_min",
            "unique_attack_rpa",
            "duplicate_filter_window_s",
            "persist_reserve",
            "persist_k",
            "method",
        ],
        metrics,
    )
    write_csv(figure_dir / "table_m10_statistical_summary.csv", summary)
    write_json(
        out / "matrix_manifest.json",
        {
            "suite": "m10_statistical_extension",
            "run_count": len(all_configs),
            "summary_rows": len(combined),
            "seeds": SEEDS,
            "combined_summary": str(combined_path),
            "paper_table": str(figure_dir / "table_m10_statistical_summary.csv"),
        },
    )


if __name__ == "__main__":
    main()
