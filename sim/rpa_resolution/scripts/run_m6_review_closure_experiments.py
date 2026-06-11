#!/usr/bin/env python3
"""Run review-closure experiments requested by the final technical review."""

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


SEEDS = [20260610, 20260611, 20260612, 20260613, 20260614]
LONG_METHODS = ["StaticRL", "ZephyrCache", "BudgetDoS", "P3-NoPersist", "P3-NoCache", "P3-NoBudget"]
BASELINE_METHODS = [
    "StaticRL",
    "Random-RL",
    "LRU-RL",
    "Freq-RL",
    "BudgetDoS",
    "AdaptiveRateLimit",
    "Oracle-Offline",
    "P3-NoPersist",
]


def base_config(run_id: str, seed: int, methods: list[str], **overrides: Any) -> dict[str, Any]:
    config: dict[str, Any] = {
        "schema_version": "m2.v1",
        "run_id": run_id,
        "ncs_version": "v3.2.1",
        "seed": seed,
        "duration_s": 1800,
        "warmup_s": 300,
        "num_bonded": 512,
        "rl_capacity": 8,
        "active_ratio": 0.2,
        "active_skew": 1.1,
        "rpa_rotation_interval_min": 15,
        "legit_adv_rate_per_device_per_min": 1.0,
        "background_rpa_rate_per_min": 100.0,
        "attack_rpa_rate_per_min": 1000.0,
        "non_rpa_ratio": 0.2,
        "rssi_noise_db": 6.0,
        "methods": methods,
        "zephyr_cache_size": 64,
        "budget_window_s": 60,
        "budget_per_window": 100,
        "write_traces": False,
    }
    config.update(overrides)
    return config


def configs() -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    scenarios = [
        ("long5_normal_capacity", LONG_METHODS, {"attack_rpa_rate_per_min": 0.0}),
        ("long5_medium_flood", LONG_METHODS, {"attack_rpa_rate_per_min": 1000.0}),
        (
            "long5_heavy_flood",
            LONG_METHODS,
            {"background_rpa_rate_per_min": 1000.0, "attack_rpa_rate_per_min": 10000.0},
        ),
        ("baseline_medium_flood", BASELINE_METHODS, {"attack_rpa_rate_per_min": 1000.0}),
        (
            "baseline_heavy_flood",
            BASELINE_METHODS,
            {"background_rpa_rate_per_min": 1000.0, "attack_rpa_rate_per_min": 10000.0},
        ),
    ]
    for scenario, methods, overrides in scenarios:
        for seed in SEEDS:
            output.append(base_config(f"m6close_{scenario}_s{seed}", seed, methods, m6_review_scenario=scenario, **overrides))

    for c_value in [8, 16, 32, 64, 512]:
        for seed in SEEDS:
            output.append(
                base_config(
                    f"m6close_capacity_c{c_value}_s{seed}",
                    seed,
                    ["StaticRL", "P3-NoPersist"],
                    m6_review_scenario="capacity_direct_expansion",
                    rl_capacity=c_value,
                    attack_rpa_rate_per_min=1000.0,
                )
            )

    for unique in [True, False]:
        for seed in SEEDS:
            output.append(
                base_config(
                    f"m6close_duplicate_{'unique' if unique else 'repeated'}_s{seed}",
                    seed,
                    ["StaticRL", "P3-NoPersist"],
                    m6_review_scenario="duplicate_filter_boundary",
                    attack_rpa_rate_per_min=1000.0,
                    unique_attack_rpa=unique,
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
    out = Path("sim/rpa_resolution/results/m6_review_closure")
    config_dir = Path("sim/rpa_resolution/configs/m6/review_closure")
    figure_dir = Path("sim/rpa_resolution/figures/m6_review_closure")
    out.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)
    figure_dir.mkdir(parents=True, exist_ok=True)

    combined: list[dict[str, str]] = []
    for config in configs():
        write_json(config_dir / f"{config['run_id']}.json", config)
        run_dir = out / config["run_id"]
        run(config, run_dir)
        for row in read_summary(run_dir / "summary.csv"):
            row.update(
                {
                    "suite": "m6_review_closure",
                    "m6_review_scenario": str(config["m6_review_scenario"]),
                    "duration_s": str(config["duration_s"]),
                    "num_bonded": str(config["num_bonded"]),
                    "rl_capacity": str(config["rl_capacity"]),
                    "background_rpa_rate_per_min": str(config["background_rpa_rate_per_min"]),
                    "attack_rpa_rate_per_min": str(config["attack_rpa_rate_per_min"]),
                    "unique_attack_rpa": str(config.get("unique_attack_rpa", True)),
                    "seed": str(config["seed"]),
                }
            )
            combined.append(row)

    fieldnames = [
        "suite",
        "m6_review_scenario",
        "run_id",
        "duration_s",
        "num_bonded",
        "rl_capacity",
        "background_rpa_rate_per_min",
        "attack_rpa_rate_per_min",
        "unique_attack_rpa",
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
        ["m6_review_scenario", "rl_capacity", "attack_rpa_rate_per_min", "unique_attack_rpa", "method"],
        metrics,
    )
    write_csv(figure_dir / "table_m6_review_closure_summary.csv", summary)
    write_json(
        out / "matrix_manifest.json",
        {
            "suite": "m6_review_closure",
            "run_count": len(configs()),
            "summary_rows": len(combined),
            "seeds": SEEDS,
            "combined_summary": str(combined_path),
            "paper_table": str(figure_dir / "table_m6_review_closure_summary.csv"),
        },
    )


if __name__ == "__main__":
    main()
