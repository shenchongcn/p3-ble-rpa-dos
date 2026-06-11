#!/usr/bin/env python3
"""Run M4 budget sensitivity experiments for the RL=8 long-window setting."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent / "src"
sys.path.insert(0, str(SRC_DIR))

from rpa_sim import run  # noqa: E402


SEEDS = [20260610, 20260611, 20260612]
BUDGETS = [100, 250, 500, 1000, 2500, 5000]
METHODS = ["StaticRL", "P3-NoPersist", "P3-NoBudget"]


def base_config(run_id: str, seed: int, budget: int, scenario: str, **overrides: Any) -> dict[str, Any]:
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
        "methods": METHODS,
        "zephyr_cache_size": 64,
        "budget_window_s": 60,
        "budget_per_window": budget,
        "write_traces": False,
        "m4_scenario": scenario,
        "m4_budget_sensitivity": True,
    }
    config.update(overrides)
    return config


def configs() -> list[dict[str, Any]]:
    scenarios = [
        ("medium_flood", {"attack_rpa_rate_per_min": 1000.0}),
        ("heavy_flood", {"background_rpa_rate_per_min": 1000.0, "attack_rpa_rate_per_min": 10000.0}),
    ]
    output: list[dict[str, Any]] = []
    for scenario, overrides in scenarios:
        for budget in BUDGETS:
            for seed in SEEDS:
                run_id = f"m4budget_{scenario}_b{budget}_s{seed}"
                output.append(base_config(run_id, seed, budget, scenario, **overrides))
    return output


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def read_summary(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def mean(rows: list[dict[str, str]], metric: str) -> float:
    values = [float(row[metric]) for row in rows]
    return sum(values) / len(values)


def main() -> None:
    out = Path("sim/rpa_resolution/results/m4_budget_sensitivity")
    config_dir = Path("sim/rpa_resolution/configs/m4/budget_sensitivity")
    figure_dir = Path("sim/rpa_resolution/figures/m4_paper")
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
                    "suite": "m4_budget_sensitivity",
                    "m4_scenario": str(config["m4_scenario"]),
                    "duration_s": str(config["duration_s"]),
                    "num_bonded": str(config["num_bonded"]),
                    "rl_capacity": str(config["rl_capacity"]),
                    "background_rpa_rate_per_min": str(config["background_rpa_rate_per_min"]),
                    "attack_rpa_rate_per_min": str(config["attack_rpa_rate_per_min"]),
                    "budget_per_window": str(config["budget_per_window"]),
                    "seed": str(config["seed"]),
                }
            )
            combined.append(row)

    fieldnames = [
        "suite",
        "m4_scenario",
        "run_id",
        "duration_s",
        "num_bonded",
        "rl_capacity",
        "background_rpa_rate_per_min",
        "attack_rpa_rate_per_min",
        "budget_per_window",
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

    grouped: dict[tuple[str, str, str], list[dict[str, str]]] = {}
    for row in combined:
        grouped.setdefault((row["m4_scenario"], row["budget_per_window"], row["method"]), []).append(row)

    summary_rows: list[dict[str, Any]] = []
    for scenario in ["medium_flood", "heavy_flood"]:
        for budget in [str(b) for b in BUDGETS]:
            static_rows = grouped[(scenario, budget, "StaticRL")]
            p3_rows = grouped[(scenario, budget, "P3-NoPersist")]
            static_attack = mean(static_rows, "attack_aes_amplification")
            p3_attack = mean(p3_rows, "attack_aes_amplification")
            reduction = 0.0 if static_attack == 0 else (static_attack - p3_attack) / static_attack
            summary_rows.append(
                {
                    "m4_scenario": scenario,
                    "budget_per_window": budget,
                    "n": len(p3_rows),
                    "duration_s": p3_rows[0]["duration_s"],
                    "attack_rpa_rate_per_min": p3_rows[0]["attack_rpa_rate_per_min"],
                    "static_attack_aes_mean": round(static_attack, 6),
                    "p3_attack_aes_mean": round(p3_attack, 6),
                    "relative_reduction": round(reduction, 6),
                    "p3_legit_resolution_rate_mean": round(mean(p3_rows, "legit_resolution_rate"), 6),
                    "p3_false_defer_legit_rate_mean": round(mean(p3_rows, "false_defer_legit_rate"), 6),
                    "p3_aes_attempts_total_mean": round(mean(p3_rows, "aes_attempts_total"), 6),
                }
            )

    summary_path = figure_dir / "table_budget_sensitivity.csv"
    with summary_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(summary_rows)

    manifest = {
        "suite": "m4_budget_sensitivity",
        "run_count": len(configs()),
        "summary_rows": len(combined),
        "methods": METHODS,
        "seeds": SEEDS,
        "budgets": BUDGETS,
        "duration_s": 1800,
        "rl_capacity": 8,
        "combined_summary": str(combined_path),
        "paper_table": str(summary_path),
    }
    write_json(out / "matrix_manifest.json", manifest)


if __name__ == "__main__":
    main()
