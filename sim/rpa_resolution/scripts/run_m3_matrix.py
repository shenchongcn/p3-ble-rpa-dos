#!/usr/bin/env python3
"""Run M3 RPA resolution experiment suites and combine summary outputs."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent / "src"
sys.path.insert(0, str(SRC_DIR))

from rpa_sim import run  # noqa: E402


P0_METHODS = [
    "FullScan-Host",
    "StaticRL",
    "ZephyrCache",
    "LRU-RL",
    "Freq-RL",
    "TrustOnly",
    "BudgetDoS",
    "P3-NoPersist",
]

ABLATION_METHODS = [
    "ZephyrCache",
    "Freq-RL",
    "BudgetDoS",
    "P3-NoPersist",
    "P3-NoCache",
    "P3-NoBudget",
    "P3-NoTrust",
    "P3-NoRL",
]

SEEDS = [20260530, 20260531, 20260601, 20260602, 20260603]


def base_config(run_id: str, seed: int, methods: list[str], **overrides: Any) -> dict[str, Any]:
    config: dict[str, Any] = {
        "schema_version": "m2.v1",
        "run_id": run_id,
        "ncs_version": "v3.2.1",
        "seed": seed,
        "duration_s": 300,
        "warmup_s": 60,
        "num_bonded": 128,
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


def p0_configs() -> list[dict[str, Any]]:
    configs: list[dict[str, Any]] = []
    for num_bonded in [16, 32, 64, 128, 256, 512, 1024]:
        for rl_capacity in [8, 16, 32]:
            for attack in [0, 100, 1000, 10000]:
                for seed in SEEDS:
                    run_id = f"m3p0_nb{num_bonded}_rl{rl_capacity}_atk{attack}_s{seed}"
                    configs.append(
                        base_config(
                            run_id,
                            seed,
                            P0_METHODS,
                            num_bonded=num_bonded,
                            rl_capacity=rl_capacity,
                            attack_rpa_rate_per_min=float(attack),
                        )
                    )
    return configs


def sensitivity_configs() -> list[dict[str, Any]]:
    configs: list[dict[str, Any]] = []
    sweeps: list[tuple[str, list[float]]] = [
        ("background_rpa_rate_per_min", [0, 10, 100, 1000]),
        ("active_skew", [0.0, 0.7, 1.1, 1.5]),
        ("rpa_rotation_interval_min", [5, 15, 30, 60]),
        ("rssi_noise_db", [0, 3, 6, 10]),
    ]
    for name, values in sweeps:
        for value in values:
            for seed in SEEDS:
                label = str(value).replace(".", "p")
                run_id = f"m3sens_{name}_{label}_s{seed}"
                configs.append(base_config(run_id, seed, P0_METHODS, **{name: value}))
    return configs


def ablation_configs() -> list[dict[str, Any]]:
    configs: list[dict[str, Any]] = []
    scenarios = [
        ("base", {"background_rpa_rate_per_min": 100.0, "attack_rpa_rate_per_min": 0.0}),
        ("flood", {"background_rpa_rate_per_min": 100.0, "attack_rpa_rate_per_min": 1000.0}),
        ("heavy_flood", {"background_rpa_rate_per_min": 1000.0, "attack_rpa_rate_per_min": 10000.0}),
    ]
    for scenario, overrides in scenarios:
        for seed in SEEDS:
            run_id = f"m3abl_{scenario}_s{seed}"
            configs.append(base_config(run_id, seed, ABLATION_METHODS, **overrides))
    return configs


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def read_summary(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def run_suite(name: str, configs: list[dict[str, Any]], out: Path, config_dir: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)
    combined: list[dict[str, str]] = []

    for idx, config in enumerate(configs, 1):
        run_dir = out / config["run_id"]
        write_json(config_dir / f"{config['run_id']}.json", config)
        run(config, run_dir)
        for row in read_summary(run_dir / "summary.csv"):
            row.update(
                {
                    "suite": name,
                    "num_bonded": str(config["num_bonded"]),
                    "rl_capacity": str(config["rl_capacity"]),
                    "background_rpa_rate_per_min": str(config["background_rpa_rate_per_min"]),
                    "attack_rpa_rate_per_min": str(config["attack_rpa_rate_per_min"]),
                    "active_skew": str(config["active_skew"]),
                    "rpa_rotation_interval_min": str(config["rpa_rotation_interval_min"]),
                    "rssi_noise_db": str(config["rssi_noise_db"]),
                    "seed": str(config["seed"]),
                }
            )
            combined.append(row)
        if idx % 50 == 0:
            print(f"{name}: completed {idx}/{len(configs)} runs")

    fieldnames = [
        "suite",
        "run_id",
        "num_bonded",
        "rl_capacity",
        "background_rpa_rate_per_min",
        "attack_rpa_rate_per_min",
        "active_skew",
        "rpa_rotation_interval_min",
        "rssi_noise_db",
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
    with (out / "combined_summary.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(combined)

    write_json(
        out / "matrix_manifest.json",
        {
            "suite": name,
            "run_count": len(configs),
            "summary_rows": len(combined),
            "methods": sorted({m for cfg in configs for m in cfg["methods"]}),
            "config_dir": str(config_dir),
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=["p0", "sensitivity", "ablation"], required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--config-dir", required=True, type=Path)
    args = parser.parse_args()

    suite_configs = {
        "p0": p0_configs,
        "sensitivity": sensitivity_configs,
        "ablation": ablation_configs,
    }[args.suite]()
    run_suite(args.suite, suite_configs, args.out, args.config_dir)


if __name__ == "__main__":
    main()
