#!/usr/bin/env python3
"""Run a small matrix of simulator configs."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent / "src"
sys.path.insert(0, str(SRC_DIR))

from rpa_sim import run


METHODS = ["FullScan-Host", "StaticRL", "LRU-RL", "Freq-RL", "BudgetDoS", "P3-NoPersist"]


def make_config(run_id: str, num_bonded: int, rl_capacity: int, attack: int, seed: int) -> dict:
    return {
        "schema_version": "m2.v1",
        "run_id": run_id,
        "ncs_version": "v3.2.1",
        "seed": seed,
        "duration_s": 1800,
        "warmup_s": 300,
        "num_bonded": num_bonded,
        "rl_capacity": rl_capacity,
        "active_ratio": 0.2,
        "active_skew": 1.1,
        "rpa_rotation_interval_min": 15,
        "legit_adv_rate_per_device_per_min": 1.0,
        "background_rpa_rate_per_min": 100.0,
        "attack_rpa_rate_per_min": float(attack),
        "non_rpa_ratio": 0.2,
        "rssi_noise_db": 6.0,
        "methods": METHODS,
        "zephyr_cache_size": 64,
        "budget_window_s": 60,
        "budget_per_window": 100,
    }


def read_summary(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    combined: list[dict[str, str]] = []

    configs: list[dict] = []
    seed = 20260530
    for num_bonded in [16, 32, 64, 128, 256, 512]:
        for attack in [0, 100, 1000, 10000]:
            configs.append(make_config(f"w3_nb{num_bonded}_rl8_atk{attack}_s{seed}", num_bonded, 8, attack, seed))
    for rl_capacity in [8, 16, 32]:
        for attack in [0, 100, 1000, 10000]:
            configs.append(make_config(f"w3_nb128_rl{rl_capacity}_atk{attack}_s{seed}", 128, rl_capacity, attack, seed))
    for seed_value in [20260530, 20260531]:
        configs.append(make_config(f"w3_nb128_rl8_atk1000_s{seed_value}", 128, 8, 1000, seed_value))
    configs = list({config["run_id"]: config for config in configs}.values())

    for config in configs:
        run_dir = args.out / config["run_id"]
        run(config, run_dir)
        for row in read_summary(run_dir / "summary.csv"):
            row.update(
                {
                    "num_bonded": str(config["num_bonded"]),
                    "rl_capacity": str(config["rl_capacity"]),
                    "attack_rpa_rate_per_min": str(int(config["attack_rpa_rate_per_min"])),
                    "seed": str(config["seed"]),
                }
            )
            combined.append(row)

    fieldnames = [
        "run_id",
        "num_bonded",
        "rl_capacity",
        "attack_rpa_rate_per_min",
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
    with (args.out / "combined_summary.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(combined)

    with (args.out / "matrix_manifest.json").open("w", encoding="utf-8") as f:
        json.dump({"run_count": len(configs), "summary_rows": len(combined)}, f, indent=2)


if __name__ == "__main__":
    main()
