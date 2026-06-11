#!/usr/bin/env python3
"""Run the P3-Persist capacity sweep used by the manuscript capacity figure."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent / "src"
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(SRC_DIR))

from rpa_sim import run  # noqa: E402
from run_m3_matrix import SEEDS, base_config  # noqa: E402


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def read_summary(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def configs() -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for num_bonded in [128, 512]:
        for rl_capacity in [8, 16, 32]:
            for seed in SEEDS:
                run_id = f"m3persist_rlcap_nb{num_bonded}_rl{rl_capacity}_atk1000_s{seed}"
                output.append(
                    base_config(
                        run_id,
                        seed,
                        ["P3-Persist"],
                        num_bonded=num_bonded,
                        rl_capacity=rl_capacity,
                        attack_rpa_rate_per_min=1000.0,
                        persist_reserve=200,
                        persist_k=1,
                    )
                )
    return output


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def aggregate(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[
            (
                row["num_bonded"],
                row["rl_capacity"],
                row["attack_rpa_rate_per_min"],
                row["method"],
            )
        ].append(row)

    output: list[dict[str, Any]] = []
    for (num_bonded, rl_capacity, attack, method), group_rows in sorted(grouped.items()):
        aes_values = [float(row["aes_attempts_total"]) for row in group_rows]
        sram_values = [float(row["sram_bytes"]) for row in group_rows]
        output.append(
            {
                "num_bonded": num_bonded,
                "rl_capacity": rl_capacity,
                "attack_rpa_rate_per_min": attack,
                "method": method,
                "n": len(group_rows),
                "aes_attempts_total_mean": round(mean(aes_values), 6),
                "aes_attempts_total_sd": round(stdev(aes_values), 6) if len(aes_values) > 1 else 0.0,
                "sram_bytes_mean": round(mean(sram_values), 6),
                "sram_bytes_sd": round(stdev(sram_values), 6) if len(sram_values) > 1 else 0.0,
            }
        )
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path("sim/rpa_resolution/results/m3_persist_rl_capacity"))
    parser.add_argument("--config-dir", type=Path, default=Path("sim/rpa_resolution/configs/m3/persist_rl_capacity"))
    parser.add_argument(
        "--figure-out",
        type=Path,
        default=Path("sim/rpa_resolution/figures/m3_paper/fig_rl_capacity_p3_persist.csv"),
    )
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    args.config_dir.mkdir(parents=True, exist_ok=True)
    combined: list[dict[str, str]] = []
    suite_configs = configs()

    for idx, config in enumerate(suite_configs, 1):
        run_dir = args.out / config["run_id"]
        write_json(args.config_dir / f"{config['run_id']}.json", config)
        run(config, run_dir)
        for row in read_summary(run_dir / "summary.csv"):
            row.update(
                {
                    "suite": "m3_persist_rl_capacity",
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
        if idx % 10 == 0:
            print(f"m3_persist_rl_capacity: completed {idx}/{len(suite_configs)} runs")

    combined_fields = [
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
    write_csv(args.out / "combined_summary.csv", combined, combined_fields)
    write_json(
        args.out / "run_manifest.json",
        {
            "suite": "m3_persist_rl_capacity",
            "run_count": len(suite_configs),
            "summary_rows": len(combined),
            "methods": ["P3-Persist"],
            "config_dir": str(args.config_dir),
        },
    )

    figure_rows = aggregate(combined)
    figure_fields = [
        "num_bonded",
        "rl_capacity",
        "attack_rpa_rate_per_min",
        "method",
        "n",
        "aes_attempts_total_mean",
        "aes_attempts_total_sd",
        "sram_bytes_mean",
        "sram_bytes_sd",
    ]
    write_csv(args.figure_out, figure_rows, figure_fields)
    print(f"wrote {args.figure_out}")


if __name__ == "__main__":
    main()
