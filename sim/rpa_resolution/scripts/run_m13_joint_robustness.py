#!/usr/bin/env python3
"""Run the short-epoch, observation-loss, benign-density review matrix."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent / "src"
sys.path.insert(0, str(SRC_DIR))
sys.path.insert(0, str(SCRIPT_DIR))

from review260715_suite_common import should_skip_run  # noqa: E402


SEEDS_SCREEN = list(range(20260610, 20260620))
SEEDS_CONFIRM = list(range(20260610, 20260630))
METHODS = ["P3-Persist", "P3-NoPersist", "BudgetDoS"]
EPOCHS_MIN = [1, 5, 15]
LOSS_RATES = [0.0, 0.2, 0.4]
DENSITIES = [100.0, 1000.0, 5000.0]
MAX_WORKERS = 4
SUMMARY_FIELDS = [
    "run_id",
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
    "reserve_grant_legit_p50_delay_ms",
    "reserve_grant_legit_p95_delay_ms",
    "reserve_grant_legit_p99_delay_ms",
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
    "observation_loss_rate_requested",
    "generated_event_count",
    "observed_event_count",
    "dropped_event_count",
    "actual_observation_loss_rate",
    "generated_legit_event_count",
    "observed_legit_event_count",
    "dropped_legit_event_count",
    "actual_legit_observation_loss_rate",
    "generated_background_event_count",
    "observed_background_event_count",
    "dropped_background_event_count",
    "actual_background_observation_loss_rate",
    "generated_attack_event_count",
    "observed_attack_event_count",
    "dropped_attack_event_count",
    "actual_attack_observation_loss_rate",
    "offered_legit_resolution_rate",
    "observed_legit_resolution_rate",
    "false_defer_observed_legit_rate",
    "reserve_grant_background_count",
    "duplicate_filter_background_count",
    "cache_hit_background_count",
    "host_scan_background_count",
    "budget_skip_background_count",
]
METRICS = [
    "offered_legit_resolution_rate",
    "observed_legit_resolution_rate",
    "false_defer_observed_legit_rate",
    "p95_resolution_delay_ms",
    "attack_aes_amplification",
    "actual_observation_loss_rate",
    "reserve_grant_background_count",
]


def base_config(run_id: str, seed: int, *, epoch_min: int, loss_rate: float, density: float, attack_rate: float, experiment: str, background_mode: str = "unique", **extra: Any) -> dict[str, Any]:
    config: dict[str, Any] = {
        "schema_version": "m13.v1",
        "run_id": run_id,
        "ncs_version": "v3.2.1",
        "seed": seed,
        "duration_s": 1800,
        "warmup_s": 300,
        "num_bonded": 512,
        "rl_capacity": 8,
        "active_ratio": 0.2,
        "active_skew": 1.1,
        "rpa_rotation_interval_min": epoch_min,
        "legit_adv_rate_per_device_per_min": 1.0,
        "background_rpa_rate_per_min": density,
        "background_address_mode": background_mode,
        "attack_rpa_rate_per_min": attack_rate,
        "unique_attack_rpa": True,
        "non_rpa_ratio": 0.2,
        "rssi_noise_db": 6.0,
        "methods": list(METHODS),
        "zephyr_cache_size": 64,
        "budget_window_s": 60,
        "budget_per_window": 100,
        "persist_reserve": 200,
        "persist_k": 1,
        "observation_loss_rate": loss_rate,
        "observation_loss_seed": int(f"{seed}{int(loss_rate * 100):02d}{epoch_min:02d}"),
        "write_traces": False,
        "write_observation_ledger": False,
        "m13_experiment": experiment,
        "m13_epoch_min": epoch_min,
        "m13_loss_rate": loss_rate,
        "m13_density": density,
        "m13_background_mode": background_mode,
    }
    config.update(extra)
    return config


def configs(seeds: list[int] = SEEDS_SCREEN) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for epoch_min in EPOCHS_MIN:
        for loss_rate in LOSS_RATES:
            for density in DENSITIES:
                for seed in seeds:
                    output.append(
                        base_config(
                            f"m13_main_e{epoch_min}_l{int(loss_rate * 100)}_d{int(density)}_s{seed}",
                            seed,
                            epoch_min=epoch_min,
                            loss_rate=loss_rate,
                            density=density,
                            attack_rate=10000.0,
                            experiment="main",
                        )
                    )

    controls = [
        ("control_no_attack_baseline", 15, 0.0, 100.0, 0.0, "unique", {}),
        ("control_no_attack_worst", 1, 0.4, 5000.0, 0.0, "unique", {}),
        (
            "control_repeated_benign_worst",
            1,
            0.4,
            5000.0,
            10000.0,
            "repeated",
            {
                "background_addr_pool_size": 256,
                "background_repeats_per_addr": 1,
                "background_repeat_interval_s": 60.0,
            },
        ),
    ]
    for label, epoch_min, loss_rate, density, attack_rate, background_mode, extra in controls:
        for seed in seeds:
            output.append(
                base_config(
                    f"m13_{label}_s{seed}",
                    seed,
                    epoch_min=epoch_min,
                    loss_rate=loss_rate,
                    density=density,
                    attack_rate=attack_rate,
                    experiment=label,
                    background_mode=background_mode,
                    **extra,
                )
            )
    return output


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def read_summary(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def decorate(config: dict[str, Any], run_dir: Path) -> list[dict[str, str]]:
    rows = read_summary(run_dir / "summary.csv")
    for row in rows:
        row.update(
            {
                "suite": "m13_joint_robustness",
                "m13_experiment": str(config["m13_experiment"]),
                "m13_epoch_min": str(config["m13_epoch_min"]),
                "m13_loss_rate": str(config["m13_loss_rate"]),
                "m13_density": str(config["m13_density"]),
                "m13_background_mode": str(config["m13_background_mode"]),
                "background_addr_pool_size": str(config.get("background_addr_pool_size", "")),
                "background_repeats_per_addr": str(config.get("background_repeats_per_addr", "")),
                "background_repeat_interval_s": str(config.get("background_repeat_interval_s", "")),
                "duration_s": str(config["duration_s"]),
                "warmup_s": str(config["warmup_s"]),
                "num_bonded": str(config["num_bonded"]),
                "rl_capacity": str(config["rl_capacity"]),
                "seed": str(config["seed"]),
            }
        )
    return rows


def run_configs(all_configs: list[dict[str, Any]], out: Path, config_dir: Path) -> list[dict[str, str]]:
    out.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)
    pending: list[tuple[dict[str, Any], Path]] = []
    combined: list[dict[str, str]] = []
    for config in all_configs:
        config_path = config_dir / f"{config['run_id']}.json"
        run_dir = out / "runs" / config["run_id"]
        write_json(config_path, config)
        if should_skip_run(config, run_dir):
            combined.extend(decorate(config, run_dir))
        else:
            pending.append((config, run_dir))

    new_run_count = len(pending)
    active: list[tuple[subprocess.Popen[bytes], dict[str, Any], Path]] = []
    completed = 0
    while pending or active:
        while pending and len(active) < MAX_WORKERS:
            config, run_dir = pending.pop(0)
            proc = subprocess.Popen(
                [sys.executable, str(SRC_DIR / "rpa_sim.py"), "--config", str(config_dir / f"{config['run_id']}.json"), "--out", str(run_dir)],
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
            if not should_skip_run(config, run_dir):
                raise RuntimeError(f"{config['run_id']} finished without a valid completion manifest")
            combined.extend(decorate(config, run_dir))
            completed += 1
            if completed % 20 == 0 or not pending and not still_active:
                print(f"m13: completed {completed}/{new_run_count} new runs", flush=True)
        active = still_active
        if active:
            time.sleep(0.2)
    return combined


def summarize(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    keys = [
        "m13_experiment",
        "m13_epoch_min",
        "m13_loss_rate",
        "m13_density",
        "m13_background_mode",
        "method",
    ]
    grouped: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[tuple(row.get(key, "") for key in keys)].append(row)
    output: list[dict[str, Any]] = []
    for values, group_rows in sorted(grouped.items()):
        item = {key: value for key, value in zip(keys, values)}
        item["n"] = len(group_rows)
        for metric in METRICS:
            values_float = [float(row[metric]) for row in group_rows]
            item[f"{metric}_mean"] = round(mean(values_float), 6)
            item[f"{metric}_sd"] = round(stdev(values_float), 6) if len(values_float) > 1 else 0.0
        output.append(item)
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument(
        "--confirm-all-20",
        action="store_true",
        help="extend every main cell and control from the 10-seed screen to 20 seeds",
    )
    parser.add_argument("--out", type=Path, default=Path("sim/rpa_resolution/results/m13_joint_robustness"))
    parser.add_argument("--config-dir", type=Path, default=Path("sim/rpa_resolution/configs/m13/joint_robustness"))
    args = parser.parse_args()
    selected_seeds = SEEDS_CONFIRM if args.confirm_all_20 else SEEDS_SCREEN
    all_configs = configs(selected_seeds)
    if args.smoke:
        all_configs = [all_configs[0], all_configs[-1]]
    combined = run_configs(all_configs, args.out, args.config_dir)
    fields = [
        "suite", "m13_experiment", "m13_epoch_min", "m13_loss_rate", "m13_density",
        "m13_background_mode", "background_addr_pool_size", "background_repeats_per_addr",
        "background_repeat_interval_s", "run_id", "duration_s", "warmup_s", "num_bonded",
        "rl_capacity", "seed", *SUMMARY_FIELDS[1:]
    ]
    write_csv(args.out / "combined_summary.csv", combined, fields)
    table = summarize(combined)
    table_fields = [
        "m13_experiment", "m13_epoch_min", "m13_loss_rate", "m13_density",
        "m13_background_mode", "method", "n",
    ] + [f"{metric}_{suffix}" for metric in METRICS for suffix in ["mean", "sd"]]
    write_csv(args.out / "table_m13_joint_robustness.csv", table, table_fields)
    write_json(
        args.out / "matrix_manifest.json",
        {
            "suite": "m13_joint_robustness",
            "status": "smoke" if args.smoke else ("complete_20_seed_confirmation" if args.confirm_all_20 else "complete_10_seed_screen"),
            "source_commit": "see run_manifest.json per run",
            "methods": METHODS,
            "seeds": selected_seeds,
            "epoch_min": EPOCHS_MIN,
            "loss_rates": LOSS_RATES,
            "densities": DENSITIES,
            "main_cell_count": len(EPOCHS_MIN) * len(LOSS_RATES) * len(DENSITIES),
            "config_count": len(all_configs),
            "summary_row_count": len(combined),
            "metrics": METRICS,
            "screen_seed_count": len(SEEDS_SCREEN),
            "final_seed_count": len(selected_seeds),
            "full_trace_default": False,
        },
    )


if __name__ == "__main__":
    main()
