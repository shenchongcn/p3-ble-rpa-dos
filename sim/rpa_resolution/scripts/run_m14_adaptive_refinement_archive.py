#!/usr/bin/env python3
"""Archive-compatible entry point for the preregistered adaptive local refinement.

This copy differs from the frozen runner only in provenance handling: outside a
Git checkout it records ``archive-no-git`` instead of aborting while writing the
matrix manifest. Simulation, configuration, selection, and analysis logic are
unchanged.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
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
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(SRC_DIR))

from analyze_m10_stats import t_critical_975  # noqa: E402
from review260715_suite_common import should_skip_run  # noqa: E402
from rpa_sim import get_git_commit  # noqa: E402


SCREEN_SEEDS = list(range(20260610, 20260615))
CONFIRM_SEEDS = list(range(20260610, 20260630))
POOL_SIZES = [128, 160, 192, 224, 256, 320, 384, 512]
INTERVALS_S = [75, 90, 105, 120, 135, 150, 180]
REPEATS = [1, 2, 4]
MAX_WORKERS = 4
ATTACK_COST = 512 - 8
CAP_AES_PER_MIN = 151200.0
OLD_WORST = (256, 1, 120)
FIXED_NEIGHBORS = [
    (224, 1, 120),
    (320, 1, 120),
    (256, 1, 105),
    (256, 1, 135),
    (256, 2, 120),
]
CORE_METRICS = [
    "attack_aes_amplification",
    "legit_resolution_rate",
    "false_defer_legit_rate",
    "reserve_grant_attack_count",
    "duplicate_filter_attack_count",
    "dup_removable_fraction",
]


def pool_strategy(pool_size: int, repeats: int, interval_s: int) -> dict[str, Any]:
    return {
        "attack_strategy": f"pool{pool_size}_r{repeats}_p{interval_s}",
        "unique_attack_rpa": False,
        "attack_addr_pool_size": pool_size,
        "attack_repeats_per_addr": repeats,
        "attack_repeat_interval_s": float(interval_s),
    }


def unique_strategy() -> dict[str, Any]:
    return {
        "attack_strategy": "unique",
        "unique_attack_rpa": True,
        "attack_addr_pool_size": 0,
        "attack_repeats_per_addr": 1,
        "attack_repeat_interval_s": 0.0,
    }


def screen_strategies() -> list[dict[str, Any]]:
    return [
        pool_strategy(pool_size, repeats, interval_s)
        for pool_size in POOL_SIZES
        for interval_s in INTERVALS_S
        for repeats in REPEATS
    ]


def base_config(
    run_id: str,
    seed: int,
    methods: list[str],
    strategy: dict[str, Any],
    duplicate_filter_window_s: int,
    phase: str,
) -> dict[str, Any]:
    config: dict[str, Any] = {
        "schema_version": "m14.v1",
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
        "background_rpa_rate_per_min": 1000.0,
        "attack_rpa_rate_per_min": 10000.0,
        "non_rpa_ratio": 0.2,
        "rssi_noise_db": 6.0,
        "methods": list(methods),
        "zephyr_cache_size": 64,
        "budget_window_s": 60,
        "budget_per_window": 100,
        "persist_reserve": 200,
        "persist_k": 1,
        "duplicate_filter_window_s": duplicate_filter_window_s,
        "write_traces": False,
        "write_observation_ledger": False,
        "m14_experiment": "adaptive_refinement",
        "m14_phase": phase,
        "m14_scenario": "heavy_flood",
    }
    config.update(strategy)
    return config


def screen_configs() -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for strategy in screen_strategies():
        for seed in SCREEN_SEEDS:
            output.append(
                base_config(
                    f"m14_screen_{strategy['attack_strategy']}_s{seed}",
                    seed,
                    ["P3-Persist"],
                    strategy,
                    60,
                    "screen",
                )
            )
    return output


def read_csv(path: Path) -> list[dict[str, str]]:
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


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def add_derived_metrics(row: dict[str, str]) -> None:
    measurement_min = float(row["summary_measurement_s"]) / 60.0
    admitted_attack = float(row["attack_aes_amplification"]) * measurement_min / ATTACK_COST
    duplicate_attack = float(row["duplicate_filter_attack_count"])
    skipped_attack = float(row["budget_skip_attack_count"])
    attack_events = admitted_attack + duplicate_attack + skipped_attack
    row["estimated_attack_event_count"] = str(round(attack_events, 6))
    row["dup_removable_fraction"] = str(
        round(duplicate_attack / attack_events, 6) if attack_events else 0.0
    )


def decorate(config: dict[str, Any], run_dir: Path) -> list[dict[str, str]]:
    rows = read_csv(run_dir / "summary.csv")
    for row in rows:
        row.update(
            {
                "suite": "m14_adaptive_refinement",
                "m14_phase": str(config["m14_phase"]),
                "m14_scenario": str(config["m14_scenario"]),
                "attack_strategy": str(config["attack_strategy"]),
                "attack_addr_pool_size": str(config.get("attack_addr_pool_size", 0)),
                "attack_repeats_per_addr": str(config.get("attack_repeats_per_addr", 1)),
                "attack_repeat_interval_s": str(config.get("attack_repeat_interval_s", 0.0)),
                "unique_attack_rpa": str(config.get("unique_attack_rpa", True)),
                "duplicate_filter_window_s": str(config["duplicate_filter_window_s"]),
                "persist_reserve": str(config["persist_reserve"]),
                "persist_k": str(config["persist_k"]),
                "seed": str(config["seed"]),
            }
        )
        add_derived_metrics(row)
    return rows


def run_configs(
    all_configs: list[dict[str, Any]],
    result_dir: Path,
    config_dir: Path,
) -> list[dict[str, str]]:
    result_dir.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)
    combined: list[dict[str, str]] = []
    pending: list[tuple[dict[str, Any], Path]] = []
    for config in all_configs:
        config_path = config_dir / f"{config['run_id']}.json"
        run_dir = result_dir / "runs" / str(config["run_id"])
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
            config_path = config_dir / f"{config['run_id']}.json"
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
            if not should_skip_run(config, run_dir):
                raise RuntimeError(f"{config['run_id']} has no valid completion manifest")
            combined.extend(decorate(config, run_dir))
            completed += 1
            if completed % 20 == 0 or (not pending and not still_active):
                print(f"m14: completed {completed}/{new_run_count} new runs", flush=True)
        active = still_active
        if active:
            time.sleep(0.2)
    return combined


def mean_ci(values: list[float]) -> dict[str, Any]:
    n = len(values)
    avg = mean(values)
    sd = stdev(values) if n > 1 else 0.0
    half = t_critical_975(n - 1) * sd / (n ** 0.5) if n > 1 else 0.0
    return {
        "mean": round(avg, 6),
        "sd": round(sd, 6),
        "ci95_low": round(avg - half, 6),
        "ci95_high": round(avg + half, 6),
    }


def summarize(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    keys = [
        "m14_phase",
        "attack_strategy",
        "attack_addr_pool_size",
        "attack_repeats_per_addr",
        "attack_repeat_interval_s",
        "unique_attack_rpa",
        "duplicate_filter_window_s",
        "method",
    ]
    grouped: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[tuple(row[key] for key in keys)].append(row)
    output: list[dict[str, Any]] = []
    for key, group_rows in sorted(grouped.items()):
        item: dict[str, Any] = dict(zip(keys, key))
        item["n"] = len(group_rows)
        for metric in CORE_METRICS:
            stats = mean_ci([float(row[metric]) for row in group_rows])
            for stat_name, value in stats.items():
                item[f"{metric}_{stat_name}"] = value
        output.append(item)
    return output


def select_top5(screen_table: list[dict[str, Any]]) -> list[dict[str, Any]]:
    p3_rows = [row for row in screen_table if row["method"] == "P3-Persist"]
    ranked = sorted(
        p3_rows,
        key=lambda row: (
            -float(row["attack_aes_amplification_mean"]),
            str(row["attack_strategy"]),
        ),
    )
    if len(ranked) != 168:
        raise RuntimeError(f"expected 168 P3 screen strategies, found {len(ranked)}")
    return ranked[:5]


def confirm_strategies(top5_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], set[str]]:
    by_name = {strategy["attack_strategy"]: strategy for strategy in screen_strategies()}
    selected_names = {str(row["attack_strategy"]) for row in top5_rows}
    selected_names.add(pool_strategy(*OLD_WORST)["attack_strategy"])
    for point in FIXED_NEIGHBORS:
        selected_names.add(pool_strategy(*point)["attack_strategy"])
    strategies = [unique_strategy()] + [by_name[name] for name in sorted(selected_names)]
    return strategies, {str(row["attack_strategy"]) for row in top5_rows}


def confirm_configs(
    strategies: list[dict[str, Any]],
    top5_names: set[str],
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for strategy in strategies:
        methods = ["P3-Persist"]
        if strategy["attack_strategy"] in top5_names:
            methods.append("BudgetDoS")
        for duplicate_filter_window_s in [0, 60]:
            for seed in CONFIRM_SEEDS:
                output.append(
                    base_config(
                        f"m14_confirm_{strategy['attack_strategy']}_dup{duplicate_filter_window_s}_s{seed}",
                        seed,
                        methods,
                        strategy,
                        duplicate_filter_window_s,
                        "confirm",
                    )
                )
    return output


def manifest(
    phase: str,
    all_configs: list[dict[str, Any]],
    combined: list[dict[str, str]],
    result_dir: Path,
    extra: dict[str, Any],
) -> None:
    source_paths = [
        Path("sim/rpa_resolution/src/rpa_sim.py"),
        Path("sim/rpa_resolution/scripts/run_m14_adaptive_refinement.py"),
        Path("sim/rpa_resolution/scripts/review260715_suite_common.py"),
    ]
    source_commit = get_git_commit()
    if source_commit == "unknown":
        source_commit = "archive-no-git"
    payload = {
        "suite": "m14_adaptive_refinement",
        "phase": phase,
        "config_count": len(all_configs),
        "method_result_row_count": len(combined),
        "source_commit": source_commit,
        "source_sha256": {str(path): sha256(path) for path in source_paths},
        "full_trace_default": False,
        **extra,
    }
    write_json(result_dir / "matrix_manifest.json", payload)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=["screen", "confirm"], default="screen")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("sim/rpa_resolution/results/m14_adaptive_refinement"),
    )
    parser.add_argument(
        "--config-root",
        type=Path,
        default=Path("sim/rpa_resolution/configs/m14/adaptive_refinement"),
    )
    args = parser.parse_args()

    if args.phase == "screen":
        all_configs = screen_configs()
        if args.smoke:
            all_configs = [all_configs[0], all_configs[-1]]
        result_dir = args.root / "screen"
        config_dir = args.config_root / "screen"
        combined = run_configs(all_configs, result_dir, config_dir)
        write_csv(result_dir / "combined_summary.csv", combined)
        table = summarize(combined)
        write_csv(result_dir / "table_m14_local_screen.csv", table)
        manifest(
            "screen_smoke" if args.smoke else "screen",
            all_configs,
            combined,
            result_dir,
            {
                "strategy_count": 2 if args.smoke else len(screen_strategies()),
                "seed_count": 1 if args.smoke else len(SCREEN_SEEDS),
                "methods": ["P3-Persist"],
                "duplicate_filter_window_s": 60,
                "objective": "maximize P3-Persist attack_aes_amplification mean",
                "tie_break": "attack_strategy lexicographic ascending",
            },
        )
        return

    screen_table_path = args.root / "screen" / "table_m14_local_screen.csv"
    if not screen_table_path.is_file():
        raise RuntimeError("run the complete screen phase before confirm")
    top5_rows = select_top5(read_csv(screen_table_path))
    strategies, top5_names = confirm_strategies(top5_rows)
    all_configs = confirm_configs(strategies, top5_names)
    if args.smoke:
        all_configs = [all_configs[0], all_configs[-1]]
    result_dir = args.root / "confirm"
    config_dir = args.config_root / "confirm"
    combined = run_configs(all_configs, result_dir, config_dir)
    write_csv(result_dir / "combined_summary.csv", combined)
    table = summarize(combined)
    write_csv(result_dir / "table_m14_confirmed_best_response.csv", table)
    max_p3 = max(
        float(row["attack_aes_amplification"])
        for row in combined
        if row["method"] == "P3-Persist"
    )
    write_json(
        result_dir / "cap_audit.json",
        {
            "cap_aes_per_min": CAP_AES_PER_MIN,
            "max_p3_attack_aes_per_min": max_p3,
            "max_over_cap": max_p3 / CAP_AES_PER_MIN,
            "pass": max_p3 <= CAP_AES_PER_MIN,
        },
    )
    manifest(
        "confirm_smoke" if args.smoke else "confirm",
        all_configs,
        combined,
        result_dir,
        {
            "strategy_count": len(strategies),
            "seed_count": 1 if args.smoke else len(CONFIRM_SEEDS),
            "duplicate_filter_windows_s": [0, 60],
            "top5": sorted(top5_names),
            "old_worst": pool_strategy(*OLD_WORST)["attack_strategy"],
            "fixed_neighbors": [pool_strategy(*point)["attack_strategy"] for point in FIXED_NEIGHBORS],
            "unique_baseline": "unique",
            "budget_dos_scope": "top5 only",
        },
    )


if __name__ == "__main__":
    main()
