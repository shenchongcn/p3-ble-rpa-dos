#!/usr/bin/env python3
"""Generate M3 analysis tables and paper figure source data."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent / "src"
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(SRC_DIR))

from rpa_sim import run  # noqa: E402
from run_m3_matrix import P0_METHODS, base_config  # noqa: E402


METRICS = [
    "aes_attempts_total",
    "aes_attempts_per_legit_resolved",
    "legit_resolution_rate",
    "p95_resolution_delay_ms",
    "attack_aes_amplification",
    "false_defer_legit_rate",
    "estimated_energy_uJ",
    "sram_bytes",
]


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def to_float(row: dict[str, str], key: str) -> float:
    return float(row.get(key, "0") or 0)


def group_mean(rows: list[dict[str, str]], keys: list[str], metrics: list[str]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[tuple(row.get(key, "") for key in keys)].append(row)

    output: list[dict[str, Any]] = []
    for values, group_rows in sorted(grouped.items()):
        item: dict[str, Any] = {key: value for key, value in zip(keys, values)}
        item["n"] = len(group_rows)
        for metric in metrics:
            vals = [to_float(row, metric) for row in group_rows]
            item[f"{metric}_mean"] = round(mean(vals), 6)
            item[f"{metric}_sd"] = round(stdev(vals), 6) if len(vals) > 1 else 0.0
        output.append(item)
    return output


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def baseline_improvement(rows: list[dict[str, Any]], key_fields: list[str], baseline: str, target: str, metric: str) -> list[dict[str, Any]]:
    by_group: dict[tuple[str, ...], dict[str, float]] = defaultdict(dict)
    for row in rows:
        key = tuple(str(row[field]) for field in key_fields)
        by_group[key][str(row["method"])] = float(row[f"{metric}_mean"])
    output = []
    for key, values in sorted(by_group.items()):
        if baseline not in values or target not in values:
            continue
        base = values[baseline]
        tgt = values[target]
        item: dict[str, Any] = {field: value for field, value in zip(key_fields, key)}
        item["baseline"] = baseline
        item["target"] = target
        item[f"{metric}_{baseline}"] = round(base, 6)
        item[f"{metric}_{target}"] = round(tgt, 6)
        item["relative_reduction"] = round((base - tgt) / base, 6) if base else 0
        output.append(item)
    return output


def q_sched_sample_configs() -> list[dict[str, Any]]:
    samples = [
        ("m3p0_nb128_rl8_atk0_s20260530", 128, 8, 0.0, 20260530),
        ("m3p0_nb128_rl8_atk1000_s20260530", 128, 8, 1000.0, 20260530),
        ("m3p0_nb1024_rl8_atk10000_s20260603", 1024, 8, 10000.0, 20260603),
    ]
    configs: list[dict[str, Any]] = []
    for run_id, num_bonded, rl_capacity, attack, seed in samples:
        configs.append(
            base_config(
                run_id,
                seed,
                P0_METHODS,
                num_bonded=num_bonded,
                rl_capacity=rl_capacity,
                attack_rpa_rate_per_min=attack,
                write_traces=True,
            )
        )
    return configs


def q_sched_actual() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="m3_q_sched_") as tmp:
        tmp_dir = Path(tmp)
        for config in q_sched_sample_configs():
            run_dir = tmp_dir / config["run_id"]
            run(config, run_dir)
            events = {row["event_id"]: row for row in read_rows(run_dir / "events.csv")}
            decisions = read_rows(run_dir / "decisions.csv")
            warmup_ms = int(config.get("warmup_s", 0)) * 1000
            legit_rpa_ids = {
                event_id
                for event_id, row in events.items()
                if row.get("source_type") == "legit_bonded"
                and row.get("addr_type") == "rpa"
                and int(row.get("ts_ms", "0") or 0) >= warmup_ms
            }
            legit_total = len(legit_rpa_ids)
            by_method: dict[str, list[dict[str, str]]] = defaultdict(list)
            for decision in decisions:
                if decision.get("event_id") in legit_rpa_ids:
                    by_method[decision["method"]].append(decision)

            for method, method_decisions in sorted(by_method.items()):
                action_counts = defaultdict(int)
                deferred = 0
                false_defer = 0
                for decision in method_decisions:
                    action_counts[decision.get("action", "")] += 1
                    if decision.get("deferred") == "True":
                        deferred += 1
                    if decision.get("false_defer") == "True":
                        false_defer += 1

                def rate(count: int) -> float:
                    return round(count / max(1, legit_total), 6)

                rows.append(
                    {
                        "sample_run_id": config["run_id"],
                        "num_bonded": config["num_bonded"],
                        "rl_capacity": config["rl_capacity"],
                        "attack_rpa_rate_per_min": config["attack_rpa_rate_per_min"],
                        "seed": config["seed"],
                        "method": method,
                        "legit_rpa_total": legit_total,
                        "rl_hit_legit": action_counts["rl_hit"],
                        "cache_hit_legit": action_counts["cache_hit"],
                        "host_scan_legit": action_counts["host_scan"],
                        "budget_skip_legit": action_counts["budget_skip"],
                        "defer_legit": action_counts["defer"],
                        "deferred_legit": deferred,
                        "false_defer_legit": false_defer,
                        "rl_hit_legit_rate": rate(action_counts["rl_hit"]),
                        "cache_hit_legit_rate": rate(action_counts["cache_hit"]),
                        "host_scan_legit_rate": rate(action_counts["host_scan"]),
                        "budget_skip_legit_rate": rate(action_counts["budget_skip"]),
                        "defer_legit_rate": rate(action_counts["defer"]),
                        "deferred_legit_rate": rate(deferred),
                        "false_defer_legit_rate": rate(false_defer),
                    }
                )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p0", type=Path, default=Path("sim/rpa_resolution/results/m3_p0/combined_summary.csv"))
    parser.add_argument("--sensitivity", type=Path, default=Path("sim/rpa_resolution/results/m3_sensitivity/combined_summary.csv"))
    parser.add_argument("--ablation", type=Path, default=Path("sim/rpa_resolution/results/m3_ablation/combined_summary.csv"))
    parser.add_argument("--out", type=Path, default=Path("sim/rpa_resolution/figures/m3_paper"))
    args = parser.parse_args()

    p0_rows = read_rows(args.p0)
    sensitivity_rows = read_rows(args.sensitivity)
    ablation_rows = read_rows(args.ablation)

    attack = group_mean(
        p0_rows,
        ["rl_capacity", "attack_rpa_rate_per_min", "method"],
        ["aes_attempts_total", "attack_aes_amplification", "legit_resolution_rate", "false_defer_legit_rate"],
    )
    write_csv(args.out / "fig_attack_aes.csv", attack)

    bonded = group_mean(
        [row for row in p0_rows if row.get("rl_capacity") == "8" and row.get("attack_rpa_rate_per_min") == "0.0"],
        ["num_bonded", "method"],
        ["aes_attempts_total", "aes_attempts_per_legit_resolved", "estimated_energy_uJ"],
    )
    write_csv(args.out / "fig_bonded_scale.csv", bonded)

    capacity = group_mean(
        [row for row in p0_rows if row.get("num_bonded") in ("128", "512")],
        ["num_bonded", "rl_capacity", "attack_rpa_rate_per_min", "method"],
        ["aes_attempts_total", "sram_bytes"],
    )
    write_csv(args.out / "fig_rl_capacity.csv", capacity)

    ablation = group_mean(
        ablation_rows,
        ["attack_rpa_rate_per_min", "background_rpa_rate_per_min", "method"],
        ["aes_attempts_total", "attack_aes_amplification", "false_defer_legit_rate", "legit_resolution_rate"],
    )
    write_csv(args.out / "fig_ablation.csv", ablation)

    correctness = group_mean(
        p0_rows + ablation_rows,
        ["suite", "method"],
        ["legit_resolution_rate", "false_defer_legit_rate", "p95_resolution_delay_ms"],
    )
    write_csv(args.out / "table_correctness.csv", correctness)

    overhead = group_mean(
        p0_rows,
        ["method"],
        ["estimated_energy_uJ", "sram_bytes", "aes_attempts_total"],
    )
    write_csv(args.out / "table_overhead.csv", overhead)

    sensitivity = group_mean(
        sensitivity_rows,
        ["background_rpa_rate_per_min", "active_skew", "rpa_rotation_interval_min", "rssi_noise_db", "method"],
        ["aes_attempts_total", "legit_resolution_rate", "false_defer_legit_rate"],
    )
    write_csv(args.out / "table_sensitivity.csv", sensitivity)

    attack_improvement = baseline_improvement(
        [row for row in attack if str(row.get("rl_capacity")) == "8"],
        ["attack_rpa_rate_per_min"],
        "StaticRL",
        "P3-NoPersist",
        "attack_aes_amplification",
    )
    write_csv(args.out / "summary_p3_vs_staticrl_attack.csv", attack_improvement)

    write_csv(args.out / "table_q_sched_actual.csv", q_sched_actual())

    manifest = {
        "p0_rows": len(p0_rows),
        "sensitivity_rows": len(sensitivity_rows),
        "ablation_rows": len(ablation_rows),
        "headline_rl_capacity": 8,
        "bonded_scale_rl_capacity": 8,
        "outputs": sorted(path.name for path in args.out.glob("*.csv")),
    }
    with (args.out / "analysis_manifest.json").open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
