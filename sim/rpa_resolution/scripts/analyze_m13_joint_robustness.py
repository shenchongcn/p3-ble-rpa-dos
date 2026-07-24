#!/usr/bin/env python3
"""Audit and analyze the 20-seed M13 joint-robustness suite."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from analyze_m10_stats import t_critical_975  # noqa: E402
from review260715_suite_common import validate_completed_run  # noqa: E402


METHODS = ["P3-Persist", "P3-NoPersist", "BudgetDoS"]
SEEDS = [str(seed) for seed in range(20260610, 20260630)]
CAP_AES_PER_MIN = 151200.0
PRACTICAL_DEGRADATION = 0.05
BASELINE_CELL = ("15", "0.0", "100.0")
WORST_CELL = ("1", "0.4", "5000.0")
SUMMARY_METRICS = [
    "offered_legit_resolution_rate",
    "observed_legit_resolution_rate",
    "false_defer_observed_legit_rate",
    "p95_resolution_delay_ms",
    "p99_resolution_delay_ms",
    "reserve_grant_legit_p95_delay_ms",
    "reserve_grant_legit_p99_delay_ms",
    "attack_aes_amplification",
    "actual_observation_loss_rate",
    "reserve_grant_legit_count",
    "reserve_grant_background_count",
    "reserve_grant_attack_count",
    "budget_skip_legit_count",
    "budget_skip_background_count",
    "budget_skip_attack_count",
]
EVENT_COUNT_FIELDS = [
    "generated_event_count",
    "observed_event_count",
    "dropped_event_count",
    "generated_legit_event_count",
    "observed_legit_event_count",
    "dropped_legit_event_count",
    "generated_background_event_count",
    "observed_background_event_count",
    "dropped_background_event_count",
    "generated_attack_event_count",
    "observed_attack_event_count",
    "dropped_attack_event_count",
]


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


def summary(values: list[float]) -> dict[str, Any]:
    n = len(values)
    avg = mean(values)
    sd = stdev(values) if n > 1 else 0.0
    half = t_critical_975(n - 1) * sd / (n ** 0.5) if n > 1 else 0.0
    return {
        "n": n,
        "mean": round(avg, 6),
        "sd": round(sd, 6),
        "ci95_low": round(avg - half, 6),
        "ci95_high": round(avg + half, 6),
    }


def grouped_statistics(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
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
        grouped[tuple(row[key] for key in keys)].append(row)
    output: list[dict[str, Any]] = []
    for group_key, group_rows in sorted(grouped.items()):
        item: dict[str, Any] = dict(zip(keys, group_key))
        item["n"] = len(group_rows)
        for metric in SUMMARY_METRICS:
            stats = summary([float(row[metric]) for row in group_rows])
            for name in ["mean", "sd", "ci95_low", "ci95_high"]:
                item[f"{metric}_{name}"] = stats[name]
        output.append(item)
    return output


def service_degradation(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    main = [
        row
        for row in rows
        if row["m13_experiment"] == "main" and row["method"] == "P3-Persist"
    ]
    baseline = {
        row["seed"]: row
        for row in main
        if (row["m13_epoch_min"], row["m13_loss_rate"], row["m13_density"])
        == BASELINE_CELL
    }
    if set(baseline) != set(SEEDS):
        raise RuntimeError("M13 baseline does not contain the frozen 20 seeds")
    grouped: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in main:
        grouped[(row["m13_epoch_min"], row["m13_loss_rate"], row["m13_density"])].append(row)
    output: list[dict[str, Any]] = []
    baseline_mean = mean(float(row["offered_legit_resolution_rate"]) for row in baseline.values())
    for cell, group_rows in sorted(
        grouped.items(), key=lambda item: tuple(float(value) for value in item[0])
    ):
        by_seed = {row["seed"]: row for row in group_rows}
        if set(by_seed) != set(SEEDS):
            raise RuntimeError(f"M13 cell {cell} does not contain the frozen 20 seeds")
        offered = [float(by_seed[seed]["offered_legit_resolution_rate"]) for seed in SEEDS]
        observed = [float(by_seed[seed]["observed_legit_resolution_rate"]) for seed in SEEDS]
        degradation = [
            float(baseline[seed]["offered_legit_resolution_rate"])
            - float(by_seed[seed]["offered_legit_resolution_rate"])
            for seed in SEEDS
        ]
        degradation_stats = summary(degradation)
        output.append(
            {
                "epoch_min": cell[0],
                "loss_rate": cell[1],
                "benign_density_rpa_per_min": cell[2],
                "n": len(group_rows),
                "baseline_offered_rate_mean": round(baseline_mean, 6),
                "offered_rate_mean": round(mean(offered), 6),
                "observed_rate_mean": round(mean(observed), 6),
                "paired_offered_degradation_mean": degradation_stats["mean"],
                "paired_offered_degradation_sd": degradation_stats["sd"],
                "paired_offered_degradation_ci95_low": degradation_stats["ci95_low"],
                "paired_offered_degradation_ci95_high": degradation_stats["ci95_high"],
                "practical_screen_threshold": PRACTICAL_DEGRADATION,
                "crosses_practical_screen": str(
                    float(degradation_stats["mean"]) >= PRACTICAL_DEGRADATION
                ),
                "false_defer_observed_mean": round(
                    mean(float(row["false_defer_observed_legit_rate"]) for row in group_rows), 6
                ),
                "attack_aes_per_min_mean": round(
                    mean(float(row["attack_aes_amplification"]) for row in group_rows), 6
                ),
            }
        )
    return output


def method_contrasts(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    main = [row for row in rows if row["m13_experiment"] == "main"]
    indexed = {
        (
            row["m13_epoch_min"],
            row["m13_loss_rate"],
            row["m13_density"],
            row["seed"],
            row["method"],
        ): row
        for row in main
    }
    output: list[dict[str, Any]] = []
    for epoch in ["1", "5", "15"]:
        for loss in ["0.0", "0.2", "0.4"]:
            for density in ["100.0", "1000.0", "5000.0"]:
                for comparator in ["P3-NoPersist", "BudgetDoS"]:
                    for metric in [
                        "offered_legit_resolution_rate",
                        "observed_legit_resolution_rate",
                        "false_defer_observed_legit_rate",
                        "attack_aes_amplification",
                    ]:
                        diffs = [
                            float(indexed[(epoch, loss, density, seed, "P3-Persist")][metric])
                            - float(indexed[(epoch, loss, density, seed, comparator)][metric])
                            for seed in SEEDS
                        ]
                        stats = summary(diffs)
                        output.append(
                            {
                                "epoch_min": epoch,
                                "loss_rate": loss,
                                "benign_density_rpa_per_min": density,
                                "contrast": f"P3-Persist_minus_{comparator}",
                                "metric": metric,
                                **stats,
                            }
                        )
    return output


def control_contrasts(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    p3 = [row for row in rows if row["method"] == "P3-Persist"]
    indexed = {
        (
            row["m13_experiment"],
            row["m13_epoch_min"],
            row["m13_loss_rate"],
            row["m13_density"],
            row["seed"],
        ): row
        for row in p3
    }
    contrasts = [
        (
            "attack_minus_no_attack_baseline",
            ("main", *BASELINE_CELL),
            ("control_no_attack_baseline", *BASELINE_CELL),
        ),
        (
            "attack_minus_no_attack_worst_unique",
            ("main", *WORST_CELL),
            ("control_no_attack_worst", *WORST_CELL),
        ),
        (
            "repeated_minus_unique_worst_under_attack",
            ("control_repeated_benign_worst", *WORST_CELL),
            ("main", *WORST_CELL),
        ),
    ]
    metrics = [
        "offered_legit_resolution_rate",
        "observed_legit_resolution_rate",
        "false_defer_observed_legit_rate",
        "attack_aes_amplification",
        "reserve_grant_background_count",
    ]
    output: list[dict[str, Any]] = []
    for label, first, second in contrasts:
        for metric in metrics:
            diffs = [
                float(indexed[(*first, seed)][metric]) - float(indexed[(*second, seed)][metric])
                for seed in SEEDS
            ]
            output.append({"contrast": label, "metric": metric, **summary(diffs)})
    return output


def audit(
    rows: list[dict[str, str]],
    result_dir: Path,
    config_dir: Path,
) -> tuple[list[dict[str, Any]], list[str]]:
    checks: list[dict[str, Any]] = []

    def add(name: str, passed: bool, observed: Any, expected: Any, details: str = "") -> None:
        checks.append(
            {
                "check": name,
                "pass": str(bool(passed)),
                "observed": str(observed),
                "expected": str(expected),
                "details": details,
            }
        )

    config_paths = sorted(config_dir.glob("*.json"))
    configs = [json.loads(path.read_text(encoding="utf-8")) for path in config_paths]
    run_dirs = sorted(path for path in (result_dir / "runs").iterdir() if path.is_dir())
    add("config_count", len(configs) == 600, len(configs), 600)
    add("run_directory_count", len(run_dirs) == 600, len(run_dirs), 600)
    add("combined_summary_rows", len(rows) == 1800, len(rows), 1800)

    invalid: list[str] = []
    commits: set[str] = set()
    for config in configs:
        run_dir = result_dir / "runs" / str(config["run_id"])
        check = validate_completed_run(config, run_dir)
        if not check.complete:
            invalid.append(f"{config['run_id']}:{check.reason}")
        manifest = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
        commits.add(str(manifest.get("git_commit", "")))
    add("completion_manifest_validation", not invalid, len(invalid), 0, ";".join(invalid[:5]))

    by_run: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_run[row["run_id"]].append(row)
    method_failures = [
        run_id
        for run_id, group in by_run.items()
        if [row["method"] for row in group] != METHODS
    ]
    add("method_rows_per_run", not method_failures, len(method_failures), 0)

    main_groups: dict[tuple[str, str, str, str], int] = defaultdict(int)
    control_groups: dict[tuple[str, str], int] = defaultdict(int)
    for row in rows:
        if row["m13_experiment"] == "main":
            main_groups[(row["m13_epoch_min"], row["m13_loss_rate"], row["m13_density"], row["method"])] += 1
        else:
            control_groups[(row["m13_experiment"], row["method"])] += 1
    add(
        "main_cell_method_counts",
        len(main_groups) == 81 and set(main_groups.values()) == {20},
        f"groups={len(main_groups)},n={sorted(set(main_groups.values()))}",
        "81 groups, n=20",
    )
    add(
        "control_method_counts",
        len(control_groups) == 9 and set(control_groups.values()) == {20},
        f"groups={len(control_groups)},n={sorted(set(control_groups.values()))}",
        "9 groups, n=20",
    )

    total_closure_failures = 0
    source_closure_failures = 0
    other_closure_failures = 0
    denom_errors: list[float] = []
    loss_errors: list[float] = []
    for row in rows:
        generated = int(row["generated_event_count"])
        observed = int(row["observed_event_count"])
        dropped = int(row["dropped_event_count"])
        total_closure_failures += int(generated != observed + dropped)
        for source in ["legit", "background", "attack"]:
            source_generated = int(row[f"generated_{source}_event_count"])
            source_observed = int(row[f"observed_{source}_event_count"])
            source_dropped = int(row[f"dropped_{source}_event_count"])
            source_closure_failures += int(source_generated != source_observed + source_dropped)
        classified_generated = sum(int(row[f"generated_{source}_event_count"]) for source in ["legit", "background", "attack"])
        classified_observed = sum(int(row[f"observed_{source}_event_count"]) for source in ["legit", "background", "attack"])
        classified_dropped = sum(int(row[f"dropped_{source}_event_count"]) for source in ["legit", "background", "attack"])
        other_closure_failures += int(
            generated - classified_generated
            != (observed - classified_observed) + (dropped - classified_dropped)
        )
        generated_legit = int(row["generated_legit_event_count"])
        observed_legit = int(row["observed_legit_event_count"])
        expected_offered = (
            float(row["observed_legit_resolution_rate"]) * observed_legit / generated_legit
        )
        denom_errors.append(abs(float(row["offered_legit_resolution_rate"]) - expected_offered))
        loss_errors.append(abs(float(row["actual_observation_loss_rate"]) - float(row["m13_loss_rate"])))
    add("overall_generated_observed_dropped_closure", total_closure_failures == 0, total_closure_failures, 0)
    add("per_source_generated_observed_dropped_closure", source_closure_failures == 0, source_closure_failures, 0)
    add("other_event_class_closure", other_closure_failures == 0, other_closure_failures, 0)
    add("double_denominator_identity", max(denom_errors) <= 1e-6, max(denom_errors), "<=1e-6")
    add("requested_vs_actual_loss", max(loss_errors) <= 0.005, max(loss_errors), "<=0.005")

    invariant_failures = 0
    for group in by_run.values():
        signatures = {tuple(row[field] for field in EVENT_COUNT_FIELDS) for row in group}
        invariant_failures += int(len(signatures) != 1)
    add("event_counts_invariant_across_methods", invariant_failures == 0, invariant_failures, 0)

    main_p3 = [
        row
        for row in rows
        if row["m13_experiment"] == "main" and row["method"] == "P3-Persist"
    ]
    work_violations = [
        row for row in main_p3 if float(row["attack_aes_amplification"]) > CAP_AES_PER_MIN
    ]
    add(
        "p3_attack_work_cap",
        not work_violations,
        max(float(row["attack_aes_amplification"]) for row in main_p3),
        f"<={CAP_AES_PER_MIN}",
    )
    simulator_path = "sim/rpa_resolution/src/rpa_sim.py"
    simulator_hashes = {
        hashlib.sha256(
            subprocess.check_output(["git", "show", f"{commit}:{simulator_path}"])
        ).hexdigest()
        for commit in commits
    }
    current_simulator_hash = sha256(Path(simulator_path))
    add(
        "simulator_source_hash_invariant_across_run_commits",
        simulator_hashes == {current_simulator_hash},
        ",".join(sorted(simulator_hashes)),
        current_simulator_hash,
    )
    add("source_commit_set", True, ",".join(sorted(commits)), "recorded per run")
    return checks, sorted(commits)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--results",
        type=Path,
        default=Path("sim/rpa_resolution/results/m13_joint_robustness"),
    )
    parser.add_argument(
        "--configs",
        type=Path,
        default=Path("sim/rpa_resolution/configs/m13/joint_robustness"),
    )
    args = parser.parse_args()
    combined_path = args.results / "combined_summary.csv"
    rows = read_csv(combined_path)

    audit_rows, source_commits = audit(rows, args.results, args.configs)
    if any(row["pass"] != "True" for row in audit_rows):
        failures = [row["check"] for row in audit_rows if row["pass"] != "True"]
        raise RuntimeError(f"M13 audit failures: {failures}")

    cell_stats = grouped_statistics(rows)
    degradation = service_degradation(rows)
    method_rows = method_contrasts(rows)
    control_rows = control_contrasts(rows)
    heatmap_rows = [
        {
            "epoch_min": row["epoch_min"],
            "loss_rate": row["loss_rate"],
            "benign_density_rpa_per_min": row["benign_density_rpa_per_min"],
            "offered_legit_resolution_rate": row["offered_rate_mean"],
            "observed_legit_resolution_rate": row["observed_rate_mean"],
            "paired_offered_degradation": row["paired_offered_degradation_mean"],
            "false_defer_observed_legit_rate": row["false_defer_observed_mean"],
            "attack_aes_per_min": row["attack_aes_per_min_mean"],
            "crosses_practical_screen": row["crosses_practical_screen"],
        }
        for row in degradation
    ]

    output_paths = {
        "audit": args.results / "audit_m13_closure.csv",
        "cell_statistics": args.results / "table_m13_cell_statistics.csv",
        "service_degradation": args.results / "table_m13_service_degradation.csv",
        "method_contrasts": args.results / "table_m13_method_contrasts.csv",
        "control_contrasts": args.results / "table_m13_control_contrasts.csv",
        "heatmap_source": args.results / "heatmap_m13_p3_persist_service.csv",
    }
    write_csv(output_paths["audit"], audit_rows)
    write_csv(output_paths["cell_statistics"], cell_stats)
    write_csv(output_paths["service_degradation"], degradation)
    write_csv(output_paths["method_contrasts"], method_rows)
    write_csv(output_paths["control_contrasts"], control_rows)
    write_csv(output_paths["heatmap_source"], heatmap_rows)

    git_commit = subprocess.check_output(
        ["git", "rev-parse", "--short=8", "HEAD"], text=True
    ).strip()
    source_paths = [
        Path("sim/rpa_resolution/src/rpa_sim.py"),
        Path("sim/rpa_resolution/scripts/run_m13_joint_robustness.py"),
        Path("sim/rpa_resolution/scripts/analyze_m13_joint_robustness.py"),
        Path("sim/rpa_resolution/scripts/analyze_m10_stats.py"),
        Path("sim/rpa_resolution/scripts/review260715_suite_common.py"),
    ]
    screen_count = sum(row["crosses_practical_screen"] == "True" for row in degradation)
    worst_three = sorted(degradation, key=lambda row: float(row["offered_rate_mean"]))[:3]
    manifest = {
        "suite": "m13_joint_robustness_analysis",
        "analysis_commit": git_commit,
        "run_source_commits": source_commits,
        "audit_pass": True,
        "config_count": 600,
        "method_result_row_count": len(rows),
        "main_cell_count": 27,
        "seed_count_per_cell": 20,
        "practical_degradation_threshold": PRACTICAL_DEGRADATION,
        "practical_screen_crossing_cell_count": screen_count,
        "worst_three_cells": [
            {
                "epoch_min": row["epoch_min"],
                "loss_rate": row["loss_rate"],
                "density": row["benign_density_rpa_per_min"],
                "offered_rate_mean": row["offered_rate_mean"],
            }
            for row in worst_three
        ],
        "source_sha256": {str(path): sha256(path) for path in source_paths},
        "output_sha256": {name: sha256(path) for name, path in output_paths.items()},
    }
    write_json(args.results / "analysis_manifest.json", manifest)


if __name__ == "__main__":
    main()
