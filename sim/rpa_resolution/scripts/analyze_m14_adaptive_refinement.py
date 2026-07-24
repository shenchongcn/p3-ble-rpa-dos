#!/usr/bin/env python3
"""Audit and analyze the completed M14 adaptive refinement."""

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
from run_m14_adaptive_refinement import (  # noqa: E402
    CAP_AES_PER_MIN,
    CONFIRM_SEEDS,
    SCREEN_SEEDS,
    confirm_configs,
    confirm_strategies,
    select_top5,
)


TOP5 = {
    "pool320_r1_p75",
    "pool320_r1_p90",
    "pool320_r1_p105",
    "pool320_r1_p120",
    "pool320_r1_p135",
}
HISTORICAL_WORST = "pool256_r1_p120"
METRICS = [
    "attack_aes_amplification",
    "legit_resolution_rate",
    "false_defer_legit_rate",
    "reserve_grant_attack_count",
    "duplicate_filter_attack_count",
    "dup_removable_fraction",
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


def stats(values: list[float]) -> dict[str, Any]:
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


def audit_phase(
    phase: str,
    configs_dir: Path,
    results_dir: Path,
    combined: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], set[str]]:
    checks: list[dict[str, Any]] = []

    def add(name: str, passed: bool, observed: Any, expected: Any) -> None:
        checks.append(
            {
                "phase": phase,
                "check": name,
                "pass": str(bool(passed)),
                "observed": str(observed),
                "expected": str(expected),
            }
        )

    config_paths = sorted(configs_dir.glob("*.json"))
    configs = [json.loads(path.read_text(encoding="utf-8")) for path in config_paths]
    expected_configs = 840 if phase == "screen" else 440
    expected_rows = 840 if phase == "screen" else 640
    add("config_count", len(configs) == expected_configs, len(configs), expected_configs)
    add("combined_rows", len(combined) == expected_rows, len(combined), expected_rows)

    invalid: list[str] = []
    commits: set[str] = set()
    for config in configs:
        run_dir = results_dir / "runs" / str(config["run_id"])
        completion = validate_completed_run(config, run_dir)
        if not completion.complete:
            invalid.append(f"{config['run_id']}:{completion.reason}")
        manifest = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
        commits.add(str(manifest["git_commit"]))
    add("completion_validation", not invalid, len(invalid), 0)

    if phase == "screen":
        grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in combined:
            grouped[row["attack_strategy"]].append(row)
        add(
            "strategy_seed_counts",
            len(grouped) == 168 and {len(rows) for rows in grouped.values()} == {5},
            f"strategies={len(grouped)},n={sorted({len(rows) for rows in grouped.values()})}",
            "168 strategies,n=5",
        )
        add(
            "p3_only",
            {row["method"] for row in combined} == {"P3-Persist"},
            sorted({row["method"] for row in combined}),
            ["P3-Persist"],
        )
        add(
            "duplicate_filter_60_only",
            {row["duplicate_filter_window_s"] for row in combined} == {"60"},
            sorted({row["duplicate_filter_window_s"] for row in combined}),
            ["60"],
        )
    else:
        p3_groups: dict[tuple[str, str], int] = defaultdict(int)
        budget_groups: dict[tuple[str, str], int] = defaultdict(int)
        scope_failures = 0
        for row in combined:
            key = (row["attack_strategy"], row["duplicate_filter_window_s"])
            if row["method"] == "P3-Persist":
                p3_groups[key] += 1
            elif row["method"] == "BudgetDoS":
                budget_groups[key] += 1
                scope_failures += int(row["attack_strategy"] not in TOP5)
            else:
                scope_failures += 1
        add(
            "p3_strategy_delta_seed_counts",
            len(p3_groups) == 22 and set(p3_groups.values()) == {20},
            f"groups={len(p3_groups)},n={sorted(set(p3_groups.values()))}",
            "22 groups,n=20",
        )
        add(
            "budget_top5_delta_seed_counts",
            len(budget_groups) == 10 and set(budget_groups.values()) == {20},
            f"groups={len(budget_groups)},n={sorted(set(budget_groups.values()))}",
            "10 groups,n=20",
        )
        add("budget_scope", scope_failures == 0, scope_failures, 0)
    return checks, commits


def confirmed_ranking(table_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for delta in ["0", "60"]:
        p3 = [
            row
            for row in table_rows
            if row["method"] == "P3-Persist" and row["duplicate_filter_window_s"] == delta
        ]
        p3.sort(
            key=lambda row: (
                -float(row["attack_aes_amplification_mean"]),
                row["attack_strategy"],
            )
        )
        for rank, row in enumerate(p3, 1):
            output.append(
                {
                    "duplicate_filter_window_s": delta,
                    "rank": rank,
                    "attack_strategy": row["attack_strategy"],
                    "n": row["n"],
                    "attack_aes_amplification_mean": row["attack_aes_amplification_mean"],
                    "attack_aes_amplification_ci95_low": row["attack_aes_amplification_ci95_low"],
                    "attack_aes_amplification_ci95_high": row["attack_aes_amplification_ci95_high"],
                    "mean_over_cap": round(
                        float(row["attack_aes_amplification_mean"]) / CAP_AES_PER_MIN, 6
                    ),
                    "cap_headroom_mean": round(
                        CAP_AES_PER_MIN - float(row["attack_aes_amplification_mean"]), 6
                    ),
                    "legit_resolution_rate_mean": row["legit_resolution_rate_mean"],
                    "false_defer_legit_rate_mean": row["false_defer_legit_rate_mean"],
                    "dup_removable_fraction_mean": row["dup_removable_fraction_mean"],
                    "reserve_grant_attack_count_mean": row["reserve_grant_attack_count_mean"],
                }
            )
    return output


def paired_method_contrasts(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    indexed = {
        (row["attack_strategy"], row["duplicate_filter_window_s"], row["seed"], row["method"]): row
        for row in rows
    }
    output: list[dict[str, Any]] = []
    for strategy in sorted(TOP5):
        for delta in ["0", "60"]:
            for metric in METRICS:
                diffs = [
                    float(indexed[(strategy, delta, str(seed), "P3-Persist")][metric])
                    - float(indexed[(strategy, delta, str(seed), "BudgetDoS")][metric])
                    for seed in CONFIRM_SEEDS
                ]
                output.append(
                    {
                        "attack_strategy": strategy,
                        "duplicate_filter_window_s": delta,
                        "contrast": "P3-Persist_minus_BudgetDoS",
                        "metric": metric,
                        **stats(diffs),
                    }
                )
    return output


def duplicate_filter_effects(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    p3 = [row for row in rows if row["method"] == "P3-Persist"]
    indexed = {
        (row["attack_strategy"], row["duplicate_filter_window_s"], row["seed"]): row
        for row in p3
    }
    strategies = sorted({row["attack_strategy"] for row in p3})
    output: list[dict[str, Any]] = []
    for strategy in strategies:
        for metric in METRICS:
            diffs = [
                float(indexed[(strategy, "60", str(seed))][metric])
                - float(indexed[(strategy, "0", str(seed))][metric])
                for seed in CONFIRM_SEEDS
            ]
            output.append(
                {
                    "attack_strategy": strategy,
                    "contrast": "dup60_minus_dup0",
                    "metric": metric,
                    **stats(diffs),
                }
            )
    return output


def repetition_effects(screen_table: list[dict[str, str]]) -> list[dict[str, Any]]:
    by_r: dict[int, list[float]] = defaultdict(list)
    cells: dict[tuple[str, str], dict[int, float]] = defaultdict(dict)
    for row in screen_table:
        repeat = int(row["attack_repeats_per_addr"])
        amp = float(row["attack_aes_amplification_mean"])
        by_r[repeat].append(amp)
        cells[(row["attack_addr_pool_size"], row["attack_repeat_interval_s"])][repeat] = amp
    output: list[dict[str, Any]] = []
    for repeat in [1, 2, 4]:
        values = by_r[repeat]
        output.append(
            {
                "analysis": "marginal_by_r",
                "contrast": f"r={repeat}",
                "n_cells": len(values),
                "mean_aes_per_min": round(mean(values), 6),
                "min_aes_per_min": round(min(values), 6),
                "max_aes_per_min": round(max(values), 6),
            }
        )
    for first, second in [(1, 2), (2, 4), (1, 4)]:
        diffs = [values[first] - values[second] for values in cells.values()]
        output.append(
            {
                "analysis": "matched_cell_difference",
                "contrast": f"r{first}_minus_r{second}",
                "n_cells": len(diffs),
                "mean_aes_per_min": round(mean(diffs), 6),
                "min_aes_per_min": round(min(diffs), 6),
                "max_aes_per_min": round(max(diffs), 6),
            }
        )
    return output


def cap_audit(rows: list[dict[str, str]], ranking: list[dict[str, Any]]) -> list[dict[str, Any]]:
    p3 = [row for row in rows if row["method"] == "P3-Persist"]
    max_row = max(p3, key=lambda row: float(row["attack_aes_amplification"]))
    worst_mean = next(
        row
        for row in ranking
        if row["duplicate_filter_window_s"] == "60" and row["rank"] == 1
    )
    old_mean = next(
        row
        for row in ranking
        if row["duplicate_filter_window_s"] == "60"
        and row["attack_strategy"] == HISTORICAL_WORST
    )
    return [
        {
            "check": "confirmed_worst_mean",
            "strategy": worst_mean["attack_strategy"],
            "value_aes_per_min": worst_mean["attack_aes_amplification_mean"],
            "cap_aes_per_min": CAP_AES_PER_MIN,
            "value_over_cap": worst_mean["mean_over_cap"],
            "cap_headroom": worst_mean["cap_headroom_mean"],
            "pass": str(float(worst_mean["attack_aes_amplification_mean"]) <= CAP_AES_PER_MIN),
        },
        {
            "check": "maximum_single_seed",
            "strategy": max_row["attack_strategy"],
            "value_aes_per_min": max_row["attack_aes_amplification"],
            "cap_aes_per_min": CAP_AES_PER_MIN,
            "value_over_cap": round(float(max_row["attack_aes_amplification"]) / CAP_AES_PER_MIN, 6),
            "cap_headroom": round(CAP_AES_PER_MIN - float(max_row["attack_aes_amplification"]), 6),
            "pass": str(float(max_row["attack_aes_amplification"]) <= CAP_AES_PER_MIN),
        },
        {
            "check": "new_minus_historical_worst_mean",
            "strategy": f"{worst_mean['attack_strategy']}_minus_{HISTORICAL_WORST}",
            "value_aes_per_min": round(
                float(worst_mean["attack_aes_amplification_mean"])
                - float(old_mean["attack_aes_amplification_mean"]),
                6,
            ),
            "cap_aes_per_min": CAP_AES_PER_MIN,
            "value_over_cap": "",
            "cap_headroom": "",
            "pass": "True",
        },
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
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
    screen_dir = args.root / "screen"
    confirm_dir = args.root / "confirm"
    screen_rows = read_csv(screen_dir / "combined_summary.csv")
    screen_table = read_csv(screen_dir / "table_m14_local_screen.csv")
    confirm_rows = read_csv(confirm_dir / "combined_summary.csv")
    confirm_table = read_csv(confirm_dir / "table_m14_confirmed_best_response.csv")

    audit_rows: list[dict[str, Any]] = []
    screen_checks, screen_commits = audit_phase(
        "screen", args.config_root / "screen", screen_dir, screen_rows
    )
    confirm_checks, confirm_commits = audit_phase(
        "confirm", args.config_root / "confirm", confirm_dir, confirm_rows
    )
    audit_rows.extend(screen_checks)
    audit_rows.extend(confirm_checks)

    selected = select_top5(screen_table)
    selected_names = {row["attack_strategy"] for row in selected}
    strategies, top5_names = confirm_strategies(selected)
    expected_confirm = confirm_configs(strategies, top5_names)
    audit_rows.append(
        {
            "phase": "cross_phase",
            "check": "top5_matches_frozen_selection",
            "pass": str(selected_names == TOP5),
            "observed": ",".join(sorted(selected_names)),
            "expected": ",".join(sorted(TOP5)),
        }
    )
    audit_rows.append(
        {
            "phase": "cross_phase",
            "check": "confirmation_config_regeneration",
            "pass": str(len(expected_confirm) == 440),
            "observed": len(expected_confirm),
            "expected": 440,
        }
    )
    all_commits = screen_commits | confirm_commits
    simulator_path = "sim/rpa_resolution/src/rpa_sim.py"
    simulator_hashes = {
        hashlib.sha256(
            subprocess.check_output(["git", "show", f"{commit}:{simulator_path}"])
        ).hexdigest()
        for commit in all_commits
    }
    current_hash = sha256(Path(simulator_path))
    audit_rows.append(
        {
            "phase": "cross_phase",
            "check": "simulator_hash_invariant",
            "pass": str(simulator_hashes == {current_hash}),
            "observed": ",".join(sorted(simulator_hashes)),
            "expected": current_hash,
        }
    )
    if any(row["pass"] != "True" for row in audit_rows):
        raise RuntimeError(
            f"M14 audit failures: {[row['check'] for row in audit_rows if row['pass'] != 'True']}"
        )

    ranking = confirmed_ranking(confirm_table)
    method_rows = paired_method_contrasts(confirm_rows)
    dup_rows = duplicate_filter_effects(confirm_rows)
    r_rows = repetition_effects(screen_table)
    cap_rows = cap_audit(confirm_rows, ranking)
    output_paths = {
        "audit": args.root / "audit_m14_closure.csv",
        "ranking": confirm_dir / "table_m14_confirmed_ranking.csv",
        "method_contrasts": confirm_dir / "table_m14_paired_method_contrasts.csv",
        "duplicate_filter_effects": confirm_dir / "table_m14_duplicate_filter_effects.csv",
        "repetition_effects": screen_dir / "table_m14_repetition_effects.csv",
        "cap_audit": confirm_dir / "table_m14_cap_audit.csv",
    }
    write_csv(output_paths["audit"], audit_rows)
    write_csv(output_paths["ranking"], ranking)
    write_csv(output_paths["method_contrasts"], method_rows)
    write_csv(output_paths["duplicate_filter_effects"], dup_rows)
    write_csv(output_paths["repetition_effects"], r_rows)
    write_csv(output_paths["cap_audit"], cap_rows)

    source_paths = [
        Path("sim/rpa_resolution/src/rpa_sim.py"),
        Path("sim/rpa_resolution/scripts/run_m14_adaptive_refinement.py"),
        Path("sim/rpa_resolution/scripts/analyze_m14_adaptive_refinement.py"),
        Path("sim/rpa_resolution/scripts/analyze_m10_stats.py"),
        Path("sim/rpa_resolution/scripts/review260715_suite_common.py"),
    ]
    write_json(
        args.root / "analysis_manifest.json",
        {
            "suite": "m14_adaptive_refinement_analysis",
            "analysis_commit": subprocess.check_output(
                ["git", "rev-parse", "--short=8", "HEAD"], text=True
            ).strip(),
            "run_source_commits": sorted(all_commits),
            "audit_pass": True,
            "screen_config_count": 840,
            "confirm_config_count": 440,
            "confirm_method_row_count": 640,
            "top5": sorted(TOP5),
            "cap_aes_per_min": CAP_AES_PER_MIN,
            "source_sha256": {str(path): sha256(path) for path in source_paths},
            "output_sha256": {name: sha256(path) for name, path in output_paths.items()},
        },
    )


if __name__ == "__main__":
    main()
