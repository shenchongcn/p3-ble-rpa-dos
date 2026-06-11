#!/usr/bin/env python3
"""Analyze the 20-seed persistence statistical extension."""

from __future__ import annotations

import argparse
import csv
import math
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev
from typing import Any


METRICS = ["attack_aes_amplification", "legit_resolution_rate", "false_defer_legit_rate"]
CAP_AES_PER_MIN = 151200.0


def read_rows(path: Path) -> list[dict[str, str]]:
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


def betacf(a: float, b: float, x: float) -> float:
    max_iter = 200
    eps = 3e-14
    fpmin = 1e-300
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < fpmin:
        d = fpmin
    d = 1.0 / d
    h = d
    for m in range(1, max_iter + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return h


def betai(a: float, b: float, x: float) -> float:
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    bt = math.exp(math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * betacf(a, b, x) / a
    return 1.0 - bt * betacf(b, a, 1.0 - x) / b


def t_cdf(t_value: float, df: int) -> float:
    x = df / (df + t_value * t_value)
    ib = betai(df / 2.0, 0.5, x)
    if t_value >= 0:
        return 1.0 - 0.5 * ib
    return 0.5 * ib


def t_p_two_sided(t_value: float, df: int) -> float:
    return max(0.0, min(1.0, 2.0 * (1.0 - t_cdf(abs(t_value), df))))


def format_p(value: float) -> str:
    if value <= 0.0:
        return "<1e-12"
    return f"{value:.6g}"


def t_critical_975(df: int) -> float:
    lo, hi = 0.0, 10.0
    for _ in range(80):
        mid = (lo + hi) / 2.0
        if t_cdf(mid, df) < 0.975:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def wilcoxon_p_approx(diffs: list[float]) -> float:
    nonzero = [d for d in diffs if abs(d) > 1e-15]
    n = len(nonzero)
    if n == 0:
        return 1.0
    ranked = sorted((abs(d), d) for d in nonzero)
    ranks: list[tuple[float, float]] = []
    i = 0
    while i < n:
        j = i + 1
        while j < n and abs(ranked[j][0] - ranked[i][0]) < 1e-15:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks.append((avg_rank, ranked[k][1]))
        i = j
    w_plus = sum(rank for rank, diff in ranks if diff > 0)
    mean_w = n * (n + 1) / 4.0
    var_w = n * (n + 1) * (2 * n + 1) / 24.0
    z = (abs(w_plus - mean_w) - 0.5) / math.sqrt(var_w)
    return math.erfc(abs(z) / math.sqrt(2.0))


def summarize(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    keys = [
        "m10_experiment",
        "m10_scenario",
        "attack_rpa_rate_per_min",
        "unique_attack_rpa",
        "duplicate_filter_window_s",
        "persist_reserve",
        "persist_k",
        "method",
    ]
    grouped: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[tuple(row.get(key, "") for key in keys)].append(row)

    output: list[dict[str, Any]] = []
    for values, group_rows in sorted(grouped.items()):
        item: dict[str, Any] = {key: value for key, value in zip(keys, values)}
        n = len(group_rows)
        item["n"] = n
        tcrit = t_critical_975(n - 1) if n > 1 else 0.0
        for metric in METRICS:
            vals = [float(row[metric]) for row in group_rows]
            avg = mean(vals)
            sd = stdev(vals) if n > 1 else 0.0
            half = tcrit * sd / math.sqrt(n) if n > 1 else 0.0
            item[f"{metric}_mean"] = round(avg, 6)
            item[f"{metric}_sd"] = round(sd, 6)
            item[f"{metric}_ci95_low"] = round(avg - half, 6)
            item[f"{metric}_ci95_high"] = round(avg + half, 6)
        output.append(item)
    return output


def paired_tests(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    comparisons = ["AdaptiveRateLimit", "BudgetDoS", "P3-NoPersist"]
    metrics = ["legit_resolution_rate", "attack_aes_amplification"]
    main_rows = [
        row
        for row in rows
        if row.get("m10_experiment") == "main"
        and row.get("method") in set(comparisons + ["P3-Persist"])
    ]
    by_scenario_method: dict[tuple[str, str], dict[str, dict[str, str]]] = defaultdict(dict)
    for row in main_rows:
        by_scenario_method[(row["m10_scenario"], row["method"])][row["seed"]] = row

    for scenario in ["medium_flood", "heavy_flood"]:
        persist = by_scenario_method[(scenario, "P3-Persist")]
        for baseline in comparisons:
            base = by_scenario_method[(scenario, baseline)]
            seeds = sorted(set(persist) & set(base))
            for metric in metrics:
                diffs = [float(persist[seed][metric]) - float(base[seed][metric]) for seed in seeds]
                n = len(diffs)
                avg = mean(diffs)
                sd = stdev(diffs) if n > 1 else 0.0
                t_value = avg / (sd / math.sqrt(n)) if sd > 0 and n > 1 else 0.0
                p_value = t_p_two_sided(t_value, n - 1) if n > 1 else 1.0
                output.append(
                    {
                        "scenario": scenario,
                        "metric": metric,
                        "comparison": f"P3-Persist_vs_{baseline}",
                        "n": n,
                        "mean_diff": round(avg, 6),
                        "sd_diff": round(sd, 6),
                        "paired_t": round(t_value, 6),
                        "paired_t_p": format_p(p_value),
                        "paired_cohens_dz": round(avg / sd, 6) if sd > 0 else 0.0,
                        "wilcoxon_p_approx": format_p(wilcoxon_p_approx(diffs)),
                    }
                )
    return output


def rate_independence(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    rate_rows = [
        row
        for row in rows
        if row.get("m10_experiment") == "rate_independence"
        and row.get("method") == "P3-Persist"
    ]
    by_rate: dict[str, list[dict[str, str]]] = defaultdict(list)
    by_seed_rate: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    for row in rate_rows:
        by_rate[row["attack_rpa_rate_per_min"]].append(row)
        by_seed_rate[row["seed"]][row["attack_rpa_rate_per_min"]] = row

    output: list[dict[str, Any]] = []
    for rate, group in sorted(by_rate.items(), key=lambda item: float(item[0])):
        vals = [float(row["attack_aes_amplification"]) for row in group]
        output.append(
            {
                "check": "rate_summary",
                "attack_rpa_rate_per_min": rate,
                "n": len(vals),
                "attack_aes_amplification_mean": round(mean(vals), 6),
                "attack_aes_amplification_sd": round(stdev(vals), 6) if len(vals) > 1 else 0.0,
                "cap_aes_per_min": CAP_AES_PER_MIN,
                "mean_over_cap": round(mean(vals) / CAP_AES_PER_MIN, 6),
                "pass_cap_105": str(mean(vals) <= CAP_AES_PER_MIN * 1.05),
                "ratio_20k_to_10k": "",
                "pass_ratio_105": "",
            }
        )

    ratios = []
    for seed, by_rate_seed in sorted(by_seed_rate.items()):
        if "10000.0" not in by_rate_seed or "20000.0" not in by_rate_seed:
            continue
        low = float(by_rate_seed["10000.0"]["attack_aes_amplification"])
        high = float(by_rate_seed["20000.0"]["attack_aes_amplification"])
        ratio = high / low if low else 0.0
        ratios.append(ratio)
        output.append(
            {
                "check": "seed_ratio",
                "attack_rpa_rate_per_min": seed,
                "n": 1,
                "attack_aes_amplification_mean": "",
                "attack_aes_amplification_sd": "",
                "cap_aes_per_min": CAP_AES_PER_MIN,
                "mean_over_cap": "",
                "pass_cap_105": "",
                "ratio_20k_to_10k": round(ratio, 6),
                "pass_ratio_105": str(ratio <= 1.05),
            }
        )
    if ratios:
        output.append(
            {
                "check": "ratio_summary",
                "attack_rpa_rate_per_min": "20000_vs_10000",
                "n": len(ratios),
                "attack_aes_amplification_mean": "",
                "attack_aes_amplification_sd": "",
                "cap_aes_per_min": CAP_AES_PER_MIN,
                "mean_over_cap": "",
                "pass_cap_105": "",
                "ratio_20k_to_10k": round(mean(ratios), 6),
                "pass_ratio_105": str(mean(ratios) <= 1.05 and all(r <= 1.05 for r in ratios)),
            }
        )
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--combined",
        type=Path,
        default=Path("sim/rpa_resolution/results/m10_statistical_extension/combined_summary.csv"),
    )
    parser.add_argument("--out", type=Path, default=Path("sim/rpa_resolution/figures/m10_statistical_extension"))
    args = parser.parse_args()

    rows = read_rows(args.combined)
    write_csv(args.out / "table_m10_headline_stats.csv", summarize(rows))
    write_csv(args.out / "table_m10_paired_tests.csv", paired_tests(rows))
    write_csv(args.out / "table_m10_rate_independence.csv", rate_independence(rows))


if __name__ == "__main__":
    main()
