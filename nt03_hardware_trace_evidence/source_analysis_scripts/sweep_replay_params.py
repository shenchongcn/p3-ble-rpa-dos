#!/usr/bin/env python3
"""Parameter sweep for the H5 real-trace replay shim.

The outputs are public-safe aggregate CSVs. They intentionally do not include
BLE addresses, DK serials, wall-clock times, or local filesystem paths.
"""

from __future__ import annotations

import argparse
import itertools
import statistics
from pathlib import Path

from replay_real_trace import (
    PATH_FIELDS,
    build_legit_set,
    count_window_repeated_addrs,
    load_trace_events,
    read_csv,
    replay,
    write_csv,
)


def parse_int_list(value: str) -> list[int]:
    return [int(part.strip()) for part in value.split(",") if part.strip()]


def parse_float_list(value: str) -> list[float]:
    return [float(part.strip()) for part in value.split(",") if part.strip()]


def fraction(numerator: int, denominator: int) -> str:
    if denominator <= 0:
        return "0.000000"
    return f"{numerator / denominator:.6f}"


def median_int(values: list[int]) -> int:
    if not values:
        return 0
    return int(statistics.median(values))


def median_float(values: list[float]) -> float:
    if not values:
        return 0.0
    return float(statistics.median(values))


def metric_values(rows: list[dict[str, str]], field: str) -> list[int]:
    return [int(row[field]) for row in rows]


def metric_float_values(rows: list[dict[str, str]], field: str) -> list[float]:
    return [float(row[field]) for row in rows]


def build_summary(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    int_metrics = [
        "legit_candidate_addr_count",
        "legit_candidate_event_count",
        "d_rv_ge2_W60_legit_addr_count",
        "rl_hit_legit_count",
        "duplicate_filter_legit_count",
        "cache_hit_legit_count",
        "host_scan_legit_count",
        "budget_skip_legit_count",
        "reserve_grant_legit_count",
        "duplicate_filter_ambient_count",
        "host_scan_ambient_count",
        "budget_skip_ambient_count",
        "reserve_grant_ambient_count",
    ]
    float_metrics = [
        "legit_non_budget_skip_fraction",
        "legit_resolution_path_fraction",
        "ambient_budget_skip_fraction",
    ]

    summary: dict[str, str] = {
        "config_count": str(len(rows)),
        "event_count": rows[0]["event_count"] if rows else "0",
        "rl_capacity_values": ";".join(sorted({row["rl_capacity"] for row in rows}, key=int)),
        "budget_per_window_values": ";".join(sorted({row["budget_per_window"] for row in rows}, key=int)),
        "duplicate_filter_window_s_values": ";".join(
            sorted({row["duplicate_filter_window_s"] for row in rows}, key=float)
        ),
        "legit_rssi_threshold_dbm_values": ";".join(
            sorted({row["legit_rssi_threshold_dbm"] for row in rows}, key=int)
        ),
    }

    for field in int_metrics:
        values = metric_values(rows, field)
        summary[f"{field}_min"] = str(min(values))
        summary[f"{field}_median"] = str(median_int(values))
        summary[f"{field}_max"] = str(max(values))

    for field in float_metrics:
        values = metric_float_values(rows, field)
        summary[f"{field}_min"] = f"{min(values):.6f}"
        summary[f"{field}_median"] = f"{median_float(values):.6f}"
        summary[f"{field}_max"] = f"{max(values):.6f}"

    summary["ground_truth_note"] = "controlled-window labels only; no IRK identity ground truth"
    return [summary]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-csv", type=Path, nargs="+", required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--out-sweep-public", type=Path, required=True)
    parser.add_argument("--out-summary-public", type=Path, required=True)
    parser.add_argument("--rl-capacity-values", default="0,4,8")
    parser.add_argument("--budget-per-window-values", default="50,100,200")
    parser.add_argument("--duplicate-filter-window-s-values", default="0.1,0.2,0.5,1.0")
    parser.add_argument("--legit-rssi-threshold-values", default="-90,-85,-80,-75")
    parser.add_argument("--cache-size", type=int, default=64)
    parser.add_argument("--budget-window-s", type=int, default=60)
    parser.add_argument("--persist-k", type=int, default=1)
    parser.add_argument("--persist-reserve", type=int, default=8)
    args = parser.parse_args()

    candidate_rows = read_csv(args.candidates)
    rows: list[dict[str, str]] = []
    config_id = 0
    for rl_capacity, budget_per_window, duplicate_window_s, rssi_threshold in itertools.product(
        parse_int_list(args.rl_capacity_values),
        parse_int_list(args.budget_per_window_values),
        parse_float_list(args.duplicate_filter_window_s_values),
        parse_int_list(args.legit_rssi_threshold_values),
    ):
        legit_addrs = build_legit_set(candidate_rows, rssi_threshold)
        repeated_counts = count_window_repeated_addrs(candidate_rows, legit_addrs)
        events = load_trace_events(args.scan_csv, legit_addrs)
        _, counts = replay(
            events,
            cache_size=args.cache_size,
            duplicate_filter_window_s=duplicate_window_s,
            budget_window_s=args.budget_window_s,
            budget_per_window=budget_per_window,
            persist_k=args.persist_k,
            persist_reserve=args.persist_reserve,
            rl_capacity=rl_capacity,
        )
        legit_events = sum(1 for row in events if row["source_class"] == "legit_candidate")
        ambient_events = len(events) - legit_events
        legit_resolution_paths = (
            counts["rl_hit_legit_count"]
            + counts["cache_hit_legit_count"]
            + counts["host_scan_legit_count"]
            + counts["reserve_grant_legit_count"]
        )
        public_row = {
            "config_id": str(config_id),
            "method": "P3-Persist-real-trace-shim",
            "trace_scope": "H2_redmi_k80_controlled_windows",
            "event_count": str(len(events)),
            "legit_candidate_event_count": str(legit_events),
            "ambient_unknown_event_count": str(ambient_events),
            "legit_candidate_addr_count": str(len(legit_addrs)),
            "cache_size": str(args.cache_size),
            "duplicate_filter_window_s": f"{duplicate_window_s:.3f}",
            "budget_window_s": str(args.budget_window_s),
            "budget_per_window": str(budget_per_window),
            "persist_k": str(args.persist_k),
            "persist_reserve": str(args.persist_reserve),
            "rl_capacity": str(rl_capacity),
            "legit_rssi_threshold_dbm": str(rssi_threshold),
            "d_rv_window_s": "60",
            "d_rv_k": "2",
            "legit_non_budget_skip_fraction": fraction(
                legit_events - counts["budget_skip_legit_count"],
                legit_events,
            ),
            "legit_resolution_path_fraction": fraction(legit_resolution_paths, legit_events),
            "ambient_budget_skip_fraction": fraction(counts["budget_skip_ambient_count"], ambient_events),
        }
        public_row.update({field: str(value) for field, value in repeated_counts.items()})
        public_row.update({field: str(counts[field]) for field in PATH_FIELDS})
        public_row["ground_truth_note"] = "controlled-window labels only; no IRK identity ground truth"
        rows.append(public_row)
        config_id += 1

    fieldnames = list(rows[0].keys()) if rows else []
    write_csv(args.out_sweep_public, rows, fieldnames)

    summary = build_summary(rows)
    write_csv(args.out_summary_public, summary, list(summary[0].keys()))
    print(f"sweep_configs={len(rows)}")
    if rows:
        print(f"event_count={rows[0]['event_count']}")
        print(f"legit_non_budget_skip_fraction_min={summary[0]['legit_non_budget_skip_fraction_min']}")
        print(f"legit_non_budget_skip_fraction_median={summary[0]['legit_non_budget_skip_fraction_median']}")
        print(f"legit_non_budget_skip_fraction_max={summary[0]['legit_non_budget_skip_fraction_max']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
