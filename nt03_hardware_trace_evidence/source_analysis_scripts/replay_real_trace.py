#!/usr/bin/env python3
"""Replay H2 real BLE trace through offline path-count accounting.

This script is intentionally not a performance benchmark. The H2 trace has
controlled-window labels but no cryptographic IRK ground truth, so the replay
only checks whether real address repetitions exercise the simulator's path
classes: duplicate filter, cache, resolving-list hit, budget skip, reserve, and
host scan.
"""

from __future__ import annotations

import argparse
import csv
from collections import OrderedDict
from pathlib import Path


PATH_FIELDS = [
    "rl_hit_legit_count",
    "rl_hit_ambient_count",
    "reserve_grant_legit_count",
    "reserve_grant_ambient_count",
    "duplicate_filter_legit_count",
    "duplicate_filter_ambient_count",
    "cache_hit_legit_count",
    "cache_hit_ambient_count",
    "host_scan_legit_count",
    "host_scan_ambient_count",
    "budget_skip_legit_count",
    "budget_skip_ambient_count",
]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def is_candidate(row: dict[str, str]) -> bool:
    return row.get("is_random") == "1" or row.get("is_rpa_candidate") == "1"


def is_rpa_like(row: dict[str, str]) -> bool:
    return row.get("is_rpa_candidate") == "1"


def build_legit_set(candidate_rows: list[dict[str, str]], rssi_threshold: int) -> set[str]:
    legit: set[str] = set()
    for row in candidate_rows:
        labels = set(filter(None, row.get("labels", "").split(";")))
        try:
            rssi_max = int(float(row.get("rssi_max_dbm", "-999")))
        except ValueError:
            rssi_max = -999
        if (
            labels == {"device_on"}
            and row.get("appears_in_off_window") == "0"
            and row.get("repeat_ge2_W60") == "1"
            and rssi_max >= rssi_threshold
        ):
            legit.add(row["addr"])
    return legit


def count_window_repeated_addrs(candidate_rows: list[dict[str, str]], legit_addrs: set[str]) -> dict[str, int]:
    repeated = [row for row in candidate_rows if row.get("repeat_ge2_W60") == "1"]
    return {
        "d_rv_ge2_W60_addr_count": len(repeated),
        "d_rv_ge2_W60_legit_addr_count": sum(1 for row in repeated if row["addr"] in legit_addrs),
        "d_rv_ge2_W60_ambient_addr_count": sum(1 for row in repeated if row["addr"] not in legit_addrs),
    }


def load_trace_events(scan_paths: list[Path], legit_addrs: set[str]) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []
    for path in scan_paths:
        for row in read_csv(path):
            if not is_candidate(row):
                continue
            events.append(
                {
                    "event_id": str(len(events)),
                    "run_id": row["run_id"],
                    "timestamp_ms": row["timestamp_ms"],
                    "window_label": row["label"],
                    "addr": row["addr"],
                    "addr_type": "rpa" if is_rpa_like(row) else "random_private",
                    "source_class": "legit_candidate" if row["addr"] in legit_addrs else "ambient_unknown",
                    "rssi_dbm": row["rssi_dbm"],
                    "adv_type": row["adv_type"],
                    "payload_len": row["payload_len"],
                }
            )
    events.sort(key=lambda r: (int(r["timestamp_ms"]), int(r["event_id"])))
    for idx, row in enumerate(events):
        row["event_id"] = str(idx)
    return events


def inc(counts: dict[str, int], path: str, source_class: str) -> None:
    suffix = "legit" if source_class == "legit_candidate" else "ambient"
    counts[f"{path}_{suffix}_count"] += 1


def replay(
    events: list[dict[str, str]],
    *,
    cache_size: int,
    duplicate_filter_window_s: float,
    budget_window_s: int,
    budget_per_window: int,
    persist_k: int,
    persist_reserve: int,
    rl_capacity: int,
) -> tuple[list[dict[str, str]], dict[str, int]]:
    counts = {field: 0 for field in PATH_FIELDS}
    cache: OrderedDict[str, str] = OrderedDict()
    resolved_addrs: set[str] = set()
    df_seen: set[tuple[int, str]] = set()
    budget_window = -1
    budget_used = 0
    reserve_window = -1
    reserve_used = 0
    reserve_denied: dict[str, int] = {}
    rl_entries = list(
        OrderedDict.fromkeys(
            row["addr"]
            for row in events
            if row["source_class"] == "legit_candidate"
        )
    )[: max(0, rl_capacity)]
    rl_set = set(rl_entries)

    decisions: list[dict[str, str]] = []
    duplicate_ms = max(1, int(duplicate_filter_window_s * 1000))
    budget_ms = max(1, budget_window_s * 1000)
    for row in events:
        addr = row["addr"]
        source = row["source_class"]
        ts_ms = int(row["timestamp_ms"])
        path = ""
        action = ""

        if row["addr_type"] == "rpa" and duplicate_filter_window_s > 0 and addr not in resolved_addrs:
            df_key = (ts_ms // duplicate_ms, addr)
            if df_key in df_seen:
                path = "duplicate_filter"
                action = "duplicate_filter"
            else:
                df_seen.add(df_key)

        if not path and addr in cache:
            cache.move_to_end(addr)
            path = "cache_hit"
            action = "cache_hit"

        if not path and addr in rl_set:
            path = "rl_hit"
            action = "rl_hit"

        if not path:
            current_budget_window = ts_ms // budget_ms
            if current_budget_window != budget_window:
                budget_window = current_budget_window
                budget_used = 0
            if current_budget_window != reserve_window:
                reserve_window = current_budget_window
                reserve_used = 0

            if budget_used < budget_per_window:
                budget_used += 1
                path = "host_scan"
                action = "host_scan"
            else:
                denied = reserve_denied.get(addr, 0)
                if denied >= persist_k and reserve_used < persist_reserve:
                    reserve_used += 1
                    path = "reserve_grant"
                    action = "host_scan_reserve"
                else:
                    reserve_denied[addr] = denied + 1
                    path = "budget_skip"
                    action = "budget_skip"

        if path in {"host_scan", "reserve_grant", "rl_hit"} and source == "legit_candidate":
            cache[addr] = "controlled_device_likely"
            cache.move_to_end(addr)
            resolved_addrs.add(addr)
            while len(cache) > cache_size:
                cache.popitem(last=False)

        inc(counts, path, source)
        decisions.append(
            {
                "event_id": row["event_id"],
                "run_id": row["run_id"],
                "timestamp_ms": row["timestamp_ms"],
                "addr": addr,
                "addr_type": row["addr_type"],
                "source_class": source,
                "rssi_dbm": row["rssi_dbm"],
                "action": action,
                "admission_path": path,
            }
        )

    return decisions, counts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-csv", type=Path, nargs="+", required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--replay-input", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--path-counts-public", type=Path, required=True)
    parser.add_argument("--cache-size", type=int, default=64)
    parser.add_argument("--duplicate-filter-window-s", type=float, default=0.2)
    parser.add_argument("--budget-window-s", type=int, default=60)
    parser.add_argument("--budget-per-window", type=int, default=100)
    parser.add_argument("--persist-k", type=int, default=1)
    parser.add_argument("--persist-reserve", type=int, default=8)
    parser.add_argument("--rl-capacity", type=int, default=8)
    parser.add_argument("--legit-rssi-threshold", type=int, default=-85)
    args = parser.parse_args()

    candidate_rows = read_csv(args.candidates)
    legit_addrs = build_legit_set(candidate_rows, args.legit_rssi_threshold)
    repeated_counts = count_window_repeated_addrs(candidate_rows, legit_addrs)
    events = load_trace_events(args.scan_csv, legit_addrs)
    decisions, counts = replay(
        events,
        cache_size=args.cache_size,
        duplicate_filter_window_s=args.duplicate_filter_window_s,
        budget_window_s=args.budget_window_s,
        budget_per_window=args.budget_per_window,
        persist_k=args.persist_k,
        persist_reserve=args.persist_reserve,
        rl_capacity=args.rl_capacity,
    )

    write_csv(
        args.replay_input,
        events,
        [
            "event_id",
            "run_id",
            "timestamp_ms",
            "window_label",
            "addr",
            "addr_type",
            "source_class",
            "rssi_dbm",
            "adv_type",
            "payload_len",
        ],
    )
    write_csv(
        args.decisions,
        decisions,
        [
            "event_id",
            "run_id",
            "timestamp_ms",
            "addr",
            "addr_type",
            "source_class",
            "rssi_dbm",
            "action",
            "admission_path",
        ],
    )

    public_row = {
        "method": "P3-Persist-real-trace-shim",
        "trace_scope": "H2_redmi_k80_controlled_windows",
        "event_count": str(len(events)),
        "legit_candidate_event_count": str(sum(1 for r in events if r["source_class"] == "legit_candidate")),
        "ambient_unknown_event_count": str(sum(1 for r in events if r["source_class"] == "ambient_unknown")),
        "legit_candidate_addr_count": str(len(legit_addrs)),
        "cache_size": str(args.cache_size),
        "duplicate_filter_window_s": f"{args.duplicate_filter_window_s:.3f}",
        "budget_window_s": str(args.budget_window_s),
        "budget_per_window": str(args.budget_per_window),
        "persist_k": str(args.persist_k),
        "persist_reserve": str(args.persist_reserve),
        "rl_capacity": str(args.rl_capacity),
        "legit_rssi_threshold_dbm": str(args.legit_rssi_threshold),
        "d_rv_window_s": "60",
        "d_rv_k": "2",
    }
    public_row.update({field: str(value) for field, value in repeated_counts.items()})
    public_row.update({field: str(counts[field]) for field in PATH_FIELDS})
    public_row["ground_truth_note"] = "controlled-window labels only; no IRK identity ground truth"
    write_csv(args.path_counts_public, [public_row], list(public_row.keys()))

    print(f"replay_events={len(events)}")
    print(f"legit_candidate_addrs={len(legit_addrs)}")
    for field in PATH_FIELDS:
        print(f"{field}={counts[field]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
