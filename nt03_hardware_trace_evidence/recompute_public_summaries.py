#!/usr/bin/env python3
"""Recompute NT-03 public summaries using only the anonymized trace."""

from __future__ import annotations

import argparse
import csv
import gzip
import math
import statistics
from collections import defaultdict
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_INPUT = SCRIPT_DIR / "data/controlled_private_address_events_anonymized.csv.gz"
SCOPES = ("random_or_rpa_candidate", "rpa_bit_pattern")
FILTER_WINDOWS_S = (0.0, 0.2, 1.0, 60.0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="Anonymized .csv.gz trace.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=SCRIPT_DIR / "recomputed",
        help="Directory for recomputed summary CSV files.",
    )
    parser.add_argument(
        "--verify-against",
        type=Path,
        help="Optional directory containing the expected summary CSV files.",
    )
    return parser.parse_args()


def read_trace(path: Path) -> list[dict[str, str]]:
    with gzip.open(path, mode="rt", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * p)))
    return ordered[index]


def select_scope(rows: list[dict[str, str]], scope: str) -> list[dict[str, str]]:
    if scope == "rpa_bit_pattern":
        return [row for row in rows if row["is_rpa_bit_pattern_candidate"] == "1"]
    return [
        row
        for row in rows
        if row["is_random"] == "1" or row["is_rpa_bit_pattern_candidate"] == "1"
    ]


def repeats_within(timestamps_ms: list[int], window_s: float) -> bool:
    ordered = sorted(timestamps_ms)
    return any(b - a <= window_s * 1000 for a, b in zip(ordered, ordered[1:]))


def repeatability_row(
    device_class: str,
    window_id: str,
    rows: list[dict[str, str]],
    scope: str,
) -> dict[str, str]:
    selected = select_scope(rows, scope)
    by_address: dict[str, list[int]] = defaultdict(list)
    for row in selected:
        by_address[row["addr_hash"]].append(int(row["timestamp_offset_ms"]))

    repeated = {address: values for address, values in by_address.items() if len(values) >= 2}
    repeated_events = sum(len(values) for values in repeated.values())
    interarrival_s = [
        (b - a) / 1000.0
        for values in by_address.values()
        for a, b in zip(sorted(values), sorted(values)[1:])
    ]
    address_count = len(by_address)
    return {
        "device_class": device_class,
        "window_id": window_id,
        "address_scope": scope,
        "event_count": str(len(selected)),
        "observed_address_value_count": str(address_count),
        "repeated_address_value_count": str(len(repeated)),
        "repeat_fraction": f"{len(repeated) / address_count:.6f}" if address_count else "0.000000",
        "event_repeat_fraction": f"{repeated_events / len(selected):.6f}" if selected else "0.000000",
        "repeat_within_60s_address_count": str(sum(repeats_within(values, 60.0) for values in by_address.values())),
        "repeat_within_120s_address_count": str(sum(repeats_within(values, 120.0) for values in by_address.values())),
        "median_interarrival_s": f"{statistics.median(interarrival_s):.3f}" if interarrival_s else "",
        "p95_interarrival_s": f"{percentile(interarrival_s, 0.95):.3f}" if interarrival_s else "",
        "measurement_note": "scanner duplicate filtering disabled during capture",
    }


def duplicate_filter_row(
    device_class: str,
    window_id: str,
    rows: list[dict[str, str]],
    scope: str,
    filter_window_s: float,
) -> dict[str, str]:
    selected = sorted(select_scope(rows, scope), key=lambda row: int(row["timestamp_offset_ms"]))
    retained = 0
    last_seen: dict[str, int] = {}
    threshold_ms = filter_window_s * 1000.0
    for row in selected:
        address = row["addr_hash"]
        timestamp = int(row["timestamp_offset_ms"])
        previous = last_seen.get(address)
        if filter_window_s <= 0 or previous is None or timestamp - previous > threshold_ms:
            retained += 1
        last_seen[address] = timestamp
    suppressed = len(selected) - retained
    return {
        "device_class": device_class,
        "window_id": window_id,
        "address_scope": scope,
        "filter_mode": "capture_disabled" if filter_window_s <= 0 else "offline_sliding_window_replay",
        "duplicate_filter_window_s": f"{filter_window_s:.3f}",
        "input_event_count": str(len(selected)),
        "retained_event_count": str(retained),
        "suppressed_event_count": str(suppressed),
        "retained_fraction": f"{retained / len(selected):.6f}" if selected else "0.000000",
        "suppressed_fraction": f"{suppressed / len(selected):.6f}" if selected else "0.000000",
        "interpretation_note": "offline accounting only; not a controller duplicate-filter measurement",
    }


def group_on_windows(rows: list[dict[str, str]]) -> dict[tuple[str, str], list[dict[str, str]]]:
    grouped: dict[tuple[str, str], list[dict[str, str]]] = {}
    for row in rows:
        if row["window_label"] != "device_on":
            continue
        key = (row["device_class"], row["window_id"])
        grouped.setdefault(key, []).append(row)
    return grouped


def verify(output_dir: Path, expected_dir: Path) -> None:
    for name in ("repeatability_summary.csv", "duplicate_filter_replay_summary.csv"):
        generated = (output_dir / name).read_bytes()
        expected = (expected_dir / name).read_bytes()
        if generated != expected:
            raise SystemExit(f"Verification failed: {name} differs from {expected_dir / name}")
    print(f"Verified recomputed summaries against {expected_dir}")


def main() -> None:
    args = parse_args()
    trace_rows = read_trace(args.input)
    grouped = group_on_windows(trace_rows)
    repeat_rows: list[dict[str, str]] = []
    filter_rows: list[dict[str, str]] = []
    for (device_class, window_id), rows in grouped.items():
        for scope in SCOPES:
            repeat_rows.append(repeatability_row(device_class, window_id, rows, scope))
            for filter_window_s in FILTER_WINDOWS_S:
                filter_rows.append(
                    duplicate_filter_row(device_class, window_id, rows, scope, filter_window_s)
                )

    write_csv(args.output_dir / "repeatability_summary.csv", repeat_rows)
    write_csv(args.output_dir / "duplicate_filter_replay_summary.csv", filter_rows)
    if args.verify_against:
        verify(args.output_dir, args.verify_against)
    print(f"Recomputed NT-03 summaries from {len(trace_rows)} anonymized events")


if __name__ == "__main__":
    main()
