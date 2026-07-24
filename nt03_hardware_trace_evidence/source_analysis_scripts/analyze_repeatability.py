#!/usr/bin/env python3
"""Analyze H2 controlled windows into the three required repeatability tables."""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * p)))
    return ordered[idx]


def window_repeat_count(timestamps_ms: list[int], window_s: int) -> int:
    if len(timestamps_ms) < 2:
        return 0
    times = sorted(timestamps_ms)
    left = 0
    for right, ts in enumerate(times):
        while ts - times[left] > window_s * 1000:
            left += 1
        if right - left + 1 >= 2:
            return 1
    return 0


def summarize_window(window: dict[str, str], rows: list[dict[str, str]]) -> dict[str, str]:
    candidates = [r for r in rows if r["is_random"] == "1" or r["is_rpa_candidate"] == "1"]
    candidate_addrs = {r["addr"] for r in candidates}
    high_rssi_candidates = {
        r["addr"] for r in candidates if r["rssi_dbm"] and int(r["rssi_dbm"]) >= -75
    }
    return {
        "run_id": window["run_id"],
        "window_id": window["window_id"],
        "label": window["label"],
        "controlled_device": window["controlled_device"],
        "start_wall_time_iso": window["start_wall_time_iso"],
        "end_wall_time_iso": window["end_wall_time_iso"],
        "duration_s": window["duration_s"],
        "event_count": str(len(rows)),
        "candidate_count": str(len(candidate_addrs)),
        "high_rssi_candidate_count": str(len(high_rssi_candidates)),
        "raw_line_count": window["line_count"],
    }


def summarize_repeatability(window: dict[str, str], rows: list[dict[str, str]]) -> dict[str, str]:
    candidates = [r for r in rows if r["is_random"] == "1" or r["is_rpa_candidate"] == "1"]
    by_addr: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in candidates:
        by_addr[row["addr"]].append(row)

    repeated = {addr: rs for addr, rs in by_addr.items() if len(rs) >= 2}
    repeat_events = sum(len(rs) for rs in repeated.values())
    interarrival: list[float] = []
    rssi: list[int] = []
    w60 = 0
    w120 = 0
    for rs in by_addr.values():
        ts = sorted(int(r["timestamp_ms"]) for r in rs)
        rssi.extend(int(r["rssi_dbm"]) for r in rs if r["rssi_dbm"])
        interarrival.extend((b - a) / 1000.0 for a, b in zip(ts, ts[1:]))
        w60 += window_repeat_count(ts, 60)
        w120 += window_repeat_count(ts, 120)

    candidate_count = len(by_addr)
    return {
        "device_label": window["controlled_device"],
        "window_id": window["window_id"],
        "candidate_addr_count": str(candidate_count),
        "repeat_addr_count": str(len(repeated)),
        "repeat_fraction": f"{(len(repeated) / candidate_count):.6f}" if candidate_count else "0.000000",
        "event_repeat_fraction": f"{(repeat_events / len(candidates)):.6f}" if candidates else "0.000000",
        "median_interarrival_s": f"{statistics.median(interarrival):.3f}" if interarrival else "",
        "p95_interarrival_s": f"{percentile(interarrival, 0.95):.3f}" if interarrival else "",
        "window_repeat_ge2_W60": str(w60),
        "window_repeat_ge2_W120": str(w120),
        "rssi_mean_dbm": f"{statistics.mean(rssi):.2f}" if rssi else "",
        "rssi_std_db": f"{statistics.pstdev(rssi):.2f}" if len(rssi) > 1 else "0.00",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window-log", type=Path, required=True)
    parser.add_argument("--scan-csv", type=Path, nargs="+", required=True)
    parser.add_argument("--window-summary", type=Path, required=True)
    parser.add_argument("--repeatability", type=Path, required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    args = parser.parse_args()

    windows = read_csv(args.window_log)
    all_rows: list[dict[str, str]] = []
    for path in args.scan_csv:
        all_rows.extend(read_csv(path))

    by_window: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in all_rows:
        by_window[row["run_id"]].append(row)

    window_summary = [summarize_window(w, by_window.get(w["run_id"], [])) for w in windows]
    repeatability = [
        summarize_repeatability(w, by_window.get(w["run_id"], []))
        for w in windows
        if w["label"] == "device_on"
    ]

    off_windows = {w["run_id"] for w in windows if w["label"] == "device_off"}
    addr_rows: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in all_rows:
        if row["is_random"] == "1" or row["is_rpa_candidate"] == "1":
            addr_rows[row["addr"]].append(row)

    candidate_rows: list[dict[str, str]] = []
    for addr, rows in sorted(addr_rows.items()):
        ts = [int(r["timestamp_ms"]) for r in rows]
        rssi = [int(r["rssi_dbm"]) for r in rows if r["rssi_dbm"]]
        window_ids = sorted({r["run_id"] for r in rows})
        labels = sorted({r["label"] for r in rows})
        candidate_rows.append(
            {
                "addr": addr,
                "addr_type": rows[0]["addr_type"],
                "is_random": rows[0]["is_random"],
                "is_rpa_candidate": "1" if any(r["is_rpa_candidate"] == "1" for r in rows) else "0",
                "seen_count": str(len(rows)),
                "first_seen_ms": str(min(ts)),
                "last_seen_ms": str(max(ts)),
                "window_ids": ";".join(window_ids),
                "labels": ";".join(labels),
                "appears_in_off_window": "1" if any(r["run_id"] in off_windows for r in rows) else "0",
                "repeat_ge2_W60": str(window_repeat_count(ts, 60)),
                "repeat_ge2_W120": str(window_repeat_count(ts, 120)),
                "rssi_mean_dbm": f"{statistics.mean(rssi):.2f}" if rssi else "",
                "rssi_max_dbm": str(max(rssi)) if rssi else "",
                "rssi_min_dbm": str(min(rssi)) if rssi else "",
            }
        )

    write_csv(
        args.window_summary,
        window_summary,
        [
            "run_id",
            "window_id",
            "label",
            "controlled_device",
            "start_wall_time_iso",
            "end_wall_time_iso",
            "duration_s",
            "event_count",
            "candidate_count",
            "high_rssi_candidate_count",
            "raw_line_count",
        ],
    )
    write_csv(
        args.repeatability,
        repeatability,
        [
            "device_label",
            "window_id",
            "candidate_addr_count",
            "repeat_addr_count",
            "repeat_fraction",
            "event_repeat_fraction",
            "median_interarrival_s",
            "p95_interarrival_s",
            "window_repeat_ge2_W60",
            "window_repeat_ge2_W120",
            "rssi_mean_dbm",
            "rssi_std_db",
        ],
    )
    write_csv(
        args.candidates,
        candidate_rows,
        [
            "addr",
            "addr_type",
            "is_random",
            "is_rpa_candidate",
            "seen_count",
            "first_seen_ms",
            "last_seen_ms",
            "window_ids",
            "labels",
            "appears_in_off_window",
            "repeat_ge2_W60",
            "repeat_ge2_W120",
            "rssi_mean_dbm",
            "rssi_max_dbm",
            "rssi_min_dbm",
        ],
    )

    print(f"window_summary_rows={len(window_summary)}")
    print(f"repeatability_rows={len(repeatability)}")
    print(f"candidate_rows={len(candidate_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
