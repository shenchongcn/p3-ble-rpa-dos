#!/usr/bin/env python3
"""Create public/anonymized H2 tables from internal trace outputs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import secrets
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


def load_or_create_salt(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    salt = secrets.token_hex(16)
    path.write_text(salt + "\n", encoding="utf-8")
    return salt


def addr_hash(salt: str, addr: str) -> str:
    return hashlib.sha256((salt + addr).encode("utf-8")).hexdigest()[:10]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window-summary", type=Path, required=True)
    parser.add_argument("--repeatability", type=Path, required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--salt-file", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()

    salt = load_or_create_salt(args.salt_file)

    window_rows = [
        {
            "window_id": r["window_id"],
            "label": r["label"],
            "controlled_device_class": "smartphone",
            "duration_s": r["duration_s"],
            "event_count": r["event_count"],
            "candidate_count": r["candidate_count"],
            "high_rssi_candidate_count": r["high_rssi_candidate_count"],
        }
        for r in read_csv(args.window_summary)
    ]
    write_csv(
        args.out_dir / "real_trace_window_summary_public.csv",
        window_rows,
        [
            "window_id",
            "label",
            "controlled_device_class",
            "duration_s",
            "event_count",
            "candidate_count",
            "high_rssi_candidate_count",
        ],
    )

    repeat_rows = [
        {
            "device_class": "smartphone",
            "window_id": r["window_id"],
            "candidate_addr_count": r["candidate_addr_count"],
            "repeat_addr_count": r["repeat_addr_count"],
            "repeat_fraction": r["repeat_fraction"],
            "event_repeat_fraction": r["event_repeat_fraction"],
            "median_interarrival_s": r["median_interarrival_s"],
            "p95_interarrival_s": r["p95_interarrival_s"],
            "window_repeat_ge2_W60": r["window_repeat_ge2_W60"],
            "window_repeat_ge2_W120": r["window_repeat_ge2_W120"],
            "rssi_mean_dbm": r["rssi_mean_dbm"],
            "rssi_std_db": r["rssi_std_db"],
        }
        for r in read_csv(args.repeatability)
    ]
    write_csv(
        args.out_dir / "real_trace_repeatability_public.csv",
        repeat_rows,
        [
            "device_class",
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

    candidate_rows = [
        {
            "addr_hash": addr_hash(salt, r["addr"]),
            "addr_type": r["addr_type"],
            "is_random": r["is_random"],
            "is_rpa_candidate": r["is_rpa_candidate"],
            "seen_count": r["seen_count"],
            "window_ids": r["window_ids"],
            "labels": r["labels"],
            "appears_in_off_window": r["appears_in_off_window"],
            "repeat_ge2_W60": r["repeat_ge2_W60"],
            "repeat_ge2_W120": r["repeat_ge2_W120"],
            "rssi_mean_dbm": r["rssi_mean_dbm"],
            "rssi_max_dbm": r["rssi_max_dbm"],
            "rssi_min_dbm": r["rssi_min_dbm"],
        }
        for r in read_csv(args.candidates)
    ]
    write_csv(
        args.out_dir / "real_trace_random_private_candidates_public.csv",
        candidate_rows,
        [
            "addr_hash",
            "addr_type",
            "is_random",
            "is_rpa_candidate",
            "seen_count",
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

    print(f"public_window_rows={len(window_rows)}")
    print(f"public_repeatability_rows={len(repeat_rows)}")
    print(f"public_candidate_rows={len(candidate_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
