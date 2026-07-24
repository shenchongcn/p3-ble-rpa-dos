#!/usr/bin/env python3
"""Parse M13 UART SCAN logs into a standard internal CSV."""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path


ADDR_RE = re.compile(r"^([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?: \(([^)]+)\))?$")


def parse_scan_line(line: str) -> dict[str, str] | None:
    if not line.startswith("SCAN,"):
        return None

    parts = line.strip().split(",")
    if len(parts) != 9:
        return None

    _, timestamp_ms, addr_raw, addr_type, is_random, is_rpa_candidate, rssi_dbm, adv_type, payload_len = parts
    match = ADDR_RE.match(addr_raw)
    if match:
        addr = match.group(1).upper()
        addr_type_label = match.group(2) or ""
    else:
        addr = addr_raw.upper()
        addr_type_label = ""

    return {
        "run_id": "",
        "timestamp_ms": timestamp_ms,
        "wall_time_iso": "",
        "addr": addr,
        "addr_type": addr_type_label or addr_type,
        "addr_type_raw": addr_type,
        "is_random": is_random,
        "is_rpa_candidate": is_rpa_candidate,
        "rssi_dbm": rssi_dbm,
        "adv_type": adv_type,
        "payload_len": payload_len,
        "label": "",
        "controlled_device": "",
        "distance_m": "",
        "notes": "",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_log", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--label", default="background")
    parser.add_argument("--notes", default="")
    args = parser.parse_args()

    rows: list[dict[str, str]] = []
    for line in args.input_log.read_text(encoding="utf-8", errors="replace").splitlines():
        row = parse_scan_line(line)
        if row is None:
            continue
        row["run_id"] = args.run_id
        row["label"] = args.label
        row["notes"] = args.notes
        rows.append(row)

    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "run_id",
        "timestamp_ms",
        "wall_time_iso",
        "addr",
        "addr_type",
        "addr_type_raw",
        "is_random",
        "is_rpa_candidate",
        "rssi_dbm",
        "adv_type",
        "payload_len",
        "label",
        "controlled_device",
        "distance_m",
        "notes",
    ]
    with args.output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"parsed_rows={len(rows)} output={args.output_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
