#!/usr/bin/env python3
"""Shared completion checks for the review260715 experiment suites.

The M12-M14 runners use these checks to avoid treating a partial or stale run
directory as complete. A run may be skipped only when its manifest config hash,
method list, run ID, and summary rows all match the requested config.
"""

from __future__ import annotations

import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent / "src"
sys.path.insert(0, str(SRC_DIR))

from rpa_sim import config_hash  # noqa: E402


@dataclass(frozen=True)
class CompletionCheck:
    complete: bool
    reason: str


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        value = json.load(f)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object in {path}")
    return value


def _read_summary(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def validate_completed_run(config: dict[str, Any], run_dir: Path) -> CompletionCheck:
    """Return complete only for an exact, internally consistent run output."""

    manifest_path = run_dir / "run_manifest.json"
    summary_path = run_dir / "summary.csv"
    if not manifest_path.is_file():
        return CompletionCheck(False, "missing run_manifest.json")
    if not summary_path.is_file():
        return CompletionCheck(False, "missing summary.csv")

    try:
        manifest = _read_json(manifest_path)
        rows = _read_summary(summary_path)
    except (OSError, ValueError, json.JSONDecodeError, csv.Error) as exc:
        return CompletionCheck(False, f"unreadable output: {exc}")

    run_id = str(config["run_id"])
    methods = [str(method) for method in config.get("methods", [])]
    if not methods:
        return CompletionCheck(False, "config has no explicit methods")
    if str(manifest.get("run_id")) != run_id:
        return CompletionCheck(False, "manifest run_id mismatch")
    if str(manifest.get("config_hash")) != config_hash(config):
        return CompletionCheck(False, "manifest config_hash mismatch")
    if [str(method) for method in manifest.get("methods", [])] != methods:
        return CompletionCheck(False, "manifest methods mismatch")
    if len(rows) != len(methods):
        return CompletionCheck(False, "summary row count mismatch")
    if any(str(row.get("run_id")) != run_id for row in rows):
        return CompletionCheck(False, "summary run_id mismatch")
    if [str(row.get("method")) for row in rows] != methods:
        return CompletionCheck(False, "summary methods mismatch")
    return CompletionCheck(True, "complete")


def should_skip_run(config: dict[str, Any], run_dir: Path) -> bool:
    """True only when validate_completed_run confirms an exact prior result."""

    return validate_completed_run(config, run_dir).complete
