#!/usr/bin/env python3
"""Run paired bonded/non-bonded modeled-observable privacy experiments.

The suite is auxiliary evidence for a narrowed privacy claim. It does not model
real scan responses, connection timing, controller timing, or application logs.
Identity labels are used only to construct the counterfactual trace and score
results; classifier features exclude source_type, matched, device ID, and IRK.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import sys
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from statistics import mean, stdev
from typing import Any

import numpy as np


SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent / "src"
sys.path.insert(0, str(SRC_DIR))
sys.path.insert(0, str(SCRIPT_DIR))

from review260715_stats import (  # noqa: E402
    auc_score,
    grouped_bootstrap_auc,
    grouped_oof_predictions,
    grouped_permutation_auc,
    ks_distance,
    wasserstein_1d,
)
from review260715_suite_common import validate_completed_run  # noqa: E402
from rpa_sim import (  # noqa: E402
    AddressEvent,
    build_devices,
    config_hash,
    generate_events,
    get_git_commit,
    init_state,
    percentile,
    resolve_event,
)


SEEDS = list(range(20260610, 20260630))
METHODS = ["P3-Persist", "P3-NoPersist", "BudgetDoS"]
LABELS = ["nonbonded", "bonded"]
LOADS = {
    "no_attack": (100.0, 0.0),
    "medium_flood": (100.0, 1000.0),
    "heavy_flood": (1000.0, 10000.0),
}
FEATURE_FIELDS = [
    "defer_rate",
    "mean_delay_ms",
    "p95_delay_ms",
    "cache_path_rate",
    "reserve_path_rate",
    "host_scan_path_rate",
    "budget_skip_path_rate",
    "duplicate_filter_path_rate",
    "rl_path_rate",
    "mean_aes_attempts",
]
EXTERNAL_PROXY_FIELDS = ["defer_rate", "mean_delay_ms", "p95_delay_ms"]
INTERNAL_DIAGNOSTIC_FIELDS = [
    field for field in FEATURE_FIELDS if field not in EXTERNAL_PROXY_FIELDS
]
FIRST_DECISION_FIELDS = [
    "action",
    "aes_attempts",
    "deferred",
    "delay_ms",
    "drop_reason",
    "admission_path",
]


def base_config(scenario: str, duplicate_filter_window_s: int, seed: int) -> dict[str, Any]:
    background_rate, attack_rate = LOADS[scenario]
    return {
        "schema_version": "m12.v1",
        "run_id": f"m12_{scenario}_dup{duplicate_filter_window_s}_s{seed}",
        "ncs_version": "v3.2.1",
        "seed": seed,
        "duration_s": 1800,
        "warmup_s": 300,
        "num_bonded": 512,
        "rl_capacity": 8,
        "active_ratio": 0.2,
        "active_skew": 1.1,
        "rpa_rotation_interval_min": 15,
        "legit_adv_rate_per_device_per_min": 1.0,
        "background_rpa_rate_per_min": background_rate,
        "attack_rpa_rate_per_min": attack_rate,
        "non_rpa_ratio": 0.2,
        "rssi_noise_db": 6.0,
        "methods": list(METHODS),
        "zephyr_cache_size": 64,
        "budget_window_s": 60,
        "budget_per_window": 100,
        "persist_reserve": 200,
        "persist_k": 1,
        "duplicate_filter_window_s": duplicate_filter_window_s,
        "unique_attack_rpa": True,
        "write_traces": False,
        "probe_interval_s": 5,
        "m12_scenario": scenario,
        "m12_analysis_version": "v3",
    }


def probe_seed(seed: int) -> int:
    payload = f"{seed}:m12-probe:v1".encode("utf-8")
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")


def visible_event_payload(event: AddressEvent) -> tuple[Any, ...]:
    return (
        event.event_id,
        event.ts_ms,
        event.addr_type,
        event.rpa_epoch,
        event.rssi_dbm,
        event.payload_len,
        event.rpa_value,
    )


def visible_trace_hash(events: list[AddressEvent]) -> str:
    payload = json.dumps(
        [visible_event_payload(event) for event in events],
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_paired_traces(
    pair_config: dict[str, Any],
) -> tuple[list[Any], list[AddressEvent], list[AddressEvent], str, int]:
    rng = random.Random(int(pair_config["seed"]))
    devices = build_devices(pair_config, rng)
    base_events = generate_events(pair_config, devices, rng)
    active_count = max(1, int(round(len(devices) * float(pair_config.get("active_ratio", 0.2)))))
    target = devices[-1]
    if target in devices[:active_count]:
        raise RuntimeError("privacy probe target unexpectedly belongs to base active set")

    duration_s = int(pair_config["duration_s"])
    interval_s = max(1, int(pair_config.get("probe_interval_s", 5)))
    rotation_s = max(1, int(float(pair_config["rpa_rotation_interval_min"]) * 60))
    probe_rng = random.Random(probe_seed(int(pair_config["seed"])))
    probe_specs: list[dict[str, Any]] = []
    for second in range(1, duration_s, interval_s):
        epoch = second // rotation_s
        probe_specs.append(
            {
                "ts_ms": second * 1000 + 500,
                "rpa_epoch": epoch,
                "rssi_dbm": round(probe_rng.gauss(-65.0, 3.0), 2),
                "payload_len": probe_rng.randint(12, 31),
                "rpa_value": f"PRIVPROBE:{epoch}",
            }
        )

    variants: dict[str, list[AddressEvent]] = {}
    for label in LABELS:
        variant_run_id = f"{pair_config['run_id']}_{label}"
        raw: list[AddressEvent] = [
            AddressEvent(**{**event.__dict__, "run_id": variant_run_id}) for event in base_events
        ]
        for index, spec in enumerate(probe_specs, start=len(raw)):
            raw.append(
                AddressEvent(
                    run_id=variant_run_id,
                    event_id=index,
                    ts_ms=int(spec["ts_ms"]),
                    source_type="legit_bonded" if label == "bonded" else "background",
                    device_id=target.device_id if label == "bonded" else "",
                    addr_type="rpa",
                    rpa_epoch=int(spec["rpa_epoch"]),
                    rssi_dbm=float(spec["rssi_dbm"]),
                    payload_len=int(spec["payload_len"]),
                    rpa_value=str(spec["rpa_value"]),
                )
            )
        raw.sort(key=lambda event: (event.ts_ms, event.event_id))
        variants[label] = [
            AddressEvent(**{**event.__dict__, "event_id": idx}) for idx, event in enumerate(raw)
        ]

    bonded = variants["bonded"]
    nonbonded = variants["nonbonded"]
    if len(bonded) != len(nonbonded):
        raise RuntimeError("paired trace length mismatch")
    for bonded_event, nonbonded_event in zip(bonded, nonbonded):
        if visible_event_payload(bonded_event) != visible_event_payload(nonbonded_event):
            raise RuntimeError("paired visible trace mismatch")
        is_probe = bonded_event.rpa_value.startswith("PRIVPROBE:")
        if is_probe:
            if bonded_event.source_type != "legit_bonded" or nonbonded_event.source_type != "background":
                raise RuntimeError("probe hidden-label construction mismatch")
        elif (
            bonded_event.source_type != nonbonded_event.source_type
            or bonded_event.device_id != nonbonded_event.device_id
        ):
            raise RuntimeError("non-probe hidden fields differ")
    trace_hash = visible_trace_hash(bonded)
    if trace_hash != visible_trace_hash(nonbonded):
        raise RuntimeError("paired visible hashes differ")
    return devices, bonded, nonbonded, trace_hash, len(probe_specs)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def feature_summary(
    run_id: str,
    method: str,
    label: str,
    pair_config: dict[str, Any],
    trace_hash: str,
    probe_decisions: list[Any],
) -> dict[str, Any]:
    total = len(probe_decisions)
    path_counts = Counter(decision.admission_path for decision in probe_decisions)
    delays = [float(decision.delay_ms) for decision in probe_decisions]
    return {
        "run_id": run_id,
        "method": method,
        "paired_trace_id": pair_config["paired_trace_id"],
        "scenario": pair_config["m12_scenario"],
        "duplicate_filter_window_s": pair_config["duplicate_filter_window_s"],
        "seed": pair_config["seed"],
        "identity_label_for_scoring": label,
        "visible_trace_sha256": trace_hash,
        "probe_event_count": total,
        "defer_rate": round(sum(1 for d in probe_decisions if d.deferred) / max(1, total), 6),
        "mean_delay_ms": round(mean(delays), 6) if delays else 0.0,
        "p95_delay_ms": round(percentile(delays, 0.95), 6),
        "cache_path_rate": round(path_counts["cache"] / max(1, total), 6),
        "reserve_path_rate": round(path_counts["reserve"] / max(1, total), 6),
        "host_scan_path_rate": round(path_counts["host_scan"] / max(1, total), 6),
        "budget_skip_path_rate": round(path_counts["budget_skip"] / max(1, total), 6),
        "duplicate_filter_path_rate": round(path_counts["duplicate_filter"] / max(1, total), 6),
        "rl_path_rate": round(path_counts["rl"] / max(1, total), 6),
        "mean_aes_attempts": round(
            mean(float(decision.aes_attempts) for decision in probe_decisions), 6
        )
        if probe_decisions
        else 0.0,
    }


def run_variant(
    config: dict[str, Any],
    devices: list[Any],
    events: list[AddressEvent],
    trace_hash: str,
    out_dir: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    completion = validate_completed_run(config, out_dir)
    first_path = out_dir / "first_probe_decisions.csv"
    probe_path = out_dir / "probe_decisions.csv"
    if completion.complete and first_path.is_file() and probe_path.is_file():
        return [dict(row) for row in read_csv(out_dir / "summary.csv")], [dict(row) for row in read_csv(first_path)]

    out_dir.mkdir(parents=True, exist_ok=True)
    warmup_ms = int(config.get("warmup_s", 0)) * 1000
    label = str(config["identity_label_for_scoring"])
    all_probe_events = {
        event.event_id: event for event in events if event.rpa_value.startswith("PRIVPROBE:")
    }
    probe_events = {
        event.event_id: event
        for event in events
        if event.ts_ms >= warmup_ms and event.rpa_value.startswith("PRIVPROBE:")
    }
    summary_rows: list[dict[str, Any]] = []
    first_rows: list[dict[str, Any]] = []
    probe_rows: list[dict[str, Any]] = []

    scheduler_config = {
        key: value
        for key, value in config.items()
        if key not in {"identity_label_for_scoring", "paired_trace_id", "visible_trace_sha256"}
    }
    for method in config["methods"]:
        state = init_state(method, scheduler_config, devices)
        decisions = [resolve_event(method, state, event, devices) for event in events]
        decisions_by_id = {decision.event_id: decision for decision in decisions}
        probe_decisions = [decisions_by_id[event_id] for event_id in sorted(probe_events)]
        summary_rows.append(
            feature_summary(
                str(config["run_id"]),
                method,
                label,
                config,
                trace_hash,
                probe_decisions,
            )
        )

        first_event_by_value: dict[str, int] = {}
        for event_id, event in sorted(all_probe_events.items()):
            first_event_by_value.setdefault(event.rpa_value, event_id)
        for rpa_value, event_id in sorted(first_event_by_value.items()):
            decision = decisions_by_id[event_id]
            first_rows.append(
                {
                    "run_id": config["run_id"],
                    "method": method,
                    "paired_trace_id": config["paired_trace_id"],
                    "identity_label_for_scoring": label,
                    "rpa_value": rpa_value,
                    "event_id": event_id,
                    **{field: getattr(decision, field) for field in FIRST_DECISION_FIELDS},
                }
            )
        for event_id in sorted(probe_events):
            decision = decisions_by_id[event_id]
            probe_rows.append(
                {
                    "run_id": config["run_id"],
                    "method": method,
                    "paired_trace_id": config["paired_trace_id"],
                    "identity_label_for_scoring": label,
                    "event_id": event_id,
                    "rpa_value": probe_events[event_id].rpa_value,
                    "action": decision.action,
                    "aes_attempts": decision.aes_attempts,
                    "deferred": decision.deferred,
                    "delay_ms": decision.delay_ms,
                    "admission_path": decision.admission_path,
                }
            )

    summary_fields = [
        "run_id",
        "method",
        "paired_trace_id",
        "scenario",
        "duplicate_filter_window_s",
        "seed",
        "identity_label_for_scoring",
        "visible_trace_sha256",
        "probe_event_count",
        *FEATURE_FIELDS,
    ]
    first_fields = [
        "run_id",
        "method",
        "paired_trace_id",
        "identity_label_for_scoring",
        "rpa_value",
        "event_id",
        *FIRST_DECISION_FIELDS,
    ]
    probe_fields = [
        "run_id",
        "method",
        "paired_trace_id",
        "identity_label_for_scoring",
        "event_id",
        "rpa_value",
        "action",
        "aes_attempts",
        "deferred",
        "delay_ms",
        "admission_path",
    ]
    write_csv(out_dir / "summary.csv", summary_rows, summary_fields)
    write_csv(first_path, first_rows, first_fields)
    write_csv(probe_path, probe_rows, probe_fields)
    write_json(
        out_dir / "run_manifest.json",
        {
            "schema_version": config["schema_version"],
            "run_id": config["run_id"],
            "git_commit": get_git_commit(),
            "config_hash": config_hash(config),
            "methods": config["methods"],
            "seed": config["seed"],
            "paired_trace_id": config["paired_trace_id"],
            "identity_label_for_scoring": label,
            "visible_trace_sha256": trace_hash,
            "probe_event_count_post_warmup": len(probe_events),
        },
    )
    return summary_rows, first_rows


def run_pair_job(job: dict[str, Any]) -> dict[str, Any]:
    pair_config = job["pair_config"]
    out_root = Path(job["out_root"])
    config_root = Path(job["config_root"])
    devices, bonded, nonbonded, trace_hash, probe_count = build_paired_traces(pair_config)
    events_by_label = {"bonded": bonded, "nonbonded": nonbonded}
    summaries: list[dict[str, Any]] = []
    first_by_label: dict[str, list[dict[str, Any]]] = {}

    for label in LABELS:
        run_id = f"{pair_config['run_id']}_{label}"
        config = dict(pair_config)
        config.update(
            {
                "run_id": run_id,
                "paired_trace_id": pair_config["run_id"],
                "identity_label_for_scoring": label,
                "visible_trace_sha256": trace_hash,
                "methods": list(METHODS),
            }
        )
        write_json(config_root / f"{run_id}.json", config)
        rows, first_rows = run_variant(
            config, devices, events_by_label[label], trace_hash, out_root / run_id
        )
        summaries.extend(rows)
        first_by_label[label] = first_rows

    cross_epoch_mismatches = 0
    first_bonded = {
        (row["method"], row["rpa_value"]): row for row in first_by_label["bonded"]
    }
    first_nonbonded = {
        (row["method"], row["rpa_value"]): row for row in first_by_label["nonbonded"]
    }
    if set(first_bonded) != set(first_nonbonded):
        raise RuntimeError("paired first-probe key mismatch")
    for key in sorted(first_bonded):
        bonded_row = first_bonded[key]
        nonbonded_row = first_nonbonded[key]
        if any(str(bonded_row[field]) != str(nonbonded_row[field]) for field in FIRST_DECISION_FIELDS):
            cross_epoch_mismatches += 1

    initial_mismatches = 0
    for method in METHODS:
        bonded_candidates = [row for row in first_by_label["bonded"] if row["method"] == method]
        nonbonded_candidates = [
            row for row in first_by_label["nonbonded"] if row["method"] == method
        ]
        bonded_initial = min(bonded_candidates, key=lambda row: int(row["event_id"]))
        nonbonded_initial = min(nonbonded_candidates, key=lambda row: int(row["event_id"]))
        if any(
            str(bonded_initial[field]) != str(nonbonded_initial[field])
            for field in FIRST_DECISION_FIELDS
        ):
            initial_mismatches += 1

    return {
        "summary_rows": summaries,
        "pair_audit": {
            "paired_trace_id": pair_config["run_id"],
            "scenario": pair_config["m12_scenario"],
            "duplicate_filter_window_s": pair_config["duplicate_filter_window_s"],
            "seed": pair_config["seed"],
            "visible_trace_sha256": trace_hash,
            "visible_trace_equal": True,
            "probe_event_count_total": probe_count,
            "initial_probe_comparison_count": len(METHODS),
            "initial_probe_pre_resolution_mismatch_count": initial_mismatches,
            "initial_probe_pre_resolution_equal": initial_mismatches == 0,
            "new_epoch_first_probe_comparison_count": len(first_bonded),
            "new_epoch_first_probe_state_mismatch_count": cross_epoch_mismatches,
        },
    }


def aggregate_paired_effects(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(str(row["scenario"]), str(row["duplicate_filter_window_s"]), str(row["method"]))].append(row)
    for (scenario, delta, method), group_rows in sorted(grouped.items()):
        by_pair: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
        for row in group_rows:
            by_pair[str(row["paired_trace_id"])][str(row["identity_label_for_scoring"])] = row
        for feature in FEATURE_FIELDS:
            differences = []
            bonded_values = []
            nonbonded_values = []
            for labels in by_pair.values():
                if set(labels) != set(LABELS):
                    continue
                bonded = float(labels["bonded"][feature])
                nonbonded = float(labels["nonbonded"][feature])
                bonded_values.append(bonded)
                nonbonded_values.append(nonbonded)
                differences.append(bonded - nonbonded)
            n = len(differences)
            avg = mean(differences) if differences else 0.0
            sd = stdev(differences) if n > 1 else 0.0
            half = 1.96 * sd / math.sqrt(n) if n > 1 else 0.0
            output.append(
                {
                    "scenario": scenario,
                    "duplicate_filter_window_s": delta,
                    "method": method,
                    "feature": feature,
                    "n_pairs": n,
                    "bonded_mean": round(mean(bonded_values), 6) if bonded_values else 0.0,
                    "nonbonded_mean": round(mean(nonbonded_values), 6) if nonbonded_values else 0.0,
                    "paired_difference_mean": round(avg, 6),
                    "paired_difference_sd": round(sd, 6),
                    "paired_difference_ci95_low": round(avg - half, 6),
                    "paired_difference_ci95_high": round(avg + half, 6),
                    "paired_effect_dz": round(avg / sd, 6) if sd > 0 else 0.0,
                    "ks_distance": round(
                        ks_distance(np.asarray(bonded_values), np.asarray(nonbonded_values)), 6
                    )
                    if bonded_values
                    else 0.0,
                    "wasserstein_distance": round(
                        wasserstein_1d(np.asarray(bonded_values), np.asarray(nonbonded_values)), 6
                    )
                    if bonded_values
                    else 0.0,
                }
            )
    return output


def aggregate_classifier(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(str(row["scenario"]), str(row["duplicate_filter_window_s"]), str(row["method"]))].append(row)
    feature_sets = {
        "external_delay_defer_proxy": EXTERNAL_PROXY_FIELDS,
        "internal_path_diagnostic": INTERNAL_DIAGNOSTIC_FIELDS,
    }
    for (scenario, delta, method), group_rows in sorted(grouped.items()):
        groups = [str(row["paired_trace_id"]) for row in group_rows]
        unique_groups = sorted(set(groups))
        labels = np.asarray(
            [1 if row["identity_label_for_scoring"] == "bonded" else 0 for row in group_rows],
            dtype=int,
        )
        for feature_set_name, fields in feature_sets.items():
            base = {
                "scenario": scenario,
                "duplicate_filter_window_s": delta,
                "method": method,
                "n_pairs": len(unique_groups),
                "feature_set_name": feature_set_name,
                "feature_set": ";".join(fields),
            }
            if len(unique_groups) < 5:
                output.append(
                    {
                        **base,
                        "grouped_cv_auc": "",
                        "bootstrap_ci95_low": "",
                        "bootstrap_ci95_high": "",
                        "permutation_auc_mean": "",
                        "permutation_ci95_low": "",
                        "permutation_ci95_high": "",
                        "status": "insufficient_groups_for_5_fold_cv",
                    }
                )
                continue
            features = np.asarray(
                [[float(row[field]) for field in fields] for row in group_rows], dtype=float
            )
            predictions = grouped_oof_predictions(features, labels, groups, folds=5)
            auc = auc_score(labels, predictions)
            bootstrap_low, bootstrap_high = grouped_bootstrap_auc(labels, predictions, groups)
            perm_mean, perm_low, perm_high = grouped_permutation_auc(labels, predictions, groups)
            output.append(
                {
                    **base,
                    "grouped_cv_auc": round(auc, 6),
                    "bootstrap_ci95_low": round(bootstrap_low, 6),
                    "bootstrap_ci95_high": round(bootstrap_high, 6),
                    "permutation_auc_mean": round(perm_mean, 6),
                    "permutation_ci95_low": round(perm_low, 6),
                    "permutation_ci95_high": round(perm_high, 6),
                    "status": "complete",
                }
            )
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true", help="run one seed for each load/filter pair")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--out", type=Path, default=Path("sim/rpa_resolution/results/m12_privacy_sidechannel")
    )
    parser.add_argument(
        "--config-dir", type=Path, default=Path("sim/rpa_resolution/configs/m12/privacy_sidechannel")
    )
    args = parser.parse_args()

    seeds = SEEDS[:1] if args.smoke else SEEDS
    jobs = []
    for scenario in LOADS:
        for delta in [0, 60]:
            for seed in seeds:
                jobs.append(
                    {
                        "pair_config": base_config(scenario, delta, seed),
                        "out_root": str(args.out / "runs"),
                        "config_root": str(args.config_dir),
                    }
                )

    all_rows: list[dict[str, Any]] = []
    pair_audits: list[dict[str, Any]] = []
    def collect(result: dict[str, Any], completed: int, total: int) -> None:
        all_rows.extend(result["summary_rows"])
        pair_audits.append(result["pair_audit"])
        if completed % 10 == 0 or completed == total:
            print(f"m12: completed {completed}/{total} paired jobs", flush=True)

    if args.workers <= 1:
        for completed, job in enumerate(jobs, 1):
            collect(run_pair_job(job), completed, len(jobs))
    else:
        try:
            with ProcessPoolExecutor(max_workers=args.workers) as executor:
                futures = [executor.submit(run_pair_job, job) for job in jobs]
                for completed, future in enumerate(as_completed(futures), 1):
                    collect(future.result(), completed, len(futures))
        except PermissionError as exc:
            print(
                f"m12: process pool unavailable ({exc}); falling back to sequential execution",
                flush=True,
            )
            all_rows.clear()
            pair_audits.clear()
            for completed, job in enumerate(jobs, 1):
                collect(run_pair_job(job), completed, len(jobs))

    all_rows.sort(
        key=lambda row: (
            str(row["scenario"]),
            int(row["duplicate_filter_window_s"]),
            int(row["seed"]),
            str(row["identity_label_for_scoring"]),
            str(row["method"]),
        )
    )
    pair_audits.sort(
        key=lambda row: (
            str(row["scenario"]),
            int(row["duplicate_filter_window_s"]),
            int(row["seed"]),
        )
    )
    summary_fields = [
        "run_id",
        "method",
        "paired_trace_id",
        "scenario",
        "duplicate_filter_window_s",
        "seed",
        "identity_label_for_scoring",
        "visible_trace_sha256",
        "probe_event_count",
        *FEATURE_FIELDS,
    ]
    pair_fields = [
        "paired_trace_id",
        "scenario",
        "duplicate_filter_window_s",
        "seed",
        "visible_trace_sha256",
        "visible_trace_equal",
        "probe_event_count_total",
        "initial_probe_comparison_count",
        "initial_probe_pre_resolution_mismatch_count",
        "initial_probe_pre_resolution_equal",
        "new_epoch_first_probe_comparison_count",
        "new_epoch_first_probe_state_mismatch_count",
    ]
    write_csv(args.out / "combined_probe_summary.csv", all_rows, summary_fields)
    write_csv(args.out / "paired_trace_audit.csv", pair_audits, pair_fields)

    effect_rows = aggregate_paired_effects(all_rows)
    effect_fields = [
        "scenario",
        "duplicate_filter_window_s",
        "method",
        "feature",
        "n_pairs",
        "bonded_mean",
        "nonbonded_mean",
        "paired_difference_mean",
        "paired_difference_sd",
        "paired_difference_ci95_low",
        "paired_difference_ci95_high",
        "paired_effect_dz",
        "ks_distance",
        "wasserstein_distance",
    ]
    write_csv(args.out / "table_m12_paired_effects.csv", effect_rows, effect_fields)

    classifier_rows = aggregate_classifier(all_rows)
    classifier_fields = [
        "scenario",
        "duplicate_filter_window_s",
        "method",
        "n_pairs",
        "feature_set_name",
        "feature_set",
        "grouped_cv_auc",
        "bootstrap_ci95_low",
        "bootstrap_ci95_high",
        "permutation_auc_mean",
        "permutation_ci95_low",
        "permutation_ci95_high",
        "status",
    ]
    write_csv(args.out / "table_m12_classifier_summary.csv", classifier_rows, classifier_fields)

    manifest = {
        "suite": "m12_privacy_sidechannel",
        "status": "smoke" if args.smoke else "complete",
        "source_commit": get_git_commit(),
        "method_whitelist": METHODS,
        "seeds": seeds,
        "load_scenarios": LOADS,
        "duplicate_filter_windows_s": [0, 60],
        "paired_job_count": len(jobs),
        "variant_run_count": len(jobs) * 2,
        "summary_row_count": len(all_rows),
        "feature_fields": FEATURE_FIELDS,
        "feature_sets": {
            "external_delay_defer_proxy": EXTERNAL_PROXY_FIELDS,
            "internal_path_diagnostic": INTERNAL_DIAGNOSTIC_FIELDS,
        },
        "classifier": {
            "model": "numpy logistic regression",
            "cv": "5-fold grouped by paired_trace_id",
            "bootstrap_unit": "paired_trace_id",
            "permutation_unit": "paired_trace_id within-pair label shuffle",
        },
        "all_visible_trace_audits_passed": all(
            bool(row["visible_trace_equal"]) for row in pair_audits
        ),
        "all_initial_probe_pre_resolution_audits_passed": all(
            bool(row["initial_probe_pre_resolution_equal"]) for row in pair_audits
        ),
        "source_files_sha256": {
            "run_m12_privacy_sidechannel.py": file_sha256(Path(__file__)),
            "review260715_stats.py": file_sha256(SCRIPT_DIR / "review260715_stats.py"),
            "review260715_suite_common.py": file_sha256(
                SCRIPT_DIR / "review260715_suite_common.py"
            ),
            "rpa_sim.py": file_sha256(SRC_DIR / "rpa_sim.py"),
        },
    }
    write_json(args.out / "matrix_manifest.json", manifest)


if __name__ == "__main__":
    main()
