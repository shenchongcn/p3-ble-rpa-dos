#!/usr/bin/env python3

from __future__ import annotations

import csv
import hashlib
import json
import random
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rpa_sim import (  # noqa: E402
    AddressEvent,
    MethodState,
    apply_observation_loss,
    build_devices,
    generate_events,
    run,
)


LEGACY_EVENT_HASH = "7e77b3a631196e9603620e7218d7809fee39a6b02e136f5726aa98c1a83a17ee"
LEGACY_SUMMARY_HASH = "63d7d5be1ec9bfaf052c15ee3230d35a698f809ba6cff9498e542ce3f311a6b9"


def base_config() -> dict[str, object]:
    return {
        "schema_version": "m2.v1-draft",
        "run_id": "legacy_fixture",
        "ncs_version": "v3.2.1",
        "seed": 20260530,
        "duration_s": 60,
        "warmup_s": 0,
        "num_bonded": 128,
        "rl_capacity": 16,
        "active_ratio": 0.2,
        "active_skew": 1.1,
        "rpa_rotation_interval_min": 15,
        "legit_adv_rate_per_device_per_min": 1.0,
        "background_rpa_rate_per_min": 100.0,
        "attack_rpa_rate_per_min": 1000.0,
        "non_rpa_ratio": 0.2,
        "rssi_noise_db": 6.0,
        "methods": ["P3-Persist"],
        "zephyr_cache_size": 64,
    }


def generate(config: dict[str, object]) -> list[AddressEvent]:
    rng = random.Random(int(config["seed"]))
    devices = build_devices(config, rng)
    return generate_events(config, devices, rng)


def event_hash(events: list[AddressEvent]) -> str:
    payload = "\n".join(
        json.dumps(event.__dict__, sort_keys=True, separators=(",", ":")) for event in events
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class LegacyCompatibilityTests(unittest.TestCase):
    def test_legacy_event_sequence_is_unchanged(self) -> None:
        events = generate(base_config())
        self.assertEqual(len(events), 1381)
        self.assertEqual(event_hash(events), LEGACY_EVENT_HASH)

    def test_legacy_summary_schema_and_values_are_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            run(base_config(), Path(temp))
            summary = Path(temp) / "summary.csv"
            self.assertEqual(hashlib.sha256(summary.read_bytes()).hexdigest(), LEGACY_SUMMARY_HASH)

    def test_positive_cache_key_uses_visible_rpa_not_identity_label(self) -> None:
        state = MethodState(method="P3-Persist", rl_entries=[])
        bonded = AddressEvent(
            "cache_test", 1, 1000, "legit_bonded", "dev_0001", "rpa", 0, -60.0, 20, "VISIBLE"
        )
        nonbonded = AddressEvent(
            "cache_test", 1, 1000, "background", "", "rpa", 0, -60.0, 20, "VISIBLE"
        )
        self.assertEqual(state.cache_key(bonded), state.cache_key(nonbonded))


class ObservationLossTests(unittest.TestCase):
    def test_loss_zero_preserves_all_events(self) -> None:
        config = base_config()
        config["observation_loss_rate"] = 0.0
        events = generate(config)
        observed, ledger = apply_observation_loss(events, config)
        self.assertEqual(events, observed)
        self.assertEqual(len(events), len(ledger))
        self.assertFalse(any(row["dropped"] for row in ledger))

    def test_loss_zero_preserves_all_legacy_summary_fields(self) -> None:
        legacy_config = base_config()
        loss_config = base_config()
        loss_config["run_id"] = "loss_zero"
        loss_config["observation_loss_rate"] = 0.0
        with tempfile.TemporaryDirectory() as legacy_temp, tempfile.TemporaryDirectory() as loss_temp:
            run(legacy_config, Path(legacy_temp))
            run(loss_config, Path(loss_temp))
            with (Path(legacy_temp) / "summary.csv").open(encoding="utf-8", newline="") as f:
                legacy_row = next(csv.DictReader(f))
            with (Path(loss_temp) / "summary.csv").open(encoding="utf-8", newline="") as f:
                loss_row = next(csv.DictReader(f))
            for key, value in legacy_row.items():
                if key == "run_id":
                    continue
                self.assertEqual(loss_row[key], value, key)

    def test_loss_one_drops_all_events_and_reports_dual_denominators(self) -> None:
        config = base_config()
        config["run_id"] = "loss_one"
        config["observation_loss_rate"] = 1.0
        with tempfile.TemporaryDirectory() as temp:
            run(config, Path(temp))
            with (Path(temp) / "summary.csv").open(encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertGreater(int(row["generated_event_count"]), 0)
            self.assertEqual(int(row["observed_event_count"]), 0)
            self.assertEqual(int(row["dropped_event_count"]), int(row["generated_event_count"]))
            self.assertEqual(float(row["offered_legit_resolution_rate"]), 0.0)
            self.assertEqual(float(row["observed_legit_resolution_rate"]), 0.0)
            self.assertEqual(float(row["false_defer_observed_legit_rate"]), 0.0)

    def test_fixed_seed_produces_same_drop_set(self) -> None:
        config = base_config()
        config["observation_loss_rate"] = 0.4
        events = generate(config)
        _, first = apply_observation_loss(events, config)
        _, second = apply_observation_loss(events, config)
        first_ids = [row["event_id"] for row in first if row["dropped"]]
        second_ids = [row["event_id"] for row in second if row["dropped"]]
        self.assertEqual(first_ids, second_ids)

    def test_same_rule_has_similar_rates_across_source_types(self) -> None:
        source_types = ["legit_bonded", "background", "attack"]
        events = []
        event_id = 0
        for source_type in source_types:
            for _ in range(3000):
                events.append(
                    AddressEvent(
                        run_id="loss_balance",
                        event_id=event_id,
                        ts_ms=event_id,
                        source_type=source_type,
                        device_id="dev" if source_type == "legit_bonded" else "",
                        addr_type="rpa",
                        rpa_epoch=0,
                        rssi_dbm=-70.0,
                        payload_len=20,
                        rpa_value=f"R{event_id}",
                    )
                )
                event_id += 1
        config = {"seed": 20260715, "observation_loss_rate": 0.3}
        _, ledger = apply_observation_loss(events, config)
        totals = Counter(row["source_type"] for row in ledger)
        dropped = Counter(row["source_type"] for row in ledger if row["dropped"])
        for source_type in source_types:
            rate = dropped[source_type] / totals[source_type]
            self.assertLess(abs(rate - 0.3), 0.035)


class RepeatedBenignTests(unittest.TestCase):
    def test_default_background_values_remain_unique(self) -> None:
        events = generate(base_config())
        values = [event.rpa_value for event in events if event.source_type == "background"]
        self.assertEqual(len(values), len(set(values)))

    def test_repeated_mode_generates_reuse_without_affecting_event_count(self) -> None:
        unique_config = base_config()
        repeated_config = base_config()
        repeated_config.update(
            {
                "background_address_mode": "repeated",
                "background_addr_pool_size": 4,
                "background_repeats_per_addr": 2,
                "background_repeat_interval_s": 15.0,
            }
        )
        unique_events = generate(unique_config)
        repeated_events = generate(repeated_config)
        self.assertEqual(len(unique_events), len(repeated_events))
        repeated_values = [
            event.rpa_value for event in repeated_events if event.source_type == "background"
        ]
        self.assertLess(len(set(repeated_values)), len(repeated_values))
        self.assertTrue(set(repeated_values).issubset({"B0", "B1", "B2", "B3"}))


if __name__ == "__main__":
    unittest.main()
