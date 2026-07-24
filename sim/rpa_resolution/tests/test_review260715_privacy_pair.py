#!/usr/bin/env python3

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from run_m12_privacy_sidechannel import (  # noqa: E402
    EXTERNAL_PROXY_FIELDS,
    FEATURE_FIELDS,
    INTERNAL_DIAGNOSTIC_FIELDS,
    base_config,
    build_paired_traces,
    run_pair_job,
    visible_trace_hash,
)


class PrivacyPairTests(unittest.TestCase):
    def small_pair_config(self) -> dict[str, object]:
        config = base_config("no_attack", 0, 20260610)
        config.update(
            {
                "run_id": "m12_pair_test",
                "duration_s": 60,
                "warmup_s": 0,
                "num_bonded": 64,
                "rl_capacity": 8,
                "background_rpa_rate_per_min": 20.0,
                "attack_rpa_rate_per_min": 0.0,
            }
        )
        return config

    def test_visible_trace_hashes_match_and_hidden_labels_are_isolated(self) -> None:
        _, bonded, nonbonded, trace_hash, probe_count = build_paired_traces(
            self.small_pair_config()
        )
        self.assertEqual(visible_trace_hash(bonded), trace_hash)
        self.assertEqual(visible_trace_hash(nonbonded), trace_hash)
        self.assertGreater(probe_count, 0)
        probe_pairs = [
            (bonded_event, nonbonded_event)
            for bonded_event, nonbonded_event in zip(bonded, nonbonded)
            if bonded_event.rpa_value.startswith("PRIVPROBE:")
        ]
        self.assertTrue(probe_pairs)
        self.assertTrue(all(a.source_type == "legit_bonded" for a, _ in probe_pairs))
        self.assertTrue(all(b.source_type == "background" for _, b in probe_pairs))
        self.assertTrue(all(a.rpa_value == b.rpa_value for a, b in probe_pairs))

    def test_pair_job_passes_initial_pre_resolution_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = run_pair_job(
                {
                    "pair_config": self.small_pair_config(),
                    "out_root": str(root / "results"),
                    "config_root": str(root / "configs"),
                }
            )
            audit = result["pair_audit"]
            self.assertTrue(audit["visible_trace_equal"])
            self.assertTrue(audit["initial_probe_pre_resolution_equal"])
            self.assertEqual(audit["initial_probe_pre_resolution_mismatch_count"], 0)
            rows = result["summary_rows"]
            self.assertEqual(len(rows), 6)
            self.assertEqual({row["identity_label_for_scoring"] for row in rows}, {"bonded", "nonbonded"})
            self.assertEqual({row["paired_trace_id"] for row in rows}, {"m12_pair_test"})
            forbidden = {"source_type", "matched", "device_id", "irk_id"}
            self.assertFalse(forbidden.intersection(FEATURE_FIELDS))
            self.assertEqual(
                EXTERNAL_PROXY_FIELDS, ["defer_rate", "mean_delay_ms", "p95_delay_ms"]
            )
            self.assertFalse(set(EXTERNAL_PROXY_FIELDS).intersection(INTERNAL_DIAGNOSTIC_FIELDS))


if __name__ == "__main__":
    unittest.main()
