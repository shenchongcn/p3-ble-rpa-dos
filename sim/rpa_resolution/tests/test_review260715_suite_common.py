#!/usr/bin/env python3

from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

from review260715_suite_common import should_skip_run, validate_completed_run  # noqa: E402
from rpa_sim import config_hash  # noqa: E402


class CompletionCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.temp.name)
        self.config = {
            "schema_version": "m2.v1",
            "run_id": "resume_test",
            "seed": 20260715,
            "methods": ["P3-Persist", "BudgetDoS"],
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_complete_output(self) -> None:
        manifest = {
            "run_id": self.config["run_id"],
            "config_hash": config_hash(self.config),
            "methods": self.config["methods"],
        }
        (self.run_dir / "run_manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        with (self.run_dir / "summary.csv").open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["run_id", "method"], lineterminator="\n")
            writer.writeheader()
            for method in self.config["methods"]:
                writer.writerow({"run_id": self.config["run_id"], "method": method})

    def test_exact_completed_run_is_skipped(self) -> None:
        self.write_complete_output()
        self.assertTrue(should_skip_run(self.config, self.run_dir))
        self.assertEqual(validate_completed_run(self.config, self.run_dir).reason, "complete")

    def test_missing_summary_is_not_skipped(self) -> None:
        self.write_complete_output()
        (self.run_dir / "summary.csv").unlink()
        check = validate_completed_run(self.config, self.run_dir)
        self.assertFalse(check.complete)
        self.assertEqual(check.reason, "missing summary.csv")

    def test_changed_config_is_not_skipped(self) -> None:
        self.write_complete_output()
        changed = dict(self.config)
        changed["seed"] = 20260716
        check = validate_completed_run(changed, self.run_dir)
        self.assertFalse(check.complete)
        self.assertEqual(check.reason, "manifest config_hash mismatch")

    def test_method_order_or_set_mismatch_is_not_skipped(self) -> None:
        self.write_complete_output()
        changed = dict(self.config)
        changed["methods"] = ["BudgetDoS", "P3-Persist"]
        check = validate_completed_run(changed, self.run_dir)
        self.assertFalse(check.complete)
        self.assertIn(check.reason, {"manifest config_hash mismatch", "manifest methods mismatch"})

    def test_partial_summary_is_not_skipped(self) -> None:
        self.write_complete_output()
        with (self.run_dir / "summary.csv").open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["run_id", "method"], lineterminator="\n")
            writer.writeheader()
            writer.writerow({"run_id": self.config["run_id"], "method": "P3-Persist"})
        check = validate_completed_run(self.config, self.run_dir)
        self.assertFalse(check.complete)
        self.assertEqual(check.reason, "summary row count mismatch")


if __name__ == "__main__":
    unittest.main()
