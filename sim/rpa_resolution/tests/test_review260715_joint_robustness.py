#!/usr/bin/env python3
"""Structural checks for the M13 joint-robustness matrix."""

from __future__ import annotations

import sys
import unittest
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from run_m13_joint_robustness import (  # noqa: E402
    METHODS,
    SEEDS_CONFIRM,
    SEEDS_SCREEN,
    configs,
)


class JointRobustnessMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.configs = configs(SEEDS_SCREEN)

    def test_matrix_has_expected_size_and_unique_ids(self) -> None:
        self.assertEqual(len(self.configs), 300)
        self.assertEqual(len({config["run_id"] for config in self.configs}), 300)

    def test_main_matrix_is_complete(self) -> None:
        main = [config for config in self.configs if config["m13_experiment"] == "main"]
        self.assertEqual(len(main), 270)
        cells = Counter(
            (
                config["m13_epoch_min"],
                config["m13_loss_rate"],
                config["m13_density"],
            )
            for config in main
        )
        self.assertEqual(len(cells), 27)
        self.assertEqual(set(cells.values()), {len(SEEDS_SCREEN)})
        self.assertTrue(all(config["attack_rpa_rate_per_min"] == 10000.0 for config in main))

    def test_controls_are_distinct_and_use_expected_attack_load(self) -> None:
        controls = [config for config in self.configs if config["m13_experiment"] != "main"]
        self.assertEqual(len(controls), 30)
        self.assertEqual(
            Counter(config["m13_experiment"] for config in controls),
            {
                "control_no_attack_baseline": len(SEEDS_SCREEN),
                "control_no_attack_worst": len(SEEDS_SCREEN),
                "control_repeated_benign_worst": len(SEEDS_SCREEN),
            },
        )
        no_attack = [
            config
            for config in controls
            if config["m13_experiment"] in {
                "control_no_attack_baseline",
                "control_no_attack_worst",
            }
        ]
        self.assertTrue(all(config["attack_rpa_rate_per_min"] == 0.0 for config in no_attack))
        repeated = [
            config
            for config in controls
            if config["m13_experiment"] == "control_repeated_benign_worst"
        ]
        self.assertTrue(all(config["attack_rpa_rate_per_min"] == 10000.0 for config in repeated))
        self.assertTrue(all(config["background_address_mode"] == "repeated" for config in repeated))
        self.assertTrue(all(config["background_addr_pool_size"] == 256 for config in repeated))

    def test_all_configs_use_fixed_methods_and_warmup(self) -> None:
        self.assertTrue(all(config["methods"] == METHODS for config in self.configs))
        self.assertTrue(all(config["duration_s"] == 1800 for config in self.configs))
        self.assertTrue(all(config["warmup_s"] == 300 for config in self.configs))
        self.assertTrue(all(config["write_traces"] is False for config in self.configs))
        self.assertTrue(all(config["write_observation_ledger"] is False for config in self.configs))

    def test_confirmation_extends_every_cell_and_control_to_20_seeds(self) -> None:
        confirmed = configs(SEEDS_CONFIRM)
        self.assertEqual(len(confirmed), 600)
        self.assertEqual(len({config["run_id"] for config in confirmed}), 600)
        self.assertEqual(
            Counter(config["m13_experiment"] for config in confirmed),
            {
                "main": 540,
                "control_no_attack_baseline": 20,
                "control_no_attack_worst": 20,
                "control_repeated_benign_worst": 20,
            },
        )


if __name__ == "__main__":
    unittest.main()
