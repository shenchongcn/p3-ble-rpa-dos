#!/usr/bin/env python3
"""Structural checks for the preregistered M14 refinement."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from run_m14_adaptive_refinement import (  # noqa: E402
    CONFIRM_SEEDS,
    FIXED_NEIGHBORS,
    OLD_WORST,
    SCREEN_SEEDS,
    confirm_configs,
    confirm_strategies,
    pool_strategy,
    screen_configs,
    screen_strategies,
    select_top5,
)


class AdaptiveRefinementTests(unittest.TestCase):
    def test_screen_grid_has_168_unique_strategies(self) -> None:
        strategies = screen_strategies()
        self.assertEqual(len(strategies), 168)
        self.assertEqual(len({strategy["attack_strategy"] for strategy in strategies}), 168)

    def test_screen_has_840_p3_only_configs(self) -> None:
        configs = screen_configs()
        self.assertEqual(len(configs), 168 * len(SCREEN_SEEDS))
        self.assertEqual(len({config["run_id"] for config in configs}), len(configs))
        self.assertTrue(all(config["methods"] == ["P3-Persist"] for config in configs))
        self.assertTrue(all(config["duplicate_filter_window_s"] == 60 for config in configs))

    def test_top5_rule_is_mean_then_lexicographic(self) -> None:
        rows = []
        for index, strategy in enumerate(screen_strategies()):
            rows.append(
                {
                    "attack_strategy": strategy["attack_strategy"],
                    "method": "P3-Persist",
                    "attack_aes_amplification_mean": 1000.0 - index,
                }
            )
        rows[0]["attack_aes_amplification_mean"] = 2000.0
        rows[1]["attack_aes_amplification_mean"] = 2000.0
        selected = select_top5(rows)
        tied = sorted([rows[0]["attack_strategy"], rows[1]["attack_strategy"]])
        self.assertEqual([selected[0]["attack_strategy"], selected[1]["attack_strategy"]], tied)

    def test_confirmation_contains_fixed_controls_and_budget_scope(self) -> None:
        rows = []
        excluded = {
            pool_strategy(*OLD_WORST)["attack_strategy"],
            *[pool_strategy(*point)["attack_strategy"] for point in FIXED_NEIGHBORS],
        }
        for strategy in screen_strategies():
            if strategy["attack_strategy"] not in excluded:
                rows.append(
                    {
                        "attack_strategy": strategy["attack_strategy"],
                        "method": "P3-Persist",
                        "attack_aes_amplification_mean": 1000.0 - len(rows),
                    }
                )
            if len(rows) == 5:
                break
        strategies, top5 = confirm_strategies(rows)
        names = {strategy["attack_strategy"] for strategy in strategies}
        self.assertIn("unique", names)
        self.assertIn(pool_strategy(*OLD_WORST)["attack_strategy"], names)
        self.assertTrue(
            all(pool_strategy(*point)["attack_strategy"] in names for point in FIXED_NEIGHBORS)
        )
        self.assertEqual(len(strategies), 12)
        configs = confirm_configs(strategies, top5)
        self.assertEqual(len(configs), len(strategies) * 2 * len(CONFIRM_SEEDS))
        for config in configs:
            if config["attack_strategy"] in top5:
                self.assertEqual(config["methods"], ["P3-Persist", "BudgetDoS"])
            else:
                self.assertEqual(config["methods"], ["P3-Persist"])


if __name__ == "__main__":
    unittest.main()
