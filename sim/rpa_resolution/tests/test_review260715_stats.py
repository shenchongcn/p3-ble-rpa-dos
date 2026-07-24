#!/usr/bin/env python3

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from review260715_stats import (  # noqa: E402
    auc_score,
    grouped_bootstrap_auc,
    grouped_oof_predictions,
    grouped_permutation_auc,
    ks_distance,
    wasserstein_1d,
)


class Review260715StatsTests(unittest.TestCase):
    def paired_data(self) -> tuple[np.ndarray, np.ndarray, list[str]]:
        features = []
        labels = []
        groups = []
        for idx in range(20):
            groups.extend([f"pair_{idx:02d}", f"pair_{idx:02d}"])
            labels.extend([0, 1])
            features.extend(
                [
                    [0.05 + idx * 0.001, 0.10],
                    [0.85 + idx * 0.001, 0.90],
                ]
            )
        return np.asarray(features), np.asarray(labels), groups

    def test_auc_handles_ties(self) -> None:
        labels = np.asarray([0, 0, 1, 1])
        scores = np.asarray([0.1, 0.5, 0.5, 0.9])
        self.assertAlmostEqual(auc_score(labels, scores), 0.875)

    def test_grouped_oof_keeps_pairs_together_and_separates_signal(self) -> None:
        features, labels, groups = self.paired_data()
        predictions = grouped_oof_predictions(features, labels, groups, folds=5)
        self.assertGreater(auc_score(labels, predictions), 0.99)

    def test_group_bootstrap_and_permutation(self) -> None:
        features, labels, groups = self.paired_data()
        predictions = grouped_oof_predictions(features, labels, groups, folds=5)
        low, high = grouped_bootstrap_auc(labels, predictions, groups, iterations=200)
        self.assertGreater(low, 0.95)
        self.assertLessEqual(high, 1.0)
        mean, perm_low, perm_high = grouped_permutation_auc(
            labels, predictions, groups, iterations=400
        )
        self.assertLess(abs(mean - 0.5), 0.06)
        self.assertLess(perm_low, 0.5)
        self.assertGreater(perm_high, 0.5)

    def test_distribution_distances(self) -> None:
        first = np.asarray([0.0, 0.0, 1.0, 1.0])
        second = np.asarray([1.0, 1.0, 2.0, 2.0])
        self.assertAlmostEqual(ks_distance(first, second), 0.5)
        self.assertGreater(wasserstein_1d(first, second), 0.9)


if __name__ == "__main__":
    unittest.main()
