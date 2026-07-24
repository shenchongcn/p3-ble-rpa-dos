#!/usr/bin/env python3
"""Small auditable statistics helpers for review260715 experiments.

This module intentionally depends only on NumPy. It provides the fixed simple
logistic-regression sensitivity analysis specified in the revision plan and
keeps cross-validation/bootstrap units at the paired-trace group level.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import numpy as np


@dataclass(frozen=True)
class LogisticModel:
    mean: np.ndarray
    scale: np.ndarray
    weights: np.ndarray
    intercept: float


def _sigmoid(values: np.ndarray) -> np.ndarray:
    clipped = np.clip(values, -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-clipped))


def fit_logistic(
    features: np.ndarray,
    labels: np.ndarray,
    *,
    l2: float = 1.0,
    learning_rate: float = 0.1,
    steps: int = 2000,
) -> LogisticModel:
    x = np.asarray(features, dtype=float)
    y = np.asarray(labels, dtype=float)
    if x.ndim != 2 or y.ndim != 1 or len(x) != len(y):
        raise ValueError("invalid feature/label shapes")
    if len(np.unique(y)) != 2:
        raise ValueError("logistic regression requires two label classes")
    mean = x.mean(axis=0)
    scale = x.std(axis=0)
    scale = np.where(scale > 1e-12, scale, 1.0)
    z = (x - mean) / scale
    weights = np.zeros(z.shape[1], dtype=float)
    intercept = 0.0
    n = float(len(z))
    for _ in range(steps):
        probabilities = _sigmoid(z @ weights + intercept)
        residual = probabilities - y
        grad_w = (z.T @ residual) / n + (l2 / n) * weights
        grad_b = float(residual.mean())
        weights -= learning_rate * grad_w
        intercept -= learning_rate * grad_b
    return LogisticModel(mean, scale, weights, intercept)


def predict_logistic(model: LogisticModel, features: np.ndarray) -> np.ndarray:
    x = np.asarray(features, dtype=float)
    z = (x - model.mean) / model.scale
    return _sigmoid(z @ model.weights + model.intercept)


def auc_score(labels: np.ndarray, scores: np.ndarray) -> float:
    y = np.asarray(labels, dtype=int)
    s = np.asarray(scores, dtype=float)
    positive = s[y == 1]
    negative = s[y == 0]
    if not len(positive) or not len(negative):
        raise ValueError("AUC requires both classes")
    comparisons = positive[:, None] - negative[None, :]
    return float((np.sum(comparisons > 0) + 0.5 * np.sum(comparisons == 0)) / comparisons.size)


def ks_distance(first: np.ndarray, second: np.ndarray) -> float:
    a = np.sort(np.asarray(first, dtype=float))
    b = np.sort(np.asarray(second, dtype=float))
    if not len(a) or not len(b):
        raise ValueError("KS distance requires non-empty samples")
    points = np.sort(np.concatenate([a, b]))
    cdf_a = np.searchsorted(a, points, side="right") / len(a)
    cdf_b = np.searchsorted(b, points, side="right") / len(b)
    return float(np.max(np.abs(cdf_a - cdf_b)))


def wasserstein_1d(first: np.ndarray, second: np.ndarray) -> float:
    a = np.sort(np.asarray(first, dtype=float))
    b = np.sort(np.asarray(second, dtype=float))
    if not len(a) or not len(b):
        raise ValueError("Wasserstein distance requires non-empty samples")
    quantiles = np.linspace(0.0, 1.0, max(len(a), len(b)) * 4 + 1)
    return float(np.mean(np.abs(np.quantile(a, quantiles) - np.quantile(b, quantiles))))


def grouped_oof_predictions(
    features: np.ndarray,
    labels: np.ndarray,
    groups: Iterable[str],
    *,
    folds: int = 5,
) -> np.ndarray:
    x = np.asarray(features, dtype=float)
    y = np.asarray(labels, dtype=int)
    group_values = np.asarray(list(groups), dtype=object)
    unique_groups = np.asarray(sorted(set(group_values.tolist())), dtype=object)
    if folds < 2 or len(unique_groups) < folds:
        raise ValueError("not enough groups for requested folds")
    predictions = np.full(len(y), np.nan, dtype=float)
    for fold in range(folds):
        test_groups = set(unique_groups[fold::folds].tolist())
        test_mask = np.asarray([group in test_groups for group in group_values], dtype=bool)
        train_mask = ~test_mask
        if len(np.unique(y[train_mask])) != 2 or len(np.unique(y[test_mask])) != 2:
            raise ValueError("each grouped fold must contain both classes")
        model = fit_logistic(x[train_mask], y[train_mask])
        predictions[test_mask] = predict_logistic(model, x[test_mask])
    if np.isnan(predictions).any():
        raise RuntimeError("grouped OOF predictions incomplete")
    return predictions


def grouped_bootstrap_auc(
    labels: np.ndarray,
    scores: np.ndarray,
    groups: Iterable[str],
    *,
    iterations: int = 2000,
    seed: int = 20260715,
) -> tuple[float, float]:
    y = np.asarray(labels, dtype=int)
    s = np.asarray(scores, dtype=float)
    group_values = np.asarray(list(groups), dtype=object)
    unique_groups = np.asarray(sorted(set(group_values.tolist())), dtype=object)
    indices_by_group = {
        group: np.flatnonzero(group_values == group) for group in unique_groups.tolist()
    }
    rng = np.random.default_rng(seed)
    values: list[float] = []
    for _ in range(iterations):
        sampled = rng.choice(unique_groups, size=len(unique_groups), replace=True)
        indices = np.concatenate([indices_by_group[group] for group in sampled.tolist()])
        if len(np.unique(y[indices])) == 2:
            values.append(auc_score(y[indices], s[indices]))
    if not values:
        raise RuntimeError("no valid bootstrap samples")
    low, high = np.quantile(np.asarray(values), [0.025, 0.975])
    return float(low), float(high)


def grouped_permutation_auc(
    labels: np.ndarray,
    scores: np.ndarray,
    groups: Iterable[str],
    *,
    iterations: int = 2000,
    seed: int = 20260716,
) -> tuple[float, float, float]:
    y = np.asarray(labels, dtype=int)
    s = np.asarray(scores, dtype=float)
    group_values = np.asarray(list(groups), dtype=object)
    unique_groups = sorted(set(group_values.tolist()))
    indices_by_group = {group: np.flatnonzero(group_values == group) for group in unique_groups}
    rng = np.random.default_rng(seed)
    values: list[float] = []
    for _ in range(iterations):
        permuted = y.copy()
        for group in unique_groups:
            indices = indices_by_group[group]
            permuted[indices] = rng.permutation(permuted[indices])
        values.append(auc_score(permuted, s))
    array = np.asarray(values)
    low, high = np.quantile(array, [0.025, 0.975])
    return float(array.mean()), float(low), float(high)
