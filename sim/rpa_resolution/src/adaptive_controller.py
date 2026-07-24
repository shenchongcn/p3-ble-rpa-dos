"""Small Hedge controller used by the L2 replay/adaptive scaffold."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AdaptiveAction:
    action_id: str
    persist_k: int
    persist_reserve: int
    gate_mode: str = "count"


def default_action_grid() -> list[AdaptiveAction]:
    return [
        AdaptiveAction(f"k{k}_r{reserve}", k, reserve)
        for k in (1, 2, 3)
        for reserve in (50, 100, 200)
    ]


def parse_action_grid(raw_actions: list[dict[str, Any]] | None = None) -> list[AdaptiveAction]:
    if not raw_actions:
        return default_action_grid()
    actions: list[AdaptiveAction] = []
    for idx, raw in enumerate(raw_actions):
        persist_k = max(1, int(raw["persist_k"]))
        persist_reserve = max(0, int(raw["persist_reserve"]))
        gate_mode = str(raw.get("gate_mode", "count"))
        action_id = str(raw.get("action_id", f"k{persist_k}_r{persist_reserve}_{idx}"))
        actions.append(AdaptiveAction(action_id, persist_k, persist_reserve, gate_mode))
    if not actions:
        raise ValueError("adaptive action grid must not be empty")
    return actions


class HedgeController:
    def __init__(self, actions: list[AdaptiveAction], eta: float = 0.5) -> None:
        if not actions:
            raise ValueError("HedgeController requires at least one action")
        self.actions = list(actions)
        self.eta = float(eta)
        self.weights = {action.action_id: 1.0 for action in self.actions}
        self.round_index = 0

    def probabilities(self) -> dict[str, float]:
        total = sum(self.weights.values())
        if total <= 0.0:
            return {action.action_id: 1.0 / len(self.actions) for action in self.actions}
        return {action_id: weight / total for action_id, weight in self.weights.items()}

    def select(self) -> AdaptiveAction:
        probabilities = self.probabilities()
        return max(self.actions, key=lambda action: (probabilities[action.action_id], -self.actions.index(action)))

    def update(self, losses: dict[str, float]) -> None:
        for action in self.actions:
            loss = min(1.0, max(0.0, float(losses[action.action_id])))
            self.weights[action.action_id] *= math.exp(-self.eta * loss)
        self.round_index += 1

    def update_selected(self, action_id: str, loss: float) -> None:
        self.weights[action_id] *= math.exp(-self.eta * min(1.0, max(0.0, float(loss))))
        self.round_index += 1
