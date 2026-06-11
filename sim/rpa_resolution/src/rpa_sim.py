#!/usr/bin/env python3
"""Event-driven BLE RPA resolution simulator for M2.

The model is intentionally lightweight. It counts AES-equivalent IRK match
attempts and preserves the privacy boundary: no method can identify an unknown
RPA without paying IRK/AES attempts.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import statistics
import subprocess
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


METHODS = (
    "FullScan-Host",
    "StaticRL",
    "ZephyrCache",
    "Random-RL",
    "LRU-RL",
    "Freq-RL",
    "TrustOnly",
    "BudgetDoS",
    "AdaptiveRateLimit",
    "Oracle-Offline",
    "P3-Persist",
    "P3-NoPersist",
    "P3-NoCache",
    "P3-NoBudget",
    "P3-NoTrust",
    "P3-NoRL",
)

P3_FAMILY = ("P3-Persist", "P3-NoPersist", "P3-NoCache", "P3-NoBudget", "P3-NoTrust", "P3-NoRL")
CACHE_METHODS = ("ZephyrCache", "P3-Persist", "P3-NoPersist", "P3-NoBudget", "P3-NoTrust", "P3-NoRL")
BUDGET_METHODS = ("BudgetDoS", "AdaptiveRateLimit", "P3-Persist", "P3-NoPersist", "P3-NoCache", "P3-NoTrust", "P3-NoRL")
TRUST_METHODS = ("TrustOnly", "P3-Persist", "P3-NoPersist", "P3-NoCache", "P3-NoBudget", "P3-NoRL")
DYNAMIC_RL_METHODS = (
    "Random-RL",
    "LRU-RL",
    "Freq-RL",
    "TrustOnly",
    "BudgetDoS",
    "P3-Persist",
    "P3-NoPersist",
    "P3-NoCache",
    "P3-NoBudget",
    "P3-NoTrust",
)


@dataclass(frozen=True)
class Device:
    device_id: str
    irk_id: str
    is_bonded: bool
    activity_weight: float
    rpa_rotation_interval_s: int
    rssi_mean_dbm: float


@dataclass(frozen=True)
class AddressEvent:
    run_id: str
    event_id: int
    ts_ms: int
    source_type: str
    device_id: str
    addr_type: str
    rpa_epoch: int
    rssi_dbm: float
    payload_len: int
    rpa_value: str = ""


@dataclass
class Decision:
    run_id: str
    method: str
    event_id: int
    action: str
    aes_attempts: int
    matched: bool
    matched_device_id: str
    deferred: bool
    delay_ms: int
    false_defer: bool
    drop_reason: str
    admission_path: str = ""


@dataclass
class MethodState:
    method: str
    rl_entries: list[str]
    cache_size: int = 64
    rpa_cache: OrderedDict[str, str] = field(default_factory=OrderedDict)
    activity_counts: dict[str, int] = field(default_factory=dict)
    last_seen: dict[str, int] = field(default_factory=dict)
    budget_window_s: int = 60
    budget_per_window: int = 100
    current_budget_window: int = -1
    budget_used: int = 0
    persist_denied: dict[str, int] = field(default_factory=dict)
    persist_reserve_window: int = -1
    persist_reserve_used: int = 0
    persist_reserve: int = 0
    persist_k: int = 1
    duplicate_filter_window_s: int = 0
    df_seen: set[tuple[int, str]] = field(default_factory=set)
    resolved_rpa_values: set[str] = field(default_factory=set)

    def cache_key(self, event: AddressEvent) -> str:
        return f"{event.source_type}:{event.device_id}:{event.rpa_epoch}"

    def get_cache(self, event: AddressEvent) -> str | None:
        key = self.cache_key(event)
        value = self.rpa_cache.get(key)
        if value is not None:
            self.rpa_cache.move_to_end(key)
        return value

    def put_cache(self, event: AddressEvent, matched_device_id: str) -> None:
        # Cache only positive RPA->identity resolutions. Unknown miss caching is
        # a different mechanism with privacy and TTL implications, so it must
        # not be part of the ZephyrCache baseline.
        if self.cache_size <= 0 or not matched_device_id:
            return
        if event.rpa_value:
            self.resolved_rpa_values.add(event.rpa_value)
        key = self.cache_key(event)
        self.rpa_cache[key] = matched_device_id
        self.rpa_cache.move_to_end(key)
        while len(self.rpa_cache) > self.cache_size:
            self.rpa_cache.popitem(last=False)


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def get_git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def config_hash(config: dict[str, Any]) -> str:
    payload = json.dumps(config, sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def weighted_index(rng: random.Random, weights: list[float]) -> int:
    total = sum(weights)
    if total <= 0:
        return rng.randrange(len(weights))
    pick = rng.random() * total
    acc = 0.0
    for idx, weight in enumerate(weights):
        acc += weight
        if pick <= acc:
            return idx
    return len(weights) - 1


def poisson_sample(rng: random.Random, lam: float) -> int:
    if lam <= 0:
        return 0
    if lam < 30.0:
        threshold = math.exp(-lam)
        k = 0
        product = 1.0
        while product > threshold:
            k += 1
            product *= rng.random()
        return k - 1
    return max(0, int(round(rng.gauss(lam, math.sqrt(lam)))))


def build_devices(config: dict[str, Any], rng: random.Random) -> list[Device]:
    num_bonded = int(config["num_bonded"])
    skew = float(config.get("active_skew", 1.1))
    rotation_s = int(float(config["rpa_rotation_interval_min"]) * 60)
    devices = []
    for idx in range(num_bonded):
        rank = idx + 1
        weight = 1.0 if skew <= 0 else 1.0 / (rank ** skew)
        devices.append(
            Device(
                device_id=f"dev_{idx:04d}",
                irk_id=f"irk_{idx:04d}",
                is_bonded=True,
                activity_weight=weight,
                rpa_rotation_interval_s=rotation_s,
                rssi_mean_dbm=rng.uniform(-78.0, -45.0),
            )
        )
    return devices


def generate_events(config: dict[str, Any], devices: list[Device], rng: random.Random) -> list[AddressEvent]:
    run_id = str(config["run_id"])
    duration_s = int(config["duration_s"])
    non_rpa_ratio = float(config.get("non_rpa_ratio", 0.0))
    rssi_noise = float(config.get("rssi_noise_db", 6.0))
    active_count = max(1, int(round(len(devices) * float(config.get("active_ratio", 0.2)))))
    active_devices = devices[:active_count]
    weights = [d.activity_weight for d in active_devices]

    legit_rate = float(config.get("legit_adv_rate_per_device_per_min", 1.0))
    legit_burst_rate = float(config.get("legit_burst_rate_per_min", 0.0))
    legit_burst_start_s = int(config.get("legit_burst_start_s", duration_s + 1))
    legit_burst_duration_s = int(config.get("legit_burst_duration_s", 0))
    background_rate = float(config.get("background_rpa_rate_per_min", 0.0))
    attack_rate = float(config.get("attack_rpa_rate_per_min", 0.0))
    unique_attack_rpa = bool(config.get("unique_attack_rpa", True))
    attack_rotation_s = max(
        1,
        int(float(config.get("attack_rotation_s", float(config["rpa_rotation_interval_min"]) * 60))),
    )
    attack_addr_pool_size = max(0, int(config.get("attack_addr_pool_size", 0)))
    attack_repeats_per_addr = max(1, int(config.get("attack_repeats_per_addr", 1)))
    attack_repeat_interval_s = max(0.0, float(config.get("attack_repeat_interval_s", 0.0)))

    events: list[AddressEvent] = []
    event_id = 0
    attack_slot_counts: dict[int, int] = {}
    for second in range(duration_s):
        minute_factor = 1.0 / 60.0
        burst_active = legit_burst_start_s <= second < legit_burst_start_s + legit_burst_duration_s
        effective_legit_rate = legit_rate + (legit_burst_rate if burst_active else 0.0)
        legit_count = poisson_sample(rng, active_count * effective_legit_rate * minute_factor)
        background_count = poisson_sample(rng, background_rate * minute_factor)
        attack_count = poisson_sample(rng, attack_rate * minute_factor)
        total_rpa_count = legit_count + background_count + attack_count
        non_rpa_count = poisson_sample(rng, total_rpa_count * non_rpa_ratio)

        for _ in range(legit_count):
            device = active_devices[weighted_index(rng, weights)]
            ts_ms = second * 1000 + rng.randrange(1000)
            rpa_epoch = second // device.rpa_rotation_interval_s
            events.append(
                AddressEvent(
                    run_id=run_id,
                    event_id=event_id,
                    ts_ms=ts_ms,
                    source_type="legit_bonded",
                    device_id=device.device_id,
                    addr_type="rpa",
                    rpa_epoch=rpa_epoch,
                    rssi_dbm=round(rng.gauss(device.rssi_mean_dbm, rssi_noise), 2),
                    payload_len=rng.randint(12, 31),
                    rpa_value=f"L{device.device_id}:{rpa_epoch}",
                )
            )
            event_id += 1

        for _ in range(background_count):
            ts_ms = second * 1000 + rng.randrange(1000)
            rpa_epoch = second // max(1, int(float(config["rpa_rotation_interval_min"]) * 60))
            events.append(
                AddressEvent(
                    run_id=run_id,
                    event_id=event_id,
                    ts_ms=ts_ms,
                    source_type="background",
                    device_id="",
                    addr_type="rpa",
                    rpa_epoch=rpa_epoch,
                    rssi_dbm=round(rng.gauss(-82.0, rssi_noise), 2),
                    payload_len=rng.randint(8, 31),
                    rpa_value=f"B{event_id}",
                )
            )
            event_id += 1

        for _ in range(attack_count):
            ts_ms = second * 1000 + rng.randrange(1000)
            if unique_attack_rpa:
                rpa_epoch = event_id
                attack_rpa_value = f"A{event_id}"
            elif attack_addr_pool_size <= 0 or attack_repeat_interval_s <= 0.0:
                rpa_epoch = second // attack_rotation_s
                attack_rpa_value = f"A{rpa_epoch}"
            else:
                attack_slot = int(second // attack_repeat_interval_s)
                attack_seq_in_slot = attack_slot_counts.get(attack_slot, 0)
                attack_slot_counts[attack_slot] = attack_seq_in_slot + 1
                addr_index = (attack_seq_in_slot // attack_repeats_per_addr) % attack_addr_pool_size
                rpa_epoch = attack_slot
                attack_rpa_value = f"A{addr_index}"
            events.append(
                AddressEvent(
                    run_id=run_id,
                    event_id=event_id,
                    ts_ms=ts_ms,
                    source_type="attack",
                    device_id="",
                    addr_type="rpa",
                    rpa_epoch=rpa_epoch,
                    rssi_dbm=round(rng.gauss(-70.0, rssi_noise), 2),
                    payload_len=rng.randint(8, 31),
                    rpa_value=attack_rpa_value,
                )
            )
            event_id += 1

        for _ in range(non_rpa_count):
            ts_ms = second * 1000 + rng.randrange(1000)
            events.append(
                AddressEvent(
                    run_id=run_id,
                    event_id=event_id,
                    ts_ms=ts_ms,
                    source_type="non_rpa",
                    device_id="",
                    addr_type="non_rpa",
                    rpa_epoch=0,
                    rssi_dbm=round(rng.gauss(-75.0, rssi_noise), 2),
                    payload_len=rng.randint(8, 31),
                    rpa_value="",
                )
            )
            event_id += 1

    events.sort(key=lambda e: (e.ts_ms, e.event_id))
    return [AddressEvent(**{**event.__dict__, "event_id": idx}) for idx, event in enumerate(events)]


def init_state(method: str, config: dict[str, Any], devices: list[Device]) -> MethodState:
    capacity = int(config["rl_capacity"])
    rl_entries = [device.device_id for device in devices[:capacity]]
    if method in DYNAMIC_RL_METHODS:
        sorted_devices = sorted(devices, key=lambda d: d.activity_weight, reverse=True)
        rl_entries = [device.device_id for device in sorted_devices[:capacity]]
    return MethodState(
        method=method,
        rl_entries=rl_entries,
        cache_size=int(config.get("zephyr_cache_size", 64)),
        budget_window_s=int(config.get("budget_window_s", 60)),
        budget_per_window=int(config.get("budget_per_window", 100)),
        persist_reserve=int(config.get("persist_reserve", 0)),
        persist_k=max(1, int(config.get("persist_k", 1))),
        duplicate_filter_window_s=max(0, int(config.get("duplicate_filter_window_s", 0))),
    )


def maybe_update_rl(state: MethodState, event: AddressEvent) -> None:
    if event.source_type != "legit_bonded" or not event.device_id:
        return
    state.activity_counts[event.device_id] = state.activity_counts.get(event.device_id, 0) + 1
    state.last_seen[event.device_id] = event.ts_ms
    if event.device_id in state.rl_entries:
        return
    if not state.rl_entries:
        return
    if state.method == "Random-RL":
        victim_index = int(hashlib.sha256(f"{event.event_id}:{event.device_id}".encode("utf-8")).hexdigest(), 16) % len(state.rl_entries)
        state.rl_entries[victim_index] = event.device_id
        return
    if state.method in ("LRU-RL", "TrustOnly"):
        victim = min(state.rl_entries, key=lambda dev_id: state.last_seen.get(dev_id, -1))
    elif state.method in (
        "Freq-RL",
        "BudgetDoS",
        "P3-Persist",
        "P3-NoPersist",
        "P3-NoCache",
        "P3-NoBudget",
        "P3-NoTrust",
    ):
        victim = min(state.rl_entries, key=lambda dev_id: state.activity_counts.get(dev_id, 0))
    else:
        return
    victim_score = state.activity_counts.get(victim, 0)
    event_score = state.activity_counts.get(event.device_id, 0)
    if state.method in ("LRU-RL", "TrustOnly") or event_score >= victim_score:
        state.rl_entries[state.rl_entries.index(victim)] = event.device_id


def budget_allows(state: MethodState, event: AddressEvent) -> bool:
    window = event.ts_ms // max(1, state.budget_window_s * 1000)
    if window != state.current_budget_window:
        state.current_budget_window = window
        state.budget_used = 0
    if state.budget_used >= state.budget_per_window:
        return False
    state.budget_used += 1
    return True


def budget_denial_action(method: str, event: AddressEvent) -> str:
    if method in P3_FAMILY and method != "P3-NoTrust" and trusted_event(event):
        return "defer"
    return "budget_skip"


def persistence_reserve_allows(state: MethodState, event: AddressEvent) -> bool:
    if state.persist_reserve <= 0:
        return False
    window = event.ts_ms // max(1, state.budget_window_s * 1000)
    if window != state.persist_reserve_window:
        state.persist_reserve_window = window
        state.persist_reserve_used = 0
    rpa_value = event.rpa_value or f"{event.addr_type}:{event.rpa_epoch}:{event.event_id}"
    denied_count = state.persist_denied.get(rpa_value, 0)
    if denied_count >= state.persist_k and state.persist_reserve_used < state.persist_reserve:
        state.persist_reserve_used += 1
        return True
    state.persist_denied[rpa_value] = denied_count + 1
    return False


def trusted_event(event: AddressEvent) -> bool:
    # RSSI is only used as a scheduling/budget signal. It never identifies a device.
    return event.rssi_dbm >= -78.0


def duplicate_filtered(state: MethodState, event: AddressEvent) -> bool:
    if state.duplicate_filter_window_s <= 0 or event.addr_type != "rpa" or not event.rpa_value:
        return False
    if event.rpa_value in state.resolved_rpa_values:
        return False
    window = event.ts_ms // max(1, state.duplicate_filter_window_s * 1000)
    key = (int(window), event.rpa_value)
    if key in state.df_seen:
        return True
    state.df_seen.add(key)
    return False


def resolve_event(method: str, state: MethodState, event: AddressEvent, devices: list[Device]) -> Decision:
    if event.addr_type != "rpa":
        return Decision(event.run_id, method, event.event_id, "skip_non_rpa", 0, False, "", False, 0, False, "", "non_rpa")

    if duplicate_filtered(state, event):
        return Decision(
            event.run_id,
            method,
            event.event_id,
            "duplicate_filter",
            0,
            False,
            "",
            False,
            0,
            event.source_type == "legit_bonded",
            "duplicate_filter",
            "duplicate_filter",
        )

    if method == "Oracle-Offline":
        if event.source_type != "legit_bonded":
            return Decision(event.run_id, method, event.event_id, "oracle_skip_unknown", 0, False, "", False, 0, False, "", "oracle_skip")
        matched = event.device_id != ""
        return Decision(
            event.run_id,
            method,
            event.event_id,
            "oracle_resolve_legit",
            1 if matched else 0,
            matched,
            event.device_id if matched else "",
            False,
            0,
            False,
            "",
            "oracle_resolve",
        )

    if method in CACHE_METHODS:
        cached = state.get_cache(event)
        if cached is not None:
            return Decision(event.run_id, method, event.event_id, "cache_hit", 0, cached != "", cached, False, 0, False, "", "cache")

    if event.source_type == "legit_bonded" and event.device_id in state.rl_entries:
        if method in CACHE_METHODS:
            state.put_cache(event, event.device_id)
        maybe_update_rl(state, event)
        return Decision(event.run_id, method, event.event_id, "rl_hit", 1, True, event.device_id, False, 0, False, "", "rl")

    # Budget applies to observable unresolved RPA work after cache/RL miss.
    # It cannot use source_type as an oracle; source_type is used only below
    # to score false-defer metrics after the decision has been made.
    admitted_by_reserve = False
    if method in BUDGET_METHODS:
        if not budget_allows(state, event):
            if method == "P3-Persist" and persistence_reserve_allows(state, event):
                admitted_by_reserve = True
            else:
                action = budget_denial_action(method, event)
                is_legit = event.source_type == "legit_bonded"
                return Decision(
                    event.run_id,
                    method,
                    event.event_id,
                    action,
                    0,
                    False,
                    "",
                    action == "defer",
                    1000 if action == "defer" else 0,
                    is_legit,
                    "budget",
                    "defer" if action == "defer" else "budget_skip",
                )

    if method == "FullScan-Host":
        aes_attempts = len(devices)
    else:
        aes_attempts = max(0, len(devices) - len(state.rl_entries))

    matched = event.source_type == "legit_bonded"
    matched_device_id = event.device_id if matched else ""
    deferred = method in TRUST_METHODS and not trusted_event(event)
    delay_ms = 100 if deferred else 0
    false_defer = deferred and matched
    if method in CACHE_METHODS:
        state.put_cache(event, matched_device_id)
    maybe_update_rl(state, event)
    return Decision(
        event.run_id,
        method,
        event.event_id,
        "host_scan",
        aes_attempts,
        matched,
        matched_device_id,
        deferred,
        delay_ms,
        false_defer,
        "",
        "reserve" if admitted_by_reserve else "host_scan",
    )


def estimate_sram_bytes(method: str, config: dict[str, Any]) -> int:
    if method == "FullScan-Host":
        return 0
    cache_size = int(config.get("zephyr_cache_size", 64))
    num_bonded = int(config.get("num_bonded", 0))
    rl_capacity = int(config.get("rl_capacity", 0))
    total = 0
    if method in CACHE_METHODS:
        total += cache_size * 16
    if method in DYNAMIC_RL_METHODS:
        total += rl_capacity * 4
        total += num_bonded * 8
    if method in BUDGET_METHODS:
        total += 64
    if method == "P3-Persist":
        total += int(config.get("persist_reserve", 0)) * 8
    if method in TRUST_METHODS:
        total += 16
    return total


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    pos = (len(ordered) - 1) * pct
    lower = math.floor(pos)
    upper = math.ceil(pos)
    if lower == upper:
        return ordered[int(pos)]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (pos - lower)


def summarize(
    method: str,
    decisions: list[Decision],
    events_by_id: dict[int, AddressEvent],
    config: dict[str, Any],
) -> dict[str, Any]:
    warmup_ms = int(config.get("warmup_s", 0)) * 1000
    duration_ms = int(config.get("duration_s", 0)) * 1000
    included_events_by_id = {eid: e for eid, e in events_by_id.items() if e.ts_ms >= warmup_ms}
    decisions = [d for d in decisions if d.event_id in included_events_by_id]
    aes_total = sum(d.aes_attempts for d in decisions)
    legit_events = [
        e for e in included_events_by_id.values() if e.source_type == "legit_bonded" and e.addr_type == "rpa"
    ]
    legit_decisions = [d for d in decisions if included_events_by_id[d.event_id].source_type == "legit_bonded"]
    legit_resolved = [d for d in legit_decisions if d.matched]
    attack_decisions = [d for d in decisions if included_events_by_id[d.event_id].source_type == "attack"]
    delays = [d.delay_ms for d in legit_resolved]
    measurement_min = max(1.0, (duration_ms - warmup_ms) / 60000.0)

    def count_path(source_type: str, admission_path: str) -> int:
        return sum(
            1
            for d in decisions
            if d.admission_path == admission_path
            and included_events_by_id[d.event_id].source_type == source_type
        )

    return {
        "method": method,
        "summary_warmup_applied": bool(warmup_ms),
        "summary_warmup_s": int(config.get("warmup_s", 0)),
        "summary_measurement_s": max(0, int(config.get("duration_s", 0)) - int(config.get("warmup_s", 0))),
        "aes_attempts_total": aes_total,
        "aes_attempts_per_legit_resolved": round(aes_total / max(1, len(legit_resolved)), 6),
        "legit_resolution_rate": round(len(legit_resolved) / max(1, len(legit_events)), 6),
        "p50_resolution_delay_ms": round(percentile(delays, 0.50), 6),
        "p95_resolution_delay_ms": round(percentile(delays, 0.95), 6),
        "p99_resolution_delay_ms": round(percentile(delays, 0.99), 6),
        "attack_aes_amplification": round(sum(d.aes_attempts for d in attack_decisions) / measurement_min, 6),
        "false_defer_legit_rate": round(
            sum(1 for d in legit_decisions if d.false_defer) / max(1, len(legit_decisions)), 6
        ),
        "reserve_grant_legit_count": count_path("legit_bonded", "reserve"),
        "reserve_grant_attack_count": count_path("attack", "reserve"),
        "duplicate_filter_legit_count": count_path("legit_bonded", "duplicate_filter"),
        "duplicate_filter_attack_count": count_path("attack", "duplicate_filter"),
        "cache_hit_legit_count": count_path("legit_bonded", "cache"),
        "host_scan_legit_count": count_path("legit_bonded", "host_scan"),
        "budget_skip_legit_count": count_path("legit_bonded", "budget_skip"),
        "budget_skip_attack_count": count_path("attack", "budget_skip"),
        "estimated_energy_uJ": round(aes_total * 0.12, 6),
        "sram_bytes": estimate_sram_bytes(method, config),
    }


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def run(config: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(int(config["seed"]))
    devices = build_devices(config, rng)
    events = generate_events(config, devices, rng)
    methods = config.get("methods", METHODS)
    events_by_id = {event.event_id: event for event in events}

    event_fields = [
        "run_id",
        "event_id",
        "ts_ms",
        "source_type",
        "device_id",
        "addr_type",
        "rpa_epoch",
        "rssi_dbm",
        "payload_len",
        "rpa_value",
    ]
    write_traces = bool(config.get("write_traces", True))
    if write_traces:
        write_csv(out_dir / "events.csv", [event.__dict__ for event in events], event_fields)

    all_decisions: list[Decision] = []
    summaries: list[dict[str, Any]] = []
    for method in methods:
        if method not in METHODS:
            raise ValueError(f"W1 simulator does not implement method: {method}")
        state = init_state(method, config, devices)
        decisions = [resolve_event(method, state, event, devices) for event in events]
        all_decisions.extend(decisions)
        summary = summarize(method, decisions, events_by_id, config)
        summary["run_id"] = config["run_id"]
        summaries.append(summary)

    decision_fields = [
        "run_id",
        "method",
        "event_id",
        "action",
        "aes_attempts",
        "matched",
        "matched_device_id",
        "deferred",
        "delay_ms",
        "false_defer",
        "drop_reason",
        "admission_path",
    ]
    if write_traces:
        write_csv(out_dir / "decisions.csv", [decision.__dict__ for decision in all_decisions], decision_fields)

    summary_fields = [
        "run_id",
        "method",
        "summary_warmup_applied",
        "summary_warmup_s",
        "summary_measurement_s",
        "aes_attempts_total",
        "aes_attempts_per_legit_resolved",
        "legit_resolution_rate",
        "p50_resolution_delay_ms",
        "p95_resolution_delay_ms",
        "p99_resolution_delay_ms",
        "attack_aes_amplification",
        "false_defer_legit_rate",
        "reserve_grant_legit_count",
        "reserve_grant_attack_count",
        "duplicate_filter_legit_count",
        "duplicate_filter_attack_count",
        "cache_hit_legit_count",
        "host_scan_legit_count",
        "budget_skip_legit_count",
        "budget_skip_attack_count",
        "estimated_energy_uJ",
        "sram_bytes",
    ]
    write_csv(out_dir / "summary.csv", summaries, summary_fields)

    manifest = {
        "schema_version": config.get("schema_version", "m2.v1-draft"),
        "run_id": config["run_id"],
        "git_commit": get_git_commit(),
        "ncs_version": config.get("ncs_version", "v3.2.1"),
        "methods": methods,
        "seed": config["seed"],
        "config_hash": config_hash(config),
        "num_bonded": config["num_bonded"],
        "rl_capacity": config["rl_capacity"],
        "duration_s": config["duration_s"],
        "warmup_s": config.get("warmup_s", 0),
        "summary_warmup_applied": bool(int(config.get("warmup_s", 0))),
        "summary_measurement_s": max(0, int(config.get("duration_s", 0)) - int(config.get("warmup_s", 0))),
        "event_count": len(events),
    }
    with (out_dir / "run_manifest.json").open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    run(load_config(args.config), args.out)


if __name__ == "__main__":
    main()
