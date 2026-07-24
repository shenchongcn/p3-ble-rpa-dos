#!/usr/bin/env python3
"""Event-driven BLE RPA resolution simulator for M2.

The model is intentionally lightweight. It counts AES-equivalent IRK match
attempts and preserves the privacy boundary: no method can identify an unknown
RPA without paying IRK/AES attempts.
"""

from __future__ import annotations

import argparse
import csv
import heapq
import hashlib
import json
import math
import random
import statistics
import subprocess
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from adaptive_controller import HedgeController, parse_action_grid


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
    "P3-SPRT",
    "P3-SeqMix",
    "P3-Adaptive",
)

P3_FAMILY = (
    "P3-Persist",
    "P3-NoPersist",
    "P3-NoCache",
    "P3-NoBudget",
    "P3-NoTrust",
    "P3-NoRL",
    "P3-SPRT",
    "P3-SeqMix",
    "P3-Adaptive",
)
CACHE_METHODS = (
    "ZephyrCache",
    "P3-Persist",
    "P3-NoPersist",
    "P3-NoBudget",
    "P3-NoTrust",
    "P3-NoRL",
    "P3-SPRT",
    "P3-SeqMix",
    "P3-Adaptive",
)
BUDGET_METHODS = (
    "BudgetDoS",
    "AdaptiveRateLimit",
    "P3-Persist",
    "P3-NoPersist",
    "P3-NoCache",
    "P3-NoTrust",
    "P3-NoRL",
    "P3-SPRT",
    "P3-SeqMix",
    "P3-Adaptive",
)
TRUST_METHODS = (
    "TrustOnly",
    "P3-Persist",
    "P3-NoPersist",
    "P3-NoCache",
    "P3-NoBudget",
    "P3-NoRL",
    "P3-SPRT",
    "P3-SeqMix",
    "P3-Adaptive",
)
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
    "P3-SPRT",
    "P3-SeqMix",
    "P3-Adaptive",
)

SEQ_MIX_CROWD_FEATURES = {
    "repeat_candidate_count_w",
    "new_candidate_count_w",
    "repeat_candidate_entropy_w",
    "reserve_contention_w",
    "attack_pressure_proxy_w",
}
SEQ_MIX_COUNT_FEATURES = {"n_seen", "n_denied", "visible_windows"}
SEQ_MIX_BURST_FEATURES = {"burst_count"}
SEQ_MIX_DEFAULT_THRESHOLDS = {
    "full": -3.3804492497802956,
    "no_crowd": -3.0634457731613836,
    "no_burst": -3.3772936754520613,
    "count_only": -0.08307077898260407,
    "no_ranking": -3.3804492497802956,
}


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
    seqmix_lane: str = ""
    seqmix_bucket: int = -1
    seqmix_score: float = 0.0
    seqmix_ranking_score: float = 0.0
    seqmix_shadow_baseline_eligible: bool = False
    seqmix_shadow_baseline_lane: str = ""
    seqmix_service_debt_before: int = 0
    seqmix_service_debt_after: int = 0
    seqmix_unique_risk_before: int = 0
    seqmix_unique_risk_after: int = 0
    seqmix_debt_action: str = ""


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
    gate_mode: str = "count"
    llr: dict[str, float] = field(default_factory=dict)
    sprt_last_seen_ms: dict[str, int] = field(default_factory=dict)
    sprt_terminated: set[str] = field(default_factory=set)
    sprt_a_upper: float = 0.0
    sprt_a_lower: float = 0.0
    sprt_legit_interarrival_mean_s: float = 12.223
    sprt_attack_interarrival_mean_s: float = 120.0
    sprt_trusted_bonus: float = 0.0
    seqmix_model: dict[str, Any] | None = None
    seqmix_disabled_features: set[str] = field(default_factory=set)
    seqmix_theta_high: float = 0.0
    seqmix_theta_low: float = 0.0
    seqmix_records: OrderedDict[str, dict[str, Any]] = field(default_factory=OrderedDict)
    seqmix_window_index: int = -1
    seqmix_window_counts: Counter[str] = field(default_factory=Counter)
    seqmix_window_total_count: int = 0
    seqmix_window_new_candidate_count: int = 0
    seqmix_window_repeat_candidate_count: int = 0
    seqmix_window_repeat_count_hist: Counter[int] = field(default_factory=Counter)
    seqmix_crowd_window_s: float = 60.0
    seqmix_candidate_heap: list[tuple[float, int, str]] = field(default_factory=list)
    seqmix_candidate_scores: dict[str, float] = field(default_factory=dict)
    seqmix_pruned: set[str] = field(default_factory=set)
    seqmix_pruned_order: deque[str] = field(default_factory=deque)
    seqmix_burst_horizon_s: float = 5.0
    seqmix_attack_pressure_budget: int = 100
    seqmix_disable_ranking: bool = False
    seqmix_rssi_gate_enabled: bool = False
    seqmix_guarded_rssi_enabled: bool = False
    seqmix_rssi_threshold_dbm: float = -72.0
    seqmix_stream_floor: float = 0.0
    seqmix_min_denied_before_rssi: int = 2
    seqmix_min_visible_windows_before_rssi: int = 1
    seqmix_guarded_count_fallback_enabled: bool = False
    seqmix_guard_window_index: int = -1
    seqmix_guard_denied_count_w: int = 0
    seqmix_guard_high_rssi_denied_count_w: int = 0
    seqmix_guard_rssi_reserve_used_w: int = 0
    seqmix_guard_service_reserve_used_w: int = 0
    seqmix_feedback_hard_stop_enabled: bool = False
    seqmix_feedback_scope: str = "group"
    seqmix_feedback_zero_success_stop_grants: int = 8
    seqmix_feedback_grants_w: int = 0
    seqmix_feedback_successes_w: int = 0
    seqmix_feedback_stopped_w: bool = False
    seqmix_feedback_lane_grants_w: Counter[str] = field(default_factory=Counter)
    seqmix_feedback_lane_successes_w: Counter[str] = field(default_factory=Counter)
    seqmix_feedback_stopped_lanes_w: set[str] = field(default_factory=set)
    seqmix_feedback_bucket_grants_w: Counter[str] = field(default_factory=Counter)
    seqmix_feedback_bucket_successes_w: Counter[str] = field(default_factory=Counter)
    seqmix_feedback_stopped_buckets_w: set[str] = field(default_factory=set)
    seqmix_high_rssi_pressure_threshold: float = 0.8
    seqmix_high_rssi_pressure_min_denied: int = 10
    seqmix_rssi_quota_fraction: float = 0.5
    seqmix_unique_flood_guard_enabled: bool = False
    seqmix_unique_new_candidate_threshold: int = 512
    seqmix_unique_repeat_to_new_min_ratio: float = 0.10
    seqmix_unique_flood_guard_action: str = "count_fallback"
    seqmix_window_ranked_enabled: bool = False
    seqmix_rank_window_ms: int = 1000
    seqmix_rank_flush_denials: int = 64
    seqmix_rank_max_grants_per_flush: int = 1
    seqmix_rank_service_max_grants_per_flush: int = 0
    seqmix_rank_max_pending: int = 256
    seqmix_rank_min_window_repeat_candidates: int = 0
    seqmix_rank_low_rssi_service_enabled: bool = False
    seqmix_rank_dense_service_enabled: bool = False
    seqmix_rank_guarded_retry_enabled: bool = False
    seqmix_guarded_retry_min_dt_median_s: float = 0.366
    seqmix_dense_service_min_repeat_candidates: int = 384
    seqmix_dense_service_max_repeat_candidates: int = 1000000
    seqmix_dense_service_min_contention: float = 1.5
    seqmix_dense_service_max_attack_pressure: float = 1000000.0
    seqmix_dense_service_min_seen: int = 2
    seqmix_dense_service_require_low_rssi: bool = True
    seqmix_dense_service_bucket_cooldown: int = 0
    seqmix_dense_service_bucket_last_grant: dict[int, int] = field(default_factory=dict)
    seqmix_dense_service_grant_sequence: int = 0
    seqmix_count_fallback_dense_limit_enabled: bool = False
    seqmix_count_fallback_dense_fraction: float = 1.0
    seqmix_count_fallback_dense_used_w: int = 0
    seqmix_service_quota_fraction: float = 0.0
    seqmix_stream_score_weight: float = 1.0
    seqmix_rssi_boost_weight: float = 1.0
    seqmix_rssi_scale_db: float = 6.0
    seqmix_rank_pending: list[dict[str, Any]] = field(default_factory=list)
    seqmix_rank_pending_by_event: dict[int, dict[str, Any]] = field(default_factory=dict)
    seqmix_rank_sequence: int = 0
    seqmix_large_pool_guard_enabled: bool = False
    seqmix_large_pool_repeat_threshold: int = 64
    seqmix_large_pool_entropy_threshold: float = 3.0
    seqmix_large_pool_contention_threshold: float = 0.5
    seqmix_large_pool_min_denied: int = 3
    seqmix_state_capacity: int = 128
    seqmix_interval_capacity: int = 32
    seqmix_pruned_capacity: int = 1024
    seqmix_candidate_capacity: int = 128
    adaptive_controller: Any = None
    adaptive_current_action: Any = None
    adaptive_window_index: int = -1
    adaptive_window_legit_events: int = 0
    adaptive_window_legit_resolved: int = 0
    adaptive_window_attack_aes: int = 0
    adaptive_lambda_l: float = 0.5
    adaptive_lambda_a: float = 0.45
    adaptive_lambda_o: float = 0.05
    adaptive_sram_budget_bytes: int = 4096
    adaptive_scan_cost: int = 0
    adaptive_sram_bytes: int = 0
    adaptive_base_sram_bytes: int = 0
    duplicate_filter_window_s: int = 0
    df_seen: set[tuple[int, str]] = field(default_factory=set)
    resolved_rpa_values: set[str] = field(default_factory=set)
    duplicate_filter_diagnostics_enabled: bool = False
    df_diag_records: dict[str, dict[str, Any]] = field(default_factory=dict)
    df_diag_window_index: int = -1
    df_diag_window_counts: Counter[str] = field(default_factory=Counter)
    df_diag_window_rssi: list[float] = field(default_factory=list)
    df_diag_pending_features: dict[int, dict[str, Any]] = field(default_factory=dict)
    df_diag_rows: list[dict[str, Any]] = field(default_factory=list)
    seqmix_dupfilter_rescue_enabled: bool = False
    seqmix_dupfilter_rescue_min_dt_median_s: float = 0.366
    seqmix_dupfilter_rescue_min_prior_duplicates: int = 1
    seqmix_dupfilter_rescue_quota_fraction: float = 0.05
    seqmix_dupfilter_rescue_disable_unique_guard_enabled: bool = False
    seqmix_dupfilter_rescue_window: int = -1
    seqmix_dupfilter_rescue_used_w: int = 0
    seqmix_dupfilter_rescued_events: set[int] = field(default_factory=set)
    seqmix_trusted_defer_retry_enabled: bool = False
    seqmix_trusted_defer_retry_threshold_dbm: float = -58.0
    seqmix_trusted_defer_retry_quota_fraction: float = 0.05
    seqmix_trusted_defer_retry_disable_unique_guard_enabled: bool = False
    seqmix_trusted_defer_retry_min_repeat_candidates: int = 0
    seqmix_trusted_defer_retry_window: int = -1
    seqmix_trusted_defer_retry_used_w: int = 0
    seqmix_trusted_defer_retry_events: set[int] = field(default_factory=set)
    seqmix_baseline_debt_enabled: bool = False
    seqmix_trace_debt_ledger_enabled: bool = False
    seqmix_shadow_baseline_mode: str = "r4p2_guarded"
    seqmix_shadow_floor_alpha: float = 0.85
    seqmix_debt_window_index: int = -1
    seqmix_shadow_floor_eligible_w: int = 0
    seqmix_service_credit_w: int = 0
    seqmix_service_debt_w: int = 0
    seqmix_unique_risk_w: int = 0
    seqmix_debt_trace_pending: dict[int, dict[str, Any]] = field(default_factory=dict)
    seqmix_debt_trace_finalized: set[int] = field(default_factory=set)
    seqmix_debt_repay_enabled: bool = False
    seqmix_debt_repay_quota_fraction: float = 0.05
    seqmix_debt_repay_used_w: int = 0
    seqmix_debt_repay_unique_soft_cap: int = 192
    seqmix_debt_repay_min_dt_median_s: float = 0.366
    seqmix_debt_repay_require_shadow_eligible: bool = True
    seqmix_debt_repay_require_strong_timing: bool = False
    seqmix_service_lane_unique_soft_cap: int = -1
    seqmix_baseline_floor_protect_enabled: bool = False
    seqmix_baseline_floor_fraction: float = 0.35
    seqmix_baseline_floor_used_w: int = 0
    seqmix_service_lane_current_unique_block: bool = False

    def cache_key(self, event: AddressEvent) -> str:
        # Positive-cache lookup must use the visible RPA value, not the
        # simulator's offline source/identity labels. The legacy legitimate
        # value L<device>:<epoch> is one-to-one with the old key, so this
        # removes label leakage without changing historical behavior.
        if event.rpa_value:
            return f"rpa:{event.rpa_value}"
        return f"fallback:{event.addr_type}:{event.rpa_epoch}"

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


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def load_seqmix_model(config: dict[str, Any]) -> dict[str, Any]:
    default_path = repo_root() / "docs/m14-sci-review/l1-seqmix-layer/outputs/l1_seqmix_model.json"
    path = Path(str(config.get("seqmix_model_path", default_path)))
    if not path.is_absolute():
        path = repo_root() / path
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def finite_float(value: Any) -> float:
    try:
        out = float(value)
    except (TypeError, ValueError):
        return -1.0
    if not math.isfinite(out):
        return -1.0
    return out


def seqmix_bin_index(value: float, edges: list[float]) -> int:
    idx = 0
    while idx < len(edges) and value > edges[idx]:
        idx += 1
    return idx


def seqmix_entropy(counts: list[int]) -> float:
    total = sum(counts)
    if total <= 0:
        return 0.0
    return -sum((count / total) * math.log(max(1e-12, count / total)) for count in counts if count > 0)


def seqmix_entropy_from_hist(hist: Counter[int]) -> float:
    total = sum(count * freq for count, freq in hist.items() if count > 0 and freq > 0)
    if total <= 0:
        return 0.0
    out = 0.0
    for count, freq in hist.items():
        if count <= 0 or freq <= 0:
            continue
        probability = count / total
        out -= freq * probability * math.log(max(1e-12, probability))
    return out


def seqmix_cv(values: list[float]) -> float:
    if len(values) < 2:
        return -1.0
    avg = sum(values) / len(values)
    if avg <= 0:
        return 0.0
    return statistics.pstdev(values) / avg


def seqmix_median(values: list[float]) -> float:
    if not values:
        return -1.0
    return statistics.median(values)


def logsumexp(values: list[float]) -> float:
    if not values:
        return float("-inf")
    vmax = max(values)
    return vmax + math.log(sum(math.exp(value - vmax) for value in values))


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
    background_address_mode = str(config.get("background_address_mode", "unique"))
    if background_address_mode not in {"unique", "repeated"}:
        raise ValueError("background_address_mode must be 'unique' or 'repeated'")
    background_addr_pool_size = max(1, int(config.get("background_addr_pool_size", 1)))
    background_repeats_per_addr = max(1, int(config.get("background_repeats_per_addr", 1)))
    background_repeat_interval_s = max(
        0.0, float(config.get("background_repeat_interval_s", 0.0))
    )
    background_rssi_mean_dbm = float(config.get("background_rssi_mean_dbm", -82.0))
    attack_rssi_mean_dbm = float(config.get("attack_rssi_mean_dbm", -70.0))

    events: list[AddressEvent] = []
    event_id = 0
    attack_slot_counts: dict[int, int] = {}
    background_slot_counts: dict[int, int] = {}
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
            if background_address_mode == "unique":
                rpa_epoch = second // max(1, int(float(config["rpa_rotation_interval_min"]) * 60))
                background_rpa_value = f"B{event_id}"
            elif background_repeat_interval_s <= 0.0:
                rpa_epoch = second // max(1, int(float(config["rpa_rotation_interval_min"]) * 60))
                slot = rpa_epoch
                seq_in_slot = background_slot_counts.get(slot, 0)
                background_slot_counts[slot] = seq_in_slot + 1
                addr_index = (seq_in_slot // background_repeats_per_addr) % background_addr_pool_size
                background_rpa_value = f"B{addr_index}"
            else:
                slot = int(second // background_repeat_interval_s)
                seq_in_slot = background_slot_counts.get(slot, 0)
                background_slot_counts[slot] = seq_in_slot + 1
                addr_index = (seq_in_slot // background_repeats_per_addr) % background_addr_pool_size
                rpa_epoch = slot
                background_rpa_value = f"B{addr_index}"
            events.append(
                AddressEvent(
                    run_id=run_id,
                    event_id=event_id,
                    ts_ms=ts_ms,
                    source_type="background",
                    device_id="",
                    addr_type="rpa",
                    rpa_epoch=rpa_epoch,
                    rssi_dbm=round(rng.gauss(background_rssi_mean_dbm, rssi_noise), 2),
                    payload_len=rng.randint(8, 31),
                    rpa_value=background_rpa_value,
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
                    rssi_dbm=round(rng.gauss(attack_rssi_mean_dbm, rssi_noise), 2),
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


def observation_loss_seed(config: dict[str, Any]) -> int:
    """Derive a stable observation RNG seed without consuming event RNG state."""

    if "observation_loss_seed" in config:
        return int(config["observation_loss_seed"])
    payload = f"{int(config['seed'])}:observation-loss:v1".encode("utf-8")
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")


def apply_observation_loss(
    events: list[AddressEvent], config: dict[str, Any]
) -> tuple[list[AddressEvent], list[dict[str, Any]]]:
    """Drop observed advertisements after generation with an independent RNG."""

    rate = float(config.get("observation_loss_rate", 0.0))
    if not 0.0 <= rate <= 1.0:
        raise ValueError("observation_loss_rate must be between 0 and 1")
    rng = random.Random(observation_loss_seed(config))
    observed: list[AddressEvent] = []
    ledger: list[dict[str, Any]] = []
    for event in events:
        dropped = rng.random() < rate
        ledger.append(
            {
                "run_id": event.run_id,
                "event_id": event.event_id,
                "ts_ms": event.ts_ms,
                "source_type": event.source_type,
                "rpa_value": event.rpa_value,
                "observed": not dropped,
                "dropped": dropped,
                "drop_reason": "observation_loss" if dropped else "",
            }
        )
        if not dropped:
            observed.append(event)
    return observed, ledger


def init_state(method: str, config: dict[str, Any], devices: list[Device]) -> MethodState:
    capacity = int(config["rl_capacity"])
    rl_entries = [device.device_id for device in devices[:capacity]]
    if method in DYNAMIC_RL_METHODS:
        sorted_devices = sorted(devices, key=lambda d: d.activity_weight, reverse=True)
        rl_entries = [device.device_id for device in sorted_devices[:capacity]]
    if method == "P3-Adaptive" and "adaptive_default_action" in config:
        action = dict(config["adaptive_default_action"])
        config = {**config, **action}
    gate_mode = str(config.get("gate_mode", "seqmix" if method == "P3-SeqMix" else "sprt" if method == "P3-SPRT" else "count"))
    sprt_alpha = min(0.999999, max(0.000001, float(config.get("sprt_alpha", 0.05))))
    sprt_beta = min(0.999999, max(0.000001, float(config.get("sprt_beta", 0.05))))
    state = MethodState(
        method=method,
        rl_entries=rl_entries,
        cache_size=int(config.get("zephyr_cache_size", 64)),
        budget_window_s=int(config.get("budget_window_s", 60)),
        budget_per_window=int(config.get("budget_per_window", 100)),
        persist_reserve=int(config.get("persist_reserve", 0)),
        persist_k=max(1, int(config.get("persist_k", 1))),
        gate_mode=gate_mode,
        sprt_a_upper=math.log((1.0 - sprt_beta) / sprt_alpha),
        sprt_a_lower=math.log(sprt_beta / (1.0 - sprt_alpha)),
        sprt_legit_interarrival_mean_s=max(0.001, float(config.get("sprt_legit_interarrival_mean_s", 12.223))),
        sprt_attack_interarrival_mean_s=max(0.001, float(config.get("sprt_attack_interarrival_mean_s", 120.0))),
        sprt_trusted_bonus=float(config.get("sprt_trusted_bonus", 0.0)),
        seqmix_burst_horizon_s=max(0.001, float(config.get("seqmix_burst_horizon_s", 5.0))),
        seqmix_attack_pressure_budget=max(1, int(config.get("budget_per_window", 100))),
        seqmix_state_capacity=max(1, int(config.get("seqmix_state_capacity", config.get("persist_reserve", 0) or 128))),
        seqmix_interval_capacity=max(1, int(config.get("seqmix_interval_capacity", 32))),
        seqmix_pruned_capacity=max(1, int(config.get("seqmix_pruned_capacity", config.get("persist_reserve", 0) * 4 or 1024))),
        seqmix_candidate_capacity=max(1, int(config.get("seqmix_heap_capacity", config.get("persist_reserve", 0) or 128))),
        adaptive_lambda_l=float(config.get("adaptive_lambda_l", 0.5)),
        adaptive_lambda_a=float(config.get("adaptive_lambda_a", 0.45)),
        adaptive_lambda_o=float(config.get("adaptive_lambda_o", 0.05)),
        adaptive_sram_budget_bytes=max(1, int(config.get("adaptive_sram_budget_bytes", 4096))),
        adaptive_scan_cost=max(0, int(config.get("num_bonded", 0)) - capacity),
        adaptive_base_sram_bytes=int(config.get("zephyr_cache_size", 64)) * 16 + capacity * 4 + int(config.get("num_bonded", 0)) * 8 + 64 + 16,
        duplicate_filter_window_s=max(0, int(config.get("duplicate_filter_window_s", 0))),
        duplicate_filter_diagnostics_enabled=bool(config.get("write_duplicate_filter_diagnostics", False)),
    )
    if method == "P3-SeqMix":
        state.seqmix_model = load_seqmix_model(config)
        variant = str(config.get("seqmix_feature_variant", "no_crowd"))
        if variant == "no_crowd":
            state.seqmix_disabled_features = set(SEQ_MIX_CROWD_FEATURES)
        elif variant == "count_only":
            state.seqmix_disabled_features = {
                feature for feature in state.seqmix_model.get("features", []) if feature not in SEQ_MIX_COUNT_FEATURES
            }
        elif variant == "no_burst":
            state.seqmix_disabled_features = set(SEQ_MIX_BURST_FEATURES)
        elif variant == "no_ranking":
            state.seqmix_disabled_features = set()
            state.seqmix_disable_ranking = True
        elif variant == "rssi_gate":
            state.seqmix_disabled_features = set()
            state.seqmix_rssi_gate_enabled = True
            state.seqmix_rssi_threshold_dbm = float(config.get("seqmix_rssi_threshold_dbm", -72.0))
        elif variant == "guarded_rssi":
            state.seqmix_disabled_features = set()
            state.seqmix_guarded_rssi_enabled = True
            state.seqmix_rssi_threshold_dbm = float(config.get("seqmix_rssi_threshold_dbm", -72.0))
            state.seqmix_min_denied_before_rssi = max(1, int(config.get("seqmix_min_denied_before_rssi", 2)))
            state.seqmix_min_visible_windows_before_rssi = max(1, int(config.get("seqmix_min_visible_windows_before_rssi", 1)))
            state.seqmix_guarded_count_fallback_enabled = bool(config.get("seqmix_guarded_count_fallback_enabled", False))
            state.seqmix_feedback_hard_stop_enabled = bool(config.get("seqmix_feedback_hard_stop_enabled", False))
            feedback_scope = str(config.get("seqmix_feedback_scope", "group"))
            state.seqmix_feedback_scope = (
                feedback_scope if feedback_scope in {"group", "lane", "bucket", "lane_bucket"} else "group"
            )
            state.seqmix_feedback_zero_success_stop_grants = max(
                1, int(config.get("seqmix_feedback_zero_success_stop_grants", 8))
            )
            state.seqmix_dupfilter_rescue_enabled = bool(config.get("seqmix_dupfilter_rescue_enabled", False))
            state.seqmix_dupfilter_rescue_min_dt_median_s = max(
                0.0, float(config.get("seqmix_dupfilter_rescue_min_dt_median_s", 0.366))
            )
            state.seqmix_dupfilter_rescue_min_prior_duplicates = max(
                0, int(config.get("seqmix_dupfilter_rescue_min_prior_duplicates", 1))
            )
            state.seqmix_dupfilter_rescue_quota_fraction = min(
                1.0, max(0.0, float(config.get("seqmix_dupfilter_rescue_quota_fraction", 0.05)))
            )
            state.seqmix_dupfilter_rescue_disable_unique_guard_enabled = bool(
                config.get("seqmix_dupfilter_rescue_disable_unique_guard_enabled", False)
            )
            state.seqmix_trusted_defer_retry_enabled = bool(config.get("seqmix_trusted_defer_retry_enabled", False))
            state.seqmix_trusted_defer_retry_threshold_dbm = float(
                config.get("seqmix_trusted_defer_retry_threshold_dbm", -58.0)
            )
            state.seqmix_trusted_defer_retry_quota_fraction = min(
                1.0, max(0.0, float(config.get("seqmix_trusted_defer_retry_quota_fraction", 0.05)))
            )
            state.seqmix_trusted_defer_retry_disable_unique_guard_enabled = bool(
                config.get("seqmix_trusted_defer_retry_disable_unique_guard_enabled", False)
            )
            state.seqmix_trusted_defer_retry_min_repeat_candidates = max(
                0, int(config.get("seqmix_trusted_defer_retry_min_repeat_candidates", 0))
            )
            state.seqmix_high_rssi_pressure_threshold = min(
                1.0, max(0.0, float(config.get("seqmix_high_rssi_pressure_threshold", 0.8)))
            )
            state.seqmix_high_rssi_pressure_min_denied = max(
                1, int(config.get("seqmix_high_rssi_pressure_min_denied", 10))
            )
            state.seqmix_rssi_quota_fraction = min(1.0, max(0.0, float(config.get("seqmix_rssi_quota_fraction", 0.5))))
            state.seqmix_unique_flood_guard_enabled = bool(config.get("seqmix_unique_flood_guard_enabled", False))
            state.seqmix_unique_new_candidate_threshold = max(
                1, int(config.get("seqmix_unique_new_candidate_threshold", 512))
            )
            state.seqmix_unique_repeat_to_new_min_ratio = max(
                0.0, float(config.get("seqmix_unique_repeat_to_new_min_ratio", 0.10))
            )
            unique_guard_action = str(config.get("seqmix_unique_flood_guard_action", "count_fallback"))
            state.seqmix_unique_flood_guard_action = (
                unique_guard_action if unique_guard_action in {"count_fallback", "block"} else "count_fallback"
            )
            state.seqmix_crowd_window_s = max(
                1.0, float(config.get("seqmix_crowd_window_s", config.get("budget_window_s", 60)))
            )
            state.seqmix_window_ranked_enabled = bool(config.get("seqmix_window_ranked_enabled", False))
            state.seqmix_rank_window_ms = max(1, int(float(config.get("seqmix_rank_window_s", 1.0)) * 1000))
            state.seqmix_rank_flush_denials = max(1, int(config.get("seqmix_rank_flush_denials", 64)))
            state.seqmix_rank_max_grants_per_flush = max(
                1, int(config.get("seqmix_rank_max_grants_per_flush", 1))
            )
            state.seqmix_rank_service_max_grants_per_flush = max(
                0, int(config.get("seqmix_rank_service_max_grants_per_flush", 0))
            )
            state.seqmix_rank_max_pending = max(1, int(config.get("seqmix_rank_max_pending", 256)))
            state.seqmix_rank_min_window_repeat_candidates = max(
                0, int(config.get("seqmix_rank_min_window_repeat_candidates", 0))
            )
            state.seqmix_rank_low_rssi_service_enabled = bool(
                config.get("seqmix_rank_low_rssi_service_enabled", False)
            )
            state.seqmix_rank_dense_service_enabled = bool(config.get("seqmix_rank_dense_service_enabled", False))
            state.seqmix_rank_guarded_retry_enabled = bool(config.get("seqmix_rank_guarded_retry_enabled", False))
            state.seqmix_guarded_retry_min_dt_median_s = max(
                0.0, float(config.get("seqmix_guarded_retry_min_dt_median_s", 0.366))
            )
            state.seqmix_dense_service_min_repeat_candidates = max(
                1, int(config.get("seqmix_dense_service_min_repeat_candidates", 384))
            )
            state.seqmix_dense_service_max_repeat_candidates = max(
                state.seqmix_dense_service_min_repeat_candidates,
                int(config.get("seqmix_dense_service_max_repeat_candidates", 1000000)),
            )
            state.seqmix_dense_service_min_contention = max(
                0.0, float(config.get("seqmix_dense_service_min_contention", 1.5))
            )
            state.seqmix_dense_service_max_attack_pressure = max(
                0.0, float(config.get("seqmix_dense_service_max_attack_pressure", 1000000.0))
            )
            state.seqmix_dense_service_min_seen = max(1, int(config.get("seqmix_dense_service_min_seen", 2)))
            state.seqmix_dense_service_require_low_rssi = bool(
                config.get("seqmix_dense_service_require_low_rssi", True)
            )
            state.seqmix_dense_service_bucket_cooldown = max(
                0, int(config.get("seqmix_dense_service_bucket_cooldown", 0))
            )
            state.seqmix_count_fallback_dense_limit_enabled = bool(
                config.get("seqmix_count_fallback_dense_limit_enabled", False)
            )
            state.seqmix_count_fallback_dense_fraction = min(
                1.0, max(0.0, float(config.get("seqmix_count_fallback_dense_fraction", 1.0)))
            )
            state.seqmix_service_quota_fraction = min(
                1.0, max(0.0, float(config.get("seqmix_service_quota_fraction", 0.0)))
            )
            state.seqmix_stream_score_weight = float(config.get("seqmix_stream_score_weight", 1.0))
            state.seqmix_rssi_boost_weight = float(config.get("seqmix_rssi_boost_weight", 1.0))
            state.seqmix_rssi_scale_db = max(0.001, float(config.get("seqmix_rssi_scale_db", 6.0)))
            state.seqmix_large_pool_guard_enabled = bool(config.get("seqmix_large_pool_guard_enabled", True))
            state.seqmix_large_pool_repeat_threshold = max(
                1, int(config.get("seqmix_large_pool_repeat_threshold", 64))
            )
            state.seqmix_large_pool_entropy_threshold = max(
                0.0, float(config.get("seqmix_large_pool_entropy_threshold", 3.0))
            )
            state.seqmix_large_pool_contention_threshold = max(
                0.0, float(config.get("seqmix_large_pool_contention_threshold", 0.5))
            )
            state.seqmix_large_pool_min_denied = max(1, int(config.get("seqmix_large_pool_min_denied", 3)))
        elif variant == "full":
            state.seqmix_disabled_features = set()
        else:
            state.seqmix_disabled_features = set(config.get("seqmix_disabled_features", []))
        thresholds = state.seqmix_model.get("validation_thresholds", {})
        variant_theta = SEQ_MIX_DEFAULT_THRESHOLDS.get(variant, thresholds.get("theta_high", 0.0))
        state.seqmix_theta_high = float(config.get("seqmix_theta_high", variant_theta))
        state.seqmix_theta_low = float(config.get("seqmix_theta_low", thresholds.get("theta_low", state.seqmix_theta_high)))
        if state.seqmix_guarded_rssi_enabled:
            state.seqmix_stream_floor = float(config.get("seqmix_stream_floor", state.seqmix_theta_low))
        state.seqmix_baseline_debt_enabled = bool(config.get("seqmix_baseline_debt_enabled", False))
        state.seqmix_trace_debt_ledger_enabled = bool(
            config.get("seqmix_trace_debt_ledger_enabled", state.seqmix_baseline_debt_enabled)
        )
        shadow_mode = str(config.get("seqmix_shadow_baseline_mode", "r4p2_guarded"))
        state.seqmix_shadow_baseline_mode = (
            shadow_mode if shadow_mode in {"r4p2_guarded", "count", "guarded_or_count"} else "r4p2_guarded"
        )
        state.seqmix_shadow_floor_alpha = min(
            1.0, max(0.0, float(config.get("seqmix_shadow_floor_alpha", 0.85)))
        )
        state.seqmix_debt_repay_enabled = bool(config.get("seqmix_debt_repay_enabled", False))
        state.seqmix_debt_repay_quota_fraction = min(
            1.0, max(0.0, float(config.get("seqmix_debt_repay_quota_fraction", 0.05)))
        )
        state.seqmix_debt_repay_unique_soft_cap = max(
            0, int(config.get("seqmix_debt_repay_unique_soft_cap", 192))
        )
        state.seqmix_debt_repay_min_dt_median_s = max(
            0.0, float(config.get("seqmix_debt_repay_min_dt_median_s", 0.366))
        )
        state.seqmix_debt_repay_require_shadow_eligible = bool(
            config.get("seqmix_debt_repay_require_shadow_eligible", True)
        )
        state.seqmix_debt_repay_require_strong_timing = bool(
            config.get("seqmix_debt_repay_require_strong_timing", False)
        )
        state.seqmix_service_lane_unique_soft_cap = int(config.get("seqmix_service_lane_unique_soft_cap", -1))
        state.seqmix_baseline_floor_protect_enabled = bool(
            config.get("seqmix_baseline_floor_protect_enabled", False)
        )
        state.seqmix_baseline_floor_fraction = min(
            1.0, max(0.0, float(config.get("seqmix_baseline_floor_fraction", 0.35)))
        )
        state.seqmix_service_lane_current_unique_block = bool(
            config.get("seqmix_service_lane_current_unique_block", False)
        )
    if method == "P3-Adaptive":
        state.adaptive_controller = HedgeController(
            parse_action_grid(config.get("adaptive_actions")),
            eta=float(config.get("adaptive_eta", 0.5)),
        )
        apply_adaptive_action(state, state.adaptive_controller.select(), config)
    return state


def apply_adaptive_action(state: MethodState, action: Any, config: dict[str, Any] | None = None) -> None:
    state.adaptive_current_action = action
    state.persist_k = max(1, int(action.persist_k))
    state.persist_reserve = max(0, int(action.persist_reserve))
    state.gate_mode = str(action.gate_mode)
    if config:
        state.adaptive_base_sram_bytes = (
            int(config.get("zephyr_cache_size", 64)) * 16
            + int(config.get("rl_capacity", len(state.rl_entries))) * 4
            + int(config.get("num_bonded", 0)) * 8
            + 64
            + 16
        )
    state.adaptive_sram_bytes = state.adaptive_base_sram_bytes + state.persist_reserve * 8


def adaptive_window_loss(state: MethodState) -> float:
    legit_shortfall = max(0, state.adaptive_window_legit_events - state.adaptive_window_legit_resolved) / max(
        1, state.adaptive_window_legit_events
    )
    window_min = max(1.0 / 60.0, state.budget_window_s / 60.0)
    attack_amp = state.adaptive_window_attack_aes / window_min
    cap_per_min = (
        (state.budget_per_window + state.persist_reserve) * state.adaptive_scan_cost / window_min
        if state.adaptive_scan_cost
        else 0.0
    )
    amp_over_cap = max(0.0, attack_amp - cap_per_min) / max(1.0, cap_per_min)
    overhead = max(0.0, state.adaptive_sram_bytes - state.adaptive_sram_budget_bytes) / max(
        1.0, state.adaptive_sram_budget_bytes
    )
    return min(
        1.0,
        max(
            0.0,
            state.adaptive_lambda_l * legit_shortfall
            + state.adaptive_lambda_a * amp_over_cap
            + state.adaptive_lambda_o * overhead,
        ),
    )


def maybe_update_adaptive_action(state: MethodState, event: AddressEvent) -> None:
    if state.method != "P3-Adaptive" or state.adaptive_controller is None:
        return
    window = event.ts_ms // max(1, state.budget_window_s * 1000)
    if state.adaptive_window_index < 0:
        state.adaptive_window_index = int(window)
        return
    if window == state.adaptive_window_index:
        return
    if state.adaptive_current_action is not None:
        state.adaptive_controller.update_selected(state.adaptive_current_action.action_id, adaptive_window_loss(state))
    apply_adaptive_action(state, state.adaptive_controller.select())
    state.adaptive_window_index = int(window)
    state.adaptive_window_legit_events = 0
    state.adaptive_window_legit_resolved = 0
    state.adaptive_window_attack_aes = 0


def record_adaptive_decision(state: MethodState, event: AddressEvent, decision: Decision) -> Decision:
    if state.method != "P3-Adaptive":
        return decision
    if event.addr_type == "rpa" and event.source_type == "legit_bonded":
        state.adaptive_window_legit_events += 1
        if decision.matched:
            state.adaptive_window_legit_resolved += 1
    if event.addr_type == "rpa" and event.source_type == "attack":
        state.adaptive_window_attack_aes += decision.aes_attempts
    return decision


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
        "P3-SPRT",
        "P3-SeqMix",
        "P3-Adaptive",
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
    if state.gate_mode == "sprt":
        return sprt_reserve_allows(state, event)
    if state.gate_mode == "seqmix":
        return seqmix_reserve_allows(state, event)
    return count_reserve_allows(state, event)


def count_reserve_allows(state: MethodState, event: AddressEvent) -> bool:
    rpa_value = event.rpa_value or f"{event.addr_type}:{event.rpa_epoch}:{event.event_id}"
    denied_count = state.persist_denied.get(rpa_value, 0)
    if denied_count >= state.persist_k and state.persist_reserve_used < state.persist_reserve:
        state.persist_reserve_used += 1
        return True
    state.persist_denied[rpa_value] = denied_count + 1
    return False


def seqmix_record_for(state: MethodState, rpa_value: str, event: AddressEvent) -> dict[str, Any]:
    record = state.seqmix_records.get(rpa_value)
    if record is not None:
        state.seqmix_records.move_to_end(rpa_value)
        return record
    while len(state.seqmix_records) >= state.seqmix_state_capacity:
        evicted, _ = state.seqmix_records.popitem(last=False)
        state.seqmix_candidate_scores.pop(evicted, None)
    record = {
        "first_seen_ms": event.ts_ms,
        "last_seen_ms": None,
        "seen_ts": deque(),
        "intervals_s": deque(maxlen=state.seqmix_interval_capacity),
        "n_seen": 0,
        "n_denied": 0,
        "windows": set(),
        "last_feature_event_id": None,
        "last_denied_event_id": None,
    }
    state.seqmix_records[rpa_value] = record
    return record


def seqmix_mark_pruned(state: MethodState, rpa_value: str) -> None:
    if rpa_value not in state.seqmix_pruned:
        state.seqmix_pruned_order.append(rpa_value)
    state.seqmix_pruned.add(rpa_value)
    while len(state.seqmix_pruned_order) > state.seqmix_pruned_capacity:
        state.seqmix_pruned.discard(state.seqmix_pruned_order.popleft())


def seqmix_feature_row(state: MethodState, event: AddressEvent, denied: bool = True) -> dict[str, float]:
    rpa_value = event.rpa_value or f"{event.addr_type}:{event.rpa_epoch}:{event.event_id}"
    window = event.ts_ms // max(1, int(state.seqmix_crowd_window_s * 1000))
    if window != state.seqmix_window_index:
        state.seqmix_window_index = int(window)
        state.seqmix_window_counts = Counter()
        state.seqmix_window_total_count = 0
        state.seqmix_window_new_candidate_count = 0
        state.seqmix_window_repeat_candidate_count = 0
        state.seqmix_window_repeat_count_hist = Counter()
    record = seqmix_record_for(state, rpa_value, event)
    first_feature_call_for_event = record.get("last_feature_event_id") != event.event_id
    if first_feature_call_for_event:
        record["last_feature_event_id"] = event.event_id
        record["n_seen"] += 1
    if denied and record.get("last_denied_event_id") != event.event_id:
        record["last_denied_event_id"] = event.event_id
        record["n_denied"] += 1
    if first_feature_call_for_event:
        if record["last_seen_ms"] is not None:
            record["intervals_s"].append(max(0.001, (event.ts_ms - int(record["last_seen_ms"])) / 1000.0))
        record["last_seen_ms"] = event.ts_ms
        record["seen_ts"].append(event.ts_ms)
        horizon_ms = int(state.seqmix_burst_horizon_s * 1000)
        while record["seen_ts"] and event.ts_ms - record["seen_ts"][0] > horizon_ms:
            record["seen_ts"].popleft()
        record["windows"].add(window)
        old_window_count = state.seqmix_window_counts.get(rpa_value, 0)
        new_window_count = old_window_count + 1
        state.seqmix_window_counts[rpa_value] = new_window_count
        state.seqmix_window_total_count += 1
        if old_window_count == 0:
            state.seqmix_window_new_candidate_count += 1
        elif old_window_count == 1:
            state.seqmix_window_new_candidate_count -= 1
            state.seqmix_window_repeat_candidate_count += 1
            state.seqmix_window_repeat_count_hist[2] += 1
        else:
            state.seqmix_window_repeat_count_hist[old_window_count] -= 1
            if state.seqmix_window_repeat_count_hist[old_window_count] <= 0:
                del state.seqmix_window_repeat_count_hist[old_window_count]
            state.seqmix_window_repeat_count_hist[new_window_count] += 1

    intervals = list(record["intervals_s"])
    features = {
        "n_seen": float(record["n_seen"]),
        "n_denied": float(record["n_denied"]),
        "span_s": max(0.0, (event.ts_ms - int(record["first_seen_ms"])) / 1000.0),
        "dt_min_s": min(intervals) if intervals else -1.0,
        "dt_median_s": seqmix_median(intervals),
        "dt_cv": seqmix_cv(intervals),
        "burst_count": float(len(record["seen_ts"])),
        "visible_windows": float(len(record["windows"])),
    }
    if not SEQ_MIX_CROWD_FEATURES.issubset(state.seqmix_disabled_features):
        features.update(
            {
                "repeat_candidate_count_w": float(state.seqmix_window_repeat_candidate_count),
                "new_candidate_count_w": float(state.seqmix_window_new_candidate_count),
                "repeat_candidate_entropy_w": seqmix_entropy_from_hist(state.seqmix_window_repeat_count_hist),
                "reserve_contention_w": state.seqmix_window_repeat_candidate_count / max(1.0, float(state.persist_reserve)),
                "attack_pressure_proxy_w": state.seqmix_window_total_count / max(1.0, float(state.seqmix_attack_pressure_budget)),
            }
        )
    return features


def seqmix_log_family_probability(state: MethodState, family: str, features: dict[str, float]) -> float:
    model = state.seqmix_model or {}
    table = model.get("likelihood_tables", {}).get("P_L") if family == "legit" else model.get("likelihood_tables", {}).get("P_Aj", {}).get(family)
    if not table:
        return float("-inf")
    edges_by_feature = model.get("binning", {}).get("feature_edges", {})
    total = 0.0
    for feature in model.get("features", []):
        if feature in state.seqmix_disabled_features:
            continue
        edges = [float(value) for value in edges_by_feature.get(feature, [])]
        probabilities = table.get("features", {}).get(feature, {}).get("probabilities", [])
        if not probabilities:
            continue
        idx = min(len(probabilities) - 1, seqmix_bin_index(finite_float(features.get(feature, -1.0)), edges))
        total += math.log(max(1e-300, float(probabilities[idx])))
    return total


def seqmix_score(state: MethodState, features: dict[str, float]) -> float:
    model = state.seqmix_model or {}
    log_pl = seqmix_log_family_probability(state, "legit", features)
    terms = []
    for family, weight in model.get("attack_family_weights", {}).items():
        terms.append(math.log(max(1e-300, float(weight))) + seqmix_log_family_probability(state, family, features))
    if not terms:
        return float("-inf")
    return log_pl - logsumexp(terms)


def seqmix_sync_guard_window(state: MethodState, event: AddressEvent) -> None:
    window = int(event.ts_ms // max(1, state.budget_window_s * 1000))
    if window == state.seqmix_guard_window_index:
        return
    state.seqmix_guard_window_index = window
    state.seqmix_guard_denied_count_w = 0
    state.seqmix_guard_high_rssi_denied_count_w = 0
    state.seqmix_guard_rssi_reserve_used_w = 0
    state.seqmix_guard_service_reserve_used_w = 0
    state.seqmix_feedback_grants_w = 0
    state.seqmix_feedback_successes_w = 0
    state.seqmix_feedback_stopped_w = False
    state.seqmix_feedback_lane_grants_w = Counter()
    state.seqmix_feedback_lane_successes_w = Counter()
    state.seqmix_feedback_stopped_lanes_w = set()
    state.seqmix_feedback_bucket_grants_w = Counter()
    state.seqmix_feedback_bucket_successes_w = Counter()
    state.seqmix_feedback_stopped_buckets_w = set()
    state.seqmix_count_fallback_dense_used_w = 0
    state.seqmix_debt_repay_used_w = 0
    state.seqmix_baseline_floor_used_w = 0


def seqmix_sync_debt_window(state: MethodState, event: AddressEvent) -> None:
    window = int(event.ts_ms // max(1, state.budget_window_s * 1000))
    if window == state.seqmix_debt_window_index:
        return
    state.seqmix_debt_window_index = window
    state.seqmix_shadow_floor_eligible_w = 0
    state.seqmix_service_credit_w = 0
    state.seqmix_service_debt_w = 0
    state.seqmix_unique_risk_w = 0
    state.seqmix_debt_trace_pending = {}
    state.seqmix_debt_trace_finalized = set()


def seqmix_unique_pressure_proxy_active(state: MethodState, features: dict[str, float]) -> bool:
    new_count = float(features.get("new_candidate_count_w", 0.0))
    if new_count < state.seqmix_unique_new_candidate_threshold:
        return False
    repeat_count = float(features.get("repeat_candidate_count_w", 0.0))
    return repeat_count / max(1.0, new_count) < state.seqmix_unique_repeat_to_new_min_ratio


def seqmix_shadow_count_eligible(state: MethodState, event: AddressEvent) -> bool:
    rpa_value = event.rpa_value or f"{event.addr_type}:{event.rpa_epoch}:{event.event_id}"
    return state.persist_denied.get(rpa_value, 0) >= state.persist_k


def seqmix_shadow_guarded_eligible(
    state: MethodState,
    event: AddressEvent,
    features: dict[str, float],
    score: float,
) -> bool:
    if event.rssi_dbm < state.seqmix_rssi_threshold_dbm:
        return False
    if float(features.get("n_denied", 0.0)) < state.seqmix_min_denied_before_rssi:
        return False
    if float(features.get("visible_windows", 0.0)) < state.seqmix_min_visible_windows_before_rssi:
        return False
    if score < state.seqmix_stream_floor:
        return False
    if seqmix_high_rssi_pressure_active(state):
        return False
    if (
        seqmix_large_pool_guard_active(state, features)
        and float(features.get("n_denied", 0.0)) < state.seqmix_large_pool_min_denied
    ):
        return False
    return True


def seqmix_shadow_baseline_eligibility(
    state: MethodState,
    event: AddressEvent,
    features: dict[str, float],
    score: float,
) -> tuple[bool, str]:
    mode = state.seqmix_shadow_baseline_mode
    guarded = seqmix_shadow_guarded_eligible(state, event, features, score)
    count = seqmix_shadow_count_eligible(state, event)
    if mode == "count":
        return count, "shadow_count" if count else ""
    if mode == "guarded_or_count":
        if guarded:
            return True, "shadow_guarded_rssi"
        if count:
            return True, "shadow_count"
        return False, ""
    return guarded, "shadow_guarded_rssi" if guarded else ""


def seqmix_recompute_service_debt(state: MethodState) -> None:
    floor_target = int(math.ceil(state.seqmix_shadow_floor_alpha * state.seqmix_shadow_floor_eligible_w))
    state.seqmix_service_debt_w = max(0, floor_target - state.seqmix_service_credit_w)


def seqmix_debt_repay_quota(state: MethodState) -> int:
    return max(0, int(state.persist_reserve * state.seqmix_debt_repay_quota_fraction))


def seqmix_baseline_floor_quota(state: MethodState) -> int:
    return max(0, int(math.ceil(state.persist_reserve * state.seqmix_baseline_floor_fraction)))


def seqmix_optional_reserve_preserves_baseline_floor(state: MethodState) -> bool:
    if not state.seqmix_baseline_floor_protect_enabled or state.seqmix_service_debt_w <= 0:
        return True
    floor_remaining = max(0, seqmix_baseline_floor_quota(state) - state.seqmix_baseline_floor_used_w)
    reserve_remaining = max(0, state.persist_reserve - state.persist_reserve_used)
    return reserve_remaining > floor_remaining


def seqmix_service_lane_unique_cap_allows(state: MethodState, features: dict[str, float] | None = None) -> bool:
    if (
        state.seqmix_service_lane_current_unique_block
        and features is not None
        and seqmix_unique_pressure_proxy_active(state, features)
    ):
        return False
    return state.seqmix_service_lane_unique_soft_cap < 0 or state.seqmix_unique_risk_w < state.seqmix_service_lane_unique_soft_cap


def seqmix_note_debt_denial(
    state: MethodState,
    event: AddressEvent,
    features: dict[str, float],
    score: float,
) -> None:
    if not state.seqmix_trace_debt_ledger_enabled:
        return
    seqmix_sync_debt_window(state, event)
    service_before = state.seqmix_service_debt_w
    unique_before = state.seqmix_unique_risk_w
    shadow_eligible, shadow_lane = seqmix_shadow_baseline_eligibility(state, event, features, score)
    if shadow_eligible:
        state.seqmix_shadow_floor_eligible_w += 1
    unique_pressure = seqmix_unique_pressure_proxy_active(state, features)
    if unique_pressure:
        state.seqmix_unique_risk_w += 1
    seqmix_recompute_service_debt(state)
    if state.seqmix_service_debt_w > 0 and unique_pressure:
        debt_action = "service_debt_with_unique_pressure"
    elif state.seqmix_service_debt_w > 0:
        debt_action = "service_debt_positive"
    elif unique_pressure:
        debt_action = "unique_pressure"
    else:
        debt_action = "observe"
    state.seqmix_debt_trace_pending[event.event_id] = {
        "shadow_eligible": shadow_eligible,
        "shadow_lane": shadow_lane,
        "service_before": service_before,
        "service_after_denial": state.seqmix_service_debt_w,
        "unique_before": unique_before,
        "unique_after_denial": state.seqmix_unique_risk_w,
        "unique_pressure": unique_pressure,
        "debt_action": debt_action,
    }


def seqmix_apply_debt_trace_fields(state: MethodState, decision: Decision, finalized: bool = False) -> None:
    if not state.seqmix_trace_debt_ledger_enabled:
        return
    pending = state.seqmix_debt_trace_pending.get(decision.event_id)
    if pending is None:
        return
    decision.seqmix_shadow_baseline_eligible = bool(pending.get("shadow_eligible", False))
    decision.seqmix_shadow_baseline_lane = str(pending.get("shadow_lane", ""))
    decision.seqmix_service_debt_before = int(pending.get("service_before", 0))
    decision.seqmix_unique_risk_before = int(pending.get("unique_before", 0))
    if finalized:
        decision.seqmix_service_debt_after = state.seqmix_service_debt_w
        decision.seqmix_unique_risk_after = state.seqmix_unique_risk_w
    else:
        decision.seqmix_service_debt_after = int(pending.get("service_after_denial", state.seqmix_service_debt_w))
        decision.seqmix_unique_risk_after = int(pending.get("unique_after_denial", state.seqmix_unique_risk_w))
    decision.seqmix_debt_action = str(pending.get("debt_action", ""))


def seqmix_finalize_debt_trace(state: MethodState, event: AddressEvent, decision: Decision) -> None:
    if not state.seqmix_trace_debt_ledger_enabled or decision.event_id in state.seqmix_debt_trace_finalized:
        seqmix_apply_debt_trace_fields(state, decision, finalized=False)
        return
    pending = state.seqmix_debt_trace_pending.get(decision.event_id)
    if pending is None:
        return
    seqmix_sync_debt_window(state, event)
    if decision.action == "host_scan" and decision.matched:
        state.seqmix_service_credit_w += 1
    if bool(pending.get("unique_pressure", False)) and decision.action == "host_scan" and decision.admission_path == "reserve":
        if decision.matched:
            state.seqmix_unique_risk_w = max(0, state.seqmix_unique_risk_w - 1)
        else:
            state.seqmix_unique_risk_w += 1
    seqmix_recompute_service_debt(state)
    state.seqmix_debt_trace_finalized.add(decision.event_id)
    seqmix_apply_debt_trace_fields(state, decision, finalized=True)


def seqmix_debt_repay_candidate_allows(
    state: MethodState,
    event: AddressEvent,
    features: dict[str, float],
    score: float,
    high_rssi: bool,
) -> bool:
    if not (
        state.seqmix_baseline_debt_enabled
        and state.seqmix_debt_repay_enabled
        and state.seqmix_window_ranked_enabled
    ):
        return False
    if state.seqmix_service_debt_w <= 0:
        return False
    if state.seqmix_debt_repay_used_w >= seqmix_debt_repay_quota(state):
        return False
    if float(features.get("n_denied", 0.0)) < state.seqmix_min_denied_before_rssi:
        return False
    if float(features.get("visible_windows", 0.0)) < state.seqmix_min_visible_windows_before_rssi:
        return False
    if score < state.seqmix_stream_floor:
        return False
    shadow_eligible, _ = seqmix_shadow_baseline_eligibility(state, event, features, score)
    if state.seqmix_debt_repay_require_shadow_eligible and not shadow_eligible:
        return False
    strong_timing = float(features.get("dt_median_s", -1.0)) >= state.seqmix_debt_repay_min_dt_median_s
    if state.seqmix_debt_repay_require_strong_timing and not strong_timing:
        return False
    if state.seqmix_unique_risk_w >= state.seqmix_debt_repay_unique_soft_cap and not strong_timing:
        return False
    if not high_rssi and not strong_timing:
        return False
    return True


def seqmix_large_pool_guard_active(state: MethodState, features: dict[str, float]) -> bool:
    if not state.seqmix_large_pool_guard_enabled:
        return False
    return (
        float(features.get("repeat_candidate_count_w", 0.0)) >= state.seqmix_large_pool_repeat_threshold
        and float(features.get("repeat_candidate_entropy_w", 0.0)) >= state.seqmix_large_pool_entropy_threshold
        and float(features.get("reserve_contention_w", 0.0)) >= state.seqmix_large_pool_contention_threshold
    )


def seqmix_note_guard_denial(state: MethodState, event: AddressEvent) -> bool:
    seqmix_sync_guard_window(state, event)
    state.seqmix_guard_denied_count_w += 1
    high_rssi = event.rssi_dbm >= state.seqmix_rssi_threshold_dbm
    if high_rssi:
        state.seqmix_guard_high_rssi_denied_count_w += 1
    return high_rssi


def seqmix_high_rssi_pressure_active(state: MethodState) -> bool:
    pressure = state.seqmix_guard_high_rssi_denied_count_w / max(1.0, float(state.seqmix_guard_denied_count_w))
    return (
        state.seqmix_guard_denied_count_w >= state.seqmix_high_rssi_pressure_min_denied
        and pressure > state.seqmix_high_rssi_pressure_threshold
    )


def seqmix_rssi_quota(state: MethodState) -> int:
    return max(1, int(state.persist_reserve * state.seqmix_rssi_quota_fraction))


def seqmix_service_quota(state: MethodState) -> int:
    return max(0, int(state.persist_reserve * state.seqmix_service_quota_fraction))


def seqmix_feedback_lane(lane: str) -> bool:
    return lane in {"guarded_rssi", "low_rssi_service", "dense_service", "guarded_retry", "service_lane", "debt_repay"}


def seqmix_feedback_bucket_key(state: MethodState, lane: str, bucket: int) -> str:
    if state.seqmix_feedback_scope == "lane_bucket":
        return f"{lane}:{bucket}"
    return str(bucket)


def seqmix_feedback_stops_lane(state: MethodState, lane: str, bucket: int = -1) -> bool:
    if not state.seqmix_feedback_hard_stop_enabled or not seqmix_feedback_lane(lane):
        return False
    if state.seqmix_feedback_scope == "group":
        return state.seqmix_feedback_stopped_w
    if state.seqmix_feedback_scope == "lane":
        return lane in state.seqmix_feedback_stopped_lanes_w
    if state.seqmix_feedback_scope in {"bucket", "lane_bucket"} and bucket >= 0:
        return seqmix_feedback_bucket_key(state, lane, bucket) in state.seqmix_feedback_stopped_buckets_w
    return False


def seqmix_note_feedback_grant(state: MethodState, lane: str, bucket: int, matched: bool) -> None:
    if not state.seqmix_feedback_hard_stop_enabled or not seqmix_feedback_lane(lane):
        return
    if state.seqmix_feedback_scope == "group":
        state.seqmix_feedback_grants_w += 1
        if matched:
            state.seqmix_feedback_successes_w += 1
        if (
            state.seqmix_feedback_grants_w >= state.seqmix_feedback_zero_success_stop_grants
            and state.seqmix_feedback_successes_w == 0
        ):
            state.seqmix_feedback_stopped_w = True
        return
    if state.seqmix_feedback_scope == "lane":
        state.seqmix_feedback_lane_grants_w[lane] += 1
        if matched:
            state.seqmix_feedback_lane_successes_w[lane] += 1
        if (
            state.seqmix_feedback_lane_grants_w[lane] >= state.seqmix_feedback_zero_success_stop_grants
            and state.seqmix_feedback_lane_successes_w[lane] == 0
        ):
            state.seqmix_feedback_stopped_lanes_w.add(lane)
        return
    if bucket < 0:
        return
    bucket_key = seqmix_feedback_bucket_key(state, lane, bucket)
    state.seqmix_feedback_bucket_grants_w[bucket_key] += 1
    if matched:
        state.seqmix_feedback_bucket_successes_w[bucket_key] += 1
    if (
        state.seqmix_feedback_bucket_grants_w[bucket_key] >= state.seqmix_feedback_zero_success_stop_grants
        and state.seqmix_feedback_bucket_successes_w[bucket_key] == 0
    ):
        state.seqmix_feedback_stopped_buckets_w.add(bucket_key)


def seqmix_unique_flood_guard_active(state: MethodState, features: dict[str, float]) -> bool:
    if not state.seqmix_unique_flood_guard_enabled:
        return False
    new_count = float(features.get("new_candidate_count_w", 0.0))
    if new_count < state.seqmix_unique_new_candidate_threshold:
        return False
    repeat_count = float(features.get("repeat_candidate_count_w", 0.0))
    return repeat_count / max(1.0, new_count) < state.seqmix_unique_repeat_to_new_min_ratio


def seqmix_unique_flood_guard_active_w(state: MethodState) -> bool:
    if not state.seqmix_unique_flood_guard_enabled:
        return False
    new_count = float(state.seqmix_window_new_candidate_count)
    if new_count < state.seqmix_unique_new_candidate_threshold:
        return False
    repeat_count = float(state.seqmix_window_repeat_candidate_count)
    return repeat_count / max(1.0, new_count) < state.seqmix_unique_repeat_to_new_min_ratio


def seqmix_dense_service_pressure_active(state: MethodState, features: dict[str, float]) -> bool:
    repeat_count = float(features.get("repeat_candidate_count_w", 0.0))
    return (
        repeat_count >= state.seqmix_dense_service_min_repeat_candidates
        and repeat_count <= state.seqmix_dense_service_max_repeat_candidates
        and float(features.get("reserve_contention_w", 0.0)) >= state.seqmix_dense_service_min_contention
        and float(features.get("attack_pressure_proxy_w", 0.0)) <= state.seqmix_dense_service_max_attack_pressure
    )


def seqmix_count_fallback_dense_quota(state: MethodState) -> int:
    return max(0, int(state.persist_reserve * state.seqmix_count_fallback_dense_fraction))


def seqmix_count_fallback_allows(
    state: MethodState,
    event: AddressEvent,
    features: dict[str, float],
) -> bool:
    if not seqmix_optional_reserve_preserves_baseline_floor(state):
        return False
    if not (
        state.seqmix_count_fallback_dense_limit_enabled
        and seqmix_dense_service_pressure_active(state, features)
    ):
        return count_reserve_allows(state, event)
    if state.seqmix_count_fallback_dense_used_w >= seqmix_count_fallback_dense_quota(state):
        return False
    before_used = state.persist_reserve_used
    allowed = count_reserve_allows(state, event)
    if allowed and state.persist_reserve_used > before_used:
        state.seqmix_count_fallback_dense_used_w += 1
    return allowed


def seqmix_guarded_candidate_allows(
    state: MethodState,
    event: AddressEvent,
    features: dict[str, float],
    score: float,
    high_rssi: bool,
) -> bool:
    if not high_rssi:
        return False
    if float(features.get("n_denied", 0.0)) < state.seqmix_min_denied_before_rssi:
        return False
    if float(features.get("visible_windows", 0.0)) < state.seqmix_min_visible_windows_before_rssi:
        return False
    if score < state.seqmix_stream_floor:
        return False
    if (
        state.seqmix_window_ranked_enabled
        and float(features.get("repeat_candidate_count_w", 0.0)) < state.seqmix_rank_min_window_repeat_candidates
    ):
        return False
    if seqmix_high_rssi_pressure_active(state):
        return False
    if state.seqmix_guard_rssi_reserve_used_w >= seqmix_rssi_quota(state):
        return False
    if seqmix_large_pool_guard_active(state, features) and float(features.get("n_denied", 0.0)) < state.seqmix_large_pool_min_denied:
        return False
    return True


def seqmix_guarded_ranking_score(state: MethodState, event: AddressEvent, features: dict[str, float], score: float) -> float:
    finite_score = score if math.isfinite(score) else -1e9
    rssi_boost = max(-1.0, min(3.0, (event.rssi_dbm - state.seqmix_rssi_threshold_dbm) / state.seqmix_rssi_scale_db))
    repeat_penalty = 0.02 * max(0.0, float(features.get("repeat_candidate_count_w", 0.0)) - 1.0)
    contention_penalty = 0.05 * max(0.0, float(features.get("reserve_contention_w", 0.0)) - 1.0)
    return (
        state.seqmix_stream_score_weight * finite_score
        + state.seqmix_rssi_boost_weight * rssi_boost
        - repeat_penalty
        - contention_penalty
    )


def seqmix_stage_ranked_pending(
    state: MethodState,
    event: AddressEvent,
    features: dict[str, float],
    score: float,
    high_rssi: bool,
    service_lane: bool = False,
    lane: str | None = None,
) -> bool:
    if len(state.seqmix_rank_pending) >= state.seqmix_rank_max_pending:
        return False
    state.seqmix_rank_sequence += 1
    lane_name = lane or ("service_lane" if service_lane else "guarded_rssi")
    bucket_count = 64
    bucket_source = event.rpa_value or f"{event.addr_type}:{event.rpa_epoch}:{event.event_id}"
    bucket = int(hashlib.sha256(bucket_source.encode("utf-8")).hexdigest()[:8], 16) % bucket_count
    if seqmix_feedback_stops_lane(state, lane_name, bucket):
        return False
    ranking_score = seqmix_guarded_ranking_score(state, event, features, score)
    pending = {
        "event": event,
        "features": features,
        "score": score,
        "high_rssi": high_rssi,
        "service_lane": service_lane,
        "lane": lane_name,
        "bucket": bucket,
        "ranking_score": ranking_score,
        "deadline_ms": event.ts_ms + state.seqmix_rank_window_ms,
        "sequence": state.seqmix_rank_sequence,
        "decision": None,
        "scan_cost": 0,
    }
    state.seqmix_rank_pending.append(pending)
    state.seqmix_rank_pending_by_event[event.event_id] = pending
    return True


def seqmix_bind_ranked_pending_decision(
    state: MethodState,
    event: AddressEvent,
    decision: Decision,
    scan_cost: int,
) -> None:
    pending = state.seqmix_rank_pending_by_event.get(event.event_id)
    if pending is None:
        return
    pending["decision"] = decision
    pending["scan_cost"] = scan_cost
    decision.seqmix_lane = str(pending.get("lane", ""))
    decision.seqmix_bucket = int(pending.get("bucket", -1))
    score = pending.get("score", 0.0)
    ranking_score = pending.get("ranking_score", 0.0)
    decision.seqmix_score = round(float(score), 6) if math.isfinite(float(score)) else -1e9
    decision.seqmix_ranking_score = round(float(ranking_score), 6) if math.isfinite(float(ranking_score)) else -1e9
    if decision.action == "defer":
        decision.delay_ms = max(decision.delay_ms, state.seqmix_rank_window_ms)


def seqmix_grant_ranked_pending(state: MethodState, pending: dict[str, Any], grant_ts_ms: int) -> None:
    event = pending["event"]
    decision = pending["decision"]
    delay_ms = max(0, grant_ts_ms - int(event.ts_ms))
    decision.action = "host_scan"
    decision.aes_attempts = int(pending["scan_cost"])
    decision.matched = event.source_type == "legit_bonded"
    decision.matched_device_id = event.device_id if decision.matched else ""
    decision.deferred = delay_ms > 0
    decision.delay_ms = delay_ms
    decision.false_defer = False
    decision.drop_reason = ""
    decision.admission_path = "reserve"
    if state.method in CACHE_METHODS:
        state.put_cache(event, decision.matched_device_id)
    maybe_update_rl(state, event)
    state.persist_reserve_used += 1
    if str(pending.get("lane", "")) == "guarded_rssi":
        state.seqmix_baseline_floor_used_w += 1
    seqmix_note_feedback_grant(
        state,
        str(pending.get("lane", "")),
        int(pending.get("bucket", -1)),
        bool(decision.matched),
    )
    seqmix_finalize_debt_trace(state, event, decision)


def seqmix_flush_ranked_pending(
    state: MethodState,
    now_ms: int,
    devices: list[Device],
    force: bool = False,
) -> None:
    if not state.seqmix_window_ranked_enabled or not state.seqmix_rank_pending:
        return
    bound = [pending for pending in state.seqmix_rank_pending if pending.get("decision") is not None]
    if not bound:
        return
    should_flush = (
        force
        or len(bound) >= state.seqmix_rank_flush_denials
        or any(int(pending["deadline_ms"]) <= now_ms for pending in bound)
    )
    if not should_flush:
        return

    batch = bound
    ranked = sorted(
        batch,
        key=lambda item: (
            -float(item["ranking_score"]),
            -float(item["score"]) if math.isfinite(float(item["score"])) else 1e9,
            -float(item["event"].rssi_dbm),
            int(item["sequence"]),
        ),
    )
    grants = 0
    selected: set[int] = set()
    max_grants = state.seqmix_rank_max_grants_per_flush
    rssi_quota = seqmix_rssi_quota(state)
    for pending in ranked:
        if bool(pending.get("service_lane", False)):
            continue
        if seqmix_feedback_stops_lane(state, str(pending.get("lane", "")), int(pending.get("bucket", -1))):
            continue
        if grants >= max_grants:
            break
        if state.persist_reserve_used >= state.persist_reserve:
            break
        if state.seqmix_guard_rssi_reserve_used_w >= rssi_quota:
            break
        grant_ts_ms = now_ms if int(pending["deadline_ms"]) > now_ms and not force else int(pending["deadline_ms"])
        seqmix_grant_ranked_pending(state, pending, grant_ts_ms)
        state.seqmix_guard_rssi_reserve_used_w += 1
        grants += 1
        selected.add(pending["event"].event_id)

    service_grants = 0
    service_quota = seqmix_service_quota(state)
    service_ranked = sorted(
        [pending for pending in batch if bool(pending.get("service_lane", False)) and pending["event"].event_id not in selected],
        key=lambda item: (
            -float(item["score"]) if math.isfinite(float(item["score"])) else 1e9,
            int(item["sequence"]),
        ),
    )
    for pending in service_ranked:
        lane_name = str(pending.get("lane", ""))
        if seqmix_feedback_stops_lane(state, lane_name, int(pending.get("bucket", -1))):
            continue
        if service_grants >= state.seqmix_rank_service_max_grants_per_flush:
            break
        if state.persist_reserve_used >= state.persist_reserve:
            break
        if state.seqmix_guard_service_reserve_used_w >= service_quota:
            break
        if not seqmix_optional_reserve_preserves_baseline_floor(state):
            continue
        if lane_name == "debt_repay" and state.seqmix_debt_repay_used_w >= seqmix_debt_repay_quota(state):
            continue
        bucket = int(pending.get("bucket", -1))
        if (
            state.seqmix_dense_service_bucket_cooldown > 0
            and lane_name == "dense_service"
            and bucket >= 0
        ):
            last_grant = state.seqmix_dense_service_bucket_last_grant.get(bucket)
            if (
                last_grant is not None
                and state.seqmix_dense_service_grant_sequence - last_grant < state.seqmix_dense_service_bucket_cooldown
            ):
                continue
        grant_ts_ms = now_ms if int(pending["deadline_ms"]) > now_ms and not force else int(pending["deadline_ms"])
        seqmix_grant_ranked_pending(state, pending, grant_ts_ms)
        state.seqmix_guard_service_reserve_used_w += 1
        if lane_name == "debt_repay":
            state.seqmix_debt_repay_used_w += 1
        service_grants += 1
        if (
            state.seqmix_dense_service_bucket_cooldown > 0
            and lane_name == "dense_service"
            and bucket >= 0
        ):
            state.seqmix_dense_service_grant_sequence += 1
            state.seqmix_dense_service_bucket_last_grant[bucket] = state.seqmix_dense_service_grant_sequence
        selected.add(pending["event"].event_id)

    for pending in batch:
        event_id = pending["event"].event_id
        if event_id not in selected:
            decision = pending["decision"]
            if decision.action == "defer":
                decision.delay_ms = max(decision.delay_ms, state.seqmix_rank_window_ms)
        state.seqmix_rank_pending_by_event.pop(event_id, None)
    flushed_ids = {pending["event"].event_id for pending in batch}
    state.seqmix_rank_pending = [
        pending for pending in state.seqmix_rank_pending if pending["event"].event_id not in flushed_ids
    ]


def seqmix_guarded_rssi_allows(state: MethodState, event: AddressEvent, features: dict[str, float], score: float) -> bool:
    high_rssi = seqmix_note_guard_denial(state, event)

    if seqmix_debt_repay_candidate_allows(state, event, features, score, high_rssi):
        seqmix_stage_ranked_pending(
            state,
            event,
            features,
            score,
            high_rssi,
            service_lane=True,
            lane="debt_repay",
        )
        return False

    if state.seqmix_window_ranked_enabled and seqmix_unique_flood_guard_active(state, features):
        if state.seqmix_unique_flood_guard_action == "block":
            return False
        return seqmix_count_fallback_allows(state, event, features)
    if state.seqmix_guarded_count_fallback_enabled and not high_rssi:
        return seqmix_count_fallback_allows(state, event, features)
    if (
        state.seqmix_window_ranked_enabled
        and state.seqmix_rank_low_rssi_service_enabled
        and not high_rssi
        and float(features.get("n_denied", 0.0)) >= state.seqmix_min_denied_before_rssi
        and float(features.get("visible_windows", 0.0)) >= state.seqmix_min_visible_windows_before_rssi
        and score >= state.seqmix_stream_floor
        and state.seqmix_guard_service_reserve_used_w < seqmix_service_quota(state)
        and seqmix_service_lane_unique_cap_allows(state, features)
    ):
        seqmix_stage_ranked_pending(
            state,
            event,
            features,
            score,
            high_rssi,
            service_lane=True,
            lane="low_rssi_service",
        )
        return False
    if (
        state.seqmix_window_ranked_enabled
        and state.seqmix_rank_guarded_retry_enabled
        and not seqmix_unique_flood_guard_active(state, features)
        and float(features.get("dt_median_s", -1.0)) >= state.seqmix_guarded_retry_min_dt_median_s
        and float(features.get("n_denied", 0.0)) >= state.seqmix_min_denied_before_rssi
        and float(features.get("visible_windows", 0.0)) >= state.seqmix_min_visible_windows_before_rssi
        and score >= state.seqmix_stream_floor
        and state.seqmix_guard_service_reserve_used_w < seqmix_service_quota(state)
        and seqmix_service_lane_unique_cap_allows(state, features)
    ):
        seqmix_stage_ranked_pending(
            state,
            event,
            features,
            score,
            high_rssi,
            service_lane=True,
            lane="guarded_retry",
        )
        return False
    if (
        state.seqmix_window_ranked_enabled
        and state.seqmix_rank_dense_service_enabled
        and (not state.seqmix_dense_service_require_low_rssi or not high_rssi)
        and not seqmix_unique_flood_guard_active(state, features)
        and seqmix_dense_service_pressure_active(state, features)
        and float(features.get("n_seen", 0.0)) >= state.seqmix_dense_service_min_seen
        and float(features.get("n_denied", 0.0)) >= state.seqmix_min_denied_before_rssi
        and float(features.get("visible_windows", 0.0)) >= state.seqmix_min_visible_windows_before_rssi
        and score >= state.seqmix_stream_floor
        and state.seqmix_guard_service_reserve_used_w < seqmix_service_quota(state)
        and seqmix_service_lane_unique_cap_allows(state, features)
    ):
        seqmix_stage_ranked_pending(
            state,
            event,
            features,
            score,
            high_rssi,
            service_lane=True,
            lane="dense_service",
        )
        return False
    if not seqmix_guarded_candidate_allows(state, event, features, score, high_rssi):
        return False
    if state.seqmix_window_ranked_enabled:
        seqmix_stage_ranked_pending(state, event, features, score, high_rssi, lane="guarded_rssi")
        return False

    if state.persist_reserve_used >= state.persist_reserve:
        return False
    state.persist_reserve_used += 1
    state.seqmix_guard_rssi_reserve_used_w += 1
    state.seqmix_baseline_floor_used_w += 1
    return True


def seqmix_reserve_allows(state: MethodState, event: AddressEvent) -> bool:
    if not state.seqmix_model:
        return count_reserve_allows(state, event)
    rpa_value = event.rpa_value or f"{event.addr_type}:{event.rpa_epoch}:{event.event_id}"
    if rpa_value in state.seqmix_pruned:
        return False
    if state.seqmix_rssi_gate_enabled:
        if event.rssi_dbm >= state.seqmix_rssi_threshold_dbm and state.persist_reserve_used < state.persist_reserve:
            state.persist_reserve_used += 1
            return True
        return False
    features = seqmix_feature_row(state, event, denied=True)
    score = seqmix_score(state, features)
    seqmix_note_debt_denial(state, event, features, score)
    if state.seqmix_guarded_rssi_enabled:
        return seqmix_guarded_rssi_allows(state, event, features, score)
    if score < state.seqmix_theta_low:
        seqmix_mark_pruned(state, rpa_value)
        state.seqmix_candidate_scores.pop(rpa_value, None)
        return False
    if score >= state.seqmix_theta_high:
        if state.seqmix_disable_ranking and state.persist_reserve_used < state.persist_reserve:
            state.persist_reserve_used += 1
            return True
        current_score = state.seqmix_candidate_scores.get(rpa_value)
        if current_score is None or score > current_score:
            state.seqmix_candidate_scores[rpa_value] = score
            heapq.heappush(state.seqmix_candidate_heap, (-score, event.event_id, rpa_value))
            if len(state.seqmix_candidate_scores) > state.seqmix_candidate_capacity:
                victim = min(state.seqmix_candidate_scores, key=state.seqmix_candidate_scores.get)
                state.seqmix_candidate_scores.pop(victim, None)
    while state.seqmix_candidate_heap:
        neg_score, _, candidate = state.seqmix_candidate_heap[0]
        current = state.seqmix_candidate_scores.get(candidate)
        if current is None or abs(current + neg_score) > 1e-9:
            heapq.heappop(state.seqmix_candidate_heap)
            continue
        if candidate == rpa_value and current >= state.seqmix_theta_high and state.persist_reserve_used < state.persist_reserve:
            heapq.heappop(state.seqmix_candidate_heap)
            state.persist_reserve_used += 1
            state.seqmix_candidate_scores.pop(candidate, None)
            return True
        return False
    return False


def sprt_log_lr_increment(state: MethodState, dt_s: float, event: AddressEvent) -> float:
    legit_mean = state.sprt_legit_interarrival_mean_s
    attack_mean = state.sprt_attack_interarrival_mean_s
    increment = math.log(attack_mean / legit_mean) + dt_s * ((1.0 / attack_mean) - (1.0 / legit_mean))
    if state.sprt_trusted_bonus and trusted_event(event):
        increment += state.sprt_trusted_bonus
    return increment


def sprt_reserve_allows(state: MethodState, event: AddressEvent) -> bool:
    rpa_value = event.rpa_value or f"{event.addr_type}:{event.rpa_epoch}:{event.event_id}"
    if rpa_value in state.sprt_terminated:
        return False
    last_seen_ms = state.sprt_last_seen_ms.get(rpa_value)
    state.sprt_last_seen_ms[rpa_value] = event.ts_ms
    if last_seen_ms is None:
        state.llr.setdefault(rpa_value, 0.0)
        return False

    dt_s = max(0.001, (event.ts_ms - last_seen_ms) / 1000.0)
    llr = state.llr.get(rpa_value, 0.0) + sprt_log_lr_increment(state, dt_s, event)
    if llr <= state.sprt_a_lower:
        state.sprt_terminated.add(rpa_value)
        state.llr.pop(rpa_value, None)
        state.sprt_last_seen_ms.pop(rpa_value, None)
        return False
    state.llr[rpa_value] = llr
    if llr >= state.sprt_a_upper and state.persist_reserve_used < state.persist_reserve:
        state.persist_reserve_used += 1
        return True
    return False


def trusted_event(event: AddressEvent) -> bool:
    # RSSI is only used as a scheduling/budget signal. It never identifies a device.
    return event.rssi_dbm >= -78.0


def duplicate_filter_diag_rank(values: list[float], current: float) -> float:
    if not values:
        return 1.0
    return sum(1 for value in values if value <= current) / len(values)


def duplicate_filter_diagnostic_features(state: MethodState, event: AddressEvent) -> dict[str, Any]:
    window = event.ts_ms // max(1, state.budget_window_s * 1000)
    if window != state.df_diag_window_index:
        state.df_diag_window_index = int(window)
        state.df_diag_window_counts = Counter()
        state.df_diag_window_rssi = []
    rpa_value = event.rpa_value or f"{event.addr_type}:{event.rpa_epoch}:{event.event_id}"
    record = state.df_diag_records.setdefault(
        rpa_value,
        {
            "first_seen_ms": event.ts_ms,
            "last_seen_ms": None,
            "seen_ts": deque(),
            "intervals_s": deque(maxlen=state.seqmix_interval_capacity),
            "n_seen": 0,
            "windows": set(),
            "prior_duplicate_filter_count": 0,
            "prior_host_scan_count": 0,
            "prior_reserve_count": 0,
            "prior_budget_drop_count": 0,
            "prior_cache_hit_count": 0,
        },
    )
    prior_seen = int(record["n_seen"])
    interarrival_s = -1.0
    if record["last_seen_ms"] is not None:
        interarrival_s = max(0.001, (event.ts_ms - int(record["last_seen_ms"])) / 1000.0)
        record["intervals_s"].append(interarrival_s)
    record["n_seen"] += 1
    record["last_seen_ms"] = event.ts_ms
    record["seen_ts"].append(event.ts_ms)
    horizon_ms = int(state.seqmix_burst_horizon_s * 1000)
    while record["seen_ts"] and event.ts_ms - int(record["seen_ts"][0]) > horizon_ms:
        record["seen_ts"].popleft()
    record["windows"].add(window)
    state.df_diag_window_counts[rpa_value] += 1
    state.df_diag_window_rssi.append(event.rssi_dbm)
    repeated_counts = [count for count in state.df_diag_window_counts.values() if count >= 2]
    repeat_candidate_count = len(repeated_counts)
    new_candidate_count = sum(1 for count in state.df_diag_window_counts.values() if count == 1)
    intervals = list(record["intervals_s"])
    features = {
        "rssi_dbm": round(event.rssi_dbm, 6),
        "rssi_rank_pct_w": round(duplicate_filter_diag_rank(state.df_diag_window_rssi, event.rssi_dbm), 6),
        "candidate_age_s": round((event.ts_ms - int(record["first_seen_ms"])) / 1000.0, 6),
        "interarrival_s": round(interarrival_s, 6),
        "n_seen": int(record["n_seen"]),
        "prior_seen_count": prior_seen,
        "prior_duplicate_filter_count": int(record["prior_duplicate_filter_count"]),
        "prior_host_scan_count": int(record["prior_host_scan_count"]),
        "prior_reserve_count": int(record["prior_reserve_count"]),
        "prior_budget_drop_count": int(record["prior_budget_drop_count"]),
        "prior_cache_hit_count": int(record["prior_cache_hit_count"]),
        "span_s": round((event.ts_ms - int(record["first_seen_ms"])) / 1000.0, 6),
        "dt_min_s": round(min(intervals), 6) if intervals else -1.0,
        "dt_median_s": round(seqmix_median(intervals), 6),
        "dt_cv": round(seqmix_cv(intervals), 6),
        "burst_count": len(record["seen_ts"]),
        "visible_windows": len(record["windows"]),
        "repeat_candidate_count_w": repeat_candidate_count,
        "new_candidate_count_w": new_candidate_count,
        "repeat_candidate_entropy_w": round(seqmix_entropy_from_hist(Counter(repeated_counts)), 6),
        "reserve_contention_w": round(repeat_candidate_count / max(1.0, float(state.persist_reserve)), 6),
        "attack_pressure_proxy_w": round(
            (repeat_candidate_count + new_candidate_count) / max(1.0, float(state.budget_per_window)),
            6,
        ),
    }
    state.df_diag_pending_features[event.event_id] = features
    return features


def duplicate_filter_diag_note_decision(state: MethodState, event: AddressEvent, decision: Decision) -> None:
    if (
        not state.duplicate_filter_diagnostics_enabled
        and not state.seqmix_dupfilter_rescue_enabled
    ) or event.addr_type != "rpa" or not event.rpa_value:
        return
    features = state.df_diag_pending_features.pop(event.event_id, None)
    if features is None:
        features = duplicate_filter_diagnostic_features(state, event)
    record = state.df_diag_records.get(event.rpa_value)
    if record is None:
        return
    if decision.action == "duplicate_filter":
        if state.duplicate_filter_diagnostics_enabled:
            state.df_diag_rows.append(
                {
                    "run_id": event.run_id,
                    "method": state.method,
                    "event_id": event.event_id,
                    "ts_ms": event.ts_ms,
                    "label": "legit" if event.source_type == "legit_bonded" else "attack" if event.source_type == "attack" else "background",
                    "source_type_eval": event.source_type,
                    **features,
                    "feature_available_at_event": True,
                }
            )
        record["prior_duplicate_filter_count"] += 1
    if decision.action == "host_scan":
        record["prior_host_scan_count"] += 1
    if decision.admission_path == "reserve":
        record["prior_reserve_count"] += 1
    if decision.drop_reason == "budget":
        record["prior_budget_drop_count"] += 1
    if decision.admission_path == "cache":
        record["prior_cache_hit_count"] += 1


def seqmix_dupfilter_rescue_quota(state: MethodState) -> int:
    return max(0, int(state.persist_reserve * state.seqmix_dupfilter_rescue_quota_fraction))


def seqmix_duplicate_filter_rescue_allows(state: MethodState, event: AddressEvent, features: dict[str, Any]) -> bool:
    if state.method != "P3-SeqMix" or not state.seqmix_dupfilter_rescue_enabled:
        return False
    window = int(event.ts_ms // max(1, state.budget_window_s * 1000))
    if window != state.persist_reserve_window:
        state.persist_reserve_window = window
        state.persist_reserve_used = 0
    if window != state.seqmix_dupfilter_rescue_window:
        state.seqmix_dupfilter_rescue_window = window
        state.seqmix_dupfilter_rescue_used_w = 0
    if state.persist_reserve_used >= state.persist_reserve:
        return False
    if not seqmix_optional_reserve_preserves_baseline_floor(state):
        return False
    if state.seqmix_dupfilter_rescue_used_w >= seqmix_dupfilter_rescue_quota(state):
        return False
    if (
        state.seqmix_dupfilter_rescue_disable_unique_guard_enabled
        and seqmix_unique_flood_guard_active(state, features)
    ):
        return False
    if float(features.get("dt_median_s", -1.0)) < state.seqmix_dupfilter_rescue_min_dt_median_s:
        return False
    if float(features.get("prior_duplicate_filter_count", 0.0)) < state.seqmix_dupfilter_rescue_min_prior_duplicates:
        return False
    state.persist_reserve_used += 1
    state.seqmix_dupfilter_rescue_used_w += 1
    state.seqmix_dupfilter_rescued_events.add(event.event_id)
    return True


def seqmix_trusted_defer_retry_quota(state: MethodState) -> int:
    return max(0, int(state.persist_reserve * state.seqmix_trusted_defer_retry_quota_fraction))


def seqmix_trusted_defer_retry_allows(state: MethodState, event: AddressEvent, action: str) -> bool:
    if state.method != "P3-SeqMix" or not state.seqmix_trusted_defer_retry_enabled:
        return False
    if action != "defer":
        return False
    if event.rssi_dbm < state.seqmix_trusted_defer_retry_threshold_dbm:
        return False
    if (
        state.seqmix_trusted_defer_retry_disable_unique_guard_enabled
        and seqmix_unique_flood_guard_active_w(state)
    ):
        return False
    if state.seqmix_window_repeat_candidate_count < state.seqmix_trusted_defer_retry_min_repeat_candidates:
        return False
    window = int(event.ts_ms // max(1, state.budget_window_s * 1000))
    if window != state.persist_reserve_window:
        state.persist_reserve_window = window
        state.persist_reserve_used = 0
    if window != state.seqmix_trusted_defer_retry_window:
        state.seqmix_trusted_defer_retry_window = window
        state.seqmix_trusted_defer_retry_used_w = 0
    if state.persist_reserve_used >= state.persist_reserve:
        return False
    if not seqmix_optional_reserve_preserves_baseline_floor(state):
        return False
    if state.seqmix_trusted_defer_retry_used_w >= seqmix_trusted_defer_retry_quota(state):
        return False
    state.persist_reserve_used += 1
    state.seqmix_trusted_defer_retry_used_w += 1
    state.seqmix_trusted_defer_retry_events.add(event.event_id)
    return True


def duplicate_filtered(state: MethodState, event: AddressEvent) -> bool:
    if state.duplicate_filter_window_s <= 0 or event.addr_type != "rpa" or not event.rpa_value:
        return False
    features = None
    if state.duplicate_filter_diagnostics_enabled or state.seqmix_dupfilter_rescue_enabled:
        features = duplicate_filter_diagnostic_features(state, event)
    if event.rpa_value in state.resolved_rpa_values:
        return False
    window = event.ts_ms // max(1, state.duplicate_filter_window_s * 1000)
    key = (int(window), event.rpa_value)
    if key in state.df_seen:
        if features is None and state.seqmix_dupfilter_rescue_enabled:
            features = duplicate_filter_diagnostic_features(state, event)
        if features is not None and seqmix_duplicate_filter_rescue_allows(state, event, features):
            return False
        return True
    state.df_seen.add(key)
    return False


def resolve_event(method: str, state: MethodState, event: AddressEvent, devices: list[Device]) -> Decision:
    if method == "P3-SeqMix":
        seqmix_flush_ranked_pending(state, event.ts_ms, devices)
    maybe_update_adaptive_action(state, event)

    def finish(decision: Decision) -> Decision:
        if method == "P3-SeqMix":
            ranked_pending = (
                decision.action == "defer"
                and decision.event_id in state.seqmix_rank_pending_by_event
            )
            if ranked_pending:
                seqmix_apply_debt_trace_fields(state, decision, finalized=False)
            else:
                seqmix_finalize_debt_trace(state, event, decision)
        duplicate_filter_diag_note_decision(state, event, decision)
        return record_adaptive_decision(state, event, decision)

    if event.addr_type != "rpa":
        return finish(Decision(event.run_id, method, event.event_id, "skip_non_rpa", 0, False, "", False, 0, False, "", "non_rpa"))

    if duplicate_filtered(state, event):
        return finish(
            Decision(
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
        )

    if method == "Oracle-Offline":
        if event.source_type != "legit_bonded":
            return finish(Decision(event.run_id, method, event.event_id, "oracle_skip_unknown", 0, False, "", False, 0, False, "", "oracle_skip"))
        matched = event.device_id != ""
        return finish(
            Decision(
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
        )

    if method in CACHE_METHODS:
        cached = state.get_cache(event)
        if cached is not None:
            return finish(Decision(event.run_id, method, event.event_id, "cache_hit", 0, cached != "", cached, False, 0, False, "", "cache"))

    if event.source_type == "legit_bonded" and event.device_id in state.rl_entries:
        if method in CACHE_METHODS:
            state.put_cache(event, event.device_id)
        maybe_update_rl(state, event)
        return finish(Decision(event.run_id, method, event.event_id, "rl_hit", 1, True, event.device_id, False, 0, False, "", "rl"))

    # Budget applies to observable unresolved RPA work after cache/RL miss.
    # It cannot use source_type as an oracle; source_type is used only below
    # to score false-defer metrics after the decision has been made.
    if method == "P3-SeqMix":
        seqmix_feature_row(state, event, denied=False)
    admitted_by_reserve = False
    rescued_from_duplicate_filter = method == "P3-SeqMix" and event.event_id in state.seqmix_dupfilter_rescued_events
    if rescued_from_duplicate_filter:
        admitted_by_reserve = True
    if method in BUDGET_METHODS:
        if not rescued_from_duplicate_filter and not budget_allows(state, event):
            if method in ("P3-Persist", "P3-SPRT", "P3-SeqMix", "P3-Adaptive") and persistence_reserve_allows(state, event):
                admitted_by_reserve = True
            else:
                action = budget_denial_action(method, event)
                is_legit = event.source_type == "legit_bonded"
                if method == "P3-SeqMix" and seqmix_trusted_defer_retry_allows(state, event, action):
                    admitted_by_reserve = True
                else:
                    decision = Decision(
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
                    if method == "P3-SeqMix":
                        seqmix_bind_ranked_pending_decision(
                            state,
                            event,
                            decision,
                            max(0, len(devices) - len(state.rl_entries)),
                        )
                    return finish(decision)

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
    decision = Decision(
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
    if method == "P3-SeqMix" and admitted_by_reserve and not decision.seqmix_lane:
        if rescued_from_duplicate_filter:
            decision.seqmix_lane = "dupfilter_rescue"
        elif event.event_id in state.seqmix_trusted_defer_retry_events:
            decision.seqmix_lane = "trusted_defer_retry"
        else:
            decision.seqmix_lane = "count_fallback"
    return finish(decision)


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
    if method in ("P3-Persist", "P3-SPRT", "P3-SeqMix", "P3-Adaptive"):
        total += int(config.get("persist_reserve", 0)) * 8
    if method == "P3-SPRT":
        total += int(config.get("sprt_llr_capacity", config.get("persist_reserve", 0))) * 16
    if method == "P3-Adaptive":
        action_count = len(config.get("adaptive_actions", [])) or 9
        total += action_count * 16
    if method == "P3-SeqMix":
        feature_count = len(config.get("seqmix_features", [])) or 13
        state_cap = int(config.get("seqmix_state_capacity", config.get("persist_reserve", 0) or 128))
        heap_cap = int(config.get("seqmix_heap_capacity", config.get("persist_reserve", 0) or 128))
        total += state_cap * 64
        total += feature_count * int(config.get("seqmix_bin_count", 8)) * 8
        total += heap_cap * 16
        if str(config.get("seqmix_feature_variant", "")) == "guarded_rssi":
            total += 96
            if bool(config.get("seqmix_window_ranked_enabled", False)):
                rank_cap = int(config.get("seqmix_rank_max_pending", heap_cap))
                total += rank_cap * 24
                if bool(config.get("seqmix_rank_low_rssi_service_enabled", False)) or bool(
                    config.get("seqmix_rank_dense_service_enabled", False)
                ) or bool(
                    config.get("seqmix_rank_guarded_retry_enabled", False)
                ):
                    total += 32
                if bool(config.get("seqmix_feedback_hard_stop_enabled", False)):
                    total += 16
                    if str(config.get("seqmix_feedback_scope", "group")) in {"lane", "bucket", "lane_bucket"}:
                        total += 64
                if bool(config.get("seqmix_count_fallback_dense_limit_enabled", False)):
                    total += 8
                if bool(config.get("seqmix_dupfilter_rescue_enabled", False)):
                    total += 32
                if bool(config.get("seqmix_trusted_defer_retry_enabled", False)):
                    total += 16
                if bool(config.get("seqmix_baseline_debt_enabled", False)):
                    total += 64
                    if bool(config.get("seqmix_debt_repay_enabled", False)):
                        total += 16
                    if bool(config.get("seqmix_baseline_floor_protect_enabled", False)):
                        total += 16
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
    generated_events_by_id: dict[int, AddressEvent] | None = None,
    include_extended_metrics: bool = False,
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
    reserve_legit_delays = [d.delay_ms for d in legit_resolved if d.admission_path == "reserve"]
    measurement_min = max(1.0, (duration_ms - warmup_ms) / 60000.0)

    def count_path(source_type: str, admission_path: str) -> int:
        return sum(
            1
            for d in decisions
            if d.admission_path == admission_path
            and included_events_by_id[d.event_id].source_type == source_type
        )

    summary = {
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
        "reserve_grant_legit_p50_delay_ms": round(percentile(reserve_legit_delays, 0.50), 6),
        "reserve_grant_legit_p95_delay_ms": round(percentile(reserve_legit_delays, 0.95), 6),
        "reserve_grant_legit_p99_delay_ms": round(percentile(reserve_legit_delays, 0.99), 6),
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
    if include_extended_metrics:
        generated_source = generated_events_by_id if generated_events_by_id is not None else events_by_id
        generated_included = {
            eid: event for eid, event in generated_source.items() if event.ts_ms >= warmup_ms
        }

        def count_events(event_map: dict[int, AddressEvent], source_type: str) -> int:
            return sum(1 for event in event_map.values() if event.source_type == source_type)

        generated_legit = count_events(generated_included, "legit_bonded")
        observed_legit = count_events(included_events_by_id, "legit_bonded")
        generated_background = count_events(generated_included, "background")
        observed_background = count_events(included_events_by_id, "background")
        generated_attack = count_events(generated_included, "attack")
        observed_attack = count_events(included_events_by_id, "attack")
        generated_total = len(generated_included)
        observed_total = len(included_events_by_id)
        false_defer_count = sum(1 for decision in legit_decisions if decision.false_defer)
        summary.update(
            {
                "observation_loss_rate_requested": float(config.get("observation_loss_rate", 0.0)),
                "generated_event_count": generated_total,
                "observed_event_count": observed_total,
                "dropped_event_count": generated_total - observed_total,
                "actual_observation_loss_rate": round(
                    (generated_total - observed_total) / max(1, generated_total), 6
                ),
                "generated_legit_event_count": generated_legit,
                "observed_legit_event_count": observed_legit,
                "dropped_legit_event_count": generated_legit - observed_legit,
                "actual_legit_observation_loss_rate": round(
                    (generated_legit - observed_legit) / max(1, generated_legit), 6
                ),
                "generated_background_event_count": generated_background,
                "observed_background_event_count": observed_background,
                "dropped_background_event_count": generated_background - observed_background,
                "actual_background_observation_loss_rate": round(
                    (generated_background - observed_background) / max(1, generated_background), 6
                ),
                "generated_attack_event_count": generated_attack,
                "observed_attack_event_count": observed_attack,
                "dropped_attack_event_count": generated_attack - observed_attack,
                "actual_attack_observation_loss_rate": round(
                    (generated_attack - observed_attack) / max(1, generated_attack), 6
                ),
                "offered_legit_resolution_rate": round(
                    len(legit_resolved) / max(1, generated_legit), 6
                ),
                "observed_legit_resolution_rate": round(
                    len(legit_resolved) / max(1, observed_legit), 6
                ),
                "false_defer_observed_legit_rate": round(
                    false_defer_count / max(1, len(legit_decisions)), 6
                ),
                "reserve_grant_background_count": count_path("background", "reserve"),
                "duplicate_filter_background_count": count_path("background", "duplicate_filter"),
                "cache_hit_background_count": count_path("background", "cache"),
                "host_scan_background_count": count_path("background", "host_scan"),
                "budget_skip_background_count": count_path("background", "budget_skip"),
            }
        )
    return summary


def summarize_windows(
    method: str,
    decisions: list[Decision],
    events_by_id: dict[int, AddressEvent],
    config: dict[str, Any],
    window_s: int | None = None,
) -> list[dict[str, Any]]:
    warmup_ms = int(config.get("warmup_s", 0)) * 1000
    duration_ms = int(config.get("duration_s", 0)) * 1000
    window_s = int(window_s or config.get("budget_window_s", 60))
    window_ms = max(1, window_s * 1000)
    scan_cost = max(0, int(config.get("num_bonded", 0)) - int(config.get("rl_capacity", 0)))
    cap_per_window = config.get("attack_aes_cap_per_window")
    if cap_per_window is None:
        cap_per_window = (int(config.get("budget_per_window", 0)) + int(config.get("persist_reserve", 0))) * scan_cost
    cap_per_min = float(config.get("attack_aes_cap_per_min", float(cap_per_window) / (window_ms / 60000.0)))

    included_events_by_id = {eid: e for eid, e in events_by_id.items() if e.ts_ms >= warmup_ms}
    windowed_decisions: dict[int, list[Decision]] = {}
    for decision in decisions:
        event = included_events_by_id.get(decision.event_id)
        if event is None:
            continue
        window_index = event.ts_ms // window_ms
        windowed_decisions.setdefault(window_index, []).append(decision)

    rows: list[dict[str, Any]] = []
    for window_index in sorted(windowed_decisions):
        window_decisions = windowed_decisions[window_index]
        window_start_ms = int(window_index * window_ms)
        window_end_ms = int(window_start_ms + window_ms)
        measurement_start_ms = max(window_start_ms, warmup_ms)
        measurement_end_ms = min(window_end_ms, duration_ms) if duration_ms else window_end_ms
        measurement_min = max(1.0 / 60000.0, (measurement_end_ms - measurement_start_ms) / 60000.0)
        window_events = [included_events_by_id[d.event_id] for d in window_decisions]
        legit_events = [e for e in window_events if e.source_type == "legit_bonded" and e.addr_type == "rpa"]
        legit_decisions = [
            d for d in window_decisions if included_events_by_id[d.event_id].source_type == "legit_bonded"
        ]
        legit_resolved = [d for d in legit_decisions if d.matched]
        attack_decisions = [d for d in window_decisions if included_events_by_id[d.event_id].source_type == "attack"]
        attack_aes_attempts = sum(d.aes_attempts for d in attack_decisions)
        attack_aes_amplification = attack_aes_attempts / measurement_min
        legit_shortfall_count = max(0, len(legit_events) - len(legit_resolved))

        def count_path(source_type: str, admission_path: str) -> int:
            return sum(
                1
                for d in window_decisions
                if d.admission_path == admission_path
                and included_events_by_id[d.event_id].source_type == source_type
            )

        rows.append(
            {
                "run_id": config["run_id"],
                "method": method,
                "window_s": window_s,
                "window_index": int(window_index),
                "window_start_ms": window_start_ms,
                "window_end_ms": window_end_ms,
                "window_measurement_s": round(measurement_min * 60.0, 6),
                "event_count": len(window_decisions),
                "legit_event_count": len(legit_events),
                "legit_resolved_count": len(legit_resolved),
                "legit_shortfall_count": legit_shortfall_count,
                "legit_shortfall_w": round(legit_shortfall_count / max(1, len(legit_events)), 6),
                "legit_shortfall_rate": round(legit_shortfall_count / max(1, len(legit_events)), 6),
                "attack_event_count": len(attack_decisions),
                "attack_aes_attempts": attack_aes_attempts,
                "attack_aes_amplification": round(attack_aes_amplification, 6),
                "attack_aes_cap_per_min": round(cap_per_min, 6),
                "amp_over_cap_w": round(max(0.0, attack_aes_amplification - cap_per_min) / max(1.0, cap_per_min), 6),
                "false_defer_legit_count": sum(1 for d in legit_decisions if d.false_defer),
                "reserve_grant_legit_count": count_path("legit_bonded", "reserve"),
                "reserve_grant_attack_count": count_path("attack", "reserve"),
                "duplicate_filter_legit_count": count_path("legit_bonded", "duplicate_filter"),
                "duplicate_filter_attack_count": count_path("attack", "duplicate_filter"),
                "cache_hit_legit_count": count_path("legit_bonded", "cache"),
                "cache_hit_attack_count": count_path("attack", "cache"),
                "host_scan_legit_count": count_path("legit_bonded", "host_scan"),
                "host_scan_attack_count": count_path("attack", "host_scan"),
                "budget_skip_legit_count": count_path("legit_bonded", "budget_skip"),
                "budget_skip_attack_count": count_path("attack", "budget_skip"),
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def run(config: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(int(config["seed"]))
    devices = build_devices(config, rng)
    generated_events = generate_events(config, devices, rng)
    observation_enabled = "observation_loss_rate" in config
    if observation_enabled:
        events, observation_ledger = apply_observation_loss(generated_events, config)
    else:
        events = generated_events
        observation_ledger = []
    include_extended_metrics = observation_enabled or "background_address_mode" in config
    methods = config.get("methods", METHODS)
    generated_events_by_id = {event.event_id: event for event in generated_events}
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
        if observation_enabled:
            write_csv(
                out_dir / "generated_events.csv",
                [event.__dict__ for event in generated_events],
                event_fields,
            )
    if observation_enabled and bool(config.get("write_observation_ledger", False)):
        observation_fields = [
            "run_id",
            "event_id",
            "ts_ms",
            "source_type",
            "rpa_value",
            "observed",
            "dropped",
            "drop_reason",
        ]
        write_csv(out_dir / "observation_ledger.csv", observation_ledger, observation_fields)

    all_decisions: list[Decision] = []
    all_diag_rows: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    window_summaries: list[dict[str, Any]] = []
    for method in methods:
        if method not in METHODS:
            raise ValueError(f"W1 simulator does not implement method: {method}")
        state = init_state(method, config, devices)
        decisions = []
        for event in events:
            decisions.append(resolve_event(method, state, event, devices))
        if method == "P3-SeqMix":
            final_ts_ms = events[-1].ts_ms if events else 0
            seqmix_flush_ranked_pending(state, final_ts_ms + state.seqmix_rank_window_ms, devices, force=True)
        all_decisions.extend(decisions)
        all_diag_rows.extend(state.df_diag_rows)
        summary = summarize(
            method,
            decisions,
            events_by_id,
            config,
            generated_events_by_id=generated_events_by_id if observation_enabled else None,
            include_extended_metrics=include_extended_metrics,
        )
        summary["run_id"] = config["run_id"]
        summaries.append(summary)
        if bool(config.get("write_window_summary", False)):
            window_summaries.extend(summarize_windows(method, decisions, events_by_id, config))

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
        "seqmix_lane",
        "seqmix_bucket",
        "seqmix_score",
        "seqmix_ranking_score",
        "seqmix_shadow_baseline_eligible",
        "seqmix_shadow_baseline_lane",
        "seqmix_service_debt_before",
        "seqmix_service_debt_after",
        "seqmix_unique_risk_before",
        "seqmix_unique_risk_after",
        "seqmix_debt_action",
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
        "reserve_grant_legit_p50_delay_ms",
        "reserve_grant_legit_p95_delay_ms",
        "reserve_grant_legit_p99_delay_ms",
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
    if include_extended_metrics:
        summary_fields.extend(
            [
                "observation_loss_rate_requested",
                "generated_event_count",
                "observed_event_count",
                "dropped_event_count",
                "actual_observation_loss_rate",
                "generated_legit_event_count",
                "observed_legit_event_count",
                "dropped_legit_event_count",
                "actual_legit_observation_loss_rate",
                "generated_background_event_count",
                "observed_background_event_count",
                "dropped_background_event_count",
                "actual_background_observation_loss_rate",
                "generated_attack_event_count",
                "observed_attack_event_count",
                "dropped_attack_event_count",
                "actual_attack_observation_loss_rate",
                "offered_legit_resolution_rate",
                "observed_legit_resolution_rate",
                "false_defer_observed_legit_rate",
                "reserve_grant_background_count",
                "duplicate_filter_background_count",
                "cache_hit_background_count",
                "host_scan_background_count",
                "budget_skip_background_count",
            ]
        )
    write_csv(out_dir / "summary.csv", summaries, summary_fields)

    window_summary_fields = [
        "run_id",
        "method",
        "window_s",
        "window_index",
        "window_start_ms",
        "window_end_ms",
        "window_measurement_s",
        "event_count",
        "legit_event_count",
        "legit_resolved_count",
        "legit_shortfall_count",
        "legit_shortfall_w",
        "legit_shortfall_rate",
        "attack_event_count",
        "attack_aes_attempts",
        "attack_aes_amplification",
        "attack_aes_cap_per_min",
        "amp_over_cap_w",
        "false_defer_legit_count",
        "reserve_grant_legit_count",
        "reserve_grant_attack_count",
        "duplicate_filter_legit_count",
        "duplicate_filter_attack_count",
        "cache_hit_legit_count",
        "cache_hit_attack_count",
        "host_scan_legit_count",
        "host_scan_attack_count",
        "budget_skip_legit_count",
        "budget_skip_attack_count",
    ]
    if bool(config.get("write_window_summary", False)):
        write_csv(out_dir / "window_summary.csv", window_summaries, window_summary_fields)

    if bool(config.get("write_duplicate_filter_diagnostics", False)):
        diag_fields = [
            "run_id",
            "method",
            "event_id",
            "ts_ms",
            "label",
            "source_type_eval",
            "rssi_dbm",
            "rssi_rank_pct_w",
            "candidate_age_s",
            "interarrival_s",
            "n_seen",
            "prior_seen_count",
            "prior_duplicate_filter_count",
            "prior_host_scan_count",
            "prior_reserve_count",
            "prior_budget_drop_count",
            "prior_cache_hit_count",
            "span_s",
            "dt_min_s",
            "dt_median_s",
            "dt_cv",
            "burst_count",
            "visible_windows",
            "repeat_candidate_count_w",
            "new_candidate_count_w",
            "repeat_candidate_entropy_w",
            "reserve_contention_w",
            "attack_pressure_proxy_w",
            "feature_available_at_event",
        ]
        write_csv(out_dir / "duplicate_filter_diagnostics.csv", all_diag_rows, diag_fields)

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
    if include_extended_metrics:
        manifest.update(
            {
                "background_address_mode": config.get("background_address_mode", "unique"),
                "generated_event_count": len(generated_events),
                "observed_event_count": len(events),
                "dropped_event_count": len(generated_events) - len(events),
            }
        )
    if observation_enabled:
        manifest.update(
            {
                "observation_loss_rate": float(config.get("observation_loss_rate", 0.0)),
                "observation_loss_seed": observation_loss_seed(config),
            }
        )
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
