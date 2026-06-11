#!/usr/bin/env python3
"""POC: persistence-aware resolving admission for P3.

Hypothesis: under RPA-flooding, attack traffic uses unique RPAs (each address
appears once) while legitimate bonded devices re-advertise the SAME address
within an RPA epoch. Address repetition is observable BEFORE resolving and does
NOT reveal identity membership, so it can be used to grant scarce host-scan
budget to sources that persist, protecting legitimate traffic that a flat budget
would starve.

This POC reuses rpa_sim's event generator and compares, on the SAME events:
  - StaticRL      (no budget; full host work)
  - BudgetDoS     (flat budget; deny -> drop)
  - P3-NoPersist       (flat budget; deny -> RSSI-aware defer/skip)  [current paper]
  - P3-Persist    (flat budget + persistence reserve)           [proposed]

It is a read-only experiment; it does not modify rpa_sim.py. The rpa_value()
helper derives an over-the-air-style address identifier from event fields,
matching reality: same device + same epoch -> same address; attack -> unique.
The persistence mechanism uses ONLY this address repetition, never source_type.
"""
from __future__ import annotations

import sys
from collections import OrderedDict
from pathlib import Path

SRC = Path("sim/rpa_resolution/src")
sys.path.insert(0, str(SRC))
import random  # noqa: E402
from rpa_sim import build_devices, generate_events  # noqa: E402


def rpa_value(ev) -> str:
    """Over-the-air address identifier (no identity leak before resolving).

    legit  : same device + same epoch -> same address (re-advertised)
    attack : unique per packet (unique_attack_rpa=True -> rpa_epoch=event_id)
    others : conservative unique (treated as distinct unknown sources)
    """
    if ev.source_type == "legit_bonded":
        return f"L_{ev.device_id}_{ev.rpa_epoch}"
    if ev.source_type == "attack":
        return f"A_{ev.rpa_epoch}"  # unique when unique_attack_rpa
    if ev.source_type == "background":
        return f"B_{ev.event_id}"
    return f"N_{ev.event_id}"


def simulate(events, devices, method, *, B, W_s, R, k, cache_size, rl_cap):
    N = len(devices)
    sorted_dev = sorted(devices, key=lambda d: d.activity_weight, reverse=True)
    rl = [d.device_id for d in sorted_dev[:rl_cap]]
    activity: dict[str, int] = {}
    cache: "OrderedDict[str,str]" = OrderedDict()
    bwin = -1
    bused = 0
    rwin = -1
    rused = 0
    denied: dict[str, int] = {}

    def admit(dev_id, ts):
        activity[dev_id] = activity.get(dev_id, 0) + 1
        if dev_id in rl or not rl:
            return
        victim = min(rl, key=lambda x: activity.get(x, 0))
        if activity.get(dev_id, 0) >= activity.get(victim, 0):
            rl[rl.index(victim)] = dev_id

    aes_total = 0
    attack_aes = 0
    legit_events = 0
    legit_resolved = 0
    legit_denied = 0  # legitimate events that did not resolve (defer or skip)
    dur_min = max(1.0, (max((e.ts_ms for e in events), default=0) + 1) / 60000.0)

    for ev in events:
        if ev.addr_type != "rpa":
            continue
        is_legit = ev.source_type == "legit_bonded"
        if is_legit:
            legit_events += 1
        rv = rpa_value(ev)

        # cache (positive-only)
        if rv in cache:
            cache.move_to_end(rv)
            if is_legit:
                legit_resolved += 1
            continue
        # RL fast path
        if is_legit and ev.device_id in rl:
            cache[rv] = ev.device_id
            cache.move_to_end(rv)
            while len(cache) > cache_size:
                cache.popitem(last=False)
            admit(ev.device_id, ev.ts_ms)
            aes_total += 1
            legit_resolved += 1
            continue
        # budget window
        w = ev.ts_ms // (W_s * 1000)
        if w != bwin:
            bwin = w
            bused = 0
        if w != rwin:
            rwin = w
            rused = 0

        granted = False
        if bused < B:
            bused += 1
            granted = True
        else:
            # budget exhausted -> method-specific denial handling
            if method == "P3-Persist":
                cnt = denied.get(rv, 0)
                if cnt >= k and rused < R:
                    rused += 1
                    granted = True  # earned host scan via persistence
                else:
                    denied[rv] = cnt + 1
                    if is_legit:
                        legit_denied += 1
                    continue
            elif method == "P3-NoPersist":
                # RSSI-aware defer/skip; neither resolves in-model
                if is_legit:
                    legit_denied += 1
                continue
            elif method == "BudgetDoS":
                if is_legit:
                    legit_denied += 1
                continue
            else:  # StaticRL: no budget, always host scan
                granted = True

        if not granted:
            continue
        # host scan
        a = N - len(rl)
        aes_total += a
        if ev.source_type == "attack":
            attack_aes += a
        matched = is_legit
        if matched:
            cache[rv] = ev.device_id
            cache.move_to_end(rv)
            while len(cache) > cache_size:
                cache.popitem(last=False)
            admit(ev.device_id, ev.ts_ms)
            legit_resolved += 1

    return {
        "method": method,
        "legit_rate": round(legit_resolved / max(1, legit_events), 4),
        "false_defer": round(legit_denied / max(1, legit_events), 4),
        "attack_amp": round(attack_aes / dur_min, 1),
        "aes_total": aes_total,
    }


def make_config(scenario, seed, duration, unique_attack=True):
    cfg = {
        "run_id": f"poc_{scenario}_{seed}", "seed": seed, "duration_s": duration,
        "num_bonded": 512, "rl_capacity": 8, "active_ratio": 0.2, "active_skew": 1.1,
        "rpa_rotation_interval_min": 15, "legit_adv_rate_per_device_per_min": 1.0,
        "non_rpa_ratio": 0.2, "rssi_noise_db": 6.0, "unique_attack_rpa": unique_attack,
    }
    if scenario == "medium_flood":
        cfg["background_rpa_rate_per_min"] = 100.0
        cfg["attack_rpa_rate_per_min"] = 1000.0
    else:  # heavy_flood
        cfg["background_rpa_rate_per_min"] = 1000.0
        cfg["attack_rpa_rate_per_min"] = 10000.0
    return cfg


def main():
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 600
    R = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    k = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    B, W, cache_size, rl_cap = 100, 60, 64, 8

    for scenario in ("medium_flood", "heavy_flood"):
        cfg = make_config(scenario, 20260610, duration)
        rng = random.Random(cfg["seed"])
        devices = build_devices(cfg, rng)
        events = generate_events(cfg, devices, rng)
        n_legit = sum(1 for e in events if e.source_type == "legit_bonded")
        n_attack = sum(1 for e in events if e.source_type == "attack")
        print(f"\n===== {scenario}  (duration={duration}s, events={len(events)}, "
              f"legit={n_legit}, attack={n_attack}, B={B}/W={W}, R={R}, k={k}) =====")
        print(f"{'method':<14}{'legit_rate':>11}{'false_defer':>12}{'attack_amp':>12}{'aes_total':>11}")
        for method in ("StaticRL", "BudgetDoS", "P3-NoPersist", "P3-Persist"):
            r = simulate(events, devices, method, B=B, W_s=W, R=R, k=k,
                         cache_size=cache_size, rl_cap=rl_cap)
            print(f"{r['method']:<14}{r['legit_rate']:>11}{r['false_defer']:>12}"
                  f"{r['attack_amp']:>12}{r['aes_total']:>11}")

    # Attacker counter-strategy: attacker REPEATS addresses to try to earn the
    # persistence reserve. unique_attack_rpa=False -> attack addresses repeat.
    print(f"\n===== ATTACKER COUNTER-STRATEGY: repeated-address attack (heavy_flood, "
          f"R={R}, k={k}) =====")
    print("If the attacker repeats addresses to game the reserve, does P3-Persist "
          "amplification blow up?")
    cfg = make_config("heavy_flood", 20260610, duration, unique_attack=False)
    rng = random.Random(cfg["seed"])
    devices = build_devices(cfg, rng)
    events = generate_events(cfg, devices, rng)
    print(f"{'method':<14}{'legit_rate':>11}{'false_defer':>12}{'attack_amp':>12}{'aes_total':>11}")
    for method in ("BudgetDoS", "P3-Persist"):
        r = simulate(events, devices, method, B=B, W_s=W, R=R, k=k,
                     cache_size=cache_size, rl_cap=rl_cap)
        print(f"{r['method']:<14}{r['legit_rate']:>11}{r['false_defer']:>12}"
              f"{r['attack_amp']:>12}{r['aes_total']:>11}")
    print("Note: repeated attack addresses are exactly what controller duplicate "
          "filtering removes, so this is the attacker's dilemma, not a free bypass.")


if __name__ == "__main__":
    main()
