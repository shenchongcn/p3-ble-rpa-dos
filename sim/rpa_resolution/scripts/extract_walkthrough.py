#!/usr/bin/env python3
"""Extract a per-event walkthrough from a write_traces run of rpa_sim.

Joins events.csv and decisions.csv and prints, for the P3-NoPersist method, one
representative event for each decision branch (skip_non_rpa / cache_hit /
rl_hit / host_scan / budget_skip / defer). Also prints a short contiguous
event stream that shows the budget window filling up, and a same-event
comparison across StaticRL / BudgetDoS / P3-NoPersist.

This is a read-only reporting helper. It does not change any decision logic
and is only used to build the manuscript running-example table.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

RUN_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("sim/rpa_resolution/results/paper_walkthrough")


def load_events(path: Path) -> dict[int, dict]:
    out: dict[int, dict] = {}
    with path.open() as f:
        for row in csv.DictReader(f):
            out[int(row["event_id"])] = row
    return out


def load_decisions(path: Path) -> list[dict]:
    with path.open() as f:
        return list(csv.DictReader(f))


def fmt(ev: dict, dec: dict) -> str:
    return (
        f"#{ev['event_id']:>3} t={int(ev['ts_ms']):>6}ms "
        f"src={ev['source_type']:<12} rssi={ev['rssi_dbm']:>7} epoch={ev['rpa_epoch']:>3} "
        f"addr={ev['addr_type']:<7} -> action={dec['action']:<14} "
        f"aes={dec['aes_attempts']:>2} matched={dec['matched']:<5} "
        f"deferred={dec['deferred']:<5} delay={dec['delay_ms']:>4} fd={dec['false_defer']}"
    )


def main() -> None:
    events = load_events(RUN_DIR / "events.csv")
    decisions = load_decisions(RUN_DIR / "decisions.csv")

    p3 = [d for d in decisions if d["method"] == "P3-NoPersist"]

    print("=" * 110)
    print("ONE REPRESENTATIVE EVENT PER P3-NoPersist DECISION BRANCH")
    print("=" * 110)
    seen: set[str] = set()
    order = ["skip_non_rpa", "cache_hit", "rl_hit", "host_scan", "defer", "budget_skip"]
    picked: dict[str, tuple] = {}
    for d in p3:
        a = d["action"]
        if a not in picked:
            picked[a] = (events[int(d["event_id"])], d)
    for a in order:
        if a in picked:
            ev, d = picked[a]
            print(fmt(ev, d))

    print()
    print("=" * 110)
    print("CONTIGUOUS P3-NoPersist STREAM AROUND FIRST BUDGET EXHAUSTION (window 0, first 60s)")
    print("=" * 110)
    # show the transition: first events resolve via host_scan, then budget runs out
    win0 = [d for d in p3 if int(events[int(d["event_id"])]["ts_ms"]) < 60000
            and events[int(d["event_id"])]["addr_type"] == "rpa"]
    # find first budget denial
    first_denial_idx = next((i for i, d in enumerate(win0)
                             if d["action"] in ("budget_skip", "defer")), None)
    if first_denial_idx is not None:
        lo = max(0, first_denial_idx - 4)
        hi = min(len(win0), first_denial_idx + 6)
        for d in win0[lo:hi]:
            print(fmt(events[int(d["event_id"])], d))

    print()
    print("=" * 110)
    print("SAME-EVENT COMPARISON ACROSS METHODS (events that P3 defers but BudgetDoS skips)")
    print("=" * 110)
    by_evmethod = {(d["event_id"], d["method"]): d for d in decisions}
    shown = 0
    for d in p3:
        if d["action"] != "defer":
            continue
        eid = d["event_id"]
        bd = by_evmethod.get((eid, "BudgetDoS"))
        sr = by_evmethod.get((eid, "StaticRL"))
        if bd is None or sr is None:
            continue
        ev = events[int(eid)]
        print(f"#{eid:>3} src={ev['source_type']:<12} rssi={ev['rssi_dbm']:>7} | "
              f"StaticRL={sr['action']:<10}(aes{sr['aes_attempts']}) | "
              f"BudgetDoS={bd['action']:<11}(aes{bd['aes_attempts']}) | "
              f"P3-NoPersist={d['action']}(delay{d['delay_ms']})")
        shown += 1
        if shown >= 4:
            break

    # action histogram for P3-NoPersist
    print()
    print("=" * 110)
    print("P3-NoPersist ACTION HISTOGRAM (all events)")
    print("=" * 110)
    hist: dict[str, int] = {}
    for d in p3:
        hist[d["action"]] = hist.get(d["action"], 0) + 1
    for a, n in sorted(hist.items(), key=lambda kv: -kv[1]):
        print(f"  {a:<16} {n:>5}")


if __name__ == "__main__":
    main()
