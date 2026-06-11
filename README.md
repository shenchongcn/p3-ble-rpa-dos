# P3: Persistence-Aware Admission Control for DoS-Resilient BLE RPA Resolution — Reproducibility Package

This repository is the reproducibility package for the manuscript *"P3:
Persistence-Aware Admission Control for DoS-Resilient BLE Resolvable Private
Address Resolution"* (under review). It contains the deterministic simulator,
all experiment runners, the configuration files, the summary CSVs, and the
figure-source CSVs needed to regenerate every quantitative result reported in
the paper.

The package supports reproduction of the **simulation evidence only**. It does
not claim a deployed P3 firmware implementation, measured current/power, or any
on-hardware timing result. Energy is reported throughout as AES-equivalent
resolving work (one unit = one IRK trial computation).

## Repository layout

```
sim/rpa_resolution/
  src/rpa_sim.py            Deterministic event-driven RPA-resolution simulator
  scripts/                  Experiment runners and analysis/plotting helpers
  configs/                  Per-experiment JSON configurations (one file per seed/point)
  results/*/combined_summary.csv   Aggregated per-method/seed/config summaries
  figures/*/*.csv           Figure- and table-source CSVs used by the manuscript
docs/figures_scripts/
  redraw_problem_figures.py Figure regeneration script (matplotlib)
```

## Requirements

- Python 3.10+
- See `requirements.txt` (`matplotlib` is only needed for figure regeneration;
  the simulator itself uses the standard library).

```bash
python3 -m pip install -r requirements.txt
```

## Reproduce

Each run is deterministic given its seed, so every number in the manuscript can
be regenerated exactly. Run from the repository root:

```bash
# Main simulation campaign, sensitivity, and ablation
python3 sim/rpa_resolution/scripts/run_m3_matrix.py --suite p0 \
    --out sim/rpa_resolution/results/m3_p0 \
    --config-dir sim/rpa_resolution/configs/m3/p0
python3 sim/rpa_resolution/scripts/analyze_m3_results.py

# Long-window replication and budget sensitivity
python3 sim/rpa_resolution/scripts/run_m4_replication.py
python3 sim/rpa_resolution/scripts/run_m4_budget_sensitivity.py

# Review-closure baselines and capacity-expansion checks
python3 sim/rpa_resolution/scripts/run_m6_review_closure_experiments.py

# Persistence-novelty suite and 20-seed statistical extension
python3 sim/rpa_resolution/scripts/run_m8_algorithm_novelty_experiments.py
python3 sim/rpa_resolution/scripts/run_m10_statistical_extension.py
python3 sim/rpa_resolution/scripts/analyze_m10_stats.py

# Adaptive-adversary strategy-space sweep
python3 sim/rpa_resolution/scripts/run_m11_adaptive_adversary.py

# Figure regeneration
python3 docs/figures_scripts/redraw_problem_figures.py
```

The pre-computed `combined_summary.csv` and figure-source CSVs are included so
that the reported numbers can be inspected without re-running the full
campaign.

## Seeds

| Suite | Seeds |
| --- | --- |
| Main P0 / sensitivity / ablation | 20260530–20260603 (5 seeds) |
| Long-window replication | 20260610–20260612 (3 seeds) |
| Review-closure / persistence-novelty | 20260610–20260614 (5 seeds) |
| Statistical extension | 20260610–20260629 (20 seeds) |

## Citation

If you use this package, please cite the manuscript. See `CITATION.cff`.

## License

Released under the MIT License. See `LICENSE`.
