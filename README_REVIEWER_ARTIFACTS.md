# Reviewer Artifact Package for electronics-4413038

This package supports the revised manuscript:

`P3: Persistence-Aware Admission Control for DoS-Resilient BLE Resolvable Private Address Resolution`

It is intended for peer review only. It contains reproducibility materials for the simulation-based results reported in the revised manuscript. It does not contain private account material, device serial numbers, screenshots, or patent-sensitive implementation details.

## Contents

- `sim/rpa_resolution/src/`
  - Simulator source code, including `rpa_sim.py` and adaptive-controller support.
- `sim/rpa_resolution/scripts/`
  - Experiment runners and analysis helpers used for the main campaign, sensitivity, ablation, long-window replication, budget sensitivity, review-closure checks, persistence novelty checks, statistical extension, adaptive-adversary sweeps, worked-example extraction, and figure-summary generation.
- `sim/rpa_resolution/configs/`
  - JSON configuration files and seed-specific run configurations used to define the simulation matrix.
- `sim/rpa_resolution/figures/`
  - Figure-source CSV files and table CSV files used by the manuscript.
- `sim/rpa_resolution/results/`
  - Lightweight result summaries: `combined_summary.csv`, `matrix_manifest.json`, and walkthrough outputs.
  - The worked-example trace `paper_walkthrough_persist/` includes `events.csv`, `decisions.csv`, `summary.csv`, and `run_manifest.json`.

## Scope Boundary

The manuscript reports AES-equivalent simulation work, not measured current, energy, CPU time, latency, or production-firmware behavior. The nRF5340 DK material in the manuscript is scanner-context auxiliary information only and is not included as hardware-validation evidence in this package.

## Reproduction Notes

The primary simulator entry point is:

```bash
python sim/rpa_resolution/src/rpa_sim.py --help
```

Representative scripts:

```bash
python sim/rpa_resolution/scripts/run_m10_statistical_extension.py
python sim/rpa_resolution/scripts/run_m11_adaptive_adversary.py
python sim/rpa_resolution/scripts/extract_walkthrough.py
python sim/rpa_resolution/scripts/plot_legit_ci.py
```

The package is designed to let reviewers inspect the exact code, parameters, seed records, summaries, figure-source CSVs, and the worked-example trace used by the revised manuscript without requiring upload of the full multi-gigabyte raw `results/` tree.
