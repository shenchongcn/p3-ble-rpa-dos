# M13 Joint Robustness Suite

Status: complete. The 27-cell main matrix and all three controls were confirmed with 20 seeds.

- Purpose: joint RPA epoch, observation-loss, and benign-unknown-density evaluation.
- GO-LOSS and GO-BENIGN passed before the matrix was executed.
- Required methods are explicit in each config and must not come from a mutable global method list.
- Screening outputs default to summary/diagnostic only. Full traces are limited to pre-registered audit samples.
- Historical M10/M11 directories must never be overwritten.
- Resume behavior must validate config hash, expected method rows, and completed summary before skipping a run.

Primary outputs:

- `combined_summary.csv`: 1800 method-result rows from 600 configurations.
- `table_m13_joint_robustness.csv`: 20-seed cell summaries for the three methods.
- `table_m13_service_degradation.csv`: preregistered practical degradation screen.
- `table_m13_control_contrasts.csv`: no-attack and repeated-benign controls.
- `audit_m13_closure.csv`: event, denominator, method, seed, and manifest closure checks.
- `matrix_manifest.json` and `analysis_manifest.json`: frozen source/config/output hashes.

Scientific interpretation is recorded in `docs/20260606ver/20260713reply/m13_joint_robustness_results_20260715.md`.
