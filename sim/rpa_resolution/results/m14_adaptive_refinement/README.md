# M14 Adaptive Refinement Suite

Status: complete. Both the 168-strategy screen and the frozen confirmation union were executed and audited.

- Purpose: dense local search around the existing M11 worst swept point.
- Screening method whitelist: `P3-Persist` only.
- Confirmation method whitelist: `P3-Persist` and `BudgetDoS`.
- The runner must not import the current M11 global `METHODS` list.
- Completed screening size: 168 strategies x 5 seeds = 840 runs.
- Screening outputs default to summary/diagnostic only. Full traces are limited to pre-registered audit samples and confirmed top strategies.
- Historical M10/M11 directories must never be overwritten.
- Resume behavior must validate config hash, expected method rows, and completed summary before skipping a run.

Primary outputs:

- `screen/table_m14_local_screen.csv`: complete 168-strategy screen.
- `screen/table_m14_repetition_effects.csv`: matched repetition-factor analysis.
- `screen/top5_selection.json`: mechanical top-five selection record.
- `confirm/combined_summary.csv`: 440 P3-Persist rows and 200 paired BudgetDoS rows.
- `confirm/table_m14_confirmed_ranking.csv`: 20-seed ranking for the 11-strategy union at both filter settings.
- `confirm/table_m14_cap_audit.csv`: mean and maximum-seed distance from the fixed cap.
- `audit_m14_closure.csv` and `analysis_manifest.json`: closure and provenance records.

Scientific interpretation is recorded in `docs/20260606ver/20260713reply/m14_adaptive_refinement_results_20260715.md`.
