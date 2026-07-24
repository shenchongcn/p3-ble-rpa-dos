# M12 Privacy Side-Channel Suite

Status: complete 20-seed paired matrix generated from source commit `6009cf23`.

- Purpose: paired bonded/non-bonded full-run modeled-observable analysis.
- Primary scientific response: narrow the manuscript claim; this suite is auxiliary evidence only.
- Required methods are explicit in each config and must not come from a mutable global method list.
- Screening outputs default to summary/diagnostic only. Full traces are limited to pre-registered audit samples.
- Historical M10/M11 directories must never be overwritten.
- Resume behavior must validate config hash, expected method rows, and completed summary before skipping a run.

Primary outputs:

- `combined_probe_summary.csv`: 720 method-result rows.
- `paired_trace_audit.csv`: 120 visible-equality and pre-resolution audits.
- `table_m12_paired_effects.csv`: seed-paired effects and distribution distances.
- `table_m12_classifier_summary.csv`: external-proxy and internal-diagnostic grouped AUC results.
- `matrix_manifest.json`: source hashes, method/seed matrix, and audit gates.
- `runs/`: 240 variant run directories with per-method summaries and probe decision evidence.

Scientific interpretation is recorded in `docs/20260606ver/20260713reply/m12_privacy_sidechannel_results_20260715.md`.
