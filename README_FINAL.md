# Final Reviewer Artifact Package

This archive accompanies manuscript `electronics-4413038`. It supersedes the round-1 reviewer archive and contains the deterministic simulator, the earlier figure/hardware-trace support material, Supplementary Tables S1–S4, and the three reviewer-closure experiment suites added on 15 July 2026.

## Evidence boundary

The headline P3 evidence is simulation-based and stack-informed. Modeled observation loss is an observation-layer proxy, not measured BLE packet loss. Modeled delay/defer values are not scan-response, connection, controller, host-stack, or application timing measurements. The anonymized nRF5340 DK trace supports only a visible candidate-address repetition sanity check; it is not used for headline P3 performance claims. The adaptive search is a bounded local grid and does not establish a global or unique attacker optimum.

## Final manuscript mapping

| Manuscript or supplementary item | Packaged evidence |
|---|---|
| Table 18 adaptive local-search boundary | `sim/rpa_resolution/results/m14_adaptive_refinement/`; `sim/rpa_resolution/scripts/run_m14_adaptive_refinement.py`; `analyze_m14_adaptive_refinement.py` |
| Table 24 paired modeled-observable privacy audit | `sim/rpa_resolution/results/m12_privacy_sidechannel/`; `sim/rpa_resolution/scripts/run_m12_privacy_sidechannel.py` |
| Tables 25–26 joint epoch–loss–density boundary | `sim/rpa_resolution/results/m13_joint_robustness/`; `sim/rpa_resolution/scripts/run_m13_joint_robustness.py`; `analyze_m13_joint_robustness.py` |
| Supplementary Tables S1–S4 | `supplementary/electronics-4413038-supplementary-tables-s1-s4-20260715.docx` and `.pdf` |
| Complete 168-strategy screen | `supplementary/adaptive_local_screen_complete.csv`; original table and manifest under `sim/rpa_resolution/results/m14_adaptive_refinement/screen/` |
| Figure 9, Figure 15, and Figure 17 regeneration | `nt02_regenerated_figures/` |
| Anonymized visible-address repetition sanity check | `nt03_hardware_trace_evidence/` |
| Previous main/sensitivity/ablation/statistical result families | `sim/rpa_resolution/results/` and `sim/rpa_resolution/figures/` |

## Reviewer-closure suite contents

### Paired modeled-observable privacy audit

- 120 paired jobs, 240 bonded/non-bonded variants, and 720 method-result rows.
- 120/120 visible-trace equality checks and initial pre-resolution audits passed.
- External-proxy and internal-diagnostic results are separated in the supplied CSVs.

### Joint epoch–loss–benign-density boundary

- 27 main cells and three controls, all confirmed with 20 seeds.
- 600 configurations and 1800 method-result rows.
- Offered- and observed-denominator service, closure audits, controls, and failure boundaries are retained.

### Adaptive local search

- 168 strategies × 5 seeds in the screen; 11 strategies × two duplicate-filter settings × 20 seeds in confirmation.
- 1280 screen/confirmation configurations, 440 confirmed P3-Persist rows, and 200 paired BudgetDoS rows.
- Complete screen, frozen selection, ranking, contrasts, duplicate-filter effects, and cap audits are supplied.

## Reproduction

Run from the directory containing `reviewer_artifact_package`.

### Fast validation and smoke tests

```bash
python3 -m unittest discover \
  -s reviewer_artifact_package/sim/rpa_resolution/tests \
  -p 'test_review260715_*.py'

python3 reviewer_artifact_package/sim/rpa_resolution/scripts/run_m12_privacy_sidechannel.py \
  --smoke \
  --out /tmp/p3-review-m12-smoke \
  --config-dir /tmp/p3-review-m12-configs

python3 reviewer_artifact_package/sim/rpa_resolution/scripts/run_m13_joint_robustness.py \
  --smoke \
  --out /tmp/p3-review-m13-smoke \
  --config-dir /tmp/p3-review-m13-configs

python3 reviewer_artifact_package/sim/rpa_resolution/scripts/run_m14_adaptive_refinement_archive.py \
  --phase screen --smoke \
  --root /tmp/p3-review-m14-smoke \
  --config-root /tmp/p3-review-m14-configs
```

### Full rerun entry points

```bash
python3 reviewer_artifact_package/sim/rpa_resolution/scripts/run_m12_privacy_sidechannel.py

python3 reviewer_artifact_package/sim/rpa_resolution/scripts/run_m13_joint_robustness.py \
  --confirm-all-20
python3 reviewer_artifact_package/sim/rpa_resolution/scripts/analyze_m13_joint_robustness.py

python3 reviewer_artifact_package/sim/rpa_resolution/scripts/run_m14_adaptive_refinement_archive.py \
  --phase screen
python3 reviewer_artifact_package/sim/rpa_resolution/scripts/run_m14_adaptive_refinement_archive.py \
  --phase confirm
python3 reviewer_artifact_package/sim/rpa_resolution/scripts/analyze_m14_adaptive_refinement.py
```

The full commands use the packaged default paths and are intended for an empty writable copy of the package. Existing frozen results should not be overwritten during review; use the explicit `--out`, `--config-dir`, `--root`, or `--config-root` options when auditing.

## Integrity and privacy

`MANIFEST_FINAL.sha256` covers every file in the package except the manifest itself. The package excludes raw BLE addresses, anonymization salts, board identifiers, device serial numbers, exact wall-clock times, location data, private account material, manuscript screenshots, Word lock files, `.DS_Store`, and patent-sensitive implementation detail not required for simulation reproduction.

## Review access

This archive is intended for restricted upload with the revision or restricted repository access supplied by the corresponding author. Public GitHub and Zenodo release remain post-acceptance actions; no public URL or DOI is asserted here.
