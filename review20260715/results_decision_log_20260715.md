# July 15 Reviewer-Closure Results Decision Log

Date frozen: 2026-07-15 (Asia/Shanghai)

Frozen manuscript SHA-256 before user-applied patches: `1c8b5d1f1bb8fab53651638031bb52b084cec7f0e0b483a278a103db3bb4f46e`

## 1. Reviewer comment 1: privacy side channels

- [x] Added a paired modeled-observable comparison with identical visible traces and different offline identity labels.
- [x] Completed 120 paired jobs, 240 variants, and 720 method-result rows.
- [x] All 120 initial pre-resolution audits passed for all three methods.
- [x] Initial P3 admission decisions are supported as identity-label invariant within the paired simulator.
- [x] Full-run modeled external delay/defer features were distinguishable for P3-Persist and P3-NoPersist under no/medium load with duplicate filtering disabled (AUC 1.0).
- [x] Heavy flood and every `Δ=60 s` external-proxy condition had AUC 0.5.
- [x] Internal path features are retained only as mechanism diagnostics and are not called externally observable.
- [x] Decision: narrow the manuscript claim. M12 is auxiliary modeled evidence, not proof that real BLE end-to-end behavior is side-channel free.

Required manuscript boundary:

1. P3 does not intentionally consume a bonded-identity label for initial pre-resolution admission.
2. Matched visible traces produced matched initial pre-resolution decisions in the tested pairs.
3. Later modeled behavior can become distinguishable after normal resolution changes cache/RL/service state.
4. Scan response, connection, controller, host-stack, logging, and application behavior remain unmeasured.

## 2. Reviewer comment 2: joint epoch/loss/density robustness

- [x] Added an independent post-generation observation-loss layer with generated/observed/dropped ledgers.
- [x] Added backward-compatible repeated-benign generation and path metrics.
- [x] Completed 27 main cells × 20 seeds × 3 methods plus three 20-seed controls.
- [x] Total M13 evidence: 600 configs and 1800 method-result rows.
- [x] Offered- and observed-denominator legitimate-resolution rates were both reported.
- [x] All event/loss conservation, method-invariant count, denominator, seed, and manifest audits passed.
- [x] P3 modeled attack work remained below the `151,200 AES/min` cap; maximum run was `49,996.8 AES/min`.
- [x] Legitimate service was not stable across the joint tested boundary: 24/27 cells crossed the 0.05 practical degradation screen.
- [x] Worst main-cell offered service was approximately `0.401–0.406` at epoch 1 min and loss 0.4.
- [x] Repeated-benign worst-boundary control further reduced offered service by `0.057604` and observed service by `0.096055` relative to unique benign traffic.
- [x] Decision: retain the work-bound result but replace unconditional service recovery with conditional service recovery.

Required manuscript boundary:

1. Short epochs and observation loss materially reduce offered service.
2. Unique benign density had a small mean range within the tested cells, but repeated benign values can consume reserve and worsen service.
3. `k=1`, `W≤epoch`, and nominal `B/R` guidance are starting hypotheses, not a universal stability guarantee.
4. The 0.05 threshold is a practical screen, not a formal non-inferiority margin.

## 3. Reviewer comment 3: denser adaptive search

- [x] Documented that M11 was not a full `(m,p,r)` crossing because `p` was bound to `m`.
- [x] Preregistered and completed a dense local grid: 168 strategies × 5 seeds = 840 screen configs.
- [x] Completed the frozen 11-strategy confirmation union at `Δ={0,60}` and 20 seeds: 440 configs and 640 method rows.
- [x] BudgetDoS was run on identical seeds/traces for the five frozen top strategies.
- [x] Historical M11 worst `pool256_r1_p120` ranked 82/168 in the local screen but reproduced its old mean (`128,962.512`).
- [x] Confirmed damaging region: `m=320`, `r=1`, `p=75–135 s`; top-five CIs overlap.
- [x] Highest confirmed mean: `146,196.288 AES/min` (96.69% of cap), 95% CI `146,018.171–146,374.405`.
- [x] Maximum single seed: `147,006.72 AES/min` (97.23% of cap).
- [x] The `r`-saturation hypothesis was rejected in the tested local region.
- [x] Decision: replace the M11 worst-point claim with a tied near-cap local region; do not claim a unique or global attacker optimum.

Required manuscript boundary:

1. The cap remains unexceeded in the tested local grid, but the headroom is small.
2. Duplicate filtering removes about 97% of attack events in the top region yet does not reduce P3 reserve work.
3. P3 retains much higher legitimate service than BudgetDoS by spending reserve work; this is a safety–service tradeoff.
4. Search outside the frozen local grid remains future work.

## 4. Cross-result claim decisions

| Claim | Decision | Evidence |
|---|---|---|
| Initial pre-resolution scheduler does not use an identity label | Retain, with paired-simulation wording | M12 initial audit 120/120 |
| End-to-end behavior is side-channel free | Remove | M12 external proxy AUC 1.0 in some conditions; no real BLE measurement |
| Arbitrary attack work is bounded by `B+R` in the model | Retain within tested/model assumptions | Proposition 2; M14 max below cap |
| Duplicate filtering collapses every repeated strategy | Remove | M14 near-cap `m=320,r=1` region despite ~97% removal |
| P3 service recovery is stable under adverse joint factors | Remove | M13 24/27 practical-screen crossings |
| P3 service recovery is conditional and exceeds tested comparators | Retain | M13 and M14 paired comparisons |
| M11 `m=256,p=120` approximates attacker optimum | Remove | M14 old point rank 82/168 |
| M14 found a global optimum | Prohibit | Bounded local grid only |
| M14 found a tied damaging local region | Add | Overlapping top-five 20-seed CIs |

## 5. Frozen artifact set

- [x] M12 runner, 240 variant configs, paired audits, effect tables, classifier tables, and result report.
- [x] M13 runner/analyzer, 600 configs, 1800 rows, closure audit, cell/contrast/degradation tables, heatmap source, and result report.
- [x] M14 runner/analyzer, 840 screen configs, 440 confirmation configs, complete screen table, selection manifest, ranking/contrast/cap tables, and result report.
- [x] All new run manifests point to committed sources; simulator source hashes are invariant within each suite audit.
- [x] The manuscript was not modified during experiment generation or result freezing.

## 6. Remaining ordered work

- [x] Produce `manuscript_patch_instructions_20260715.md` without editing the manuscript.
- [x] User applied the patch manually; the validated marked manuscript is `electronics-4413038-reply0715V2.docx`.
- [x] Assistant completed read-only structural/text/numeric validation and issued the required incremental patches.
- [x] Supplementary S2–S4 and Data Availability were frozen against the validated manuscript.
- [x] The allowed response-letter and Supplementary Word files were rebuilt and validated.
- [ ] Update the cover letter if it will be included in the final resubmission.
- [x] Rebuild the completed PDFs and perform page-by-page QA for the marked manuscript, response letter, and Supplementary tables.
