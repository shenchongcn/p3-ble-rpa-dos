# M12 Paired Modeled-Observable Privacy Analysis

Date: 2026-07-15 (Asia/Shanghai)

Source commit: `6009cf23`

Scientific role: auxiliary simulation evidence supporting a mandatory narrowing of the manuscript's privacy claim. This suite does not measure real BLE scan responses, connection timing, controller timing, or application logs.

## 1. Matrix and audit coverage

- [x] 3 load scenarios: no attack, medium flood, heavy flood.
- [x] Duplicate-filter windows: 0 s and 60 s.
- [x] 20 paired seeds per load/filter condition.
- [x] 120 paired jobs, 240 bonded/nonbonded variant runs, and 720 method-result rows.
- [x] Methods: `P3-Persist`, `P3-NoPersist`, `BudgetDoS`.
- [x] 120/120 pairs passed visible-trace hash equality.
- [x] 120/120 pairs passed the initial-probe pre-resolution decision audit for all three methods.
- [x] The classifier split, bootstrap, and permutation units were paired trace/seed, not event rows.

Each pair used the same timestamp, RSSI, payload length, RPA value, repetition pattern, load, and duplicate-filter setting. Only the offline identity label and normal resolution outcome differed.

## 2. Feature boundary

Two feature sets were deliberately separated:

1. Primary modeled external proxy: defer rate, mean delay, and p95 delay.
2. Internal mechanism diagnostic: cache/reserve/host-scan/budget-skip/duplicate-filter/RL path fractions and mean AES-equivalent attempts.

Internal path fields are not claimed to be directly externally observable. They explain mechanism state only.

## 3. Grouped classifier results

### External delay/defer proxy AUC

| Scenario | Delta | BudgetDoS | P3-NoPersist | P3-Persist |
|---|---:|---:|---:|---:|
| heavy flood | 0 s | 0.5 | 0.5 | 0.5 |
| heavy flood | 60 s | 0.5 | 0.5 | 0.5 |
| medium flood | 0 s | 0.5 | 1.0 | 1.0 |
| medium flood | 60 s | 0.5 | 0.5 | 0.5 |
| no attack | 0 s | 0.5 | 1.0 | 1.0 |
| no attack | 60 s | 0.5 | 0.5 | 0.5 |

All reported 0.5 and 1.0 AUC values had bootstrap intervals collapsed at the same value in this deterministic modeled feature set. Pair-level permutation means remained approximately 0.5.

Interpretation:

- Initial pre-resolution behavior did not depend on the identity label in any tested pair.
- Full-run modeled delay/defer sequences were distinguishable for `P3-Persist` and `P3-NoPersist` under no/medium load when duplicate filtering was disabled.
- The modeled external proxy was not distinguishable under heavy flood or with the 60 s duplicate filter in this matrix.
- Internal path diagnostics frequently remained distinguishable because successful normal resolution changes later positive-cache/RL/service state. This is mechanism evidence, not a direct external-channel measurement.

## 4. Paired effect examples

For `P3-Persist` with duplicate filtering disabled:

- medium flood: bonded-minus-nonbonded mean delay difference `-3.333333 ms` per probe event; defer-rate difference `-0.003333`.
- no attack: bonded-minus-nonbonded mean delay difference `-3.333333 ms` per probe event; defer-rate difference `-0.003333`.

For `P3-NoPersist` with duplicate filtering disabled:

- medium flood: mean delay difference `-915.166667 ms`; p95 difference `-1000 ms`.
- no attack: mean delay difference `-173.666667 ms`; p95 difference `-1000 ms`.

These are simulator delay outputs, not measured wall-clock BLE latency.

## 5. Cross-epoch state audit

The first-ever probe decision matched in every pair. Across later new-epoch first probes, 102 state-dependent mismatches occurred out of 720 comparisons:

- heavy flood: 0/240 mismatches.
- medium flood: 62/240 mismatches.
- no attack: 40/240 mismatches.

These later differences arise after prior normal resolution/cache/RL/service history and belong to the full-run modeled-observable boundary, not the initial pre-resolution invariance claim.

## 6. Required manuscript conclusion

The current absolute statement that repeatedly sending the same RPA should not produce a stable membership signal is too strong. The manuscript patch must instead state:

- the scheduler does not intentionally consume bonded-identity labels for initial pre-resolution admission;
- identical visible traces produced identical initial pre-resolution decisions in the paired simulation;
- later modeled behavior can become statistically distinguishable after normal resolution changes cache/RL/service state in some tested conditions;
- no claim is made that real end-to-end BLE behavior is side-channel free;
- production-stack timing, scan-response, connection, log, and application-channel evaluation remains future work.

## 7. Reproducibility artifacts

| Artifact | SHA-256 |
|---|---|
| `combined_probe_summary.csv` | `40142e92e0786c244b22c1bbccc8119e2b16c948f952d525608767c4f09fef5c` |
| `paired_trace_audit.csv` | `970f2560dd815ed94c80b67003d34c578b81846cd22781f8382e28435dc6a98b` |
| `table_m12_paired_effects.csv` | `e54b326f41e7116aa00c5a72e624822e9073d491af89c8b2652c592aa7a00b7d` |
| `table_m12_classifier_summary.csv` | `6cc2a5199cfb8528c68328a1eb1b65e9543175db9b77f5e3b390e525fa833ce8` |
| `matrix_manifest.json` | `3849cc3f03b9a469b37cc3ae56be47676d8be444af7ae7676729782b77364626` |

The manifest also records exact source-file SHA-256 values. Results occupy approximately 37 MB; configs occupy approximately 960 KB. No manuscript file was modified.
