# M13 Joint Epoch–Loss–Density Robustness Analysis

Date: 2026-07-15 (Asia/Shanghai)

Analysis commit: `f75e03a6`

Run source commits: `50e8a904`, `6d3a9c72`, and `5ebf9865`. The simulator source SHA-256 was identical across all three run commits: `ae8c3f9086eb038111cebf2b5abc344f7d88f93988cd36edb8cfe2642f1bcb60`.

Scientific boundary: these are lightweight simulator results, not packet captures, controller measurements, real BLE timing, or hardware energy measurements.

## 1. Matrix and audit coverage

- [x] Main matrix: epoch `{1,5,15 min}` × observation loss `{0,0.2,0.4}` × unique benign density `{100,1000,5000 RPA/min}`.
- [x] Main attack load: `10000 RPA/min`.
- [x] Methods: `P3-Persist`, `P3-NoPersist`, and `BudgetDoS`.
- [x] All 27 main cells were extended to 20 seeds.
- [x] No-attack baseline, no-attack worst-boundary, and repeated-benign worst-boundary controls were extended to 20 seeds.
- [x] Total: 600 configs and 1800 method-result rows.
- [x] The repeated-benign control retained the worst-cell attack load; only the benign address mode changed from unique to repeated.
- [x] All 600 config hashes, run IDs, method sets, and completion manifests passed validation.
- [x] Generated = observed + dropped closed globally, by source, and for the residual non-RPA class.
- [x] Event/loss counts were identical across the three methods within each run.
- [x] The offered/observed legitimate-resolution denominator identity held with maximum absolute error `8.85e-7`.
- [x] Requested versus realized observation loss differed by at most `0.003613`.

## 2. Practical degradation screen

The pre-confirmation operational rule was an absolute decrease of at least `0.05` in P3-Persist `offered_legit_resolution_rate`, relative to the lowest-pressure attacked main cell `(epoch=15 min, loss=0, density=100 RPA/min)`. This is a seed-extension screen, not a formal non-inferiority margin or significance test.

- Baseline attacked main-cell offered rate: `0.955313`.
- Cells crossing the screen: `24/27`.
- The only cells not crossing were the three `epoch=15 min, loss=0` density levels.
- Because 24 cells crossed and resources permitted, all 27 main cells and all controls were confirmed at 20 seeds rather than selectively extending only favorable cells.

### Worst three P3-Persist main cells by offered service

| Epoch | Loss | Unique benign density | Offered rate | Observed rate | Observed false defer | Attack AES/min |
|---:|---:|---:|---:|---:|---:|---:|
| 1 min | 0.4 | 100 | 0.400575 | 0.668126 | 0.336391 | 49,645.008 |
| 1 min | 0.4 | 5000 | 0.402741 | 0.671334 | 0.333547 | 33,477.696 |
| 1 min | 0.4 | 1000 | 0.405555 | 0.673816 | 0.331320 | 45,566.640 |

The worst-cell ordering by density should not be over-interpreted: within a fixed epoch/loss pair, the range of mean offered rates across the three unique-benign densities was at most `0.00498`. Epoch and loss dominated this tested unique-benign matrix.

## 3. Safety and service must be separated

### 3.1 Modeled work safety

- [x] Every P3-Persist main run remained below the existing `151,200 AES/min` cap.
- Maximum observed P3 attack work was `49,996.8 AES/min`, or `0.3307` of the cap.
- Mean work varied with load composition because benign and attack events compete for the modeled budget. This result supports the tested work bound only; it is not a hardware throughput or energy claim.

### 3.2 Legitimate service

- [x] Service stability did not hold across the joint tested boundary.
- At zero loss, shortening the epoch from 15 min to 5 min reduced mean offered service from about `0.955` to `0.853–0.855`; at 1 min it fell to about `0.705–0.707`.
- At 40% observation loss and a 1 min epoch, mean offered service was about `0.401–0.406`, while observed-denominator service was about `0.668–0.674`. The gap is the reason both denominators must be reported.
- P3-Persist still outperformed the two non-persistent comparators at the unique-benign worst cell. Its paired offered-rate advantage was `0.072129` versus P3-NoPersist (95% CI `0.050880–0.093379`) and `0.074306` versus BudgetDoS (95% CI `0.051563–0.097050`). This comparative benefit does not restore absolute service stability.

The correct conclusion is therefore: the tested scheduler preserves the modeled work cap and P3-Persist improves service relative to the tested comparators, but service recovery is conditional on epoch/loss/background behavior and is not guaranteed over the full joint boundary.

## 4. Control results

### 4.1 Attack effect

- At the 15 min / zero-loss / density-100 baseline, adding the attack reduced P3-Persist offered service by `0.033071` (95% CI `0.031487–0.034655`).
- At the 1 min / 40%-loss / density-5000 unique-benign boundary, the attacked-minus-no-attack offered difference was `-0.003321` (95% CI `-0.009255–0.002614`). In that cell, epoch/loss/background pressure already dominated service.

### 4.2 Repeated-benign control

At the worst attacked boundary, changing only benign addresses from unique-per-event to the frozen repeated pattern produced:

- offered-rate difference `-0.057604` (95% CI `-0.068431–-0.046777`);
- observed-rate difference `-0.096055` (95% CI `-0.114101–-0.078010`);
- observed false-defer difference `+0.091536` (95% CI `0.074059–0.109014`);
- background reserve grants `+4998.8` per measurement interval on average.

This control is a failure boundary that must be disclosed. Repeated unknown addresses can consume the modeled persistent reserve path and materially worsen legitimate service. The manuscript must not generalize the unique-benign density result to arbitrary benign repetition patterns.

## 5. Delay interpretation

Across P3 main runs, modeled overall p95 resolution delay was `0 ms`; p99 reached at most `100 ms`, and reserve-grant p95/p99 reached at most `100 ms`. These are simulator scheduling outputs. They do not validate real BLE scan-response, connection, controller, host-stack, or application latency.

## 6. Required Section 7.2 patch direction

The manuscript patch must:

- [x] retain the tested `B+R`/AES work-bound statement only within the simulated parameter boundary;
- [x] replace unconditional service-recovery wording with conditional service recovery;
- [x] report both offered- and observed-denominator legitimate-resolution rates;
- [x] state that 24/27 cells crossed the practical 0.05 degradation screen;
- [x] disclose the repeated-benign failure control and reserve-pressure mechanism;
- [x] avoid presenting `epoch=15 min` as a global optimum or production recommendation;
- [x] state that short epochs require separate budget/reserve tuning and validation;
- [x] keep real packet loss, BLE timing, and hardware behavior outside the demonstrated scope.

No tuning was performed after observing these results. Any tuning study must be separately preregistered and reported as a new experiment.

## 7. Reproducibility artifacts

| Artifact | SHA-256 |
|---|---|
| `combined_summary.csv` | `44436a36316491e95d7617c414f0dbf62150068a98396877c15dc7937891e52e` |
| `table_m13_joint_robustness.csv` | `82035d0a12d8c7edd7488df297251296b99d49600828729d0ba89213b4e67896` |
| `audit_m13_closure.csv` | `56dbb227af98891e81ecf557796e7755a024cad0aa296e6966c4d043bfaf2a46` |
| `table_m13_service_degradation.csv` | `fc14281fe19f26ed4a3dc461eaf8d8f853d414957b20d621325cfc0e56e59ac5` |
| `table_m13_control_contrasts.csv` | `db80c35b396774bbe7bd116141b1d5160f58fc2701d56e8d9122eee65fef9c28` |
| `heatmap_m13_p3_persist_service.csv` | `7bc2bfb711162fa4b6729005777f301606a296b18171c6d66e45fcc48a59199e` |
| `matrix_manifest.json` | `e56e8277b98f9eea3eb65ff8b2432f9e39a284691ad344a54f057d4cae800046` |
| `analysis_manifest.json` | `86e0ce2fb23d7250cf5c198482b849597bbdf32ec4c418fbbdbcd15f4ea25a45` |

Results occupy approximately 5.5 MB and configs approximately 2.3 MB. The manuscript `electronics-4413038.docx` was not modified.
