# M14 Adaptive-Address Refinement Results

Date: 2026-07-15 (Asia/Shanghai)

Analysis commit: `89a37b16`

Run source commits: `6e66dbd2` (screen) and `8c430297` (confirmation). The simulator SHA-256 was identical across both phases: `ae8c3f9086eb038111cebf2b5abc344f7d88f93988cd36edb8cfe2642f1bcb60`.

Scientific boundary: this is a bounded simulator search over a preregistered local grid. It does not establish a global attacker optimum and is not a hardware throughput or BLE timing measurement.

## 1. Matrix and audit closure

- [x] Phase A completed 168 strategies × 5 seeds = 840 P3-Persist-only configs.
- [x] Phase A used heavy flood, `R=200`, `k=1`, and `Δ=60 s` for every strategy.
- [x] The top-five ranking was generated mechanically from the complete screen table.
- [x] Phase B deduplicated the preregistered union to 11 strategies.
- [x] Phase B completed 11 strategies × 2 duplicate-filter windows × 20 seeds = 440 configs.
- [x] P3-Persist produced 440 confirmation rows; BudgetDoS produced 200 paired rows for the top five, giving 640 method-result rows.
- [x] All 1,280 screen/confirm configs passed exact config-hash, run-ID, method-list, row-count, and manifest validation.
- [x] The simulator source hash was invariant across the two run commits.

## 2. Local screen result

The denser search materially changes the M11 conclusion.

- Historical M11 worst: `pool256_r1_p120`, mean `128,962.512 AES/min` at `Δ=60 s`.
- M14 screen rank of that point: 82/168.
- Screen top region: `m=320, r=1`, with `p=75–180 s` nearly flat at approximately `145.94k AES/min`.
- Preregistered top five: `pool320_r1_p75`, `p90`, `p105`, `p120`, and `p135`.
- `p150` and `p180` had the same 5-seed mean/CI as ranks 3–5 but were excluded only by the frozen top-five count and lexicographic exact-tie rule.

Therefore, the correct description is a damaging local region near `m=320,r=1`, not a unique point optimum.

## 3. Repetition-factor result

The earlier working hypothesis that `r` was saturated is not supported.

| Repeats `r` | Mean across 56 `(m,p)` cells (AES/min) | Minimum | Maximum |
|---:|---:|---:|---:|
| 1 | 115,106.688 | 64,076.544 | 145,946.304 |
| 2 | 113,884.488 | 63,915.264 | 142,656.192 |
| 4 | 112,155.552 | 64,092.672 | 138,059.712 |

Matched-cell mean differences were `r1-r2 = 1,222.2`, `r2-r4 = 1,728.936`, and `r1-r4 = 2,951.136 AES/min`. Some low-work cells reversed locally, so `r` interacts with `(m,p)` and should not be removed from future searches. In the damaging `m=320` region, `r=1` was consistently worst among the tested values.

## 4. Twenty-seed confirmed best-response region

### 4.1 Duplicate filter enabled (`Δ=60 s`)

| Rank | Strategy | Mean AES/min | 95% CI | Mean/cap | Legitimate rate | False defer | Duplicate-removable fraction |
|---:|---|---:|---:|---:|---:|---:|---:|
| 1 | `pool320_r1_p75` | 146,196.288 | 146,018.171–146,374.405 | 0.966907 | 0.674902 | 0.325627 | 0.970628 |
| 2 | `pool320_r1_p135` | 146,195.280 | 146,015.168–146,375.392 | 0.966900 | 0.675190 | 0.325339 | 0.970628 |
| 3 | `pool320_r1_p90` | 146,193.264 | 146,014.002–146,372.526 | 0.966887 | 0.674165 | 0.326364 | 0.970629 |
| 4 | `pool320_r1_p105` | 146,192.256 | 146,012.078–146,372.434 | 0.966880 | 0.673834 | 0.326695 | 0.970628 |
| 5 | `pool320_r1_p120` | 146,192.256 | 146,012.078–146,372.434 | 0.966880 | 0.673232 | 0.327297 | 0.970628 |

All five intervals overlap almost completely. No unique optimum is identifiable within this confirmed region.

The confirmed `pool320_r1_p75` mean exceeds the historical worst by `17,233.776 AES/min` but remains below the fixed `151,200 AES/min` cap by `5,003.712 AES/min`. The maximum single-seed P3 value was `147,006.72 AES/min`, leaving `4,193.28 AES/min` headroom.

This is a near-boundary pass, not a comfortable safety margin.

### 4.2 Duplicate filter disabled (`Δ=0 s`)

All confirmed finite-pool repeated strategies collapsed to the same modeled behavior: mean `146,162.016 AES/min` (95% CI `145,986.621–146,337.411`), legitimate rate `0.640442`, and zero duplicate-removable fraction. Without duplicate filtering, their visible repetition pattern does not reduce the admitted reserve work in this model.

The unique-address P3 baseline was much lower in work (`45,765.216 AES/min`) and much higher in legitimate service (`0.955667`).

## 5. Duplicate-filter interpretation

For the `m=320,r=1` top region, enabling the 60 s filter did not reduce attacker-induced P3 work. The paired `Δ60-Δ0` mean work differences were small but positive: about `+30.2` to `+34.3 AES/min`, with 95% CIs above zero. The filter removed roughly 97.1% of attack events, but the surviving repeated candidates continued to fill almost the entire modeled attack reserve (`≈4985` grants per measurement interval).

At the same time, P3 legitimate service improved from about `0.640` to `0.673–0.675` because the duplicate filter reduced contention. Thus the filter improves service while failing to lower the near-cap reserve work for this adaptive region.

For the unique-address baseline, `Δ=60 s` changed attack work by only `-7.056 AES/min` (95% CI `-14.087–-0.025`) but reduced legitimate rate by `0.027020` because legitimate repeated advertisements can also be filtered. These modeled tradeoffs must be reported explicitly.

## 6. BudgetDoS alignment

BudgetDoS was run only for the five frozen top strategies on identical seeds/traces.

- At `Δ=60 s`, BudgetDoS mean work was `45,644.256 AES/min` and legitimate rate `0.078791` for each top strategy.
- For `pool320_r1_p75`, P3-Persist minus BudgetDoS was `+100,552.032 AES/min` (95% CI `100,515.541–100,588.523`) and `+0.596111` legitimate rate (95% CI `0.583401–0.608821`).

The comparison exposes the intended safety–service tradeoff: P3 preserves much more legitimate service by using reserve work, but the adaptive repeated-address region drives that work close to the tested cap.

## 7. Required manuscript conclusion

Table 18, Section 6.1, and the Conclusion must be patched to state:

- [x] M11 was a coarse, non-factorial strategy sample and its reported worst point was not stable under denser local search;
- [x] the M14 worst observed region is near `m=320,r=1,p=75–135 s` at `Δ=60 s`, with overlapping confidence intervals;
- [x] the confirmed highest mean is `146,196.288 AES-equivalent/min`, not `128,962.51`;
- [x] the mean is 96.69% of the `151,200` cap and the maximum seed is 97.23% of the cap;
- [x] the cap remains unexceeded in the tested grid, but the remaining margin is small;
- [x] duplicate filtering removes most attack events yet does not reduce reserve work in the confirmed damaging region;
- [x] `r` is not saturated and must remain an explicit adaptive-attacker factor;
- [x] the result is “worst observed in the tested local grid,” never a global optimum;
- [x] further search outside `m={128…512}`, `p={75…180}s`, and `r={1,2,4}` remains future work.

No post-result tuning was performed, and the manuscript DOCX was not edited.

## 8. Reproducibility artifacts

| Artifact | SHA-256 |
|---|---|
| `screen/table_m14_local_screen.csv` | `c77aa7ba30380950fd55c24d89194ec5ef95335858209af87e183437f8a35205` |
| `screen/table_m14_repetition_effects.csv` | `5aaf291f697177a8cefd1397370b4375cc160adf5f86025c4732212ed27a2484` |
| `screen/top5_selection.json` | `360cc62d366c108e8eb77d4d18eda368c88d16405db1110067725fb2850d4205` |
| `confirm/combined_summary.csv` | `3666bd5b3b97d700da1bc18aa938debf24978aa5c4a8e38a0a11f10c86b40572` |
| `confirm/table_m14_confirmed_best_response.csv` | `7bdc403ade844018ca466d1bd38ebf81513e1f43accb9412f9c7efc6391beb24` |
| `confirm/table_m14_confirmed_ranking.csv` | `a2ebc1fef3bd9c41c01e6467eb7ab83f7a7dd27c33acd392a9bd575f820fa251` |
| `confirm/table_m14_paired_method_contrasts.csv` | `c409713a879561fbbfce044122cb4e24ef7ba9ebdc73951ee72af7d556e90a48` |
| `confirm/table_m14_duplicate_filter_effects.csv` | `8552468c134e52737369cf6ebba60a41f31cacb2fbd52c879657d77bf083946f` |
| `confirm/table_m14_cap_audit.csv` | `8660a7bb58924dc27234d18a1cabbd27b315212fdd4a3f233356c140e59532cc` |
| `audit_m14_closure.csv` | `e058bb40d6058e0622ae98bc8a893a9099b62bdaa251f5cb7c973d811fd900ea` |
| `analysis_manifest.json` | `5b1e135b07486db7194802e5f1bde3675c560cf93905def01aab18074d50b523` |

Results occupy approximately 11 MB and configs approximately 5 MB.
