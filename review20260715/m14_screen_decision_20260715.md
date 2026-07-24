# M14 Local Screen Decision Record

Date: 2026-07-15 (Asia/Shanghai)

Source commit: `6e66dbd2`

This record was frozen after all 840 screen runs completed and before any confirmation run was started.

## 1. Closure

- [x] 168/168 strategies completed.
- [x] 5/5 seeds completed per strategy.
- [x] 840/840 configs and 840 P3-Persist rows completed.
- [x] Every screen config used heavy flood, `R=200`, `k=1`, and `Δ=60 s`.
- [x] No non-P3 method was present in the screen.
- [x] Resume validation reproduced the complete table without rerunning completed configs.

## 2. Frozen top-five selection

The preregistered ordering was applied without substitution.

| Rank | Strategy | Mean AES/min | 95% CI | Legitimate rate | Duplicate-removable fraction | Attack reserve grants |
|---:|---|---:|---:|---:|---:|---:|
| 1 | `pool320_r1_p75` | 145,946.304 | 145,482.166–146,410.442 | 0.688184 | 0.970667 | 4,984.0 |
| 2 | `pool320_r1_p90` | 145,942.272 | 145,470.833–146,413.711 | 0.687950 | 0.970667 | 4,983.8 |
| 3 | `pool320_r1_p105` | 145,938.240 | 145,459.351–146,417.129 | 0.686628 | 0.970666 | 4,983.6 |
| 4 | `pool320_r1_p120` | 145,938.240 | 145,459.351–146,417.129 | 0.685540 | 0.970667 | 4,983.6 |
| 5 | `pool320_r1_p135` | 145,938.240 | 145,459.351–146,417.129 | 0.685540 | 0.970667 | 4,983.6 |

The next two strategies, `pool320_r1_p150` and `pool320_r1_p180`, had the same screen mean and CI as ranks 3–5. They were excluded only by the preregistered top-five count and lexicographic exact-tie rule. The final report must describe a tied damaging region rather than a unique optimum.

## 3. Historical worst-point check

- Historical M11 worst: `pool256_r1_p120`.
- M14 screen rank: 82/168.
- M14 screen mean: `128,963.520 AES/min`.
- Historical 20-seed mean: `128,962.512 AES/min`.

The one-AES/min difference is negligible and supports continuity with M11, while the denser search identifies a substantially more damaging region near `m=320,r=1`.

## 4. Repetition-factor hypothesis

Mean attack work averaged over all `(m,p)` cells was:

| Repeats `r` | Mean AES/min | Cell minimum | Cell maximum |
|---:|---:|---:|---:|
| 1 | 115,106.688 | 64,076.544 | 145,946.304 |
| 2 | 113,884.488 | 63,915.264 | 142,656.192 |
| 4 | 112,155.552 | 64,092.672 | 138,059.712 |

Across matched `(m,p)` cells, `r=1` exceeded `r=2` by 1,222.2 AES/min on average, and `r=2` exceeded `r=4` by 1,728.936 AES/min on average. A few low-work cells reversed locally, so the effect is interactive rather than globally monotone. In the damaging `m=320` region, however, the decrease from `r=1` to `r=2` and `r=4` was large and consistent. The “r saturation” hypothesis is rejected for the tested local region.

## 5. Frozen confirmation union

- [x] Five selected screen strategies.
- [x] Historical worst `pool256_r1_p120`.
- [x] Fixed single-axis neighbors: `pool224_r1_p120`, `pool320_r1_p120`, `pool256_r1_p105`, `pool256_r1_p135`, and `pool256_r2_p120`.
- [x] Unique-address baseline.
- [x] Union deduplicated to 11 strategies.
- [x] Each strategy will run `Δ=0/60 s` × 20 seeds.
- [x] BudgetDoS will be added only to the five top strategies.
- [x] Expected totals: 440 configs and 640 method-result rows.

No strategy was added or removed after viewing its service cost.
