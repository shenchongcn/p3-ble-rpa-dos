# M14 Adaptive-Address Local Refinement Preregistration

Date frozen: 2026-07-15 (Asia/Shanghai), before the M14 screen was run.

Scientific role: test whether the M11 reported worst point is stable under a denser local search. This is a bounded local search, not a proof of a global attacker optimum.

## 1. Historical M11 boundary

- [x] M11 contains `unique`, `legacy_repeated`, and ten manually selected pool strategies.
- [x] The pool interval was bound to pool size in M11: `m∈{1,4}→p=15 s`, `m∈{16,64}→p=60 s`, and `m=256→p=120 s`.
- [x] M11 therefore did not independently scan `(m,p)`.
- [x] The reported `Δ=60 s` P3-Persist worst point was `(m=256,r=1,p=120 s)`, mean `128,962.512 AES-equivalent/min`.
- [x] The hypotheses that `r` is saturated and that `m/p` dominate remain hypotheses to be tested, not dimensionality-reduction assumptions.

## 2. Phase A screen

- [x] Grid: `m={128,160,192,224,256,320,384,512}`, `p={75,90,105,120,135,150,180}s`, and `r={1,2,4}`.
- [x] Complete crossing: 168 strategies.
- [x] Scenario: heavy flood, `R=200`, `k=1`, and duplicate-filter window `Δ=60 s`.
- [x] Method whitelist: P3-Persist only.
- [x] Seeds: `20260610–20260614` (5 seeds), giving 840 configs.
- [x] Primary ranking objective: descending mean P3-Persist attack AES-equivalent/min.
- [x] Deterministic exact-tie rule: attack-strategy name, lexicographic ascending.
- [x] Secondary reported metrics: legitimate rate, false defer, duplicate-removable fraction, attack reserve grants, and 95% CI.

## 3. Phase B confirmation selection

- [x] Select the top five screen strategies without manual replacement.
- [x] Always include the historical worst `(256,1,120)`.
- [x] Always include the five single-axis neighbors of the historical worst: `(224,1,120)`, `(320,1,120)`, `(256,1,105)`, `(256,1,135)`, and `(256,2,120)`.
- [x] Always include the unique-address baseline.
- [x] Deduplicate the union; no strategy is counted twice.
- [x] Run the union at `Δ={0,60}s` with seeds `20260610–20260629` (20 seeds).
- [x] P3-Persist is run for every confirmation strategy.
- [x] BudgetDoS is added only to the final top five, under the identical seed/trace configuration.

If several confirmed strategies have overlapping 95% CIs, they will be reported as a tied damaging region using mean, CI upper bound, legitimate-service cost, and cap distance; no unique optimum will be asserted.

## 4. Claim boundary

- [x] The fixed reference cap is `151,200 AES-equivalent/min`.
- [x] A cap approach or exceedance triggers a counting/applicability audit before any manuscript change.
- [x] The final language will say “worst observed in the tested local grid,” never “global optimum.”
- [x] No manuscript DOCX is edited during M14; the result only feeds the later Markdown patch package.
