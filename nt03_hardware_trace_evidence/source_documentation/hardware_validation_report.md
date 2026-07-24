# nRF5340 DK Hardware Validation Report

## 1. Scope

This report records hardware-preparation and source-audit evidence for M13. It is a sanity-check support package, not a deployment-performance evaluation.

## 2. Hardware And Software

- Hardware: one nRF5340 DK visible to `nrfjprog`; serial retained only in internal raw log.
- Host OS: macOS 26.5 (Build 25F71), Darwin 25.5.0, arm64.
- NCS/Zephyr workspace: `/opt/nordic/ncs/v3.2.1/zephyr`.
- Zephyr/NCS version: `ncs-v3.2.1-dirty`.
- Nordic toolchain bundle: `322ac893fe`.
- west: `West version: v1.4.0`.
- App core board target: `nrf5340dk/nrf5340/cpuapp`.
- Network core board target: `nrf5340dk/nrf5340/cpunet`.

## 3. H0 Toolchain Result

Decision: GO for build; flash executed later only after explicit human authorization.

Evidence:

- `nrfjprog --ids` returned one DK.
- macOS enumerated J-Link/CDC serial ports.
- `west --version` works inside the NCS/Zephyr workspace.
- `west boards | rg nrf5340dk` finds `nrf5340dk`.
- Internal raw evidence is retained outside the public package.

## 4. Build And Network-Core Preparation

Observer app build completed:

- Sample: `zephyr/samples/bluetooth/observer`.
- Command: `west build -p always --sysbuild -b nrf5340dk/nrf5340/cpuapp samples/bluetooth/observer -d docs/m13-hardware-validation/build_m13_observer`.
- App artifacts: `observer/zephyr/zephyr.hex`, `observer/zephyr/zephyr.elf`, `observer/zephyr/zephyr.bin`.
- Merged artifact: `build_m13_observer/merged.hex`.
- Config evidence: `CONFIG_BT_HCI_IPC=y`.

Network-core HCI IPC/controller build completed:

- Sample: `zephyr/samples/bluetooth/hci_ipc`.
- Command: `west build -p always -b nrf5340dk/nrf5340/cpunet samples/bluetooth/hci_ipc -d docs/m13-hardware-validation/build_m13_hci_ipc_cpunet`.
- cpunet artifacts: `hci_ipc/zephyr/zephyr.hex`, `hci_ipc/zephyr/zephyr.elf`, `hci_ipc/zephyr/zephyr.bin`.
- Merged artifact: `build_m13_hci_ipc_cpunet/merged.hex`.
- Config evidence: `CONFIG_BT_HCI_RAW=y`, `CONFIG_BT_CTLR_HCI=y`, `CONFIG_BT_CTLR_PRIVACY=y`, `CONFIG_BT_CTLR_RL_SIZE=8`, `CONFIG_BT_RPA=y`.

Flash completed after explicit authorization:

- network core HCI IPC/controller: success.
- official observer app core: success, used for initial serial/scanning smoke test.
- M13 CSV scanner app core: success, used for H1 background trace.

CSV scanner firmware:

- App: `docs/m13-hardware-validation/scanner_app`.
- Output format: `SCAN,timestamp_ms,addr,addr_type,is_random,is_rpa_candidate,rssi_dbm,adv_type,payload_len`.
- Serial console: internal serial device path, omitted from public report.

## 5. H1 Background Trace

Completed.

- Run: `H1_background_01`.
- Scanner: M13 CSV passive scanner with duplicate filtering disabled.
- Duration: 600.026 s.
- Raw log and standardized CSV: retained outside the public package.
- Processed summary and candidate table: retained outside the public package.
- Events: 30798.
- Unique addresses: 18.
- Random-address events: 16740.
- RPA-candidate events: 14445.
- RPA-candidate addresses: 10.
- Addresses repeated at least twice: 17.
- Addresses with `D(rv)>=2` within W=60 s: 17.
- Addresses with `D(rv)>=2` within W=120 s: 17.

Interpretation: H1 establishes a live BLE background baseline and scanner functionality. It does not provide controlled-device attribution and is not evidence for H2.

## 6. H2 Controlled Device Trace

Completed with one controlled smartphone trace.

- Controlled device: Redmi K80 smartphone.
- `off_1`: 300 s, 17535 events.
- `on_1`: 1200 s, 59120 events.
- `off_2`: 300 s, 16385 events.
- `on_2`: 1200 s, 49940 events.
- Internal window/repeatability/candidate tables: retained outside the public package.
- Public/anonymized tables:
  - `data/processed/real_trace_window_summary_public.csv`
  - `data/processed/real_trace_repeatability_public.csv`
  - `data/processed/real_trace_random_private_candidates_public.csv`

Candidate-table definition: a public candidate row is a random-address observation or an RPA-bit-pattern candidate. The table does not assert that every row is a cryptographically confirmed RPA.

Repeatability summary:

| Device class | Window | Candidate addresses | Repeated candidates | Repeat fraction | Event repeat fraction | Median interarrival (s) | P95 interarrival (s) | W=60s repeats | W=120s repeats |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| smartphone | on_1 | 34 | 31 | 0.911765 | 0.999913 | 0.189 | 0.525 | 31 | 31 |
| smartphone | on_2 | 29 | 27 | 0.931034 | 0.999931 | 0.252 | 0.526 | 27 | 27 |

Interpretation: H2 passes as a controlled repetition-observation sanity check. Both controlled-on windows exceed 15 minutes, both contain repeated random/private-address candidates, and W=60 s and W=120 s repeat counts are reported. The on/off separation is partial rather than clean: off windows also contain candidate and high-RSSI addresses, and some addresses appear across off/on windows. Controlled-device attribution should therefore be treated as likely only for the subset of candidates that are on-only, repeated, and high-RSSI. This is not cryptographic IRK ground truth and not a production deployment result.

## 7. H3 Multi-Device Trace

Completed with a second controlled smartphone trace.

- Additional controlled device: iPhone 6s, reported publicly as a legacy iOS smartphone.
- `off_1`: 300 s, 13995 events.
- `on_1`: 1200 s, 44384 events.
- `off_2`: 300 s, 9708 events.
- `on_2`: 1200 s, 36408 events.
- Internal H3 raw logs, standardized CSVs, and candidate tables are retained outside the public package.
- Public/anonymized H3 tables:
  - `data/processed/h3_iphone_6s_window_summary_public.csv`
  - `data/processed/h3_iphone_6s_repeatability_public.csv`
  - `data/processed/h3_iphone_6s_random_private_candidates_public.csv`
  - `data/processed/h3_multidevice_repeatability_public.csv`

Multi-device repeatability summary:

| Device class | Window | Candidate addresses | Repeated candidates | Repeat fraction | Event repeat fraction | Median interarrival (s) | P95 interarrival (s) | W=60s repeats | W=120s repeats |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Android smartphone | on_1 | 34 | 31 | 0.911765 | 0.999913 | 0.189 | 0.525 | 31 | 31 |
| Android smartphone | on_2 | 29 | 27 | 0.931034 | 0.999931 | 0.252 | 0.526 | 27 | 27 |
| Legacy iOS smartphone | on_1 | 37 | 35 | 0.945946 | 0.999936 | 0.187 | 0.452 | 35 | 35 |
| Legacy iOS smartphone | on_2 | 26 | 23 | 0.884615 | 0.999869 | 0.271 | 0.727 | 23 | 23 |

Interpretation: H3 passes as a two-smartphone controlled-trace enhancement. Both devices have two controlled-on windows of at least 1200 s, and every controlled-on window contains repeated random/private-address candidates with `D(rv)>=2` under W=60 s and W=120 s. This reduces the single-device concern, but it remains a controlled-window/RSSI/repetition sanity check. It still does not provide cryptographic IRK identity ground truth, deployed P3 firmware evidence, or a real attack-defense trace.

## 8. H4 Stack Fallback Evidence

Completed as source/Kconfig audit only.

Evidence:

- `zephyr/subsys/bluetooth/host/id.c:56`: `bt_lookup_id_addr()` calls `bt_keys_find_irk()` for identity lookup when SMP is enabled.
- `zephyr/subsys/bluetooth/host/keys.c:239`: `bt_keys_find_irk()` checks whether an address is an RPA and scans stored IRKs.
- `zephyr/subsys/bluetooth/host/keys.c:273`: host-side matching calls `bt_rpa_irk_matches()`.
- `zephyr/subsys/bluetooth/host/keys.c:42`: key storage is sized by `CONFIG_BT_MAX_PAIRED`.
- `zephyr/subsys/bluetooth/host/Kconfig:818`: `CONFIG_BT_MAX_PAIRED` supports a 0..250 range.
- `zephyr/subsys/bluetooth/controller/Kconfig:697`: controller resolving-list size defaults to 8 and is range-limited to 1..8 on nRF.
- `zephyr/subsys/bluetooth/host/hci_core.c:3914`: host queries controller resolving-list size through `BT_HCI_OP_LE_READ_RL_SIZE`.

Interpretation: Zephyr-class stacks contain host-side IRK lookup and controller resolving-list capacity evidence. This supports mechanism-existence discussion only; it does not show P3 firmware implementation, measured fallback performance, or production deployment.

## 9. H5 Replay Result

Completed on the H2 Redmi K80 controlled trace as a real-trace replay shim, not as a firmware performance benchmark. H3/iPhone 6s was used for repeatability only and is not included in the current replay or robustness sweep tables.

- Replay script: `docs/m13-hardware-validation/scripts/replay_real_trace.py`.
- Internal replay input and decisions: retained outside the public package.
- Public path-count summary: `data/processed/real_trace_replay_path_counts_public.csv`.
- Replay method label: `P3-Persist-real-trace-shim`.
- Replay events: 82229.
- Controlled-device-likely candidate addresses: 21.
- `D(rv)>=2` within W=60 s: 70 candidate addresses total; 21 controlled-device-likely, 49 ambient/unknown.
- Parameter snapshot: cache size 64, duplicate-filter window 0.200 s, budget window 60 s, budget 100 events/window, persistence k=1, reserve 8, RL capacity 8, legit RSSI threshold -85 dBm.

Path-count summary:

| Path | Controlled-device-likely | Ambient/unknown |
| --- | ---: | ---: |
| RL hit | 8 | 0 |
| Duplicate filter | 13 | 6042 |
| Cache hit | 39712 | 0 |
| Host scan | 13 | 4065 |
| Budget skip | 472 | 31584 |
| Persistence reserve | 0 | 320 |

Interpretation: H5 passes as an internal path-count sanity check. The replay shim exercises cache, resolving-list, duplicate-filter, budget, host-scan, and reserve accounting on the H2 trace, but the labels remain controlled-window/RSSI based. It should not be read as real P3 runtime evidence; there is no cryptographic IRK ground truth, no real attack trace, and no deployed P3 firmware measurement.

Robustness sweep:

- Sweep script: `docs/m13-hardware-validation/scripts/sweep_replay_params.py`.
- Public sweep table: `data/processed/real_trace_replay_robustness_public.csv`.
- Public summary table: `data/processed/real_trace_replay_robustness_summary_public.csv`.
- Parameter grid: RL capacity 0/4/8, budget per 60 s window 50/100/200, duplicate-filter window 0.1/0.2/0.5/1.0 s, legit RSSI threshold -90/-85/-80/-75 dBm.
- Configurations: 144.
- Legit non-budget-skip fraction: min 0.962990, median 0.988045, max 0.999776.
- Legit resolution-path fraction: min 0.959112, median 0.978766, max 0.999776.
- Ambient budget-skip fraction: min 0.154468, median 0.556061, max 0.885323.

Interpretation: The H5 result is not a single-parameter artifact. Across the sweep, controlled-device-likely replay events remain mostly outside the budget-skip path, while ambient/unknown events are sensitive to budget and duplicate-filter settings. This strengthens the manuscript's sanity-check claim but still does not establish deployed P3 performance.

## 10. Manuscript Revision Recommendation

Decision: ADD_TO_MANUSCRIPT

Reason: H0, scanner build/flash, H1 background trace, H2 controlled Redmi K80 trace, H3 controlled iPhone 6s trace, public/anonymized H2/H3 tables, H4 source/Kconfig audit, H5 real-trace path-count replay, and H5 robustness sweep are complete. Attribution remains partial/likely rather than IRK-ground-truth, and deployed P3 firmware measurement is still absent, so the manuscript should only add a small controlled-trace sanity-check note and must not claim hardware validation of P3.

Recommended manuscript action now: add at most a short Discussion/Evaluation subsection titled `Controlled BLE Trace Sanity Check`, using the public repeatability table. Use weak wording such as:

```text
We additionally collected a controlled nRF5340 DK passive-scan trace to sanity-check the visible-address repetition assumption. The trace is not used for headline performance claims; it only confirms that repeated private-address candidates occur in controlled real BLE advertising windows.
```

Optional H5 sentence:

```text
An offline replay shim over the controlled trace produced aggregate cache, resolving-list, budget, duplicate-filter, and persistence-reserve path counts, but this remains an accounting sanity check without IRK identity ground truth or P3 runtime evidence.
```

Do not use `hardware validated`, `real deployment`, or `production implementation`.
