# NT-03 硬件轨迹证据包

## 结论

本证据包复用 `docs/m13-hardware-validation` 中同一项目、同一作者控制下的 nRF5340 DK 被动扫描实验。采集日期为 2026-06-06，扫描器采集时关闭 duplicate filtering；受控设备包括一台 Android smartphone 和一台 legacy iOS smartphone，每台设备均有两个 1200 s 的 `device_on` 窗口及配套 `device_off` 窗口。

这些数据能够支持的结论是：**在真实 BLE 广播窗口中，同一个被观测到的 random/private-address value 会在 60 s 内重复出现**。这些数据不能证明每个候选值都经过 IRK 密码学确认，不能证明真实 RPA epoch 边界，也不能证明 P3 已在硬件上部署。

## 实测重复结果

| 设备类别 | 窗口 | 观测地址值 | 重复地址值 | 重复比例 | 60 s 内重复地址值 | 中位到达间隔 (s) | P95 (s) |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| android_smartphone | on_1 | 34 | 31 | 91.18% | 31 | 0.189 | 0.525 |
| android_smartphone | on_2 | 29 | 27 | 93.10% | 27 | 0.252 | 0.526 |
| legacy_ios_smartphone | on_1 | 37 | 35 | 94.59% | 35 | 0.187 | 0.452 |
| legacy_ios_smartphone | on_2 | 26 | 23 | 88.46% | 23 | 0.271 | 0.727 |

统计口径为 `is_random=1 OR is_rpa_bit_pattern_candidate=1`。另见 `data/repeatability_summary.csv` 中更严格的 `rpa_bit_pattern` 子集。地址值计数不是身份计数；同一身份在不同地址轮换后会形成不同地址值。

## Duplicate-Filter 对照

| 模式 | 输入事件 | 保留事件 | 抑制事件 | 保留比例 |
| --- | ---: | ---: | ---: | ---: |
| 关闭（采集实测） | 117334 | 117334 | 0 | 100.000% |
| 0.2 s（离线重放） | 117334 | 55370 | 61964 | 47.190% |
| 1 s（离线重放） | 117334 | 3137 | 114197 | 2.674% |
| 60 s（离线重放） | 117334 | 130 | 117204 | 0.111% |

`关闭`行来自扫描器实际采集配置。`0.2 s`、`1 s` 和 `60 s` 行是在同一批实测事件上执行的离线 sliding-window duplicate-filter accounting，不是控制器固件实测，因此论文中必须写成 offline replay。

## 数据与可复现性

- `data/controlled_private_address_events_anonymized.csv.gz`：149633 条匿名化 random/private-address candidate 事件，保留窗口内相对时间、地址哈希、RPA 位型标记、RSSI、advertising type 和 payload length。
- `data/repeatability_summary.csv`：四个受控开启窗口的重复统计，分别给出宽口径 candidate 和严格 RPA-bit-pattern candidate。
- `data/duplicate_filter_replay_summary.csv`：关闭采集与三个离线过滤窗口的对照。
- `recompute_public_summaries.py`：只依赖上述匿名化 `.csv.gz`，可重新生成两份 summary CSV，不需要原始 BLE 地址、匿名化盐或仓库外目录。
- `source_public_data/`：从原 M13 目录复制的公开安全数据。
- `source_analysis_scripts/`：原始分析和 replay 脚本副本。
- `provenance_manifest.csv`：原始内部 CSV 的路径与 SHA-256；原始 CSV 含未哈希 BLE 地址，因此不复制进审稿包。

从本目录执行公开安全复现：

```bash
python3 recompute_public_summaries.py \
  --output-dir /tmp/nt03-recomputed \
  --verify-against data
```

该命令只读取 `data/controlled_private_address_events_anonymized.csv.gz`。输出必须与 `data/repeatability_summary.csv` 和 `data/duplicate_filter_replay_summary.csv` 逐字节一致。

## 论文可直接加入的英文文字

建议在 Assumption A2 后新增：

> We additionally sanity-checked Assumption A2 using passive advertising traces captured by an nRF5340 DK with controller duplicate filtering disabled. Across two 1200-s controlled-on windows for each of two smartphones, 31/34, 27/29, 35/37, and 23/26 observed random/private-address candidate values were repeated, and the same candidate values reappeared within 60 s. These observations support visible candidate-value repetition as a real-traffic phenomenon, but they do not provide IRK-confirmed identity labels or exact RPA-epoch boundaries. Offline duplicate-filter replay over the same anonymized events is reported separately and is not treated as a controller-performance measurement.

建议在数据可用性段新增：

> The supplementary artifact also includes an anonymized nRF5340 DK advertising trace, repeatability summaries, and offline duplicate-filter replay tables. Raw BLE addresses, board identifiers, exact wall-clock times, and location data are excluded for privacy.

## 审稿边界

1. 不得写 `hardware validated P3`、`real deployment` 或 `measured P3 performance`。
2. 不得把 `random/private-address candidate` 简写成 cryptographically confirmed RPA。
3. duplicate-filter 开启结果必须标明 `offline replay`，因为采集固件只实测了关闭状态。
4. headline 性能结论仍来自确定性模拟；本包仅用于补强 A2 的外部有效性。
