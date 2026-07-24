# nRF5340 DK 真实硬件验证详细计划与实施文档

> 目标：在不改变当前 simulation-supported 主定位的前提下，用一块 nRF5340 DK 补足真实 BLE 地址流、真实栈路径和外部有效性证据。本文档承接 `docs/m11-novelty-strengthening/06_followup_plan.md` 的 J2a/J2b，并吸收 M2 硬件记录中未完成的 DK 工具链/RSSI 采样待办。

## 0. 当前定位

| 项 | 结论 |
| --- | --- |
| 是否阻塞 Q2 投稿 | 否。当前论文已可按 simulation-supported embedded/BLE scheduling paper 推进。 |
| 是否支撑 Q1/系统安全类投稿 | 有帮助，但不是单独通行证。至少需要 H2/H3 受控 trace、H4 真实栈路径证据、H5 replay/path-count 一致性共同成立。 |
| 当前硬件条件 | 用户仅有 1 块 nRF5340 DK；因此本文优先设计“1 个 DK 做 scanner + 手机/手表/耳机等真实 BLE 设备做广告源”的方案。 |
| 不做的 overclaim | 不声称 P3 已在生产固件部署；不声称测得端到端防御性能；不把单一场景硬件 trace 外推为所有 BLE 部署。 |

### 0.1 本轮评审修订结论

本文件已按计划评审意见修订为“agent 主执行、人工只做实体配合”的可执行版。核心调整如下：

- H2 的通过标准从“看到一次重复”收紧为“至少两个独立 controlled-on 窗口均有可解释重复，且 off/on 差异明显”；
- 最低版结果只允许写成 `controlled BLE trace sanity check`，不进入 headline 结果，不写 `hardware validated`；
- H4 真实栈证据分成“源码/Kconfig 审计”（低成本、当前优先）和“运行日志”（高成本、Q1/返修可选）；
- H5 replay 明确需要新增转换/回放脚本；当前仓库没有现成 real-trace replay 入口，不能把 H5 当作默认一两小时任务；
- raw BLE 地址、DK serial、地点/时间等均按 internal data 处理；公开材料只放聚合统计或 hash 后地址；
- Abstract/Conclusion 默认不加入硬件验证句。只有 H2/H3 多设备正结果 + H5 replay 稳定后，才允许在 Conclusion 轻描淡写加入 sanity-check 句。
- 新增 agent/人工分工：凡是能通过当前电脑完成的 H0-H5 准备、构建、日志采集、数据处理、报告撰写和论文修订，默认由 agent 执行；只有必须触碰实体设备或做投稿/伦理/作者确认的动作单独标为人工。

### 0.2 Agent 默认执行原则

除必须触碰实体设备、授权烧录、确认投稿/作者/专利等事项外，本计划默认由 agent 在当前电脑上执行。执行时坚持四条红线：

1. H0 不过就停止，不硬烧录、不硬写硬件结果；
2. H1/H2 只采集真实地址流和重复性，不做真实攻击、防御或功耗结论；
3. 所有原始日志只存 internal raw，公开表格必须脱敏；
4. 结果不理想也算有效结果，按 negative trace 记录，不为论文强行解释。

### 0.3 Agent 与人工分工总览

| 类别 | 默认责任人 | 具体动作 | 备注 |
| --- | --- | --- | --- |
| H0 工具链检查 | Agent | `nrfjprog --ids`、串口枚举、`west`/board name/SDK 路径检查、记录输出 | 当前电脑可直接执行 |
| build | Agent | 编译 Zephyr observer/scanner sample，保存 build log | 只编译不碰板子，无需人工 |
| flash | Agent 执行，人工授权 | `west flash` 或 `nrfjprog --program` 烧录 DK | 会覆盖 DK 当前固件，必须先获得用户确认 |
| 串口日志采集 | Agent | 打开串口、保存 raw log、记录行数和时间戳 | 人工只需保持 DK 接入 |
| H1 背景扫描 | Agent | 启停采集、保存背景扫描日志、生成统计 | 人工只需保证环境相对稳定 |
| H2 受控窗口 | Agent + 人工配合 | Agent 计时、记录、采集；人工按提示开关/移动手机或 BLE 设备 | 必须人工操作真实设备状态 |
| H3 多设备 trace | Agent + 人工配合 | Agent 采集分析；人工逐个拿近/拿远设备 | 可选增强 |
| H4 源码/Kconfig 审计 | Agent | 查 Zephyr/NCS 源码、Kconfig、已有 code mapping，写证据表 | 低成本优先 |
| H4 运行日志 | Agent + 人工配合 | Agent 配置/采集；人工提供多个可配对设备并确认配对动作 | Q1/返修增强，不是 M13-A 必做 |
| H5 replay 脚本与分析 | Agent | 编写/运行 parse、repeatability、replay 脚本，输出 path-count | 若脚本不存在，由 agent 补齐后再勾选 |
| H6/H7 可选项 | Agent + 人工授权 | checklist、CPU/PPK2 记录 | PPK2/功耗相关需人工接线 |
| 数据脱敏 | Agent | hash 地址、剔除 DK serial/本地路径、生成 public CSV | raw 不进公开包 |
| 报告与论文修订建议 | Agent | 写 `hardware_validation_report.md`、判断是否进正文、给出准确措辞 | 不伪造人工确认 |
| 投稿/作者/导师/专利确认 | 人工 | 导师/合作者意见、作者顺序、通讯作者、投稿系统、专利 disclosure | Agent 只能记录 gate，不能代替确认 |

### 0.4 当前电脑本地检查摘要（待证据归档）

截至 2026-06-06，用户已将 nRF5340 DK 接入当前电脑。以下内容是本机检查摘要，用于说明下一步从哪里继续；**本摘要本身不等于 H0/build checkbox 已关闭**。正式执行前必须把脱敏后的命令输出、build log 路径和镜像产物写入 `reports/agent_run_log.md` 与 `data/raw/h0_toolchain_YYYYMMDD.txt`，否则不得把 H0/build 作为可审计完成项。

- `nrfjprog --ids` 可见 1 块 DK；具体 DK serial 只写入 internal H0 raw log，不进入公开材料；
- macOS 已能枚举 J-Link/CDC 串口，例如 `/dev/tty.usbmodem...` 与 `/dev/cu.usbmodem...`；
- 本机存在 NCS v3.2.1，Nordic toolchain bundle `322ac893fe` 可用；
- `west --version` 可执行，版本为 `1.4.0`；
- board target 已确认为 `nrf5340dk/nrf5340/cpuapp`；
- Zephyr Bluetooth observer sample 已 build 成功，并生成 `merged.hex`。

归档要求：

- H0 不可只写“已验证”，必须记录脱敏命令输出；
- build 不可只写“成功”，必须记录 build 命令、是否使用 sysbuild、app/net core 镜像产物和 build log 路径；
- flash 不可因为 build 成功而自动执行，仍需单独人工授权。

已执行事项：

- flash DK：已在人工明确授权后执行，并记录 build/flash 证据；
- H1/H2 真实扫描采集：已使用 DK scanner 固件采集并生成内部与公开脱敏统计；
- H3 第二设备 trace：已新增 iPhone 6s 受控窗口，人工按提示完成设备状态切换。

仍未执行的事项：

- H4 真实栈 fallback 运行日志：可作为 Q1/返修增强；
- H7 CPU/PPK2 趋势：需要额外人工授权和接线/功耗设备；
- 投稿口径最终确认与导出 gate：仍需人工确认目标期刊和最终稿件版本。

## 1. 实验分层

### 1.1 最低可行版（1 块 nRF5340 DK + 1 台手机）

这一层的目标是补一条真实 trace sanity check：

- [x] [Agent] nRF5340 DK 工具链可用；
- [x] [Agent，需人工授权 flash] DK 跑 BLE observer/scanner，能记录 advertising 地址、地址类型、RSSI 和时间戳；
- [x] [Agent + 人工] 在至少两个受控 BLE 设备开启窗口中，观察 private/random 地址值是否在短窗口内重复出现，并用 off 窗口评估背景误归因；
- [x] [Agent] 形成 `real_trace_repeatability.csv` 和一张重复性统计表；
- [ ] [Agent 建议 + 人工确认] 论文只增加“真实地址流 sanity check”，不改 headline 仿真结论。

最低版对应 **M13-A：投稿前可选 sanity check**。若 1 天内完成且结果清楚，可进入 Discussion/Evaluation 的半页小节；若失败或结论含糊，不影响 Q2 投稿。

### 1.2 增强版（1 块 DK + 2-3 个真实 BLE 设备）

这一层用于提高审稿说服力：

- [x] [人工准备 + Agent 记录] 使用 2 个不同设备：Redmi K80 与 iPhone 6s；
- [x] [Agent + 人工] 每个设备单独开启，采集独立控制窗口；
- [x] [Agent] 对比不同设备的 RPA/private address 重复率、重复间隔和 RSSI 分布；
- [x] [Agent] 本轮未出现需标记为 negative/unsupported 的设备；归因仍按 partial/likely 记录，不写 IRK ground truth。

### 1.3 Q1 版（真实栈路径 + trace replay）

这一层对应 M11 follow-up 的 J2a/J2b：

- [x] [Agent] J2a：确认真实 host stack 存在 IRK fallback/code path，例如 Zephyr `bt_keys_find_irk()` 相关路径；
- [x] [Agent + 人工] J2b：给出带 ground-truth 或受控窗口标签的真实 private-address repeatability 统计；
- [x] [Agent] H5：将真实 trace 转为 simulator replay 输入，检查 path-count 与 P3 assumptions 是否一致；
- [ ] [Agent 建议 + 人工确认] 只声明机制存在性和分布事实，不声明真实部署性能。

Q1 版对应 **M13-B：返修/Q1 增强包**。H4 运行日志、H5 replay、H6 privacy observability 和 H7 CPU/PPK2 不作为首投前硬门槛。

## 2. 设备与环境

### 2.1 必需硬件

| 设备 | 用途 | 是否必须 |
| --- | --- | --- |
| nRF5340 DK | BLE passive scanner / observer | 必须 |
| USB 数据线 | 供电、烧录、串口日志 | 必须 |
| 一台手机 | 真实 BLE 广播源；可用系统蓝牙或 nRF Connect mobile app | 必须 |
| 另一台手机/手表/耳机/标签 | 增强多设备证据 | 可选 |
| PPK2 | 功耗趋势实验 | 可选，不建议作为当前主线 |

### 2.2 软件环境

| 工具 | 用途 | 验收 |
| --- | --- | --- |
| `nrfjprog` | 确认 DK/J-Link 可见 | `nrfjprog --ids` 返回 DK serial |
| NCS/Zephyr `west` | 编译 observer sample；授权后烧录 | `west --version` 可执行 |
| 串口工具 | 收集 scan log | `minicom`、`screen`、`picocom` 或 VS Code Serial Monitor 均可 |
| Python/pandas | 解析 CSV、生成统计表 | 能运行后续分析脚本 |

> 备注：NCS/Zephyr 版本不同会影响 board name。优先在 NCS/Zephyr workspace 内运行 `west boards | rg nrf5340dk`；不要在论文仓库根目录直接运行 `west boards`，否则可能因不在 west workspace 中而误判工具链不可用。常见写法包括 `nrf5340dk/nrf5340/cpuapp` 或旧式 `nrf5340dk_nrf5340_cpuapp`。

### 2.3 nRF5340 DK 双核注意事项

nRF5340 DK 是双核 SoC，本实验必须显式区分两层：

| 核 | 典型 target/镜像 | 在本实验中的角色 |
| --- | --- | --- |
| Application core | `nrf5340dk/nrf5340/cpuapp` | 跑 Zephyr Host、observer/scanner application、日志输出和实验控制逻辑 |
| Network core | `nrf5340dk/nrf5340/cpunet` 或 child image | 跑 BLE Controller/radio 相关固件，例如 controller 或 `hci_rpmsg` 类镜像 |

执行规则：

- 只 build `cpuapp` 不一定保证 BLE radio 可用；必须确认 build 是否同时生成/包含 network core controller image；
- NCS v3.x 下优先尝试 sysbuild 路径，例如 `west build --sysbuild -b nrf5340dk/nrf5340/cpuapp ...`，但以本地 sample 实际支持为准；
- 若使用非 sysbuild/child-image 路径，必须记录 network core 当前固件状态，避免 app core 已更新但 network core 不兼容；
- flash 可能覆盖 app core 和/或 network core 当前固件，因此仍属于人工授权 gate；
- H1/H2 若烧录后没有扫描日志，优先检查 network core controller image 是否已正确构建和烧录，而不是直接判定 scanner 代码失败。

network core 确认顺序：

1. build observer 后先检查产物和配置：

```bash
find build_m13_observer \( -name '*.hex' -o -name '*.elf' -o -name '*.bin' \) -print
find build_m13_observer -path '*/zephyr/.config' -print
rg -n "SB_CONFIG_NETCORE_HCI_IPC|CONFIG_BT_HCI_IPC|hci_ipc|cpunet" build_m13_observer
```

2. 若 build 中已有 `hci_ipc`/`cpunet`/controller 相关镜像，记录镜像路径，后续 flash 授权时按 build 系统生成的 merged/domain 规则烧录。
3. 若 build 只有 app core 镜像，但 app 配置中出现 `CONFIG_BT_HCI_IPC=y`，说明 app 需要 network core 侧 HCI IPC/controller 配合。此时必须选择并记录以下三种处理之一：
   - 已确认 DK 的 network core 预装/保留了兼容 HCI IPC/controller 固件，记录确认来源；
   - 先 build network core 固件，例如 Zephyr `samples/bluetooth/hci_ipc` 或本地 NCS 推荐的 `nrf/applications/ipc_radio`，并在人工授权后先烧录 cpunet，再烧录 app core；
   - 无法确认 network core 状态，则停止 H1/H2，报告为 `NETCORE_UNVERIFIED`，不得把 scanner 失败写成实验阴性结果。

## 3. 数据目录与命名

建议新增如下结构：

```text
docs/m13-hardware-validation/
  01_nrf5340dk_hardware_experiment_plan.md
  reports/
    hardware_validation_report.md
    agent_run_log.md
  scripts/
    parse_scan_log.py
    analyze_repeatability.py
    anonymize_trace.py
    replay_real_trace.py
  data/
    raw/
      h0_toolchain_YYYYMMDD.txt
      h1_background_scan_YYYYMMDD.csv
      h2_deviceA_on_YYYYMMDD.csv
      h2_deviceA_off_YYYYMMDD.csv
      h2_deviceB_on_YYYYMMDD.csv
    processed/
      real_trace_repeatability.csv
      real_trace_window_summary.csv
      real_trace_random_private_candidates.csv
      real_trace_repeatability_public.csv
    figures/
      fig_real_trace_repeat_counts.svg
      fig_real_trace_interarrival.svg
      fig_real_trace_rssi_windows.svg
```

CSV 文件统一使用 UTF-8，无 BOM。所有原始日志不手改；处理脚本只读 `data/raw/`，输出 `data/processed/`。

> 当前文档只定义这些脚本的职责。若仓库尚无对应脚本，H5 不得标记完成。

## 4. 统一日志字段

scanner 固件或串口转换脚本应尽量输出以下字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `run_id` | string | 实验段编号，如 `H1_background_01`、`H2_phoneA_on_01` |
| `timestamp_ms` | int | DK 启动后的毫秒时间戳 |
| `wall_time_iso` | string | 可选，电脑侧接收日志时间 |
| `addr` | string | BLE 广播地址，规范化为 `AA:BB:CC:DD:EE:FF` |
| `addr_type` | string/int | public/random/RPA/NRPA 等；若 Zephyr 只给 type，则保留原值 |
| `is_random` | bool | 是否 random address |
| `is_rpa_candidate` | bool | 是否符合 RPA bit pattern；优先用 Zephyr helper 或后处理统一判断 |
| `rssi_dbm` | int | RSSI |
| `adv_type` | string/int | advertising event type |
| `payload_len` | int | 广播 payload 长度 |
| `label` | string | `background`、`device_on`、`device_off`、`unknown_ambient` |
| `controlled_device` | string | 控制设备名，如 `phone_A`；未知则空 |
| `distance_m` | float | 设备到 DK 大致距离 |
| `notes` | string | 屏幕状态、App 状态、是否配对、是否飞行模式等 |

### 4.1 RPA candidate 判定

优先级：

1. 若 Zephyr/host API 提供 `bt_addr_le_is_rpa()` 等 helper，直接使用 helper 的结果；
2. 否则在后处理脚本中按 Bluetooth random private address bit pattern 判断；
3. 若地址显示字节序不确定，不硬判定，只保留 `random_private_candidate` 并在报告中说明。

红线：不要把所有 random address 都写成 RPA；无法确认时写 `random/private-address candidate`。

### 4.2 数据脱敏与公开边界

原始 BLE 地址、DK serial、精确地点、精确采集时间、手机型号完整串号均按 internal data 处理。

公开或投稿材料只能包含：

- 聚合统计，例如 event count、candidate count、repeat fraction、interarrival 分位数；
- hash 后地址标识，例如 `addr_hash = sha256(salt + addr)[:10]`；
- 模糊地点，例如 `office/lab environment`，不写详细地址；
- 模糊时间，例如日期或上午/下午，不写精确墙钟时间；
- DK serial 写成 `one nRF5340 DK`，不公开设备序列号。

禁止进入公开包：

- raw scan CSV；
- 未 hash 的 BLE address；
- DK serial/J-Link ID；
- `/Users/...` 本地路径；
- 手机账号、截图、联系人、蓝牙设备真实名称中可识别个人的信息。

## 5. 实验 H0：工具链与板卡可用性

### 5.1 目的

关闭 M2 记录中遗留的 DK 工具链阻塞：之前 `nrfjprog --ids` 未返回 DK ID，`west` 不可用。

### 5.2 步骤

1. 连接 nRF5340 DK，确认供电和 USB 数据口。
2. 在仓库根目录创建本轮目录：

```bash
mkdir -p docs/m13-hardware-validation/data/raw \
         docs/m13-hardware-validation/data/processed \
         docs/m13-hardware-validation/reports
```

3. 在任意目录先确认 J-Link/DK 可见：

```bash
nrfjprog --ids
```

4. 切到 NCS/Zephyr workspace 后再运行 `west` 扩展命令。不要在论文仓库根目录直接运行 `west boards`：

```bash
cd <NCS_OR_ZEPHYR_WORKSPACE>/zephyr
west --version
west boards | rg nrf5340
```

5. 记录输出到 `data/raw/h0_toolchain_YYYYMMDD.txt`。Agent 直接保存终端输出，不用截图代替文本记录。
6. 若 `west --version` 可用但 `west boards` 失败，先确认是否在 NCS/Zephyr workspace 内；只有在 workspace 内仍失败，才判定 H0 不通过。
7. 若 `west` 不可用，先只完成 H0 环境报告，不进入 H1/H2。

### 5.3 验收

- [x] `nrfjprog --ids` 返回至少一个 serial；
- [x] `west --version` 可执行；
- [x] 在 NCS/Zephyr workspace 中找到正确 board name；
- [x] 记录 NCS/Zephyr 版本、host OS、日期和 DK serial。

### 5.4 失败处理

若 H0 失败，论文不增加硬件结果；只保留当前 simulation-supported 定位。报告中写明“DK environment was unavailable; hardware validation deferred”。

### 5.5 Agent 记录模板

将以下内容写入 `reports/agent_run_log.md`：

```markdown
## H0 Toolchain
- Date:
- Executor: agent
- Host OS:
- DK connected: yes/no
- `nrfjprog --ids` result:
- NCS/Zephyr workspace:
- west command cwd:
- `west --version` result:
- board name selected:
- Decision: GO / STOP

## Build Evidence
- sample path:
- build dir:
- build command:
- sysbuild used: yes/no
- app core image:
- network core/controller image:
- merged hex:
- build log path:
- flash command: not executed / <command after human authorization>
- flash result: not executed / success / failed
```

### 5.6 编译 observer sample 的 Agent 步骤（默认不烧录）

若 H0 中 `west` 和 board name 均可用，再执行本步骤。以下命令在 NCS/Zephyr workspace 中执行，不是在本论文仓库中执行。默认动作只到 build，不自动 flash。

```bash
cd <NCS_OR_ZEPHYR_WORKSPACE>/zephyr
west build --sysbuild -b <BOARD_NAME> samples/bluetooth/observer -d build_m13_observer
```

示例 board name 以 H0 的 `west boards | rg nrf5340` 输出为准，例如：

```bash
west build --sysbuild -b nrf5340dk/nrf5340/cpuapp samples/bluetooth/observer -d build_m13_observer
```

build 完成后，Agent 必须先检查产物，不得只看 `merged.hex` 是否存在：

```bash
find build_m13_observer \( -name '*.hex' -o -name '*.elf' -o -name '*.bin' \) -print
find build_m13_observer -path '*/zephyr/.config' -print
rg -n "SB_CONFIG_NETCORE_HCI_IPC|CONFIG_BT_HCI_IPC|hci_ipc|cpunet" build_m13_observer
```

判定规则：

- 若同时看到 app core 与 cpunet/controller 相关镜像，记录路径；
- 若只看到 app core 镜像，但配置显示 `CONFIG_BT_HCI_IPC=y`，不得直接假设 BLE radio 可用，必须进入 network core 确认分支；
- 若无法解释产物结构，先停止在 build 阶段，不进入 flash。

如果本地 NCS/Zephyr workspace 不支持 `--sysbuild`，允许退回本地 sample 文档要求的 child-image 或 legacy build 命令，但必须在 `agent_run_log.md` 写清楚：

- 为什么没有使用 sysbuild；
- network core controller image 是否由 child image 自动构建；
- build 产物中是否存在 app core 与 network core 相关 hex/elf；
- 若只生成 app core 镜像，当前 network core 固件如何确认可用。

### 5.7 network core 确认分支（仅在需要时执行）

如果 5.6 只生成 app core 镜像，而 app 侧使用 HCI IPC，Agent 必须先完成以下三选一：

1. **记录已知可用的 cpunet 固件**：例如 DK 当前 network core 已由同版本 NCS 的 HCI IPC/controller 固件烧录，且来源可追溯。
2. **build cpunet HCI IPC/controller 固件**：优先按本地 NCS/Zephyr 文档选择 `zephyr/samples/bluetooth/hci_ipc` 或 `nrf/applications/ipc_radio`。常见 Zephyr fallback 命令：

```bash
cd <NCS_OR_ZEPHYR_WORKSPACE>/zephyr
west build -p always -b nrf5340dk/nrf5340/cpunet \
  samples/bluetooth/hci_ipc -d build_m13_hci_ipc_cpunet
```

3. **无法确认则停止**：在 `agent_run_log.md` 写 `NETCORE_UNVERIFIED`，不进入 H1/H2，不把后续无扫描日志解释为设备或算法阴性。

### 5.8 flash gate 与串口确认

人工明确授权前，Agent 只能 build、检查产物和写日志，不得执行 flash。授权后按 5.6/5.7 的判定选择一种路径：

| 场景 | flash 命令口径 |
| --- | --- |
| app core 镜像可用，且 cpunet 固件已确认兼容 | `west flash -d build_m13_observer` |
| 需要先烧录独立 cpunet HCI IPC/controller 固件 | 先 `west flash -d build_m13_hci_ipc_cpunet`，再 `west flash -d build_m13_observer` |
| sysbuild/domain 统一生成可烧录 merged/domain 产物 | 按本地 build 系统给出的 domain/merged flash 命令执行，并记录 domain 与 hex 路径 |

flash 后打开串口，至少确认能看到 observer/scanner 类日志。若原始 sample 不输出 CSV，也可以先保留原生日志；H1/H2 正式采集前再改 scanner callback 或用 `parse_scan_log.py` 转换。

Agent 必须记录：

- NCS/Zephyr workspace 路径；
- board name；
- 是否使用 sysbuild；
- build 命令；
- app core 镜像产物；
- network core / controller 镜像产物，若无则记录原因；
- flash 命令（仅在人工授权并实际执行后填写）；
- build 是否成功；
- flash 是否成功（未授权/未执行时写 `not executed`）；
- 串口设备名，例如 `/dev/tty.usbmodem...`。

## 6. 实验 H1：被动背景扫描

### 6.1 目的

记录真实环境中的 BLE advertising 地址流，建立 background baseline。

### 6.2 固件

使用 Zephyr Bluetooth observer sample，或最小 scanner 程序。需要在 scan callback 中输出 CSV 行。

伪代码：

```c
on_scan_recv(info, ad) {
    addr = format(info->addr);
    ts = k_uptime_get_32();
    rpa = is_rpa_candidate(info->addr);
    printk("SCAN,%u,%s,%d,%d,%d,%u\n",
           ts, addr, info->addr->type, rpa, info->rssi, info->adv_type);
}
```

建议先用现成 observer sample 跑通，再改日志格式。

### 6.2.1 串口采集方式

Agent 优先使用命令行或可保存文本的串口方式，必须产出 raw log 文件。

macOS 常用检查：

```bash
ls /dev/tty.usbmodem* /dev/tty.usbserial*
```

方式 A：VS Code Serial Monitor / nRF Connect for Desktop

- 波特率按 sample 配置选择，常见为 `115200`；
- 开始采集前清空窗口；
- 采集结束后保存为 `data/raw/<run_id>_YYYYMMDD.log` 或 `.csv`。

方式 B：命令行串口工具

```bash
screen /dev/tty.usbmodemXXXX 115200
```

若使用 `screen`，Agent 需把终端输出保存到 raw log；若使用 `picocom`/`minicom`，优先开启日志文件功能。采集完成后用：

```bash
wc -l docs/m13-hardware-validation/data/raw/<file>
```

记录原始日志行数。

### 6.3 执行

1. 放置 DK 在固定位置，距离大型金属/电脑主机至少 0.5 m。
2. 不主动打开测试设备，仅记录环境背景 10-15 分钟。
3. 保存为 `data/raw/h1_background_scan_YYYYMMDD.csv`。
4. 重复 2 次，最好在不同时间段采集。

Agent 执行细化：

1. 开始前在 `agent_run_log.md` 写下房间、DK 位置、周围已知 BLE 设备；
2. 打开串口工具并确认每行日志持续输出；
3. 采集开始时写一行 marker，例如 `# H1_background_01 start 2026-..` 到运行日志；
4. 采集期间请人工不要移动 DK，不要打开测试手机的 BLE advertiser；
5. 采集结束后立即记录文件名、开始/结束时间、文件行数；
6. 若日志不是 CSV，而是 Zephyr 原生日志，保存在 raw 中，后续用 `parse_scan_log.py` 转换。

### 6.4 记录

实验记录表：

| 项 | 内容 |
| --- | --- |
| 日期/时间 |  |
| 地点 |  |
| DK serial |  |
| scan duration |  |
| scan interval/window |  |
| 周围已知 BLE 设备 |  |
| 是否有手机/耳机主动测试 | 否 |

### 6.5 分析

对每个地址统计：

- `seen_count`；
- `first_seen_ms`、`last_seen_ms`；
- `interarrival_ms_mean`、`interarrival_ms_min`、`interarrival_ms_p50`；
- 是否在 `W=60s` 内出现 `D(rv)>=2`；
- 是否在 `W=120s` 内出现 `D(rv)>=2`；
- RSSI 均值和标准差。

### 6.6 论文用途

背景扫描只作为环境描述，不能直接证明合法 bonded 设备重复性。可用于说明真实环境中 random/private-address candidates 的规模、RSSI 范围和重复分布。

## 7. 实验 H2：单设备受控重复性 trace

### 7.1 目的

这是当前最重要的硬件实验。目标是在真实 BLE 广播源上观察：同一个可见 private/random address value 是否会在短窗口内重复出现，从而支持 P3-Persist 使用 visible-value repetition 作为 privacy-admissible signal。

### 7.2 是否需要多个设备

不需要。最低配置是：

- 1 块 nRF5340 DK 做 scanner；
- 1 台手机或其他 BLE 设备做 controlled advertising source。

多个设备只提高外部有效性，不是执行前提。

### 7.3 推荐设备选择

优先级从高到低：

1. 手机 + nRF Connect mobile app advertiser；
2. 手机系统蓝牙处于可发现/配对/附近共享相关状态；
3. 手表/耳机/标签进入配对或广播状态；
4. 平板/另一台手机；
5. 其他 BLE beacon。

注意：部分手机 App 可能使用 non-resolvable private address 或 static random address，而非严格 RPA。报告必须如实区分。

### 7.4 控制窗口设计

每个设备执行以下窗口：

| 窗口 | 时长 | 设备状态 | 目的 |
| --- | --- | --- | --- |
| `off_1` | 5 min | 测试设备关闭蓝牙或远离 | 背景对照 |
| `on_1` | 20 min | 测试设备靠近 DK，开启 BLE advertising/配对/可发现 | 观察重复地址 |
| `off_2` | 5 min | 再次关闭/远离 | 确认高 RSSI 地址消失 |
| `on_2` | 20 min | 再次开启 | 观察是否出现新地址 epoch 和重复 |

如果时间足够，每台设备做 3 个 `on` 窗口。

最低验收要求是 **两个独立 `on` 窗口**。只做一个 `on` 窗口只能算 pilot，不得写入正文。

### 7.5 实施步骤

1. DK 开始扫描，保存串口日志；
2. 记录 `off_1` 起止时间；
3. 将手机放在 DK 0.5-1 m 内；
4. 开启 BLE advertising 或进入配对/可发现状态；
5. 记录 `on_1` 起止时间、手机型号、系统版本、App 名称、是否已配对、屏幕状态；
6. 关闭蓝牙或将设备移到 8-10 m 外，记录 `off_2`；
7. 重复 `on_2`；
8. 保存原始 CSV。

Agent 执行细化：

1. 每个窗口开始前，在 `agent_run_log.md` 写：
   - window id；
   - executor: agent；
   - human operator（若有人操作手机/设备）；
   - 手机/设备型号；
   - 蓝牙状态；
   - App 名称和 advertising 设置；
   - 设备到 DK 距离；
   - 屏幕状态；
2. Agent 发出窗口切换提示；人工按提示操作手机/设备；
3. `off` 窗口要求人工关闭手机蓝牙或将设备移动到 8-10 m 外；只锁屏不算 off；
4. `on` 窗口要求人工把设备固定在 0.5-1 m，不要边走边测；
5. Agent 负责计时、串口采集、保存 raw log 和窗口记录；
6. 每个窗口结束后 Agent 记录异常，例如手机自动息屏、App 停止广播、串口断开；
7. 不要在采集期间手工删除或合并日志行。

人工参与点：

- 按 Agent 提示开/关手机蓝牙或 BLE advertiser；
- 按 Agent 提示把设备拿近 DK 或拿远；
- 告知 Agent 手机/设备型号、App 名称、是否配对、屏幕状态；
- 采集期间尽量不要移动 DK 或测试设备。

### 7.6 Ground truth 标签

只有 1 块 DK 时，不一定能拿到 IRK 级 ground truth。可采用“受控窗口标签”：

- 若某个高 RSSI address 只在 `device_on` 窗口出现，且 `device_off` 后消失，可标为 `controlled_device_likely`；
- 若不能区分，则标为 `unknown_ambient`；
- 不把 `controlled_device_likely` 写成“已密码学确认 bonded identity”。

强 ground truth 需要额外条件：

- 设备与测试 host 已配对并能导出/确认 IRK；
- 或设备日志能标注自身 RPA；
- 或使用第二块可编程 BLE 板作为 advertiser。

### 7.7 分析指标

核心表 `real_trace_repeatability.csv`：

| 指标 | 说明 |
| --- | --- |
| `device_label` | `phone_A`、`watch_B` 等 |
| `window_id` | `on_1`、`on_2` |
| `candidate_addr_count` | 窗口内 random/private candidates 数量 |
| `repeat_addr_count` | 出现次数 >= 2 的地址数 |
| `repeat_fraction` | `repeat_addr_count / candidate_addr_count` |
| `event_repeat_fraction` | 落在重复地址上的 event 占比 |
| `median_interarrival_s` | 同一地址重复出现的中位间隔 |
| `p95_interarrival_s` | 同一地址重复出现的 95 分位间隔 |
| `window_repeat_ge2_W60` | 60s 窗口内 `D(rv)>=2` 的地址数 |
| `window_repeat_ge2_W120` | 120s 窗口内 `D(rv)>=2` 的地址数 |
| `rssi_mean_dbm` | RSSI 均值 |
| `rssi_std_db` | RSSI 标准差 |

### 7.8 验收标准

通过条件：

- [x] 至少两个独立 controlled-on 窗口完成，每个窗口有效时长不少于 15 min；
- [x] 至少两个 controlled-on 窗口内均观察到 private/random address candidate 重复出现；
- [x] 至少一个 candidate 在 `W=60s` 内满足 `D(rv)>=2`，并报告 `W=120s` 对照；
- [x] on/off 差异评估完成：分离只部分成立；整体 attribution 不写成充分证明，仅把 on-only、repeated、高 RSSI candidate 标为 controlled-device-likely；
- [x] 报告 `repeat_addr_count`、`repeat_fraction`、`event_repeat_fraction`、`median_interarrival_s` 和 `p95_interarrival_s`；
- [x] 重复间隔落在合理 advertising/private-address observation 范围内；
- [x] 报告明确区分 RPA、random private candidate、unknown ambient；
- [x] 结论写成“supports the repeated-visible-value assumption in a controlled trace”，不写成全面真实部署证明。

降级通过条件：

- [ ] 只有一个窗口观察到重复，或 on/off 归因不够清楚；
- [ ] 可作为 internal pilot，不进入正文；
- [ ] 报告建议换设备、延长窗口或借第二块可编程 BLE 板。

未通过也有价值：

- 若手机不产生可识别 RPA/private repeat，报告为 negative trace；
- 论文不加入硬件支持句，只保留 limitation；
- 后续换设备或借第二块 BLE 板。

### 7.9 Agent 数据检查口径

Agent 交付 H2 时必须同时提交三张表：

1. `real_trace_window_summary.csv`：每个窗口一行，含 `window_id/start/end/duration/event_count/candidate_count/high_rssi_candidate_count`；
2. `real_trace_repeatability.csv`：每个设备窗口一行，含第 7.7 节核心指标；
3. `real_trace_random_private_candidates.csv`：每个 random-address/RPA-bit-pattern candidate address/hash 一行，含 seen count、first/last seen、RSSI、是否出现在 off 窗口。该表不表示每行均为密码学确认的 RPA。

负责人只看这三张表即可初判是否值得写入论文。

## 8. 实验 H3：多设备受控 trace（可选增强）

### 8.1 目的

降低单设备偶然性，证明 repeatability 不是某个手机/某个 App 的特例。

### 8.2 执行

对每个设备重复 H2 的 `off/on/off/on` 窗口。推荐最少 3 类设备：

- 手机；
- 可穿戴或耳机；
- BLE 标签/信标。

每个设备单独开启，不要多个设备同时靠近 DK，否则 ground-truth 标签会变弱。

### 8.3 论文用途

如果 2-3 个设备均有重复 private/random address candidates，可在论文新增一张小表：

| Device class | Trace duration | Candidate addresses | Repeated candidates | Median repeat interval | Note |
| --- | ---: | ---: | ---: | ---: | --- |

表题应写为 “Controlled BLE private-address trace sanity check”，不要写 “hardware performance evaluation”。

## 9. 实验 H4：真实栈 fallback/code-path 存在性

### 9.1 目的

回应审稿人可能提出的问题：simulator 假设 controller resolving-list miss 后 host 需要 IRK fallback，这在真实栈中是否存在？

### 9.2 低成本版本：源码与配置证据

不需要第二块 DK，先做静态证据。此项是当前 M13 推荐优先完成的 H4 版本：

1. 记录 Zephyr/NCS 中 host key lookup / IRK resolving 相关源码路径；
2. 记录 `CONFIG_BT_CTLR_RL_SIZE`、`CONFIG_BT_MAX_PAIRED` 等 Kconfig 范围；
3. 说明 `host paired identities > controller RL capacity` 时，存在 host-side fallback pressure；
4. 引用当前论文已有 model-to-stack mapping。

### 9.3 中成本版本：调试日志存在性

若能配对多个设备，开启 Zephyr Bluetooth debug log，构造 RL 容量小于 bonded peers 的配置。此项属于 Q1/返修增强，不作为投稿前 M13-A 硬门槛：

```text
CONFIG_BT=y
CONFIG_BT_OBSERVER=y
CONFIG_BT_CENTRAL=y
CONFIG_BT_SMP=y
CONFIG_BT_SETTINGS=y
CONFIG_BT_MAX_PAIRED=16
CONFIG_BT_CTLR_RL_SIZE=8
```

执行：

1. 与超过 8 个 peer 建立或导入 bond；
2. 限制 controller RL capacity；
3. 触发 advertising scan；
4. 记录 host fallback/key lookup 相关日志。

只有一块 DK 时，这一步通常需要手机/多个 BLE 设备配合，或先不做。

### 9.4 验收

- [x] 给出源码路径和 Kconfig 截图/日志；
- [ ] 若有运行日志，标注为 “mechanism existence, not performance”；
- [x] 不声称已完成 P3 固件实现。

## 10. 实验 H5：真实 trace replay 到 simulator

### 10.1 当前可行性说明

当前 simulator 主要生成合成事件；本轮已新增真实 BLE scan CSV 的 replay shim。H5 结果仅用于 path-count 语义 sanity check，不能替代主仿真或真实固件部署性能测量。

H5 完成前必须具备三个脚本：

| 脚本 | 输入 | 输出 | 完成条件 |
| --- | --- | --- | --- |
| `parse_scan_log.py` | raw 串口日志 | 标准 scan CSV | 字段符合第 4 节 |
| `analyze_repeatability.py` | 标准 scan CSV + window log | processed repeatability tables | 能复现 H2 指标 |
| `replay_real_trace.py` | processed trace | simulator replay summary/path counts | 输出 cache/RL/budget/reserve path counts |

本轮已生成 `replay_real_trace.py` 和 path-count summary，因此 H5 可作为完成项记录。正文仍不得写 “trace replay validated”，只能写 controlled trace replay sanity check。

### 10.1.1 本轮 H5 执行结果

- replay 脚本：`docs/m13-hardware-validation/scripts/replay_real_trace.py`；
- internal replay input：`docs/m13-hardware-validation/data/processed/real_trace_replay_input.csv`；
- internal replay decisions：`docs/m13-hardware-validation/data/processed/real_trace_replay_decisions.csv`；
- public path-count summary：`docs/m13-hardware-validation/data/processed/real_trace_replay_path_counts_public.csv`；
- replay events：82,229；
- controlled-device-likely candidate addresses：21；
- `D(rv)>=2` within W=60 s：70 个 candidate addresses，其中 21 个为 controlled-device-likely，49 个为 ambient/unknown；
- public summary 不含明文 BLE address、DK serial 或本机路径；
- 解释边界：只使用受控窗口标签和 RSSI/重复性规则生成 `legit_candidate`，没有 IRK identity ground truth。

### 10.1.2 H5 robustness sweep

本轮进一步对 H5 replay 做参数扫描，避免只报告单点参数：

- sweep 脚本：`docs/m13-hardware-validation/scripts/sweep_replay_params.py`；
- public sweep table：`docs/m13-hardware-validation/data/processed/real_trace_replay_robustness_public.csv`；
- public summary table：`docs/m13-hardware-validation/data/processed/real_trace_replay_robustness_summary_public.csv`；
- 参数网格：RL capacity 0/4/8，budget per 60 s window 50/100/200，duplicate-filter window 0.1/0.2/0.5/1.0 s，legit RSSI threshold -90/-85/-80/-75 dBm；
- 完成配置数：144；
- legit non-budget-skip fraction：min 0.962990，median 0.988045，max 0.999776；
- legit resolution-path fraction：min 0.959112，median 0.978766，max 0.999776；
- ambient budget-skip fraction：min 0.154468，median 0.556061，max 0.885323；
- public robustness tables 不含明文 BLE address、DK serial 或本机路径。

### 10.2 目的

把 H1/H2 的真实地址流转成 simulator 可读 workload，检查 P3-Persist 的 `D(rv)`、reserve、budget skip 等机制在真实 trace 上是否语义正常。

### 10.3 输入转换

从 raw scan CSV 生成 replay CSV：

| 字段 | 来源 |
| --- | --- |
| `timestamp_s` | `timestamp_ms / 1000` |
| `rpa_value` | `addr` |
| `source_type` | controlled window 可标 `legit_candidate`；未知环境标 `unknown` |
| `rssi_dbm` | scan log |
| `is_attack` | 真实 trace 默认 false；synthetic attack 另行生成 |
| `run_id` | 原始 run |

### 10.4 分析

运行 simulator replay/shim 后输出：

- cache hit count；
- RL hit/miss；
- host fallback attempts；
- budget skip；
- persistence reserve allow；
- `D(rv)>=k` 命中次数；
- controlled candidates 的服务恢复次数。

### 10.5 论文用途

如果 replay 结果正常，可新增一句：

> A controlled nRF5340 DK trace replay was used only as a sanity check for address-repetition semantics; headline reductions remain from the reproducible simulation campaign.

如果 replay 不稳定，不写入正文，只保留内部报告。

H5 的正文用语必须弱于仿真主结果。它只能说明“真实 trace 上重复性语义和 path-count 统计未与模型假设冲突”，不能说明 P3 在真实设备上达到仿真中的防御比例。

## 11. 实验 H6：privacy observability 黑盒检查（可选）

### 11.1 目的

检查 P3 设计是否可能产生外部可观察 membership oracle。当前没有 P3 固件实现，因此只能做 checklist 或未来实现的测试规范。

### 11.2 检查项

- [ ] budget skip、reserve allow、ordinary no-match 不应产生不同 scan response；
- [ ] 不应发起可被对端区分的 per-address connection attempt；
- [ ] 不应暴露 per-address error code；
- [ ] 日志/telemetry 应 aggregate-only，不暴露具体 RPA 是否 bonded；
- [ ] timing 差异若存在，应在论文中写为 deployment risk。

### 11.3 论文用途

没有真实 P3 固件前，不写成实验结果；可作为 Discussion 中 “production deployment checklist”。

## 12. 实验 H7：CPU/wall-clock/PPK2（可选）

### 12.1 目的

支撑 AES-equivalent work proxy 的合理性，而非替代主实验。

### 12.2 可做项目

| 项 | 方法 | 论文用途 |
| --- | --- | --- |
| AES/IRK lookup wall-clock | 在 host 或 DK 上测固定次数 AES/IRK 解析耗时 | 支撑 AES-equivalent proxy |
| CPU-cycle | 若平台支持 cycle counter，测均值/方差 | supplementary |
| PPK2 current trend | flood-like scan load 下测电流趋势 | 只做趋势，不做核心 claim |

### 12.3 不建议

不建议把 PPK2 功耗作为当前论文主贡献，因为功耗强依赖 radio state、连接状态、log level、firmware 和供电路径，容易引入新审稿风险。

## 13. 分析报告模板

`reports/hardware_validation_report.md` 建议结构：

```markdown
# nRF5340 DK Hardware Validation Report

## 1. Scope
- This report is a sanity check, not a deployment-performance evaluation.

## 2. Hardware And Software
- DK serial:
- NCS/Zephyr version:
- Scanner firmware commit:
- Host OS:

## 3. H0 Toolchain Result

## 4. H1 Background Trace
- duration:
- event count:
- random/private candidate count:
- repeated candidate count:

## 5. H2 Controlled Device Trace
- device model:
- on/off windows:
- repeatability table:

## 6. H4 Stack Fallback Evidence
- source paths:
- config:
- logs if any:

## 7. H5 Replay Result
- path counts:
- observed D(rv)>=k:
- limitations:

## 8. Manuscript Revision Recommendation
- Add / do not add hardware sanity-check subsection.
- Exact claim wording.
- Tables/figures to insert.
```

## 14. 论文修订规则

### 14.1 若 H2/H5 结果为正

可做以下修订：

1. 在 Evaluation 或 Discussion 增加小节：`Real BLE Trace Sanity Check`；
2. 加一张小表，不超过半页；
3. 在 Limitations 中把“真实 trace 未完成”改为“仅完成 controlled trace sanity check，未完成 production deployment”；
4. 默认不改 Abstract；只有 H2/H3 多设备正结果 + H5 replay 稳定时，才可在 Conclusion 末尾加一句 “a controlled BLE trace sanity check supports the visible-address repetition assumption”，不要写 “hardware validated”。

推荐措辞：

```text
We additionally collected a controlled nRF5340 DK passive-scan trace to sanity-check
the visible-address repetition assumption. The trace is not used for headline
performance claims; it only confirms that repeated private-address candidates
occur in controlled real BLE advertising windows.
```

### 14.2 若 H2 没观察到可用重复

论文不应硬加硬件结果。只在内部报告中记录：

- 使用设备；
- 为什么无法确认 RPA；
- 是否可能是设备使用 NRPA/static random；
- 后续需要第二设备或可编程 advertiser。

正文保持当前 simulation-supported 定位。

### 14.3 若 H4 只完成源码证据

写法：

```text
A source-level stack audit confirms that host-side IRK lookup paths exist in
Zephyr-class BLE stacks, but this paper does not claim a measured production
implementation of P3.
```

不要写：

```text
P3 was implemented and validated on nRF5340 DK.
```

除非真的实现了 P3 固件并完成运行验证。

## 15. 执行顺序

### 15.1 一天内最低可行流程

1. H0：工具链和 DK 识别；
2. H1：背景扫描 15 min；
3. H2：手机单设备 `off/on/off/on` trace，约 50 min；若时间允许改为 `off/on/off/on/off/on`；
4. 初步分析 repeat counts；
5. 写 `hardware_validation_report.md`。

一天内流程的论文决策：

- H2 降级通过：可考虑 Discussion 小表，但只能写 repetition/path-count sanity check；
- H2 降级通过：只做 internal pilot；
- H2 negative：不改正文。

### 15.2 两到三天增强流程

1. 完成最低可行流程；
2. 增加 2-3 个设备；
3. 做 H4 源码/Kconfig fallback 记录；
4. 若 replay 脚本已补齐，再做 H5 trace replay；否则只完成 H2/H3/H4；
5. 生成论文候选表/图；
6. 决定是否修订正文。

### 15.3 Q1 冲刺流程

1. H2/H3 多设备 controlled trace；
2. H4 真实栈 fallback 运行日志；
3. H5 trace replay；
4. J1 Prop 5 严格化与真实 trace 互证；
5. J3 R-sweep 与 `r` 根因；
6. 重跑 manuscript number verifier 和导出 QA。

## 16. 风险与规避

| 风险 | 表现 | 处理 |
| --- | --- | --- |
| 手机不产生 RPA | 只看到 static random 或无法分类 | 换设备；改写为 random/private candidate；不硬称 RPA |
| 环境 BLE 太多 | 地址无法归因 | 使用 on/off 窗口、近距离高 RSSI、夜间/空房间采集 |
| 只有一个 DK，无法发攻击流 | 不能 over-the-air unique flood | 攻击仍用 simulator；硬件只验证 legit repeatability |
| `west`/NCS 不可用 | 无法烧录 observer | 先关闭 H0；不影响 Q2 投稿 |
| trace 没有 ground truth IRK | 不能证明 bonded identity | 写 controlled-device likely，不写 cryptographic ground truth |
| 结果为负 | 未观察到重复 | 如实记录，不修正文；换设备或借第二块 BLE 板 |
| H5 replay 脚本缺失 | 有真实 trace 但无法进 simulator path-count | 不勾 H5；先完成脚本，再谈正文 replay |
| raw trace 泄露隐私 | BLE 地址、地点、DK serial 进入公开包 | raw/internal 分离；公开表 hash 地址和聚合统计 |
| 执行者误写硬件验证 | 报告中出现 hardware validated/real deployment | 按第 14 节统一改为 sanity check |

## 17. 验收清单

- [x] [Agent] H0：DK 和工具链可用；
- [x] [Agent] H1：背景扫描 CSV 完成；
- [x] [Agent + 人工] H2：至少 1 个 controlled device trace 完成；
- [x] [Agent + 人工] H2：至少两个 controlled-on 窗口观察到重复；attribution 降级为 partial/likely；
- [x] [Agent] H2：repeatability/window/candidate 三张统计表完成；
- [x] [Agent + 人工] H3：多设备 trace 完成（可选）：Redmi K80 与 iPhone 6s 均完成独立 `off/on/off/on` 窗口，公开表见 `h3_multidevice_repeatability_public.csv`；
- [x] [Agent] H4：Zephyr/stack fallback 源码/Kconfig 证据完成；
- [ ] [Agent + 人工] H4：真实运行日志完成（可选增强）；
- [x] [Agent] H5：replay 脚本存在且 trace replay path-count 完成（Q1 建议）；
- [ ] [Agent] H6：privacy observability checklist 完成（可选）；
- [ ] [Agent + 人工授权] H7：CPU/PPK2 趋势完成（可选）；
- [x] [Agent] raw/internal 与 public/anonymized 数据已分离；
- [x] [Agent] 公开表不含明文 BLE address、DK serial、精确地点和本地路径；
- [x] [Agent] 报告写明哪些结果进入论文、哪些只作为内部记录；
- [ ] [Agent 建议 + 人工确认] 论文修订不使用 `hardware validated`、`real deployment`、`production implementation` 等过度表述；
- [ ] [Agent] 若加入正文，重新导出 DOCX/PDF/TeX 并跑数字/图表 gate。

## 18. Agent 交付流程与人工参与点

本节列出的人工参与点是强制人工动作；未列入人工参与点的准备、采集、分析、脱敏、报告和论文措辞建议，默认由 Agent 执行。

### 18.1 开工前确认

Agent 开始采集前，先确认以下信息：

| 项 | Agent 检查/填写 | 人工确认 |
| --- | --- | --- |
| DK 是否在手边 |  |  |
| USB 数据线是否可传数据 |  |  |
| `nrfjprog --ids` 是否有输出 |  |  |
| `west --version` 是否可用 |  |  |
| board name |  |  |
| 计划使用的测试设备 |  |  |
| 是否允许烧录 DK |  | 必须人工确认 |
| 是否只做 M13-A |  |  |

若 `nrfjprog` 或 `west` 不通过，Agent 只写 H0 失败报告，不进入 H1/H2。

### 18.2 采集当天流程

按以下顺序执行，不要跳步：

1. Agent 创建目录并记录 H0；
2. Agent build observer sample，并记录是否使用 sysbuild、app core/network core 镜像产物；
3. 人工确认允许烧录后，Agent flash observer sample；若 flash 后无扫描日志，优先检查 nRF5340 network core controller image；
4. Agent 打开串口并确认有日志；
5. Agent 做 H1 背景扫描；
6. H2 时 Agent 负责计时与采集，人工按提示完成 `off_1/on_1/off_2/on_2` 设备状态切换；
7. 若时间允许，追加 `off_3/on_3`；
8. Agent 立即备份 raw log；
9. Agent 在 `agent_run_log.md` 写异常和备注。

每个窗口都要有起止时间、设备状态、距离、设备型号和人工操作者。没有窗口记录的 raw log 不进入论文判断。

### 18.3 Agent 分析流程

Agent 按顺序生成：

1. 标准化 scan CSV；
2. `real_trace_window_summary.csv`；
3. `real_trace_repeatability.csv`；
4. `real_trace_random_private_candidates.csv`；
5. `real_trace_repeatability_public.csv`；
6. 可选图：repeat counts、interarrival、RSSI windows。

分析后在 `hardware_validation_report.md` 写一个明确判定：

```text
Decision: ADD_TO_MANUSCRIPT / INTERNAL_ONLY / NEGATIVE_TRACE
Reason:
```

### 18.4 人工验收口径

负责人/用户只按下表决定是否进论文。Agent 可以生成建议判定和证据摘要，但不能替代人工确认投稿口径。

| 判定 | 条件 | 论文动作 |
| --- | --- | --- |
| `ADD_TO_MANUSCRIPT` | H2 repetition sanity check 通过；public 表已脱敏；结论不越界 | Discussion/Evaluation 加小段 sanity-check 说明 |
| `INTERNAL_ONLY` | 只有 pilot 证据、单窗口重复、on/off 不够清楚、或 H5 缺脚本 | 不改正文，只保存报告 |
| `NEGATIVE_TRACE` | 未观察到可用 private/random candidate 重复，或设备行为无法解释 | 不改正文；记录为 negative trace |
| `Q1_FOLLOWUP` | H2/H3 多设备正结果，H4/H5 可继续推进 | 放入 M13-B/Q1 或返修任务 |

### 18.5 最终交付包

Agent 最终至少交付：

- `reports/agent_run_log.md`；
- `reports/hardware_validation_report.md`；
- `data/raw/h0_toolchain_YYYYMMDD.txt`；
- H1/H2 raw logs；
- `data/processed/real_trace_window_summary.csv`；
- `data/processed/real_trace_repeatability.csv`；
- `data/processed/real_trace_random_private_candidates.csv`；
- `data/processed/real_trace_repeatability_public.csv`；
- 若生成图片，则放入 `data/figures/`；
- 一段建议论文措辞，或明确写“不建议进入正文”。

交付包不完整时，不得勾选 M13 完成。
