#!/usr/bin/env python3
"""Build a public-safe hardware-trace evidence package for NT-03."""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import math
import os
import shutil
import statistics
import tempfile
from collections import defaultdict
from pathlib import Path

os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "mplconfig-btky-nt03"))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


REPO = Path(__file__).resolve().parents[4]
M13 = REPO / "docs/m13-hardware-validation"
RAW = M13 / "data/raw"
OUT = Path(__file__).resolve().parent
DATA_OUT = OUT / "data"
SOURCE_PUBLIC = OUT / "source_public_data"
SOURCE_SCRIPTS = OUT / "source_analysis_scripts"
SOURCE_DOCS = OUT / "source_documentation"

WINDOWS = [
    ("android_smartphone", "off_1", RAW / "h2_redmi_k80_off_1_20260606.csv"),
    ("android_smartphone", "on_1", RAW / "h2_redmi_k80_on_1_20260606.csv"),
    ("android_smartphone", "off_2", RAW / "h2_redmi_k80_off_2_20260606.csv"),
    ("android_smartphone", "on_2", RAW / "h2_redmi_k80_on_2_20260606.csv"),
    ("legacy_ios_smartphone", "off_1", RAW / "h3_iphone_6s_off_1_20260606.csv"),
    ("legacy_ios_smartphone", "on_1", RAW / "h3_iphone_6s_on_1_20260606.csv"),
    ("legacy_ios_smartphone", "off_2", RAW / "h3_iphone_6s_off_2_20260606.csv"),
    ("legacy_ios_smartphone", "on_2", RAW / "h3_iphone_6s_on_2_20260606.csv"),
]

PUBLIC_FILES = [
    "data/processed/real_trace_window_summary_public.csv",
    "data/processed/real_trace_repeatability_public.csv",
    "data/processed/real_trace_random_private_candidates_public.csv",
    "data/processed/h3_iphone_6s_window_summary_public.csv",
    "data/processed/h3_iphone_6s_repeatability_public.csv",
    "data/processed/h3_iphone_6s_random_private_candidates_public.csv",
    "data/processed/h3_multidevice_repeatability_public.csv",
    "data/processed/real_trace_replay_path_counts_public.csv",
    "data/processed/real_trace_replay_robustness_public.csv",
    "data/processed/real_trace_replay_robustness_summary_public.csv",
]

SCRIPT_FILES = [
    "scripts/parse_scan_log.py",
    "scripts/analyze_repeatability.py",
    "scripts/anonymize_trace.py",
    "scripts/replay_real_trace.py",
    "scripts/sweep_replay_params.py",
]

DOC_FILES = [
    "01_nrf5340dk_hardware_experiment_plan.md",
    "reports/hardware_validation_report.md",
]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * p)))
    return ordered[index]


def repeats_within(timestamps_ms: list[int], window_s: float) -> bool:
    if len(timestamps_ms) < 2:
        return False
    ordered = sorted(timestamps_ms)
    return any(b - a <= window_s * 1000 for a, b in zip(ordered, ordered[1:]))


def address_hash(salt: str, address: str) -> str:
    return hashlib.sha256((salt + address).encode("utf-8")).hexdigest()[:16]


def scope_rows(rows: list[dict[str, str]], scope: str) -> list[dict[str, str]]:
    if scope == "rpa_bit_pattern":
        return [row for row in rows if row["is_rpa_candidate"] == "1"]
    return [row for row in rows if row["is_random"] == "1" or row["is_rpa_candidate"] == "1"]


def repeatability_row(
    device_class: str,
    window_id: str,
    rows: list[dict[str, str]],
    scope: str,
) -> dict[str, str]:
    selected = scope_rows(rows, scope)
    by_address: dict[str, list[int]] = defaultdict(list)
    for row in selected:
        by_address[row["addr"]].append(int(row["timestamp_ms"]))

    repeated = {address: values for address, values in by_address.items() if len(values) >= 2}
    repeated_events = sum(len(values) for values in repeated.values())
    interarrival_s = [
        (b - a) / 1000.0
        for values in by_address.values()
        for a, b in zip(sorted(values), sorted(values)[1:])
    ]
    addr_count = len(by_address)
    return {
        "device_class": device_class,
        "window_id": window_id,
        "address_scope": scope,
        "event_count": str(len(selected)),
        "observed_address_value_count": str(addr_count),
        "repeated_address_value_count": str(len(repeated)),
        "repeat_fraction": f"{len(repeated) / addr_count:.6f}" if addr_count else "0.000000",
        "event_repeat_fraction": f"{repeated_events / len(selected):.6f}" if selected else "0.000000",
        "repeat_within_60s_address_count": str(sum(repeats_within(values, 60.0) for values in by_address.values())),
        "repeat_within_120s_address_count": str(sum(repeats_within(values, 120.0) for values in by_address.values())),
        "median_interarrival_s": f"{statistics.median(interarrival_s):.3f}" if interarrival_s else "",
        "p95_interarrival_s": f"{percentile(interarrival_s, 0.95):.3f}" if interarrival_s else "",
        "measurement_note": "scanner duplicate filtering disabled during capture",
    }


def duplicate_filter_row(
    device_class: str,
    window_id: str,
    rows: list[dict[str, str]],
    scope: str,
    filter_window_s: float,
) -> dict[str, str]:
    selected = sorted(scope_rows(rows, scope), key=lambda row: int(row["timestamp_ms"]))
    if filter_window_s <= 0:
        retained = len(selected)
    else:
        last_seen: dict[str, int] = {}
        retained = 0
        threshold_ms = filter_window_s * 1000.0
        for row in selected:
            address = row["addr"]
            timestamp = int(row["timestamp_ms"])
            previous = last_seen.get(address)
            if previous is None or timestamp - previous > threshold_ms:
                retained += 1
            last_seen[address] = timestamp
    suppressed = len(selected) - retained
    return {
        "device_class": device_class,
        "window_id": window_id,
        "address_scope": scope,
        "filter_mode": "capture_disabled" if filter_window_s <= 0 else "offline_sliding_window_replay",
        "duplicate_filter_window_s": f"{filter_window_s:.3f}",
        "input_event_count": str(len(selected)),
        "retained_event_count": str(retained),
        "suppressed_event_count": str(suppressed),
        "retained_fraction": f"{retained / len(selected):.6f}" if selected else "0.000000",
        "suppressed_fraction": f"{suppressed / len(selected):.6f}" if selected else "0.000000",
        "interpretation_note": "offline accounting only; not a controller duplicate-filter measurement",
    }


def write_anonymized_trace(salt: str, loaded: dict[tuple[str, str], list[dict[str, str]]]) -> int:
    output_path = DATA_OUT / "controlled_private_address_events_anonymized.csv.gz"
    fieldnames = [
        "device_class",
        "window_id",
        "window_label",
        "timestamp_offset_ms",
        "addr_hash",
        "addr_type",
        "is_random",
        "is_rpa_bit_pattern_candidate",
        "rssi_dbm",
        "adv_type",
        "payload_len",
    ]
    event_count = 0
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as raw_handle:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_handle, mtime=0) as gzip_handle:
            with io.TextIOWrapper(gzip_handle, encoding="utf-8", newline="") as text_handle:
                writer = csv.DictWriter(text_handle, fieldnames=fieldnames, lineterminator="\n")
                writer.writeheader()
                for device_class, window_id, _ in WINDOWS:
                    rows = loaded[(device_class, window_id)]
                    selected = scope_rows(rows, "random_or_rpa_candidate")
                    if not selected:
                        continue
                    first_timestamp = min(int(row["timestamp_ms"]) for row in selected)
                    for row in selected:
                        writer.writerow(
                            {
                                "device_class": device_class,
                                "window_id": window_id,
                                "window_label": "device_on" if window_id.startswith("on") else "device_off",
                                "timestamp_offset_ms": str(int(row["timestamp_ms"]) - first_timestamp),
                                "addr_hash": address_hash(salt, row["addr"]),
                                "addr_type": row["addr_type"],
                                "is_random": row["is_random"],
                                "is_rpa_bit_pattern_candidate": row["is_rpa_candidate"],
                                "rssi_dbm": row["rssi_dbm"],
                                "adv_type": row["adv_type"],
                                "payload_len": row["payload_len"],
                            }
                        )
                        event_count += 1
    return event_count


def copy_sources() -> None:
    for relative in PUBLIC_FILES:
        source = M13 / relative
        destination = SOURCE_PUBLIC / Path(relative).name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    for relative in SCRIPT_FILES:
        source = M13 / relative
        destination = SOURCE_SCRIPTS / Path(relative).name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    for relative in DOC_FILES:
        source = M13 / relative
        destination = SOURCE_DOCS / Path(relative).name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def make_figure(repeat_rows: list[dict[str, str]], filter_rows: list[dict[str, str]]) -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10.5,
            "axes.labelsize": 11.5,
            "axes.titlesize": 11.8,
            "xtick.labelsize": 10.0,
            "ytick.labelsize": 10.0,
            "legend.fontsize": 9.8,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "grid.color": "#D8DEE9",
            "grid.alpha": 0.6,
            "savefig.dpi": 600,
            "svg.fonttype": "none",
            "pdf.fonttype": 42,
        }
    )
    selected_repeat = [row for row in repeat_rows if row["address_scope"] == "random_or_rpa_candidate"]
    labels = [
        f"{'Android' if row['device_class'].startswith('android') else 'Legacy iOS'}\n{row['window_id']}"
        for row in selected_repeat
    ]
    repeat_values = [float(row["repeat_fraction"]) * 100 for row in selected_repeat]

    selected_filter = [
        row
        for row in filter_rows
        if row["address_scope"] == "random_or_rpa_candidate" and row["window_id"].startswith("on")
    ]
    filter_windows = [0.0, 0.2, 1.0, 60.0]
    retained_by_window: list[float] = []
    for window in filter_windows:
        values = [
            float(row["retained_fraction"]) * 100
            for row in selected_filter
            if math.isclose(float(row["duplicate_filter_window_s"]), window)
        ]
        retained_by_window.append(statistics.mean(values))

    fig, axes = plt.subplots(1, 2, figsize=(8.6, 3.8))
    axes[0].bar(range(len(labels)), repeat_values, color=["#0072B2", "#56B4E9", "#009E73", "#66C2A5"])
    axes[0].set_title("Observed private-address value repetition")
    axes[0].set_ylabel("Repeated address values (%)")
    axes[0].set_xticks(range(len(labels)))
    axes[0].set_xticklabels(labels)
    axes[0].tick_params(axis="x", labelsize=9.2)
    axes[0].set_ylim(0, 105)
    axes[0].grid(axis="y")

    filter_labels = ["Disabled\n(capture)", "0.2 s\noffline", "1 s\noffline", "60 s\noffline"]
    axes[1].bar(range(len(filter_labels)), retained_by_window, color=["#4D4D4D", "#E69F00", "#D55E00", "#CC79A7"])
    axes[1].set_title("Duplicate-filter replay over captured events")
    axes[1].set_ylabel("Events retained (%)")
    axes[1].set_xticks(range(len(filter_labels)))
    axes[1].set_xticklabels(filter_labels)
    axes[1].set_ylim(0, 105)
    axes[1].grid(axis="y")
    fig.subplots_adjust(left=0.09, right=0.985, bottom=0.21, top=0.86, wspace=0.30)
    for extension in ("png", "pdf", "svg"):
        fig.savefig(OUT / f"figure_nt03_controlled_trace_evidence.{extension}", dpi=600, bbox_inches="tight")
    plt.close(fig)


def write_provenance() -> None:
    rows: list[dict[str, str]] = []
    for device_class, window_id, path in WINDOWS:
        rows.append(
            {
                "role": "internal_raw_source_not_copied",
                "source_path": str(path.relative_to(REPO)),
                "package_path": "",
                "device_class": device_class,
                "window_id": window_id,
                "sha256": sha256(path),
                "privacy_note": "contains unhashed BLE addresses; retained outside review package",
            }
        )
    copied_groups = [
        (PUBLIC_FILES, SOURCE_PUBLIC, "copied_public_source_data"),
        (SCRIPT_FILES, SOURCE_SCRIPTS, "copied_analysis_script"),
        (DOC_FILES, SOURCE_DOCS, "copied_source_documentation"),
    ]
    for relative_paths, directory, role in copied_groups:
        for relative in relative_paths:
            path = directory / Path(relative).name
            rows.append(
                {
                    "role": role,
                    "source_path": "docs/m13-hardware-validation/" + relative,
                    "package_path": str(path.relative_to(OUT)),
                    "device_class": "",
                    "window_id": "",
                    "sha256": sha256(path),
                    "privacy_note": "public-safe copied artifact",
                }
            )
    write_csv(
        OUT / "provenance_manifest.csv",
        rows,
        ["role", "source_path", "package_path", "device_class", "window_id", "sha256", "privacy_note"],
    )


def write_readme(repeat_rows: list[dict[str, str]], filter_rows: list[dict[str, str]], event_count: int) -> None:
    main_scope = [row for row in repeat_rows if row["address_scope"] == "random_or_rpa_candidate"]
    table_lines = [
        "| 设备类别 | 窗口 | 观测地址值 | 重复地址值 | 重复比例 | 60 s 内重复地址值 | 中位到达间隔 (s) | P95 (s) |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in main_scope:
        table_lines.append(
            f"| {row['device_class']} | {row['window_id']} | {row['observed_address_value_count']} | "
            f"{row['repeated_address_value_count']} | {float(row['repeat_fraction']) * 100:.2f}% | "
            f"{row['repeat_within_60s_address_count']} | {row['median_interarrival_s']} | {row['p95_interarrival_s']} |"
        )

    aggregate_filter: list[str] = []
    for window in [0.0, 0.2, 1.0, 60.0]:
        rows = [
            row
            for row in filter_rows
            if row["address_scope"] == "random_or_rpa_candidate"
            and row["window_id"].startswith("on")
            and math.isclose(float(row["duplicate_filter_window_s"]), window)
        ]
        retained = sum(int(row["retained_event_count"]) for row in rows)
        total = sum(int(row["input_event_count"]) for row in rows)
        aggregate_filter.append(
            f"| {'关闭（采集实测）' if window == 0 else f'{window:g} s（离线重放）'} | {total} | {retained} | {total - retained} | {retained / total * 100:.3f}% |"
        )

    readme = f"""# NT-03 硬件轨迹证据包

## 结论

本证据包复用 `docs/m13-hardware-validation` 中同一项目、同一作者控制下的 nRF5340 DK 被动扫描实验。采集日期为 2026-06-06，扫描器采集时关闭 duplicate filtering；受控设备包括一台 Android smartphone 和一台 legacy iOS smartphone，每台设备均有两个 1200 s 的 `device_on` 窗口及配套 `device_off` 窗口。

这些数据能够支持的结论是：**在真实 BLE 广播窗口中，同一个被观测到的 random/private-address value 会在 60 s 内重复出现**。这些数据不能证明每个候选值都经过 IRK 密码学确认，不能证明真实 RPA epoch 边界，也不能证明 P3 已在硬件上部署。

## 实测重复结果

{chr(10).join(table_lines)}

统计口径为 `is_random=1 OR is_rpa_bit_pattern_candidate=1`。另见 `data/repeatability_summary.csv` 中更严格的 `rpa_bit_pattern` 子集。地址值计数不是身份计数；同一身份在不同地址轮换后会形成不同地址值。

## Duplicate-Filter 对照

| 模式 | 输入事件 | 保留事件 | 抑制事件 | 保留比例 |
| --- | ---: | ---: | ---: | ---: |
{chr(10).join(aggregate_filter)}

`关闭`行来自扫描器实际采集配置。`0.2 s`、`1 s` 和 `60 s` 行是在同一批实测事件上执行的离线 sliding-window duplicate-filter accounting，不是控制器固件实测，因此论文中必须写成 offline replay。

## 数据与可复现性

- `data/controlled_private_address_events_anonymized.csv.gz`：{event_count} 条匿名化 random/private-address candidate 事件，保留窗口内相对时间、地址哈希、RPA 位型标记、RSSI、advertising type 和 payload length。
- `data/repeatability_summary.csv`：四个受控开启窗口的重复统计，分别给出宽口径 candidate 和严格 RPA-bit-pattern candidate。
- `data/duplicate_filter_replay_summary.csv`：关闭采集与三个离线过滤窗口的对照。
- `recompute_public_summaries.py`：只依赖上述匿名化 `.csv.gz`，可重新生成两份 summary CSV，不需要原始 BLE 地址、匿名化盐或仓库外目录。
- `source_public_data/`：从原 M13 目录复制的公开安全数据。
- `source_analysis_scripts/`：原始分析和 replay 脚本副本。
- `provenance_manifest.csv`：原始内部 CSV 的路径与 SHA-256；原始 CSV 含未哈希 BLE 地址，因此不复制进审稿包。

从本目录执行公开安全复现：

```bash
python3 recompute_public_summaries.py \\
  --output-dir /tmp/nt03-recomputed \\
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
"""
    (OUT / "README.md").write_text(readme, encoding="utf-8")


def write_package_hashes() -> None:
    paths = [
        path
        for path in sorted(OUT.rglob("*"))
        if path.is_file() and path.name != "MANIFEST.sha256"
    ]
    lines = [f"{sha256(path)}  {path.relative_to(OUT)}" for path in paths]
    (OUT / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    for _, _, path in WINDOWS:
        if not path.exists():
            raise FileNotFoundError(f"Required internal source trace is missing: {path}")
    salt_path = RAW / "anonymization_salt_20260606.txt"
    if not salt_path.exists():
        raise FileNotFoundError(f"Required internal anonymization salt is missing: {salt_path}")
    salt = salt_path.read_text(encoding="utf-8").strip()

    loaded = {(device_class, window_id): read_csv(path) for device_class, window_id, path in WINDOWS}
    on_windows = [entry for entry in WINDOWS if entry[1].startswith("on")]
    repeat_rows: list[dict[str, str]] = []
    filter_rows: list[dict[str, str]] = []
    for device_class, window_id, _ in on_windows:
        rows = loaded[(device_class, window_id)]
        for scope in ["random_or_rpa_candidate", "rpa_bit_pattern"]:
            repeat_rows.append(repeatability_row(device_class, window_id, rows, scope))
            for window_s in [0.0, 0.2, 1.0, 60.0]:
                filter_rows.append(duplicate_filter_row(device_class, window_id, rows, scope, window_s))

    write_csv(
        DATA_OUT / "repeatability_summary.csv",
        repeat_rows,
        list(repeat_rows[0].keys()),
    )
    write_csv(
        DATA_OUT / "duplicate_filter_replay_summary.csv",
        filter_rows,
        list(filter_rows[0].keys()),
    )
    event_count = write_anonymized_trace(salt, loaded)
    copy_sources()
    make_figure(repeat_rows, filter_rows)
    write_provenance()
    write_readme(repeat_rows, filter_rows, event_count)
    write_package_hashes()
    print(f"Built NT-03 evidence package with {event_count} anonymized candidate events in {OUT}")


if __name__ == "__main__":
    main()
