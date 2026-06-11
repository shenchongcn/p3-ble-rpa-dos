#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

python3 sim/rpa_resolution/scripts/run_m3_matrix.py \
  --suite sensitivity \
  --out sim/rpa_resolution/results/m3_sensitivity \
  --config-dir sim/rpa_resolution/configs/m3/sensitivity
