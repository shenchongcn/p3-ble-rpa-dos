#!/usr/bin/env bash
set -euo pipefail

python3 sim/rpa_resolution/src/rpa_sim.py \
  --config sim/rpa_resolution/configs/w1_smoke.json \
  --out sim/rpa_resolution/results/w1_smoke
