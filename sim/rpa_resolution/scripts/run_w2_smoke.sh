#!/usr/bin/env bash
set -euo pipefail

python3 sim/rpa_resolution/src/rpa_sim.py \
  --config sim/rpa_resolution/configs/w2_smoke_base.json \
  --out sim/rpa_resolution/results/w2_smoke_base

python3 sim/rpa_resolution/src/rpa_sim.py \
  --config sim/rpa_resolution/configs/w2_smoke_attack.json \
  --out sim/rpa_resolution/results/w2_smoke_attack
