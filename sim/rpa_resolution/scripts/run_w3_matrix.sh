#!/usr/bin/env bash
set -euo pipefail

PYTHONPATH=sim/rpa_resolution/src \
python3 sim/rpa_resolution/scripts/run_matrix.py \
  --out sim/rpa_resolution/results/w3_matrix
