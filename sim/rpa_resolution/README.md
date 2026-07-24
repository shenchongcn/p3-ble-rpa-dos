# BLE RPA Resolution Simulator

M2 prototype for the P3 paper direction: resource-constrained BLE RPA resolution scheduling under resolving-list limits and RPA-flooding traffic.

Current W1 scope:

- event generation for bonded devices, background RPAs, attack RPAs, RPA rotation, and non-RPA traffic;
- baseline interface;
- `FullScan-Host`, `StaticRL`, and `ZephyrCache`;
- CSV/JSON outputs compatible with the M2 schema draft.

Run:

```bash
python3 sim/rpa_resolution/src/rpa_sim.py \
  --config sim/rpa_resolution/configs/w1_smoke.json \
  --out sim/rpa_resolution/results/w1_smoke
```

Outputs:

- `run_manifest.json`
- `events.csv`
- `decisions.csv`
- `summary.csv`

The simulator intentionally treats each IRK match attempt as one AES-equivalent operation. It does not implement real Bluetooth cryptography; M2 uses it to freeze experiment semantics and generate reproducible evaluation data.
