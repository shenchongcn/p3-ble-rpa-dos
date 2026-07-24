# P3: Persistence-Aware Admission Control for DoS-Resilient BLE RPA Resolution

This repository is the public reproducibility package for the accepted article
*P3: Persistence-Aware Admission Control for DoS-Resilient BLE Resolvable
Private Address Resolution*. It contains the deterministic simulator,
experiment runners, frozen configurations, result summaries, figure-source
data, supplementary tables, and anonymized hardware-trace evidence used in the
article and its review-closure analyses.

Release `v1.0.0` is the archival version associated with the accepted article.
The package was finalized on 15 July 2026; the article was accepted on 23 July
2026.

## Evidence boundary

The headline P3 evidence is simulation-based and stack-informed. Modeled
observation loss is an observation-layer proxy, not measured BLE packet loss.
Modeled delay/defer values are not controller, host-stack, connection, or
application timing measurements. The anonymized nRF5340 DK trace supports only
a visible candidate-address repetition sanity check and is not used for the
headline performance claims. Energy is reported as AES-equivalent resolving
work (one unit equals one IRK trial computation).

## Repository contents

```text
sim/rpa_resolution/          Simulator, configurations, runners, tests, results, and figures
supplementary/               Supplementary Tables S1-S4 and complete adaptive screen
review20260715/              Review-closure reports and decision records
nt02_regenerated_figures/    Regenerated figure assets and source script
nt03_hardware_trace_evidence/ Anonymized trace evidence and provenance material
MANIFEST_FINAL.sha256        SHA-256 integrity manifest for the reviewed package
README_FINAL.md              Detailed final-package guide and manuscript mapping
```

## Quick validation

Python 3.9 or newer is recommended. The numeric simulator uses only the Python
standard library; `matplotlib` is optional and is needed for figure generation.

```bash
python3 -m pip install -r requirements.txt
python3 -m unittest discover \
  -s sim/rpa_resolution/tests \
  -p 'test_review260715_*.py'
```

Detailed smoke-test and full-rerun commands are provided in
[`README_FINAL.md`](README_FINAL.md). Frozen results should not be overwritten
when auditing the release; direct test outputs to a separate writable path.

## Integrity and privacy

`MANIFEST_FINAL.sha256` covers the complete reviewed artifact package, excluding
the manifest itself. Repository-level publication metadata (`README.md`,
`CITATION.cff`, `.zenodo.json`, `LICENSE`, `.gitignore`, and
`requirements.txt`) is intentionally maintained outside that package manifest.

The public package excludes raw BLE addresses, anonymization salts, board and
device identifiers, exact wall-clock times, location data, private account
material, manuscript screenshots, editor lock files, and patent-sensitive
implementation detail not required for simulation reproduction.

## Citation

Use the metadata in [`CITATION.cff`](CITATION.cff). The permanent Zenodo DOI is
also shown in the GitHub release after archival.

## License

Released under the [MIT License](LICENSE).
