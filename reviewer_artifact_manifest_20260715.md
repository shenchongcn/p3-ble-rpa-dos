# Reviewer Artifact Manifest — 15 July 2026 Revision

Date: 2026-07-15

Manuscript: `electronics-4413038`

Package: `electronics-4413038-reviewer-artifacts-20260715.zip`

## Package update

This package supersedes `electronics-4413038-reviewer-artifacts-round1-final.zip`. It retains the previously supplied simulation, figure-regeneration, anonymized hardware-trace sanity-check, and long-window materials, and adds:

- Supplementary Tables S1–S4 in DOCX, PDF, Markdown, and frozen JSON-source form;
- the validated observation-loss and repeated-benign simulator capabilities;
- paired modeled-observable privacy runner, configurations, results, audits, and statistical tables;
- joint epoch–loss–benign-density runner/analyzer, 600 configurations, 1800 method rows, controls, closure audit, and analysis tables;
- adaptive local-search runner/analyzer, 840 screen configurations, 440 confirmation configurations, complete 168-strategy screen, frozen top-five selection, confirmation ranking, contrasts, and cap audit;
- reviewer-closure unit tests, result reports, decision log, and source/config/output manifests;
- a package-wide SHA-256 manifest and updated reproduction instructions.

## Publication-facing supplementary tables

- Table S1: 18 long-window scenario/method rows.
- Table S2: 18 external-proxy privacy-audit rows; the initial paired audit matched in every tested pair.
- Table S3: 27 main P3-Persist joint-boundary cells plus three controls.
- Table S4: 22 twenty-seed P3-Persist confirmation rows; the complete 168-strategy screen remains available as CSV.

## Scientific boundary

The privacy experiment is auxiliary modeled evidence supporting claim narrowing. Observation loss is simulated, not measured. The joint-factor result supports a modeled work bound but shows conditional service degradation. The adaptive result identifies a tied near-cap local region within the tested grid, not a global or unique optimum.

## Integrity

The archive root contains `MANIFEST_FINAL.sha256`. The outer ZIP SHA-256 is recorded in the repository freeze record after package construction.
