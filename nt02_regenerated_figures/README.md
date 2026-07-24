# NT-02 Figure Regeneration

This directory contains print-readable replacements for manuscript Figures 9, 15, and 17.

## Portable Reproduction

The generator reads only the packaged M10 inputs below a data root containing `sim/rpa_resolution`:

- `sim/rpa_resolution/figures/m10_statistical_extension/table_m10_headline_stats.csv`
- `sim/rpa_resolution/results/m10_statistical_extension/combined_summary.csv`

From the repository root:

```bash
python3 docs/20260606ver/20260708review/nt02_regenerated_figures/regenerate_figures.py \
  --data-root . \
  --output-dir /tmp/nt02-regenerated
```

From an extracted reviewer package, set `--data-root` to the directory that contains `sim/rpa_resolution`.

The PNG, PDF, SVG, and `figure_manifest.csv` outputs are deterministic for the same Matplotlib/Pillow environment and input CSV files. The Word manuscript should use the PNG files through the manual `Change Picture` operation described in the revision plan; this script does not modify DOCX files.
