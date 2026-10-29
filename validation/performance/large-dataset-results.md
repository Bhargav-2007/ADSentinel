# Larger graph performance

ADSentinel 0.2.0, Windows Python 3.11, 2026-10-29. Source: pinned official public AD sample, Apache-2.0. Each scale is a disjoint namespace copy of actual topology, explicitly a synthetic scale expansion, not independent enterprise data. No network contact.

Command: python scripts/validate_public.py --output results/public-validation-final.json

| Topology copies | Nodes | Edges | BFS analysis seconds | Returned paths |
|---:|---:|---:|---:|---:|
| 1 | 1478 | 12521 | 0.005627 | 1 |
| 10 | 14780 | 125210 | 0.049715 | 1 |
| 25 | 36950 | 313025 | 0.102478 | 1 |

Expected: preserve the known one-edge path in copy zero without cross-copy edges. Actual: one valid path at each scale; no crash or graph-limit error. These are single local timings, not a latency SLO or large-directory collection benchmark. Dense all-path searches have explicit expansion/path/depth limits and can fail closed. Full import/memory numbers appear in the public validation report. FP/FN: not measured by this performance benchmark; reviewed correctness controls are separate. Final result: PASS for this bounded graph workload only.
