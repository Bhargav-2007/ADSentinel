# Official public sample validation

Date: 2026-10-29. ADSentinel: 0.2.0. Source: official SpecterOps BloodHound CE AD sample (Apache-2.0). The pinned provenance and license are in datasets/public/. This is maintainer sample/lab data, not a private client environment.

## Commands

```bash
adsentinel import --source bloodhound-ce --input datasets/public/bloodhound-sample-data --output results/public-imported-graph.json
adsentinel adcs --graph results/public-imported-graph.json --find-vulnerable --output results/public-adcs.json
adsentinel acl --graph results/public-imported-graph.json --find-dangerous --output results/public-acl.json
adsentinel attack-path --graph results/public-imported-graph.json --find-shortest --to "DOMAIN ADMINS" --output results/public-path.json
adsentinel report --input results/public-imported-graph.json --output reports/public-dataset-report.html
python scripts/validate_public.py --output results/public-validation-final.json
```

Existing outputs are exclusive-created; use fresh names when reproducing.

## Object accounting

| Collection | Raw rows | Unique retained objects |
|---|---:|---:|
| aiacas | 6 | 6 |
| certtemplates | 106 | 106 |
| computers | 34 | 34 |
| containers | 1121 | 939 |
| domains | 3 | 3 |
| enterprisecas | 4 | 4 |
| gpos | 32 | 32 |
| groups | 285 | 219 |
| ntauthstores | 2 | 2 |
| ous | 20 | 20 |
| rootcas | 5 | 5 |
| users | 100 | 99 |

Imported graph: 1478 nodes (1469 collected objects plus unresolved referenced identities), 12521 relationships including conditional derived edges.

Independent raw-archive comparison preserved all 10628 unique ACE relationships and all nondeleted object identifiers: missing ACEs 0, missing objects 0.

## Reviewed controls and accuracy boundary

Five manually reviewed AD CS controls are specified in expected-findings.md. Actual: 3 true positives, 2 true negatives, 0 false positives, 0 false negatives **within those five controls only**. This is not a whole-dataset precision/recall claim. Current template indicators: 7 ESC1, 4 ESC2, 4 ESC3 and 2 ESC4. Conditional CA/template paths are not proof of certificate authentication.

An actual AddMember path from SVC_PAYADMIN@PHANTOM.CORP to DOMAIN ADMINS@PHANTOM.CORP was recovered from the graph. Object names do not drive findings. The named ESC1 template is correctly excluded because its authorized-signature count is one.

## Discrepancies and fixes

249 duplicate object occurrences; 67 differing duplicates merged relationship arrays while keeping deterministic first conflicting scalar values. Six source metadata counts differ from their actual arrays. These are surfaced as 73 provenance issues; no parser crash occurred. Nine referenced identities lack collected node detail. Unknown rights are retained and skipped conservatively during path traversal.

Fixes applied: preserve stable IDs instead of conflating display names; merge duplicate ACL/membership data; avoid treating publication/enrollment as unconditional domain control; check approval/signatures rather than template names; distinguish historic sample timestamps from current account dormancy.

Import with tracemalloc: 1.632167 seconds; peak Python allocations 18811878 bytes (not total process RSS). Scale metrics are in validation/performance/large-dataset-results.md.

Evidence: pinned original archive, executable integration assertions, local results/public-validation-final.json, and examples/report.html generated from public data. No live lab screenshots or private assessment data are presented.

Final result: PASS for object/ACE preservation and the defined public controls. Live AD/Entra behavior, complete ACL effective access and whole-dataset false-negative/positive review remain unvalidated. Production release remains blocked.
