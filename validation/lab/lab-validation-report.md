# Live lab validation — BLOCKED

Environment: ADSentinel Lab. Permission reference: ADS-LAB-ROE-001, owner-authorized isolated lab, provided in this session. Version: 0.2.0. Date: 2026-10-29, Asia/Kolkata.

Command: adsentinel lab-preflight --scope-file results/authorization/lab-scope.json --json

Expected: permitted source assigned locally and correct routes before any target contact.
Actual: preflight refused execution because the permitted source interface was not locally assigned. The expected credential variables were also unset. No lab TCP/UDP packet, authentication, scan or intrusive validation was attempted.

TP/FP/FN: not measured; no lab data. Parser findings: none measured. Performance: no scan executed. Sanitized evidence: preflight error only; actual network/owner/account details remain private under ignored results/.
Fix needed: attach the explicitly authorized host-only source environment, configure local inventory/account/CA trust, rerun preflight, then passive collection and native/manual comparisons. Do not alter routes or scan from a different source to bypass this restriction.

Final status: BLOCKED / NOT VALIDATED. Not a passing lab report.
