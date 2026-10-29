# ADSentinel

**Authorized Active Directory attack-path discovery, privilege-escalation assessment, and remediation reporting.**

ADSentinel 0.2.0 is a terminal-only Python 3.11+ assessment tool. **Development / not production-ready:** official public collector-data validation passes the documented checks. Live AD validation is blocked because the authorized source interface and local credentials are unavailable. Unit tests do not prove effective access or exploitation.

## Implemented

- Verified read-only LDAPS domain/configuration/schema collection: objects, memberships, policies, trusts, delegation, AD CS and owner/DACL metadata.
- Bounded binary security-descriptor parsing with object-specific rights and explicit effective-access limitations.
- Actual SharpHound v5/v6 JSON/ZIP/GZIP and node/edge graph import, stable identifiers, checksums, duplicate merging and parser issues.
- BFS shortest paths, bounded DFS simple paths, high-value targets, heuristic scores, common intermediates and JSON/GraphML.
- Evidence-based Kerberos, ESC1/2/3/4, ACL, replication-permission, trust, LAPS/gMSA-reader, identity and policy checks.
- Actual SMB signing/share/root listing, DNS queries and authorized AXFR, RDP negotiation and WS-Management Identify.
- Optional bounded SYSVOL policy reads and INF/POL/GPP metadata parsing.
- Read-only Graph inventory, direct roles, permission grants, consent and expiry metadata with partial-error coverage.
- Local JSON/CSV/Markdown/HTML/terminal reports with unique IDs, confidence, evidence, ATT&CK, detection and remediation.
- Authorization gates, host allowlists, source/route preflight, broad-scan confirmation, protected output, redaction and cancellation.

Read the [capability matrix](docs/modules.md). Native session/SAM collection, complete Windows effective-access evaluation, live LDAP signing/CBT tests, NTLMv1 authentication tests, full PIM/MFA/sync-agent checks and intrusive Kerberos/certificate/relay/DCSync backends are **unsupported**. Unsupported selectors fail explicitly.

## Installation and public-data validation

Create and activate a Python virtual environment, then run:

```bash
python -m pip install -e '.[dev]'
adsentinel --help
adsentinel import --source bloodhound-ce --input datasets/public/bloodhound-sample-data --output results/imported-graph.json
adsentinel attack-path --graph results/imported-graph.json --find-shortest --to "DOMAIN ADMINS" --output results/path.json
adsentinel adcs --graph results/imported-graph.json --find-vulnerable --output results/adcs.json
adsentinel report --input results/adcs.json --output reports/adcs.html
python scripts/validate_public.py --output results/public-validation.json
python -m pytest -q
```

The pinned, licensed archive is the [official SpecterOps sample](https://bloodhound.specterops.io/get-started/quickstart/ce-ingest-sample-data), not private engagement data. Outputs never overwrite existing files. Fabricated unit records are confined to tests; the [example report](examples/report.html) comes from public collector data.

## Authorized lab

Keep actual inventory and secrets local. Use `adsentinel lab-preflight --scope-file results/authorization/lab-scope.json` and a scoped `--dry-run` first. Session authorization is ADS-LAB-ROE-001; private details remain under ignored results/authorization/.

Secrets are environment/prompt-only. With no input, domain/DC or target arguments select live read-only collection. An isolated AD scope excludes cloud calls. No lab target was contacted.

[Installation](docs/installation.md) · [Usage](docs/usage.md) · [Architecture](docs/architecture.md) · [Modules](docs/modules.md) · [Authorization](docs/authorization.md) · [Security](docs/security-audit.md) · [Validation](validation/README.md) · [Development](docs/development.md)

No unauthorized scanning, persistence, malware, destructive action, telemetry, automatic updates or evidence uploads. Manual review and actual authorized-lab validation are required before release.
