# Usage

Import and analyze real collector data locally:

```bash
adsentinel import --source bloodhound-ce --input datasets/public/bloodhound-sample-data/ --output results/imported-graph.json
adsentinel acl --graph results/imported-graph.json --find-dangerous --output results/acl.json
adsentinel adcs --graph results/imported-graph.json --find-vulnerable --output results/adcs.json
adsentinel attack-path --graph results/imported-graph.json --find-shortest --to "DOMAIN ADMINS" --export-graph results/graph.graphml
adsentinel report --input results/imported-graph.json --format html --output reports/public-dataset-report.html
```

Import accepts v5/v6 SharpHound JSON, ZIP, gzipped JSON, directories and explicit nodes/edges graphs. Archives are never extracted. Public-data results do not prove live host policy or exploitation.

Without input, an authorized domain/DC or target selects the command's read-only protocol. --collect overrides this choice. --dry-run prints actions, targets, permissions and limits without prompts, calls or writes. --scope-file enforces dates, hosts, source and route. CIDRs require interactive exact-range confirmation and are limited to explicit scoped hosts.

LDAP/SMB secrets come from ADS_SENTINEL_PASSWORD or --prompt-password. --anonymous cannot combine with --user. Use --ca-cert and --tls-server-name for private CA trust and a certificate DNS identity when connecting to a DC IP; verification stays enabled. Graph uses an existing ADS_SENTINEL_GRAPH_TOKEN; its token selects the tenant. The current lab scope refuses cloud endpoints.

--read-sysvol --mode network opts into bounded GPO file reads. --check-smb1 adds a negotiation attempt; failure is not proof that SMBv1 is disabled. No write probes or remote commands run.

--json emits machine-readable stdout; human output goes to stderr. --quiet suppresses summaries, not failures; --verbose adds controlled structured events/coverage; --no-color disables color. Extensions select JSON/CSV/Markdown/HTML; otherwise --format applies. Raw evidence and reports are separate, protected, workspace-confined and never overwritten. CSV formulas are neutralized.

YAML supports domain/DC, username/environment names, passive/detection/network mode, full-audit modules, timeout and output formats. Authorization cannot come from YAML. Concurrency is one. Config timeout/port/secret-variable names take precedence in this version. Unsupported selectors fail; absent findings never establish coverage.
