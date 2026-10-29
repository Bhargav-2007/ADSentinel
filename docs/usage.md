# Usage

Start offline with synthetic evidence. These commands contact no assessment targets:
```bash
adsentinel full-audit --input examples/evidence.json --output results/audit.json
adsentinel report --input results/audit.json --output results/audit.html
adsentinel report --input results/audit.json --output results/audit.csv
adsentinel report --input results/audit.json --output results/audit.md
adsentinel attack-path --input examples/evidence.json --from jdoe --to "DOMAIN ADMINS" --find-all --max-depth 6
adsentinel kerberos --input examples/evidence.json --enum --json
adsentinel recon --domain corp.lab --dc dc01.corp.lab --collect ldap --dry-run
```

Use unique output names: existing evidence and reports are never overwritten. All paths must remain inside the current workspace; traversal and symbolic links are rejected. Raw JSON and final reports are separate. Explicit `.html`, `.md`, `.csv` or `.json` output extensions select that format; otherwise `--format` applies. `--json` prints the full JSON report to stdout, while human output goes to stderr. `--quiet` suppresses summaries and progress; failures remain visible. `--no-color` disables color. `--verbose` adds coverage and collection detail without secrets.

Explicit live read-only collection:
```bash
adsentinel recon --domain corp.lab --dc dc01.corp.lab --user jdoe@corp.lab --collect ldap
adsentinel azure-ad --collect graph --tenant your-lab-tenant
```

Provide the LDAP password as `ADS_SENTINEL_PASSWORD` and the Graph access token as `ADS_SENTINEL_GRAPH_TOKEN` through your shell's secure secret mechanism. Do not paste secrets into command history. The Graph token selects the tenant; `--tenant` is a scope label, not authentication or tenant verification. Only Microsoft Graph receives its intended authentication token and GET requests; collected data and reports are never uploaded. Local-only evidence mode does not call Graph.

`--config examples/lab.yaml` supplies domain, DC, username, environment variable names, module selection and output settings. CLI `--authorize` and ownership acknowledgement cannot come from YAML. Collection is sequential; concurrency is bounded at one. No shell commands, remote writes or credential tests are used.

Selectors such as `--find-vulnerable`, `--find-readers` and `--check-signing` describe intent; each module evaluates all its implemented rules against the available evidence. They do not enable additional network probes. Baseline framework labels are review context, not CIS or Microsoft compliance certification. See the capability matrix before relying on results.
