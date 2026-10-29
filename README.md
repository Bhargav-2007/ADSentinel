# ADSentinel

**ADSentinel** is a cross-platform, terminal-based Active Directory and hybrid-identity security assessment tool for Linux and Windows. It helps authorized security professionals discover AD misconfigurations, analyze privilege-escalation paths, assess AD CS security, evaluate protocol hardening, and generate actionable remediation reports.

> **Ethical use notice:** ADSentinel is intended only for authorized security testing, education, and defensive research in environments you own or are explicitly permitted to assess. Unauthorized use is illegal and unethical.

## Features

- Cross-platform CLI for Linux and Windows
- Passive-first Active Directory reconnaissance
- BloodHound-compatible relationship collection workflow
- Graph-based attack-path analysis
- Kerberoasting and AS-REP Roasting detection
- AD CS and certificate template assessment
- ESC1 and ESC8 condition checks
- Unconstrained and constrained delegation analysis
- Dangerous ACL discovery
- DCSync permission analysis
- GPO, LAPS, gMSA, and service-account assessment
- SMB, LDAP, NTLM, DNS, RDP, and WinRM hardening checks
- Domain and forest trust analysis
- Microsoft Entra ID and hybrid-identity assessment
- Account hygiene, password-policy, and privileged-access analysis
- Security baseline and detection-coverage assessment
- MITRE ATT&CK mapping
- JSON, CSV, Markdown, HTML, and terminal reporting
- Authorization gates for active or high-impact checks
- Redacted evidence handling and secure output controls

## Installation

### Linux

```bash
git clone [https://github.com/your-username/adsentinel.git](https://github.com/your-username/adsentinel.git)
cd adsentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
adsentinel --help
```

### Windows PowerShell

```powershell
git clone [https://github.com/your-username/adsentinel.git](https://github.com/your-username/adsentinel.git)
cd adsentinel
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
adsentinel --help
```

### Docker

```bash
docker build -t adsentinel .
docker run --rm -it adsentinel --help
```

## Quick start

### Passive reconnaissance

```bash
adsentinel recon \
  --domain corp.lab \
  --dc 10.10.10.10 \
  --output results/recon.json
```

### Authenticated enumeration

```bash
export ADS_SENTINEL_PASSWORD='your-lab-password'

adsentinel recon \
  --domain corp.lab \
  --dc 10.10.10.10 \
  --user jdoe \
  --output results/recon.json
```

### BloodHound collection

```bash
adsentinel bloodhound \
  --domain corp.lab \
  --dc 10.10.10.10 \
  --user jdoe \
  --collection all \
  --output results/bloodhound/
```

### Attack-path analysis

```bash
adsentinel attack-path \
  --domain corp.lab \
  --dc 10.10.10.10 \
  --from jdoe \
  --to "DOMAIN ADMINS"
```

### AD CS assessment

```bash
adsentinel adcs \
  --domain corp.lab \
  --dc 10.10.10.10 \
  --user jdoe \
  --find-vulnerable \
  --output results/adcs.json
```

### GPO assessment

```bash
adsentinel gpo \
  --domain corp.lab \
  --dc 10.10.10.10 \
  --find-writable
```

### LAPS assessment

```bash
adsentinel laps \
  --domain corp.lab \
  --dc 10.10.10.10 \
  --find-readers
```

### SMB and LDAP hardening

```bash
adsentinel smb \
  --target 10.10.10.0/24 \
  --check-signing \
  --find-shares

adsentinel ldap \
  --domain corp.lab \
  --dc 10.10.10.10 \
  --check-signing
```

### Entra ID assessment

```bash
export ADS_SENTINEL_GRAPH_TOKEN='your-lab-graph-token'

adsentinel azure-ad \
  --tenant your-lab-tenant \
  --find-privileged-apps
```

### Generate report

```bash
adsentinel report \
  --input results/scan.json \
  --format html \
  --output reports/ad-report.html
```

## Safety model

ADSentinel uses a safety-first design:

| Mode | Behavior | Authorization required |
|---|---|---|
| Passive | LDAP, DNS, and metadata enumeration | No |
| Detection | Identify risky configurations and attack paths | No |
| Network-sensitive | SMB, LDAP, RDP, WinRM, DNS, and NTLM checks | Target confirmation recommended |
| Active validation | Controlled certificate, relay, or authentication tests | Yes |
| Credential testing | Kerberoasting, AS-REP Roasting, offline cracking | Yes |
| Credential extraction | DCSync validation or secret extraction | Yes, lab-only |
| Password spraying | Authentication testing across accounts | Yes, lab-only |

Active and high-impact modules require explicit authorization:

```bash
--authorize
--i-own-this-environment
```

A dry run is always available:

```bash
adsentinel full-audit --config examples/lab.yaml --dry-run
```

## Modules

| Module | Purpose |
|---|---|
| `recon` | Enumerate domain users, groups, computers, OUs, SPNs, trusts, shares, and policies |
| `bloodhound` | Collect AD relationship data for attack-path analysis |
| `attack-path` | Discover paths from users or computers to high-value assets and privileged groups |
| `kerberos` | Find Kerberoastable and AS-REP Roastable accounts |
| `adcs` | Assess certificate authorities, templates, and ESC-class misconfigurations |
| `delegation` | Detect unconstrained, constrained, and resource-based delegation risks |
| `acl` | Identify dangerous ACLs, ownership issues, and privilege paths |
| `dcsync-check` | Identify accounts with dangerous replication permissions |
| `gpo` | Assess GPO permissions, scripts, scheduled tasks, and Restricted Groups |
| `laps` | Assess Windows LAPS deployment and password-read permissions |
| `gmsa` | Assess managed service accounts and service-account hygiene |
| `smb` | Check SMB signing, SMBv1, shares, null sessions, and relay exposure |
| `ldap` | Check LDAP signing, channel binding, LDAPS, and anonymous access |
| `ntlm` | Assess NTLM usage and relay-relevant configurations |
| `dns` | Enumerate DNS records, zone transfers, dynamic updates, and stale entries |
| `rdp` | Assess RDP access, NLA, and lateral-movement exposure |
| `winrm` | Assess WinRM and PowerShell Remoting access |
| `trusts` | Assess domain and forest trusts, SID filtering, and SIDHistory |
| `azure-ad` | Assess Microsoft Entra ID roles, apps, service principals, and hybrid identity |
| `account-hygiene` | Find inactive, stale, privileged, and risky accounts |
| `password-policy` | Assess domain password and lockout policy |
| `privileged-access` | Identify privileged groups, nesting, and tiering issues |
| `baseline` | Compare configurations against Microsoft or CIS-style hardening baselines |
| `detection-coverage` | Assess logging and telemetry coverage |
| `report` | Create professional security assessment reports |

## Example output

```text
[*] Target domain: corp.lab
[*] Domain controller: 10.10.10.10
[*] Starting passive reconnaissance...

[+] Domain found: corp.lab
[+] Domain SID: S-1-5-21-1004336348-1177238915-682003330
[+] Domain controllers: 1
[!] Kerberoastable accounts: 2
    - svc_sql      [HIGH]
    - svc_web      [HIGH]
[!] AS-REP Roastable accounts: 1
    - legacy_user  [HIGH]
[!] Potentially vulnerable AD CS template: CORP-WebServer-ESC1 [CRITICAL]
[!] DCSync-capable principal: svc_backup [CRITICAL]
[!] LAPS password readable by: HELPDESK [HIGH]
[!] Writable GPO: CORP-Workstation-Baseline [CRITICAL]
[!] Attack path found: jdoe -> HELPDESK -> LAPS read -> CLIENT01 -> Domain Admin [CRITICAL]

[*] Scan complete.
[*] Findings: 7
[*] Report: reports/ad-report.html
```

## Secure development practices

ADSentinel follows secure development practices:

- No hard-coded secrets
- Environment-variable or prompt-based credential handling
- No credentials, hashes, tickets, certificates, or private keys in logs by default
- Evidence redaction enabled by default
- Strict input validation for domains, hosts, users, paths, LDAP filters, and Graph parameters
- Parameterized LDAP and Microsoft Graph query construction
- Path-traversal protection
- Restrictive permissions on sensitive result files
- `.gitignore` protection for credentials, captures, tickets, certificates, and scan output
- Dependency auditing and secret scanning in CI
- Unit and integration tests
- Manual security review before release

## Lab use

For safe testing, use an isolated Active Directory lab:

- Windows Server 2022 Domain Controller
- Windows 10/11 domain-joined client
- Linux assessment host
- Internal-only virtual network
- Intentional but documented misconfigurations
- Optional Microsoft Entra ID tenant for hybrid-identity testing

See `docs/lab-setup.md` for a complete lab build guide.

## MITRE ATT&CK mapping

| Finding | MITRE ATT&CK |
|---|---|
| Domain reconnaissance | T1087, T1069 |
| Kerberoasting | T1558.003 |
| AS-REP Roasting | T1558.004 |
| AD CS abuse | T1649 |
| Delegation abuse | T1558 / T1550 |
| DCSync | T1003.006 |
| ACL abuse | T1069 / T1098 |
| GPO abuse | T1484 |
| LAPS abuse | T1552 / T1098 |
| SMB relay exposure | T1557 |
| RDP lateral movement | T1021.1 |
| WinRM lateral movement | T1021.006 |
| Cloud application abuse | T1098 / T1078 |

## Reporting

ADSentinel generates:

- Executive summary
- Risk-rated findings
- Affected AD and Entra ID objects
- Evidence references
- Attack-path analysis
- MITRE ATT&CK mappings
- Detection recommendations
- Remediation guidance
- Prioritized remediation roadmap

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
mypy adsentinel
```

## License

MIT License.

## Disclaimer

This tool must only be used in authorized environments. The developers and contributors are not responsible for misuse.
