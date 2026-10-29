# Module capability matrix

Version 0.1 is an evidence-driven assessment implementation with two limited live inventory collectors. It is not a full protocol scanner. Every module command exists; below is the implemented scope. Missing evidence is unknown, not healthy.

| Command | Implemented assessment | Live data source / limitation |
|---|---|---|
| recon | Users, groups, computers, OUs, membership and password policy inventory | Verified LDAPS; no SID, NetBIOS, DNS or share inventory yet |
| bloodhound | Normalized edge preparation and graph JSON export | Not native BloodHound CE/SharpHound output; no sessions or local groups |
| kerberos | SPN exposure, preauthentication, RC4-only indicators | LDAPS attributes; no ticket requests or cracking |
| adcs | Compound ESC1 configuration indicators | Imported template settings; no live CA/template ACL parser, ESC8 probe or enrollment |
| delegation | Unconstrained non-DC delegation and protocol transition | LDAPS; constrained targets and RBCD descriptors not yet parsed |
| acl | Dangerous supplied control edges | Imported resolved edges; no binary ACL or effective access evaluator |
| dcsync-check | Combined replication-right indicators | Imported permissions; domain root, deny ACEs, group expansion and filtered sets need manual review |
| attack-path | Shortest / bounded simple paths, risk score, frequent intermediate nodes, per-edge remediation | Supplied graph; scores are prioritization heuristics |
| gpo | Low-privilege write indicators | Imported GPO evidence; no SYSVOL/script/task collection |
| laps | Coverage gaps and excessive readers | Imported metadata; never retrieves passwords |
| gmsa | Unmanaged service accounts and excessive readers | Imported metadata; never retrieves managed passwords |
| smb | Signing, SMBv1 and anonymous-share indicators | Imported policy evidence; no SMB negotiation or write probes |
| ldap | Signing and channel-binding policy indicators | Imported policy evidence; successful LDAPS does not establish signing/CBT policy |
| ntlm | NTLMv1 acceptance indicators | Imported policy evidence; no relay listener or credential coercion |
| dns | Insecure updates and unrestricted transfer indicators | Imported evidence; no DNS transfer attempt |
| rdp | NLA and excessive access indicators | Imported policy evidence; no logon attempts |
| winrm | Basic authentication over HTTP indicator | Imported policy evidence; no remote execution |
| trusts | SID filtering disabled indicator | Imported evidence; trust context must be reviewed |
| azure-ad | App credential expiry, reported overprivilege and hybrid privilege | Graph users/apps/service-principal inventory; roles, MFA, consent and sync-agent policies not collected |
| account-hygiene | Non-expiring/reversible passwords and reported dormant privilege | LDAPS for account flags; dormancy requires imported evidence |
| password-policy | Minimum length/history review thresholds | LDAPS domain policy; no fine-grained effective policy resolution |
| privileged-access | Reported tiering violations | Imported evidence; membership graph supports separate path analysis |
| baseline | Cross-module configuration review | Not a benchmark compliance engine; framework is a label |
| detection-coverage | Security auditing and script-block logging gaps | Imported evidence; cannot prove SIEM event receipt |

Normalized evidence is documented in `docs/evidence-schema.md`. Requests for unavailable intrusive modes fail closed after checking authorization; no exploit is run. `--collection` records BloodHound preparation intent and does not invoke a collector executable. Path results do not prove exploitability. Chokepoints are frequency counts among returned paths, not graph-theoretic dominators.
