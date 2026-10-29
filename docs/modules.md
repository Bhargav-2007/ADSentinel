# Capability matrix

These are actual implementations, with explicit limits. No module is certified complete against a live AD domain yet.

| Command | Real implementation | Boundary |
|---|---|---|
| recon | LDAPS RootDSE/domain/config/schema, SID/functional metadata, objects, policies, sites/subnets; DNS when DC is an IP | SMB shares use the SMB collector; no plaintext bind probes |
| bloodhound | Native directory/ACL graph collection; actual SharpHound import including sessions/local groups | Native SAM/session collection unsupported; internal JSON is not a CE collector ZIP |
| attack-path | ID-based BFS/DFS, cycle avoidance, low-privilege source selection, high-value targets, JSON/GraphML | Heuristic candidate paths; common intermediates are not whole-graph dominators |
| kerberos | Actual LDAP SPNs, preauth/UAC, encryption and delegation metadata | Ticket capture, roasting requests and cracking unsupported |
| adcs | CA/template publication, settings/EKUs/ACLs; ESC1/2/3/4 indicators and conditional ESC1 graph edges | No enrollment/authentication or ESC8/EPA probe; CA trust/authentication remain unvalidated |
| delegation | UAC, constrained targets, RBCD descriptor metadata and relationships | Conditional ACEs and end-to-end impersonation unsupported |
| acl | Binary self-relative SDs, owner/DACL, object rights and inheritance filtering | Not a full ordered Windows AccessCheck; token denies/OWNER RIGHTS require review |
| dcsync-check | Domain-root replication combinations; group paths through graph | Permission indicators only; no credential extraction |
| gpo | LDAP links/paths/control rights; optional bounded INF/POL/GPP/script metadata | --read-sysvol --mode network required; no effective-host-policy claim |
| laps | Collected expiration metadata, reported coverage, parsed attribute-read edges | Missing expiration is unknown; never retrieves passwords or infers encryption decryptors |
| gmsa | Membership descriptor and READ_PROPERTY reader indicators; SPN/service-account review | No password retrieval or complete token access calculation |
| smb | Real negotiation/signing, optional SMBv1 attempt, one login, share/root listing | No write probes or complete NTFS/share effective ACL evaluation |
| ldap | Verified TLS and actual directory reads, including anonymous exposure when observed | Live signing/CBT enforcement tests explicitly unsupported |
| ntlm | Actual SMB relay-relevant signing surface and imported policy evidence | Does not infer NTLMv1 from negotiation; relay validation unsupported |
| dns | Real A/AAAA/MX/NS/SOA, DC/Kerberos/GC SRV, wildcard query; authorized AXFR | No secure-update or stale-record inference from TTL; no updates |
| rdp | Actual X.224 TLS-only acceptance or HYBRID-required negotiation | No logons, effective group access or Restricted Admin verification |
| winrm | Actual WSMan Identify/401/advertised auth; client API supports verified TLS | No commands/effective remoting-access claims; auth header is not proof Basic succeeds |
| trusts | Actual direction/type/flags and SIDHistory observations | Intra-forest filtering handled separately; no cross-domain access attempts |
| azure-ad | Read-only Graph inventory, direct roles, application grants, consent, expiry and sync metadata | PIM/group roles, MFA, PHS/PTA host settings unsupported; lab scope excludes cloud |
| account-hygiene | Actual UAC/enabled/SPN flags; disabled privilege; inactivity with a collection reference time | Old public data is not labeled dormant relative to today |
| password-policy | Domain/fine-grained length/history/complexity/lockout metadata | No per-account resultant-policy computation |
| privileged-access | Transitive privileged membership and standing-access inventory | No tiering inference without session/tier evidence |
| baseline | Cross-module configuration and optional GPO policy review | Microsoft/CIS-inspired review, not compliance certification |
| detection-coverage | Imported host indicators and actual optional GPO logging/audit metadata | No proof of host effective policy or SIEM receipt; Sysmon/CA probes unsupported |

Sources resolve uniquely; use qualified names/IDs for ambiguity. Destinations may span collected domains. Unknown edges remain exported and are listed as skipped during traversal. Authorization never executes an unavailable backend.
