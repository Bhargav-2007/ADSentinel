# Security review and limits

Threat model: untrusted CLI/YAML, collector JSON/archives, directory attributes, Graph pagination, network responses and report viewers. Controls include workspace-confined paths, symlink/ADS/traversal rejection, exclusive writes, private directories, bounded JSON/archive reads, fixed LDAP queries and escaped filter helpers, Graph allowlists/origin checks, verified TLS, no LDAP referrals/HTTP redirects, bounded graph traversal, safe YAML/XML, secret-key redaction, HTML autoescaping and CSV formula neutralization.

Import limits: 64 MiB per source/member, 256 MiB uncompressed total, 1,000 JSON documents, 250,000 explicit objects and 2,000,000 edges. ZIP entries are never extracted; unsafe names, symlinks, encryption and oversized files are rejected. Normalized JSON input is limited to 256 MB. Unknown relationship types are retained but not automatically traversed. Conflicting duplicates merge relationship arrays and keep deterministic first conflicting scalars, with issues recorded.

Binary ACL mapping is conservative and is not a full Windows AccessCheck. Conditional/unsupported ACEs, token deny groups, OWNER RIGHTS, property sets and incomplete schema/CA policy can alter effective access. AD CS paths remain conditional until trust, enrollment, mapping and authentication are manually validated. A named ESC template is never enough.

GPO metadata is configured policy, not effective host state. NTLMv1/LDAP signing/CBT enforcement, MFA, PIM and sync-agent settings are not inferred from endpoint reachability. Key-based redaction cannot detect secrets hidden in arbitrary strings. Output is not encrypted; use a private filesystem. Administrative access/backups/concurrent local races remain outside these controls.

Collections are sequential, with request timeouts, object/page limits, cancellation and deadline checks. Blocking protocol operations finish or hit their transport timeout before the next deadline check. This is not a hard process-kill deadline or automatic lab-stability monitor. Stop on instability with Ctrl+C. The isolated engagement's missing source/route blocks contact. No intrusive credential/ticket/certificate/relay backend is enabled.

No telemetry, auto-updates, data uploads, persistence or destructive actions. Windows owner-only output DACLs were inspected; POSIX permissions are tested on Linux temporary filesystems. Docker and packaged Windows EXEs still require separate validation. See validation/README.md for actual evidence and release blockers.

Primary references: https://ldap3.readthedocs.io/en/latest/ssltls.html ; https://learn.microsoft.com/graph/paging ; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e6685d31-5d87-42d0-8a5f-e55d337f47cd
