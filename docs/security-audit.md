# Security review and limitations

Threat model: untrusted CLI inputs, YAML, evidence JSON, directory attributes, Graph response links and report viewers. Controls include workspace-confined paths, symbolic-link rejection, exclusive output creation, restricted directories, LDAP filter escaping, fixed Graph resource allowlists, TLS verification, disabled LDAP referrals and HTTP redirects, bounded graph exploration, JSON size limits, YAML safe loading, secret-key redaction, HTML escaping, CSV formula neutralization and CLI-only authorization gates.

Output is not encrypted. Redaction is key-based, not a DLP classifier. Effective ACLs, exploitability, MFA and compliance cannot be inferred from missing data. A malicious concurrent local user could race filesystem validation; use an owner-private workspace. POSIX/NTFS permissions depend on the underlying filesystem. Administrative access bypasses local file protections. Preserve reports according to engagement retention policy.

No credential harvesting, ticket extraction, certificate enrollment, relay, spraying or exploit backend is included. No external collector executable is invoked. Sequential requests cap concurrency at one; LDAP operation time limits and HTTP request timeouts apply. Page/object/graph bounds stop oversized collections; Graph throttling is reported rather than retried automatically. A collection can span multiple request timeouts; there is no whole-run wall-clock deadline.

Dependency auditing is an explicit development/CI operation that contacts vulnerability services with package metadata. Runtime scans do not upload assessment data. Review dependency updates and source manually before every release. CI does not constitute a penetration test or proof of security.

Sources: [ldap3 TLS](https://ldap3.readthedocs.io/en/latest/ssltls.html), [read-only connections](https://ldap3.readthedocs.io/en/latest/connection.html), [Graph paging](https://learn.microsoft.com/graph/paging).
