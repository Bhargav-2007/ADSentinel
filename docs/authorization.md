# Authorization and ethical use

Authorized use only. Obtain written permission identifying systems, owners, scope, testing windows, allowed techniques and data retention before connecting to an environment. `--authorization-reference` records a local reference; it is an acknowledgement, not proof of legal authority.

Default operation analyzes local evidence and sends no network traffic. `--collect ldap` explicitly opts into authenticated read-only LDAPS inventory (or an anonymous directory bind if no username is provided). `--collect graph` explicitly opts into read-only Microsoft Graph inventory. Authentication can create audit events and should use least-privilege identities. Avoid repeated authentication with an incorrect password.

Active flags require `--authorize`. Ticket requests, offline cracking, zone transfer and write-validation selectors are classified conservatively. Credential extraction, password spraying, relay validation, certificate-request validation and `dcsync-validate` additionally require `--i-own-this-environment`. All these intrusive backends are currently unavailable and return failure without executing. Dry-run checks authorization before showing the plan, and performs no network calls or output writes.

`--no-redact` additionally requires ownership acknowledgement for a private lab. Redaction strips recognized secret-bearing keys recursively; it cannot recognize arbitrary secrets concealed in unstructured strings. Do not import credential dumps or put secrets in names, notes or authorization references. No secret attributes are requested by collectors. Passwords and tokens are environment-only and never written to logs. No cloud uploads, telemetry or auto-updates exist.

Output directories receive owner-only permissions: 0700 on POSIX, protected owner-rights DACLs on Windows. New files are exclusive-created, with 0600 on POSIX and directory inheritance on Windows. Use a private local workspace; these controls do not protect against the current user, administrators, malicious concurrent filesystem changes, backups or a compromised OS.
