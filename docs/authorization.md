# Authorization

Only assess owned or explicitly permitted environments. A reference records acknowledgement; it does not independently establish legal permission. The owner supplied ADS-LAB-ROE-001 for an isolated host-only lab. Actual owner/host/source details remain under ignored results/authorization/.

Passive/detection operation reads directory/DNS metadata or local data. Network mode permits read-only endpoint checks and optional SYSVOL. Active AXFR requires --authorize; other intrusive backends are unavailable. High-impact flags require both acknowledgements and, for this lab, a separate maintenance window. Spraying, relay and unapproved changes require separate permission. None was run.

The lab active window is 10:00–22:00 IST. Scope validation checks dates, explicit hosts, locally assigned source and selected route. lab-preflight sends no target packets. Missing source stops the run. CIDRs require interactive confirmation.

Use environment variables or a secure prompt. Never put secrets in YAML, source, logs, reports or fixtures. Unit markers are unusable test strings. Key-based redaction is not a classifier for secrets hidden in arbitrary text. --no-redact requires private-lab ownership acknowledgement.

No assessment data is uploaded. Explicit Graph authentication sends its intended token only to Microsoft Graph; an isolated AD scope refuses Graph. No telemetry, automatic updates, coercion, persistence or remote execution exists.

POSIX outputs use 0700/0600. Windows output directories use protected owner-rights DACLs inherited by new files. Paths reject traversal, alternate data streams and symlinks; writes are exclusive. Use a private workspace/local filesystem. Administrators, backups and hostile local races are outside this control. Retain private evidence for the authorized 90-day period, then follow owner-approved deletion; the tool never silently deletes files.
