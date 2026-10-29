# Remediation planning

Review critical replication permissions and high-impact directory control edges first. Verify object scope, inheritance, deny rules and legitimate service dependencies before removing rights. Then prioritize dangerous certificate templates, unconstrained delegation, weak protocol policies and privileged identity tiering.

Require SMB and LDAP signing, deploy channel binding after compatibility assessment, remove SMBv1/NTLMv1, deploy Windows LAPS, adopt gMSAs, restrict credential readers and separate cloud administrators from synchronized identities. Rotate credentials when exposure is confirmed. Test policy changes with a pilot group and documented rollback. Findings are indicators; reports include a severity-ordered roadmap rather than executing changes.
