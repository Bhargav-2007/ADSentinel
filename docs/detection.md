# Detection engineering

Findings include specific detection guidance. Collect directory changes (5136), sensitive directory access (4662 with narrowly scoped SACLs), account changes (4738), Kerberos authentication (4768/4769), logons (4624), audit policy changes (4719), share access (5140/5145), PowerShell script blocks (4104), WinRM operational logs and CA audit events where appropriate.

Validate audit subcategories, SACLs, forwarding, retention and analyst visibility with a controlled lab event. An enabled-policy indicator does not prove event generation or SIEM delivery. Correlate Entra service-principal sign-ins, consent changes and app role assignments. No event-log scraping or SIEM integration is implemented.
