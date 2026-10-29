# Microsoft Entra ID and hybrid identity

Graph inventory uses only GET requests to the fixed Microsoft Graph v1.0 origin. Supply an existing tenant-scoped token; the application never requests consent or write permissions. Typical inventory permissions are User.Read.All and Application.Read.All (subject to tenant policy and endpoint documentation). Do not grant Directory.ReadWrite.All. The tenant option is a human scope label; verify the token tenant independently.

Current collection includes user synchronization indicators, application/service-principal identifiers and application credential expiry metadata. Secret values and key material are discarded. Imported normalized evidence can flag hybrid privileged identities and overprivileged applications, but live effective role assignment, risky consent, MFA posture, Connect configuration, PHS and PTA agents are not assessed. Unknown coverage must be resolved with separate authorized exports.

References: [Graph permissions](https://learn.microsoft.com/graph/permissions-overview), [paging](https://learn.microsoft.com/graph/paging), [best practices](https://learn.microsoft.com/graph/best-practices-concept). Pagination URLs are checked before the token is sent; redirects and environment proxies are disabled.
