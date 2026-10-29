# Hybrid identity

Graph uses allowlisted GET resources, bounded same-origin v1.0 pagination, verified TLS and no redirects/environment proxies. Supply an existing token; no consent or write permission is requested. Endpoint-specific read permissions may include User.Read.All, Group.Read.All, Application.Read.All, RoleManagement.Read.Directory and Directory.Read.All for delegated-consent inventory. Denial/throttling remains incomplete coverage.

Collected data covers users/groups, sync flags, apps/SPs, expiry metadata, direct roles, application grants, delegated consent and organization sync metadata. Secret values/key material are discarded. Sensitive grants trigger review, not a claim that a necessary business permission is excessive. Requested permissions are not treated as granted consent.

Group roles, PIM, full MFA, Connect/PTA/PHS agents and conditional-access effectiveness are unsupported. A sync flag does not prove PHS. The token determines the tenant; --tenant is a label. The current isolated-lab scope excludes cloud endpoints; no live Graph validation occurred.

References: https://learn.microsoft.com/graph/permissions-overview ; https://learn.microsoft.com/graph/paging ; https://learn.microsoft.com/graph/api/serviceprincipal-list-approleassignments
