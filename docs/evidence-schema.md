# Normalized evidence schema
Evidence is a JSON object containing optional arrays of records. Unknown fields are retained (with recognized secret fields redacted); absent fields are unknown. Boolean indicators must be JSON `true`/`false`, not strings or numbers. Records use an `id` string. The complete synthetic example is `examples/evidence.json`. Evidence represents observations from an approved source; do not fabricate flags from assumptions.

Common collections: `users`, `groups`, `computers`, `ous`, `gpos`, `templates`, `trusts`, `dns`, `applications`, `edges`, `replication_rights`, `password_policies`. Supply only metadata, never secret values.

| Module | Collection | Field | Finding when equal to |
|---|---|---|---|
| kerberos | users | `preauth_required` | `false` |
| kerberos | users | `has_spn` | `true` |
| kerberos | users | `rc4_only` | `true` |
| delegation | computers | `unconstrained_delegation` | `true` |
| delegation | users | `protocol_transition` | `true` |
| gpo | gpos | `writable_by_low_privilege` | `true` |
| laps | computers | `laps_enabled` | `false` |
| laps | computers | `excessive_laps_readers` | `true` |
| gmsa | users | `excessive_gmsa_readers` | `true` |
| gmsa | users | `manual_service_account` | `true` |
| smb | computers | `smb_signing_required` | `false` |
| smb | computers | `smb1_enabled` | `true` |
| smb | computers | `anonymous_shares` | `true` |
| ldap | computers | `ldap_signing_required` | `false` |
| ldap | computers | `channel_binding_required` | `false` |
| ntlm | computers | `ntlmv1_enabled` | `true` |
| dns | dns | `insecure_dynamic_updates` | `true` |
| dns | dns | `zone_transfer_unrestricted` | `true` |
| rdp | computers | `nla_required` | `false` |
| rdp | computers | `excessive_rdp_access` | `true` |
| winrm | computers | `winrm_basic_http` | `true` |
| trusts | trusts | `sid_filtering` | `false` |
| account-hygiene | users | `password_never_expires` | `true` |
| account-hygiene | users | `reversible_encryption` | `true` |
| account-hygiene | users | `dormant_privileged` | `true` |
| privileged-access | users | `tiering_violation` | `true` |
| baseline | computers | `unsupported_os` | `true` |
| detection-coverage | computers | `script_block_logging` | `false` |
| detection-coverage | computers | `security_auditing` | `false` |
| azure-ad | users | `hybrid_privileged` | `true` |
| azure-ad | applications | `overprivileged` | `true` |
| azure-ad | applications | `expired_credential` | `true` |

`templates`: ESC1 requires all of `enrollee_supplies_subject=true`, `client_authentication=true`, `low_privilege_enrollment=true`, `manager_approval=false`, `authorized_signatures=0`, and `published=true`. This is a configuration indicator; effective enrollment and CA policy need independent review.

`replication_rights`: each record has a string `principal` and a `rights` string array. Both `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` generate a critical permission indicator. Resolve effective groups, domain-root scope and deny rules before treating this as effective DCSync access.

`password_policies`: string `id`, integer `minimum_length` and `history_length`. Values below 14 and 24 respectively generate review findings. These are project review thresholds, not universal compliance requirements.

`edges`: each has string `source`, `target` and `relation`. Allowed relationships: `MemberOf`, `GenericAll`, `GenericWrite`, `WriteDACL`, `WriteOwner`, `AddMember`, `ForceChangePassword`, `DCSync`, `ReadLAPSPassword`, `ReadGMSAPassword`, `CanRDP`, `CanPSRemote`, `AdminTo`, `AllowedToDelegate`, `Enroll`, `GPLink`, `Owns`. Direction runs from the controlling principal toward the object. Names match case-insensitively during path traversal. Use canonical names consistently to avoid conflating objects.

Graph risk is a capped sum of edge weights (10 for membership, 30 for other edges), intended for triage. Analysis returns at most 1,000 paths, explores at most 50,000 states and accepts depth 1?12. It fails rather than reporting complete coverage when expansion limits are exceeded.

Finding reports have `schema_version=1.0`, scope, authorization acknowledgement, UTC timestamp, raw evidence reference, coverage, inventory counts, findings and candidate attack paths. Re-render with `adsentinel report --input ...`. Report import is different from normalized evidence import.
