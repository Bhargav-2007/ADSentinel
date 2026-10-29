# MITRE ATT&CK mapping

Mappings indicate related adversary behavior, not execution or confirmed compromise.

| Module | Indicator | Technique |
|---|---|---|
| kerberos | Kerberos preauthentication disabled | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) |
| kerberos | Service principal eligible for service-ticket requests | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| kerberos | RC4-only Kerberos account | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| delegation | Unconstrained delegation enabled | [T1558](https://attack.mitre.org/techniques/T1558/) |
| delegation | Protocol transition configured | [T1550.003](https://attack.mitre.org/techniques/T1550/003/) |
| gpo | Low-privilege GPO modification path | [T1484.001](https://attack.mitre.org/techniques/T1484/001/) |
| laps | LAPS coverage gap | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) |
| laps | Excessive LAPS password-read rights | [T1555](https://attack.mitre.org/techniques/T1555/) |
| gmsa | Excessive gMSA password-read rights | [T1555](https://attack.mitre.org/techniques/T1555/) |
| gmsa | Unmanaged service account | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |
| smb | SMB signing not required | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) |
| smb | SMBv1 enabled | [T1210](https://attack.mitre.org/techniques/T1210/) |
| smb | Anonymous share access reported | [T1135](https://attack.mitre.org/techniques/T1135/) |
| ldap | LDAP signing not required | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) |
| ldap | LDAP channel binding not enforced | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) |
| ntlm | NTLMv1 accepted | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) |
| dns | Insecure DNS dynamic updates | [T1557](https://attack.mitre.org/techniques/T1557/) |
| dns | Unrestricted zone transfer reported | [T1018](https://attack.mitre.org/techniques/T1018/) |
| rdp | RDP NLA not required | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) |
| rdp | Excessive RDP access | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) |
| winrm | WinRM Basic authentication over HTTP | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) |
| trusts | SID filtering disabled on a trust | [T1134.005](https://attack.mitre.org/techniques/T1134/005/) |
| account-hygiene | Account password never expires | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |
| account-hygiene | Reversible password encryption enabled | [T1003](https://attack.mitre.org/techniques/T1003/) |
| account-hygiene | Dormant privileged account | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |
| privileged-access | Privileged account used on lower-tier host | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |
| baseline | Unsupported operating system reported | [T1210](https://attack.mitre.org/techniques/T1210/) |
| detection-coverage | PowerShell script-block logging disabled | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| detection-coverage | Security auditing disabled | [T1562.002](https://attack.mitre.org/techniques/T1562/002/) |
| azure-ad | Synchronized identity has cloud privilege | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) |
| azure-ad | Overprivileged application reported | [T1098.003](https://attack.mitre.org/techniques/T1098/003/) |
| azure-ad | Expired application credential metadata | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) |
| adcs | ESC1 configuration | T1649 |
| acl | Directory control edges | T1098 |
| dcsync-check | Replication permission combination | T1003.006 |
| password-policy | Password policy review | T1110 |
