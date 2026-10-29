# Isolated lab

Begin with `examples/evidence.json`; all names and findings are synthetic. Use snapshots and an isolated virtual network for any real AD lab. Never connect deliberately vulnerable lab controllers to production or public networks. Create a dedicated low-privilege read account, a trusted test CA and a DNS name matching the LDAPS certificate.

Enable only the settings needed for a test, export normalized policy evidence without passwords, analyze it, then restore the snapshot. Use mock Graph transport and ldap3 MOCK_SYNC in tests; CI does not connect to a real directory. No network scan was performed during development. Actual AD/Entra behavior and packaged binaries require independent lab verification before use.
