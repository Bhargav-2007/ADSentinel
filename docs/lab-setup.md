# Isolated lab validation

Authorization reference: ADS-LAB-ROE-001. Keep the actual inventory local. The required source interface must be assigned on the host-only/internal network; do not route tests over physical networks, VPNs or external infrastructure.

1. Validate official public data and unit/loopback tests first.
2. Attach the authorized source interface and verify isolation. Configure the approved account/password locally.
3. Trust the lab CA or supply --ca-cert; use --tls-server-name when connecting to a DC IP.
4. Run lab-preflight with the local scope file, then a scoped --dry-run.
5. Collect passive directory/DNS data and manually compare native tools/configuration.
6. Check only explicitly permitted hosts; stop immediately if instability appears.
7. Keep unavailable intrusive checks unvalidated. High-impact work needs the separate maintenance window.

Live pytest is disabled by default. Set ADS_SENTINEL_RUN_LAB=1, ADS_SENTINEL_LAB_SCOPE, ADS_SENTINEL_LAB_DC, ADS_SENTINEL_USERNAME and ADS_SENTINEL_PASSWORD locally, then run tests/integration/test_authorized_lab.py. These collection smoke checks do not replace manual false-positive/negative review. The simplified harness expects system CA trust; use the CLI for custom CA/server-name options.

No live data was collected: the permitted source was unavailable and local credential variables were unset. See validation/lab/lab-validation-report.md.

Populate the local scope file allowed_accounts array from the approved local account inventory before any named authentication; an empty list refuses named accounts. Use the exact bind identity/UPN, matched case-insensitively. Never publish that inventory.
