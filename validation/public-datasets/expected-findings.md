# Reviewed public-data controls

Source: pinned official SpecterOps AD sample; Properties/Aces/publication were inspected independently. Names identify test cases, never drive finding generation.

| Rule | Public sample object | Expected | Reason |
|---|---|---|---|
| ESC1 | ESC1SMARTCARD@PHANTOM.CORP | Positive configuration indicator | Published; supplied subject; client-auth EKU; broad enrollment; approval false; signatures zero |
| ESC1 | ESC1@PHANTOM.CORP | Negative | Authorized signatures = 1 |
| ESC1 | SMARTCARDLOGON@PHANTOM.CORP | Negative | Manager approval required; subject not supplied |
| ESC3 | ESC3-SELF2@PHANTOM.CORP | Positive configuration indicator | Published enrollment-agent EKU with broad enrollment and no approval/signature gate |
| ESC4 | ABUSABLETEMPLATE@PHANTOM.CORP | Positive configuration indicator | Broad principal controls the published template |

An actual AddMember edge connects SVC_PAYADMIN@PHANTOM.CORP to DOMAIN ADMINS@PHANTOM.CORP. Validation requires the discovered path to use edges from the imported graph.

The benchmark also compares every unique raw allow-ACE relationship and nondeleted ObjectIdentifier to imported sets. It does not establish whole-dataset attack ground truth. CA trust, enrollment restrictions, strong mapping and authentication outcomes require separate lab review.
