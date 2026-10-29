"""AD CS template configuration assessment; never requests or authenticates with certificates."""

from __future__ import annotations

from typing import Any

from ..importers.bloodhound import broad_principal
from ..models import Finding

ADCS_REFERENCE = "https://specterops.io/blog/2024/01/24/adcs-attack-paths-in-bloodhound-part-1/"


def assess(data: dict[str, Any]) -> list[Finding]:
    findings = []
    for template in data.get("templates", []):
        if template.get("published") is not True:
            continue
        requirements = (
            template.get("manager_approval") is False
            and type(template.get("authorized_signatures")) is int
            and template["authorized_signatures"] == 0
            and template.get("low_privilege_enrollment") is True
        )
        ekus = template.get("ekus")
        codes = []
        if (
            requirements
            and template.get("enrollee_supplies_subject") is True
            and template.get("client_authentication") is True
        ):
            codes.append(
                (
                    "ESC1",
                    "Published template allows broad enrollment, supplied subject and client authentication",
                    "HIGH",
                )
            )
        if requirements and isinstance(ekus, list) and (not ekus or "2.5.29.37.0" in ekus):
            codes.append(
                ("ESC2", "Published broad-enrollment template has Any Purpose or no EKU restriction", "HIGH")
            )
        if requirements and isinstance(ekus, list) and "1.3.6.1.4.1.311.20.2.1" in ekus:
            codes.append(("ESC3", "Broad enrollment in a certificate-request-agent template", "HIGH"))
        controls = [
            e
            for e in data.get("edges", [])
            if e["target"] == template["id"]
            and e["relation"]
            in {
                "GenericAll",
                "GenericWrite",
                "WriteDACL",
                "WriteOwner",
                "Owns",
                "WritePKIEnrollmentFlag",
                "WritePKINameFlag",
            }
            and broad_principal(e["source"])
        ]
        if controls:
            codes.append(("ESC4", "Broad principal controls a published certificate template", "HIGH"))
        for code, title, severity in codes:
            evidence = {
                "template": template["id"],
                "template_name": template.get("name"),
                "published_cas": template.get("published_cas", []),
                "enrollees": template.get("enrollers", []),
                "ekus": ekus,
                "manager_approval": template.get("manager_approval"),
                "authorized_signatures": template.get("authorized_signatures"),
                "evidence_reference": template.get("evidence_reference", template["id"]),
                "control_edges": controls if code == "ESC4" else [],
            }
            findings.append(
                Finding(
                    "ADS-" + code,
                    "adcs",
                    title,
                    severity,
                    template["id"],
                    evidence,
                    "T1649",
                    "Monitor CA issuance 4886/4887 and template changes 5136; correlate requester and subject identities.",
                    "Restrict enrollment and template control, remove unnecessary subject/EKU flexibility, require approval where appropriate.",
                    confidence="configuration indicator; CA policy, trust and authentication validation still required",
                    description=f"{code} template-side conditions are present. This does not prove end-to-end impersonation.",
                    references=[ADCS_REFERENCE],
                )
            )
    return findings


def candidate_edges(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Compose ESC1 only when template publication and collected CA enrollment both support it."""
    edges = []
    cas = {c["id"]: c for c in data.get("cas", [])}
    domains = {
        n.get("properties", {}).get("domain"): n["id"]
        for n in data.get("nodes", [])
        if n.get("type") == "Domain"
    }
    for finding in assess(data):
        if finding.rule_id != "ADS-ESC1":
            continue
        template = next(t for t in data["templates"] if t["id"] == finding.affected_object)
        domain = domains.get(template.get("properties", {}).get("domain"))
        if not domain:
            continue
        for ca_id in template.get("published_cas", []):
            ca = cas.get(ca_id, {})
            if ca.get("ca_security_collected") is not True:
                continue
            for principal in template.get("enrollers", []):
                if principal in ca.get("enrollers", []) or any(
                    broad_principal(p) for p in ca.get("enrollers", [])
                ):
                    edges.append(
                        {
                            "source": principal,
                            "target": domain,
                            "relation": "ADCSESC1",
                            "template": template["id"],
                            "ca": ca_id,
                            "evidence_reference": finding.id,
                            "confidence": "conditional configuration path; CA trust, PKINIT and strong mapping require lab validation",
                        }
                    )
    return edges
