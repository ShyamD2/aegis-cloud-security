"""Adapter normalizing Amazon Inspector v2 findings into canonical SecurityFinding models."""

from datetime import UTC, datetime
from typing import Any

from services.common.models import FindingSeverity, FindingStatus, SecurityFinding


def map_inspector_severity(severity_str: str, cvss_score: float) -> FindingSeverity:
    """Map Inspector severity and CVSS score to AEGIS FindingSeverity."""
    upper = severity_str.upper()
    if upper == "CRITICAL" or cvss_score >= 9.0:
        return FindingSeverity.CRITICAL
    if upper == "HIGH" or cvss_score >= 7.0:
        return FindingSeverity.HIGH
    if upper == "MEDIUM" or cvss_score >= 4.0:
        return FindingSeverity.MEDIUM
    return FindingSeverity.LOW


def normalize_inspector_finding(raw: dict[str, Any]) -> SecurityFinding:
    """Transform an Amazon Inspector v2 finding into a canonical SecurityFinding."""
    detail = raw.get("detail", raw)
    finding_arn = detail.get("findingArn") or raw.get("id")
    if not finding_arn:
        raise ValueError("Inspector finding is missing mandatory identifier ('findingArn')")

    title = detail.get("title", "Amazon Inspector Vulnerability")
    description = detail.get("description", "")
    account_id = detail.get("awsAccountId", raw.get("account", "000000000000"))
    region = detail.get("region", raw.get("region", "us-east-1"))
    raw_severity = detail.get("severity", "MEDIUM")

    # Extract CVSS score
    vulnerability = detail.get("packageVulnerabilityDetails", {})
    cve_id = vulnerability.get("vulnerabilityId", "CVE-UNKNOWN")
    cvss_score = 0.0
    for score in vulnerability.get("cvss", []):
        base_score = score.get("baseScore", 0.0)
        if base_score > cvss_score:
            cvss_score = base_score

    severity = map_inspector_severity(raw_severity, cvss_score)

    # Extract resources
    target_resources: list[str] = []
    for res in detail.get("resources", []):
        r_id = res.get("id")
        if r_id:
            target_resources.append(r_id)

    if not target_resources:
        target_resources.append(f"arn:aws:inspector2:{region}:{account_id}:finding/{cve_id}")

    clean_id = finding_arn.split("/")[-1]
    return SecurityFinding(
        finding_id=f"aegis-insp-{clean_id}",
        rule_id=f"INSPECTOR-{cve_id}",
        title=f"{cve_id}: {title}",
        description=description,
        severity=severity,
        confidence=0.95,
        status=FindingStatus.NEW,
        created_at=datetime.now(UTC),
        account_id=account_id,
        region=region,
        principal_arn=f"arn:aws:iam::{account_id}:root",
        target_resources=target_resources,
        mitre_attack_technique="T1190",  # Exploit Public-Facing Application
        evidence={
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "vulnerable_packages": vulnerability.get("vulnerablePackages", []),
            "inspector_severity": raw_severity,
        },
        recommended_response=f"Upgrade vulnerable package identified in {cve_id}.",
    )
