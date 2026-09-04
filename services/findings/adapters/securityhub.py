"""Adapter normalizing AWS Security Hub ASFF findings into canonical SecurityFinding models."""

from datetime import UTC, datetime
from typing import Any

from services.common.models import FindingSeverity, FindingStatus, SecurityFinding


def map_asff_severity(label: str) -> FindingSeverity:
    """Map ASFF Severity.Label string to AEGIS FindingSeverity."""
    upper = label.upper()
    if upper == "CRITICAL":
        return FindingSeverity.CRITICAL
    if upper == "HIGH":
        return FindingSeverity.HIGH
    if upper == "MEDIUM":
        return FindingSeverity.MEDIUM
    if upper == "LOW":
        return FindingSeverity.LOW
    return FindingSeverity.INFORMATIONAL


def normalize_securityhub_finding(raw: dict[str, Any]) -> SecurityFinding:
    """Transform an AWS Security Hub ASFF finding into a canonical SecurityFinding."""
    detail = raw.get("detail", raw)
    # Support findings array or single finding
    findings_list = detail.get("findings", [detail])
    finding = findings_list[0] if findings_list else detail

    finding_id = finding.get("Id") or raw.get("id")
    if not finding_id:
        raise ValueError("Security Hub finding is missing mandatory identifier ('Id')")

    title = finding.get("Title", "Security Hub Finding")
    description = finding.get("Description", "")
    account_id = finding.get("AwsAccountId", raw.get("account", "000000000000"))
    region = finding.get("Region", raw.get("region", "us-east-1"))
    severity_label = finding.get("Severity", {}).get("Label", "MEDIUM")
    severity = map_asff_severity(severity_label)

    # Extract target resources
    target_resources: list[str] = []
    for res in finding.get("Resources", []):
        res_id = res.get("Id")
        if res_id:
            target_resources.append(res_id)

    if not target_resources:
        target_resources.append(f"arn:aws:securityhub:{region}:{account_id}:finding/{finding_id}")

    created_at_str = finding.get("CreatedAt")
    created_at = (
        datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
        if created_at_str
        else datetime.now(UTC)
    )

    clean_id = finding_id.split("/")[-1]
    return SecurityFinding(
        finding_id=f"aegis-sh-{clean_id}",
        rule_id=finding.get("GeneratorId", "SECURITY-HUB-GENERATOR"),
        title=title,
        description=description,
        severity=severity,
        confidence=0.85,
        status=FindingStatus.NEW,
        created_at=created_at,
        account_id=account_id,
        region=region,
        principal_arn=f"arn:aws:iam::{account_id}:root",
        target_resources=target_resources,
        mitre_attack_technique=finding.get("Compliance", {}).get("SecurityControlId"),
        evidence={
            "product_arn": finding.get("ProductArn"),
            "compliance_status": finding.get("Compliance", {}).get("Status"),
            "remediation_text": finding.get("Remediation", {})
            .get("Recommendation", {})
            .get("Text"),
        },
        recommended_response="Remediate configuration drift according to Security Hub recommendation.",
    )
