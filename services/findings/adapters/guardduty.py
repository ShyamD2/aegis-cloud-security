"""Adapter normalizing Amazon GuardDuty findings into canonical SecurityFinding models."""

from datetime import UTC, datetime
from typing import Any

from services.common.models import FindingSeverity, FindingStatus, SecurityFinding


def map_guardduty_severity(score: float) -> FindingSeverity:
    """Map GuardDuty 0.1-10.0 numeric severity to AEGIS FindingSeverity."""
    if score >= 9.0:
        return FindingSeverity.CRITICAL
    if score >= 7.0:
        return FindingSeverity.HIGH
    if score >= 4.0:
        return FindingSeverity.MEDIUM
    if score >= 1.0:
        return FindingSeverity.LOW
    return FindingSeverity.INFORMATIONAL


def normalize_guardduty_finding(raw: dict[str, Any]) -> SecurityFinding:
    """Transform an Amazon GuardDuty finding into a canonical SecurityFinding."""
    detail = raw.get("detail", raw)
    finding_id = detail.get("id") or raw.get("id")
    if not finding_id:
        raise ValueError("GuardDuty finding is missing mandatory identifier ('id')")

    title = detail.get("title") or detail.get("type", "Unknown GuardDuty Finding")
    description = detail.get("description", "")
    account_id = detail.get("accountId", raw.get("account", "000000000000"))
    region = detail.get("region", raw.get("region", "us-east-1"))
    raw_severity = float(detail.get("severity", 0.0))
    severity = map_guardduty_severity(raw_severity)

    # Extract target resource ARNs
    target_resources: list[str] = []
    resource_block = detail.get("resource", {})
    resource_type = resource_block.get("resourceType", "")

    if resource_type == "Instance":
        inst_id = resource_block.get("instanceDetails", {}).get("instanceId")
        if inst_id:
            target_resources.append(f"arn:aws:ec2:{region}:{account_id}:instance/{inst_id}")
    elif resource_type == "S3Bucket":
        for bucket in resource_block.get("s3BucketDetails", []):
            b_name = bucket.get("name")
            if b_name:
                target_resources.append(f"arn:aws:s3:::{b_name}")
    elif resource_type == "AccessKey":
        key_user = resource_block.get("accessKeyDetails", {}).get("userName")
        if key_user:
            target_resources.append(f"arn:aws:iam::{account_id}:user/{key_user}")

    if not target_resources:
        target_resources.append(f"arn:aws:guardduty:{region}:{account_id}:detector/unknown")

    # Extract actor principal ARN
    actor_principal = (
        resource_block.get("accessKeyDetails", {}).get("principalId")
        or f"arn:aws:iam::{account_id}:principal/unknown"
    )

    created_at_str = detail.get("createdAt")
    created_at = (
        datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
        if created_at_str
        else datetime.now(UTC)
    )

    return SecurityFinding(
        finding_id=f"aegis-gd-{finding_id}",
        rule_id=detail.get("type", "GUARDDUTY-RULE"),
        title=title,
        description=description,
        severity=severity,
        confidence=min(1.0, max(0.5, raw_severity / 10.0)),
        status=FindingStatus.NEW,
        created_at=created_at,
        account_id=account_id,
        region=region,
        principal_arn=actor_principal,
        target_resources=target_resources,
        mitre_attack_technique=detail.get("service", {})
        .get("evidence", {})
        .get("threatIntelligenceDetails", [{}])[0]
        .get("threatNames", [None])[0],
        evidence={
            "guardduty_id": finding_id,
            "raw_severity": raw_severity,
            "finding_type": detail.get("type"),
            "service_action": detail.get("service", {}).get("action", {}),
        },
        recommended_response="Review GuardDuty actor IP and quarantine compromised credentials/instances.",
    )
