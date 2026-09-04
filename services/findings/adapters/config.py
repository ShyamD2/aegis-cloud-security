"""Adapter normalizing AWS Config compliance notifications into canonical SecurityFinding models."""

from datetime import UTC, datetime
from typing import Any

from services.common.models import FindingSeverity, FindingStatus, SecurityFinding


def normalize_config_finding(raw: dict[str, Any]) -> SecurityFinding:
    """Transform an AWS Config compliance change event into a canonical SecurityFinding."""
    detail = raw.get("detail", raw)
    config_rule = detail.get("configRuleName", "unknown-config-rule")
    compliance_type = detail.get("newEvaluationResult", {}).get("complianceType", "NON_COMPLIANT")
    account_id = detail.get("awsAccountId", raw.get("account", "000000000000"))
    region = detail.get("awsRegion", raw.get("region", "us-east-1"))

    resource_id = (
        detail.get("newEvaluationResult", {})
        .get("evaluationResultIdentifier", {})
        .get("evaluationResultQualifier", {})
        .get("resourceId", "unknown-resource")
    )
    resource_type = (
        detail.get("newEvaluationResult", {})
        .get("evaluationResultIdentifier", {})
        .get("evaluationResultQualifier", {})
        .get("resourceType", "AWS::Resource")
    )

    finding_id = f"cfg-{account_id}-{config_rule}-{resource_id}"

    # Determine severity based on rule sensitivity
    severity = FindingSeverity.MEDIUM
    if "s3-bucket-public" in config_rule.lower() or "iam-root" in config_rule.lower():
        severity = FindingSeverity.HIGH

    return SecurityFinding(
        finding_id=f"aegis-cfg-{finding_id}",
        rule_id=f"CONFIG-{config_rule}",
        title=f"Config Rule Non-Compliant: {config_rule}",
        description=f"Resource {resource_id} ({resource_type}) evaluated as {compliance_type} for rule {config_rule}.",
        severity=severity,
        confidence=0.90,
        status=FindingStatus.NEW if compliance_type == "NON_COMPLIANT" else FindingStatus.RESOLVED,
        created_at=datetime.now(UTC),
        account_id=account_id,
        region=region,
        principal_arn=f"arn:aws:iam::{account_id}:root",
        target_resources=[f"arn:aws:{resource_type.lower()}:{region}:{account_id}:{resource_id}"],
        mitre_attack_technique=None,
        evidence={
            "config_rule": config_rule,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "compliance_type": compliance_type,
        },
        recommended_response="Review resource configuration and remediate non-compliant settings.",
    )
