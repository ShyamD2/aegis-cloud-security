"""Adapter normalizing Amazon Detective investigation summaries into canonical SecurityFinding models."""

from datetime import UTC, datetime
from typing import Any

from services.common.models import FindingSeverity, FindingStatus, SecurityFinding


def normalize_detective_finding(raw: dict[str, Any]) -> SecurityFinding:
    """Transform an Amazon Detective finding/investigation event into a canonical SecurityFinding."""
    detail = raw.get("detail", raw)
    investigation_id = detail.get("investigationId") or raw.get("id")
    if not investigation_id:
        raise ValueError("Detective event is missing mandatory identifier ('investigationId')")

    entity_arn = detail.get("entityArn", "")
    account_id = detail.get("accountId", raw.get("account", "000000000000"))
    region = detail.get("region", raw.get("region", "us-east-1"))
    title = detail.get("title", f"Detective Investigation: {investigation_id}")

    return SecurityFinding(
        finding_id=f"aegis-det-{investigation_id}",
        rule_id="DETECTIVE-INVESTIGATION",
        title=title,
        description=detail.get("description", "Cross-account investigation graph anomaly"),
        severity=FindingSeverity.HIGH,
        confidence=0.88,
        status=FindingStatus.ANALYZING,
        created_at=datetime.now(UTC),
        account_id=account_id,
        region=region,
        principal_arn=entity_arn or f"arn:aws:iam::{account_id}:root",
        target_resources=[entity_arn]
        if entity_arn
        else [f"arn:aws:detective:{region}:{account_id}:investigation/{investigation_id}"],
        mitre_attack_technique="T1078",
        evidence={
            "investigation_id": investigation_id,
            "indicators": detail.get("indicators", []),
            "triage_scope": detail.get("scope", {}),
        },
        recommended_response="Review Detective graph investigation timeline and correlate with AEGIS Neptune graph.",
    )
