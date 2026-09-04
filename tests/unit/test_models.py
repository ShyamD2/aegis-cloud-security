"""Unit tests for AEGIS telemetry models and normalized schemas."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from services.common.models import (
    CloudTrailRecord,
    FindingSeverity,
    FindingStatus,
    NormalizedSecurityEvent,
    SecurityFinding,
)


@pytest.mark.unit
def test_cloudtrail_record_parsing(sample_cloudtrail_raw_event: dict) -> None:
    """Verify that AWS CloudTrail JSON structures parse correctly into CloudTrailRecord."""
    record = CloudTrailRecord.model_validate(sample_cloudtrail_raw_event)
    assert record.event_id == "f1e2d3c4-b5a6-0987-6543-21fedcba0987"
    assert record.event_name == "CreateAccessKey"
    assert record.user_identity.arn == "arn:aws:iam::123456789012:user/developer-dave"
    assert record.user_identity.user_name == "developer-dave"
    assert record.recipient_account_id == "123456789012"
    assert record.aws_region == "us-east-1"


@pytest.mark.unit
def test_normalized_event_validation(sample_normalized_event: NormalizedSecurityEvent) -> None:
    """Verify NormalizedSecurityEvent schema integrity and serialization."""
    assert sample_normalized_event.action == "iam:CreateAccessKey"
    assert sample_normalized_event.source == "cloudtrail"
    data = sample_normalized_event.model_dump()
    assert data["status"] == "SUCCESS"
    assert "event_id" in data


@pytest.mark.unit
def test_normalized_event_extra_fields_forbidden() -> None:
    """NormalizedSecurityEvent must reject unrecognized fields (extra='forbid')."""
    with pytest.raises(ValidationError):
        NormalizedSecurityEvent(  # type: ignore[call-arg]
            event_id="test-1",
            source="cloudtrail",
            timestamp=datetime.now(UTC),
            account_id="123456789012",
            region="us-east-1",
            principal_arn="arn:aws:iam::123456789012:user/alice",
            principal_type="IAMUser",
            action="s3:GetObject",
            unrecognized_field="malicious_payload",
        )


@pytest.mark.unit
def test_security_finding_confidence_bounds(sample_critical_finding: SecurityFinding) -> None:
    """Verify that finding confidence must fall strictly between 0.0 and 1.0."""
    assert sample_critical_finding.severity == FindingSeverity.CRITICAL
    assert sample_critical_finding.confidence == 0.92

    # Test confidence out of bounds (> 1.0)
    with pytest.raises(ValidationError):
        SecurityFinding(
            finding_id="f-bad",
            rule_id="AEGIS-001",
            title="Bad Confidence",
            description="Test",
            severity=FindingSeverity.HIGH,
            confidence=1.5,  # Invalid
            account_id="123456789012",
            region="us-east-1",
            principal_arn="arn:aws:iam::123456789012:user/alice",
        )

    # Test confidence out of bounds (< 0.0)
    with pytest.raises(ValidationError):
        SecurityFinding(
            finding_id="f-bad-2",
            rule_id="AEGIS-001",
            title="Bad Confidence",
            description="Test",
            severity=FindingSeverity.HIGH,
            confidence=-0.1,  # Invalid
            account_id="123456789012",
            region="us-east-1",
            principal_arn="arn:aws:iam::123456789012:user/alice",
        )


@pytest.mark.unit
def test_finding_status_lifecycle() -> None:
    """Verify transitions across finding statuses."""
    finding = SecurityFinding(
        finding_id="f-100",
        rule_id="AEGIS-002",
        title="Test Status Lifecycle",
        description="Verify status progression",
        severity=FindingSeverity.MEDIUM,
        confidence=0.85,
        account_id="123456789012",
        region="us-east-1",
        principal_arn="arn:aws:iam::123456789012:role/WorkloadRole",
    )
    assert finding.status == FindingStatus.NEW
    finding.status = FindingStatus.CONTAINING
    assert finding.status == FindingStatus.CONTAINING
    finding.status = FindingStatus.VERIFIED
    assert finding.status == FindingStatus.VERIFIED
