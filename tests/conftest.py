"""Shared Pytest fixtures and mock telemetry payloads for AEGIS test suite."""

from datetime import UTC, datetime
from typing import Any

import pytest

from services.common.models import (
    FindingSeverity,
    FindingStatus,
    NormalizedSecurityEvent,
    SecurityFinding,
)


@pytest.fixture
def sample_cloudtrail_raw_event() -> dict[str, Any]:
    """Sample raw AWS CloudTrail JSON record representing an IAM key creation event."""
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE123456789",
            "arn": "arn:aws:iam::123456789012:user/developer-dave",
            "accountId": "123456789012",
            "userName": "developer-dave",
        },
        "eventTime": "2026-09-04T12:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.24",
        "userAgent": "aws-cli/2.15.0 Python/3.11 Linux/5.15",
        "requestParameters": {
            "userName": "developer-dave",
        },
        "responseElements": {
            "accessKey": {
                "accessKeyId": "AKIAEXAMPLE987654321",
                "status": "Active",
                "userName": "developer-dave",
                "createDate": "Sep 4, 2026 12:00:00 PM",
            }
        },
        "requestID": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
        "eventID": "f1e2d3c4-b5a6-0987-6543-21fedcba0987",
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": "123456789012",
    }


@pytest.fixture
def sample_normalized_event() -> NormalizedSecurityEvent:
    """Pre-built NormalizedSecurityEvent fixture."""
    return NormalizedSecurityEvent(
        event_id="f1e2d3c4-b5a6-0987-6543-21fedcba0987",
        source="cloudtrail",
        timestamp=datetime(2026, 9, 4, 12, 0, 0, tzinfo=UTC),
        account_id="123456789012",
        region="us-east-1",
        principal_arn="arn:aws:iam::123456789012:user/developer-dave",
        principal_type="IAMUser",
        action="iam:CreateAccessKey",
        resource_arns=["arn:aws:iam::123456789012:user/developer-dave"],
        source_ip="198.51.100.24",
        user_agent="aws-cli/2.15.0 Python/3.11",
        status="SUCCESS",
        raw_payload={"test": "payload"},
    )


@pytest.fixture
def sample_critical_finding() -> SecurityFinding:
    """Pre-built CRITICAL SecurityFinding fixture."""
    return SecurityFinding(
        finding_id="aegis-find-20260904-001",
        rule_id="AEGIS-DET-001",
        title="Suspicious IAM Access Key Created by Non-Admin User",
        description="IAM access key created outside standard deployment pipelines from non-corporate IP.",
        severity=FindingSeverity.CRITICAL,
        confidence=0.92,
        status=FindingStatus.NEW,
        created_at=datetime(2026, 9, 4, 12, 0, 5, tzinfo=UTC),
        account_id="123456789012",
        region="us-east-1",
        principal_arn="arn:aws:iam::123456789012:user/developer-dave",
        target_resources=["arn:aws:iam::123456789012:user/developer-dave"],
        mitre_attack_technique="T1078.004",
        evidence={
            "source_ip": "198.51.100.24",
            "access_key_id": "AKIAEXAMPLE987654321",
        },
        recommended_response="Deactivate access key AKIAEXAMPLE987654321 and attach quarantine session policy.",
    )
