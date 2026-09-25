"""
Project AEGIS - OCSF v1.1.0 Schema & Adapter Unit Tests
Validates bidirectional normalization between AWS telemetry and OCSF events.
"""

from __future__ import annotations

from datetime import UTC, datetime

from services.common.models import FindingSeverity, NormalizedSecurityEvent
from services.common.ocsf import (
    OCSFAdapter,
    OCSFCategory,
    OCSFClass,
    OCSFSeverity,
)


def test_normalized_event_to_ocsf_iam_action() -> None:
    """Verify that an IAM mutation translates to OCSF Account Change (Class 3001)."""
    norm_event = NormalizedSecurityEvent(
        event_id="evt-ocsf-001",
        source="aws.iam",
        timestamp=datetime.now(UTC),
        account_id="197550036081",
        region="us-east-1",
        principal_arn="arn:aws:iam::197550036081:user/test-admin",
        principal_type="IAMUser",
        action="iam:CreateAccessKey",
        resource_arns=["arn:aws:iam::197550036081:user/compromised-user"],
        source_ip="198.51.100.24",
    )

    ocsf = OCSFAdapter.from_normalized_event(norm_event)

    assert ocsf.class_uid == OCSFClass.ACCOUNT_CHANGE
    assert ocsf.category_uid == OCSFCategory.IDENTITY_ACCESS_MANAGEMENT
    assert ocsf.type_uid == 300101
    assert ocsf.cloud.account_uid == "197550036081"
    assert ocsf.actor.name == "test-admin"
    assert ocsf.src_endpoint is not None
    assert ocsf.src_endpoint.ip == "198.51.100.24"


def test_cloudtrail_to_ocsf_authentication() -> None:
    """Verify CloudTrail AssumeRole converts to OCSF Authentication (Class 3002)."""
    raw_ct = {
        "eventVersion": "1.08",
        "eventID": "ct-uuid-12345",
        "eventTime": "2026-09-25T12:00:00Z",
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.50",
        "recipientAccountId": "197550036081",
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": "AROAEXAMPLE:session-1",
            "arn": "arn:aws:sts::197550036081:assumed-role/DevRole/session-1",
            "accountId": "197550036081",
            "userName": "DevRole",
        },
        "requestParameters": {
            "roleArn": "arn:aws:iam::111111111111:role/ProductionAdmin",
            "roleSessionName": "lateral-pivot",
        },
    }

    ocsf = OCSFAdapter.from_cloudtrail(raw_ct)

    assert ocsf.class_uid == OCSFClass.AUTHENTICATION
    assert ocsf.category_uid == OCSFCategory.IDENTITY_ACCESS_MANAGEMENT
    assert ocsf.actor.name == "DevRole"
    assert ocsf.api is not None
    assert ocsf.api.operation == "AssumeRole"
    assert ocsf.src_endpoint is not None
    assert ocsf.src_endpoint.ip == "203.0.113.50"


def test_security_finding_to_ocsf() -> None:
    """Verify AEGIS security finding converts to OCSF Security Finding (Class 2001)."""
    ocsf = OCSFAdapter.from_security_finding(
        finding_id="aegis-f-9999",
        title="Unauthorized Root Access Detected",
        severity=FindingSeverity.CRITICAL,
        account_id="197550036081",
        region="us-east-1",
        resource_arns=["arn:aws:iam::197550036081:root"],
        description="Root user logged in without hardware MFA.",
    )

    assert ocsf.class_uid == OCSFClass.SECURITY_FINDING
    assert ocsf.category_uid == OCSFCategory.FINDINGS
    assert ocsf.severity_id == OCSFSeverity.CRITICAL
    assert len(ocsf.resources) == 1
    assert ocsf.resources[0].uid == "arn:aws:iam::197550036081:root"


def test_bidirectional_ocsf_normalization() -> None:
    """Verify OCSF event converts cleanly back to an AEGIS NormalizedSecurityEvent."""
    original = NormalizedSecurityEvent(
        event_id="evt-roundtrip-777",
        source="aws.s3",
        timestamp=datetime.now(UTC),
        account_id="197550036081",
        region="us-west-2",
        principal_arn="arn:aws:iam::197550036081:role/pipeline-worker",
        principal_type="AssumedRole",
        action="s3:DeleteBucketPolicy",
        resource_arns=["arn:aws:s3:::sensitive-financial-records"],
        source_ip="10.0.4.15",
    )

    ocsf = OCSFAdapter.from_normalized_event(original)
    reconstituted = ocsf.to_normalized_event()

    assert reconstituted.source == original.source
    assert reconstituted.account_id == original.account_id
    assert reconstituted.region == original.region
    assert reconstituted.action == original.action
    assert reconstituted.resource_arns == original.resource_arns
    assert reconstituted.source_ip == original.source_ip
