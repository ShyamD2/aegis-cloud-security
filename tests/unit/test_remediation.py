"""
Project AEGIS - Automated Incident Response & Self-Healing Unit Tests
Validates IAM key/session containment, EC2 quarantine, S3 public access blocking,
account approval gates, DynamoDB idempotency locking, and automated rollback.
"""

from __future__ import annotations

from services.remediation import (
    SECURITY_LAB_ACCOUNT_ID,
    AccountQuarantineRemediator,
    EC2Remediator,
    IAMRemediator,
    IdempotencyStore,
    RemediationAction,
    RemediationOrchestrator,
    RemediationRequest,
    RemediationStatus,
    S3Remediator,
)


def test_iam_remediation_key_deactivation() -> None:
    """Verify IAM access key deactivation, verification, and rollback."""
    remediator = IAMRemediator()
    request = RemediationRequest(
        remediation_id="rem-iam-001",
        finding_id="find-001",
        action=RemediationAction.DEACTIVATE_ACCESS_KEY,
        target_resource_id="arn:aws:iam::111122223333:user/contractor-alice",
        account_id="111122223333",
        risk_score=85.0,
        idempotency_key="key-iam-001",
        parameters={"access_key_id": "AKIAIOSFODNN7EXAMPLE"},
    )

    result = remediator.remediate(request)
    assert result.status == RemediationStatus.VERIFIED
    assert result.verified is True
    assert result.post_state["status"] == "Inactive"
    assert "AKIAIOSFODNN7EXAMPLE" in result.verification_details

    # Test Rollback
    rolled_back = remediator.rollback(request, result.pre_state)
    assert rolled_back is True
    assert remediator._mock_key_statuses["AKIAIOSFODNN7EXAMPLE"] == "Active"


def test_iam_remediation_session_revocation() -> None:
    """Verify IAM session invalidation policy with aws:TokenIssueTime condition."""
    remediator = IAMRemediator()
    request = RemediationRequest(
        remediation_id="rem-iam-002",
        finding_id="find-002",
        action=RemediationAction.REVOKE_IAM_SESSIONS,
        target_resource_id="arn:aws:iam::111122223333:role/CompromisedDevRole",
        account_id="111122223333",
        risk_score=90.0,
        idempotency_key="key-iam-002",
    )

    result = remediator.remediate(request)
    assert result.status == RemediationStatus.VERIFIED
    assert result.verified is True
    assert result.post_state["policy_name"] == "AEGIS-SessionRevocation-Policy"

    # Test Rollback
    rolled_back = remediator.rollback(request, result.pre_state)
    assert rolled_back is True
    assert "AEGIS-SessionRevocation-Policy" not in remediator._mock_inline_policies.get(
        "CompromisedDevRole", {}
    )


def test_ec2_remediation_isolation() -> None:
    """Verify EC2 instance isolation into quarantine security group and rollback."""
    remediator = EC2Remediator()
    remediator.set_mock_instance("i-0123456789abcdef0", ["sg-web", "sg-ssh"])

    request = RemediationRequest(
        remediation_id="rem-ec2-001",
        finding_id="find-003",
        action=RemediationAction.ISOLATE_EC2_INSTANCE,
        target_resource_id="i-0123456789abcdef0",
        account_id="111122223333",
        risk_score=95.0,
        idempotency_key="key-ec2-001",
        parameters={"quarantine_sg_id": "sg-aegis-quarantine"},
    )

    result = remediator.remediate(request)
    assert result.status == RemediationStatus.VERIFIED
    assert result.verified is True
    assert result.post_state["active_security_groups"] == ["sg-aegis-quarantine"]
    assert result.pre_state["original_security_groups"] == ["sg-web", "sg-ssh"]

    # Test Rollback
    rolled_back = remediator.rollback(request, result.pre_state)
    assert rolled_back is True
    assert remediator._mock_instances["i-0123456789abcdef0"] == ["sg-web", "sg-ssh"]


def test_s3_remediation_block_public() -> None:
    """Verify S3 Block Public Access enforcement across all 4 flags and rollback."""
    remediator = S3Remediator()
    remediator.set_mock_bucket(
        "exposed-data-bucket",
        {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )

    request = RemediationRequest(
        remediation_id="rem-s3-001",
        finding_id="find-004",
        action=RemediationAction.ENFORCE_S3_BLOCK_PUBLIC,
        target_resource_id="arn:aws:s3:::exposed-data-bucket",
        account_id="111122223333",
        risk_score=80.0,
        idempotency_key="key-s3-001",
    )

    result = remediator.remediate(request)
    assert result.status == RemediationStatus.VERIFIED
    assert result.verified is True
    assert all(result.post_state.values())

    # Test Rollback
    rolled_back = remediator.rollback(request, result.pre_state)
    assert rolled_back is True
    assert remediator._mock_pab["exposed-data-bucket"]["BlockPublicAcls"] is False


def test_account_quarantine_approval_gate() -> None:
    """Verify non-lab account quarantine requires valid human approval token."""
    remediator = AccountQuarantineRemediator()

    # Attempt 1: Production account without approval token -> Rejected
    unapproved_req = RemediationRequest(
        remediation_id="rem-acc-001",
        finding_id="find-005",
        action=RemediationAction.QUARANTINE_ACCOUNT,
        target_resource_id="111111111111",  # Prod Account
        account_id="111111111111",
        risk_score=100.0,
        idempotency_key="key-acc-001",
        requires_human_approval=True,
    )
    result_rejected = remediator.remediate(unapproved_req)
    assert result_rejected.status == RemediationStatus.FAILED
    assert result_rejected.verified is False
    assert "requires valid human approval token" in result_rejected.verification_details

    # Attempt 2: Production account with approval token -> Approved
    approved_req = unapproved_req.model_copy(
        update={"approval_token": "SOC-AUTH-APPROVED-SEC-LEAD-2026"}
    )
    result_approved = remediator.remediate(approved_req)
    assert result_approved.status == RemediationStatus.VERIFIED
    assert result_approved.verified is True

    # Attempt 3: Security Lab account defaults to allowed without approval token
    lab_req = RemediationRequest(
        remediation_id="rem-acc-002",
        finding_id="find-006",
        action=RemediationAction.QUARANTINE_ACCOUNT,
        target_resource_id=SECURITY_LAB_ACCOUNT_ID,
        account_id=SECURITY_LAB_ACCOUNT_ID,
        risk_score=95.0,
        idempotency_key="key-acc-002",
    )
    result_lab = remediator.remediate(lab_req)
    assert result_lab.status == RemediationStatus.VERIFIED


def test_idempotency_locking() -> None:
    """Verify idempotency store blocks repeated concurrent containment executions."""
    store = IdempotencyStore()
    key = "idem-unique-hash-12345"

    # First lock attempt succeeds
    assert store.acquire_lock(key, "rem-001") is True

    # Second lock attempt with identical key fails
    assert store.acquire_lock(key, "rem-002") is False


def test_orchestrator_risk_gating() -> None:
    """Verify orchestrator gates execution based on calculated risk score."""
    orchestrator = RemediationOrchestrator()

    # Risk score = 30.0 (LOW/MEDIUM) -> Log only, zero active containment
    low_risk_req = RemediationRequest(
        remediation_id="rem-gate-001",
        finding_id="find-gate-001",
        action=RemediationAction.ISOLATE_EC2_INSTANCE,
        target_resource_id="i-testlowrisk",
        account_id="111122223333",
        risk_score=30.0,
        idempotency_key="key-gate-low",
    )
    result_low = orchestrator.execute(low_risk_req)
    assert result_low.status == RemediationStatus.COMPLETED
    assert "below containment threshold" in result_low.verification_details

    # Risk score = 85.0 (CRITICAL) -> Autonomous containment executes
    orchestrator.ec2.set_mock_instance("i-testhighrisk", ["sg-prod"])
    high_risk_req = RemediationRequest(
        remediation_id="rem-gate-002",
        finding_id="find-gate-002",
        action=RemediationAction.ISOLATE_EC2_INSTANCE,
        target_resource_id="i-testhighrisk",
        account_id="111122223333",
        risk_score=85.0,
        idempotency_key="key-gate-high",
    )
    result_high = orchestrator.execute(high_risk_req)
    assert result_high.status == RemediationStatus.VERIFIED
    assert result_high.verified is True
