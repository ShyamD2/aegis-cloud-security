"""
Project AEGIS - Autonomous Remediation Safety & Governance Tests
Validates recommendation mode, dry-run mode, kill switch, blast-radius limits, and approval tokens.
"""

from __future__ import annotations

import os

from services.remediation.models import (
    RemediationAction,
    RemediationExecutionMode,
    RemediationRequest,
    RemediationStatus,
)
from services.remediation.orchestrator import RemediationOrchestrator


def test_recommendation_mode_default_generates_advisory() -> None:
    """Verify RECOMMENDATION mode generates structured proposals without mutating AWS resources."""
    orchestrator = RemediationOrchestrator(default_mode=RemediationExecutionMode.RECOMMENDATION)
    orchestrator.ec2.set_mock_instance("i-rec-001", ["sg-prod-web"])

    request = RemediationRequest(
        remediation_id="rem-safety-001",
        finding_id="find-safety-001",
        action=RemediationAction.ISOLATE_EC2_INSTANCE,
        target_resource_id="i-rec-001",
        account_id="111122223333",
        risk_score=85.0,
        idempotency_key="key-safety-rec-001",
    )

    result = orchestrator.execute(request)

    assert result.status == RemediationStatus.COMPLETED
    assert result.execution_mode == RemediationExecutionMode.RECOMMENDATION
    assert result.is_dry_run is False
    assert result.recommendation_text is not None
    assert "RECOMMENDATION:" in result.recommendation_text
    # Verify mock instance was NOT modified
    assert orchestrator.ec2._mock_instances["i-rec-001"] == ["sg-prod-web"]


def test_dry_run_mode_simulates_validation_without_mutation() -> None:
    """Verify DRY_RUN mode validates policy, boundary, and returns verified dry run flag."""
    orchestrator = RemediationOrchestrator(default_mode=RemediationExecutionMode.ENFORCE)
    orchestrator.ec2.set_mock_instance("i-dry-001", ["sg-prod-app"])

    request = RemediationRequest(
        remediation_id="rem-safety-002",
        finding_id="find-safety-002",
        action=RemediationAction.ISOLATE_EC2_INSTANCE,
        target_resource_id="i-dry-001",
        account_id="111122223333",
        risk_score=75.0,
        execution_mode=RemediationExecutionMode.DRY_RUN,
        idempotency_key="key-safety-dry-001",
    )

    result = orchestrator.execute(request)

    assert result.status == RemediationStatus.VERIFIED
    assert result.is_dry_run is True
    assert result.execution_mode == RemediationExecutionMode.DRY_RUN
    assert "DRY RUN SUCCESSFUL:" in result.verification_details
    # Verify mock instance was NOT mutated
    assert orchestrator.ec2._mock_instances["i-dry-001"] == ["sg-prod-app"]


def test_emergency_kill_switch_aborts_all_actions() -> None:
    """Verify global kill switch immediately halts all containment execution."""
    orchestrator = RemediationOrchestrator(kill_switch_active=True)

    request = RemediationRequest(
        remediation_id="rem-safety-003",
        finding_id="find-safety-003",
        action=RemediationAction.REVOKE_IAM_SESSIONS,
        target_resource_id="arn:aws:iam::111122223333:role/CompromisedRole",
        account_id="111122223333",
        risk_score=95.0,
        execution_mode=RemediationExecutionMode.ENFORCE,
        idempotency_key="key-safety-kill-001",
    )

    result = orchestrator.execute(request)

    assert result.status == RemediationStatus.FAILED
    assert "kill switch is ACTIVE" in result.verification_details
    assert "KillSwitchActiveException" in (result.error_message or "")


def test_blast_radius_rate_limiter() -> None:
    """Verify orchestrator blocks excess containment actions on a single account."""
    orchestrator = RemediationOrchestrator(
        default_mode=RemediationExecutionMode.ENFORCE,
        max_actions_per_account_hour=2,
    )
    orchestrator.ec2.set_mock_instance("i-rate-1", ["sg-1"])
    orchestrator.ec2.set_mock_instance("i-rate-2", ["sg-2"])
    orchestrator.ec2.set_mock_instance("i-rate-3", ["sg-3"])

    # Action 1: Passes
    req1 = RemediationRequest(
        remediation_id="rem-rate-01",
        finding_id="find-01",
        action=RemediationAction.ISOLATE_EC2_INSTANCE,
        target_resource_id="i-rate-1",
        account_id="999888777666",
        risk_score=80.0,
        idempotency_key="key-rate-01",
    )
    res1 = orchestrator.execute(req1)
    assert res1.status == RemediationStatus.VERIFIED

    # Action 2: Passes
    req2 = RemediationRequest(
        remediation_id="rem-rate-02",
        finding_id="find-02",
        action=RemediationAction.ISOLATE_EC2_INSTANCE,
        target_resource_id="i-rate-2",
        account_id="999888777666",
        risk_score=80.0,
        idempotency_key="key-rate-02",
    )
    res2 = orchestrator.execute(req2)
    assert res2.status == RemediationStatus.VERIFIED

    # Action 3: Rejected by rate limiter
    req3 = RemediationRequest(
        remediation_id="rem-rate-03",
        finding_id="find-03",
        action=RemediationAction.ISOLATE_EC2_INSTANCE,
        target_resource_id="i-rate-3",
        account_id="999888777666",
        risk_score=80.0,
        idempotency_key="key-rate-03",
    )
    res3 = orchestrator.execute(req3)
    assert res3.status == RemediationStatus.FAILED
    assert "rate limit exceeded" in res3.verification_details


def test_confidence_gate_rejection() -> None:
    """Verify action is rejected when detection confidence is below safety policy threshold."""
    orchestrator = RemediationOrchestrator(default_mode=RemediationExecutionMode.ENFORCE)

    request = RemediationRequest(
        remediation_id="rem-conf-001",
        finding_id="find-conf-001",
        action=RemediationAction.DEACTIVATE_ACCESS_KEY,
        target_resource_id="AKIAEXAMPLETESTKEY",
        account_id="111122223333",
        risk_score=75.0,
        confidence=0.50,  # Below policy minimum 0.80
        idempotency_key="key-conf-001",
    )

    result = orchestrator.execute(request)
    assert result.status == RemediationStatus.FAILED
    assert "below safety policy threshold" in result.verification_details
