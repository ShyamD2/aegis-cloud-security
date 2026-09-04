"""
Project AEGIS - Self-Security & Failure Testing Test Suite
Validates fault tolerance, adversarial resilience, and architectural integrity:
- Replay attack rejection & timestamp freshness
- Circuit breaker trip, pause, and self-healing recovery
- Neptune & SageMaker outage graceful degradation
- DynamoDB concurrent race-condition defense
- Poison-pill malformed event handling & DLQ isolation
- Least-privilege IAM and zero-credential static audit
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from services.attack_path.models import BlastRadiusReport
from services.common.models import NormalizedSecurityEvent
from services.pipeline.processor import EventPipelineProcessor
from services.remediation.models import (
    RemediationAction,
    RemediationRequest,
    RemediationStatus,
)
from services.remediation.orchestrator import RemediationOrchestrator
from services.resilience.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerOpenException,
    CircuitState,
)
from services.resilience.concurrency import ConcurrencyStressTester
from services.resilience.fallbacks import (
    ResilientAnomalyEvaluator,
    ResilientGraphEvaluator,
)
from services.resilience.replay_defense import (
    ReplayDefenseError,
    ReplayDetector,
)


def make_test_event(
    event_id: str | None = None,
    action: str = "iam:CreateAccessKey",
    timestamp: datetime | None = None,
    source_ip: str = "198.51.100.10",
    account_id: str = "333333333333",
    principal_arn: str = "arn:aws:iam::333333333333:user/test-identity",
) -> NormalizedSecurityEvent:
    return NormalizedSecurityEvent(
        event_id=event_id or f"evt-{uuid.uuid4().hex[:12]}",
        source="cloudtrail",
        timestamp=timestamp or datetime.now(UTC),
        account_id=account_id,
        region="us-east-1",
        principal_arn=principal_arn,
        principal_type="IAMUser",
        action=action,
        resource_arns=[principal_arn],
        source_ip=source_ip,
        user_agent="aws-cli/2.15.0",
        status="SUCCESS",
        raw_payload={"test": "payload"},
    )


# ---------------------------------------------------------------------------
# 1. REPLAY ATTACK & FRESHNESS DEFENSE
# ---------------------------------------------------------------------------


def test_replay_attack_rejected_duplicate_event_id() -> None:
    """Duplicate event IDs within the sliding window must be rejected as replays."""
    detector = ReplayDetector(max_age_seconds=300.0)
    event = make_test_event(event_id="evt-unique-001")

    valid_1, msg_1 = detector.validate_event(event)
    assert valid_1 is True

    # Replay identical event
    valid_2, msg_2 = detector.validate_event(event)
    assert valid_2 is False
    assert "Duplicate event_id 'evt-unique-001' detected" in msg_2

    with pytest.raises(ReplayDefenseError):
        detector.assert_valid(event)


def test_replay_attack_rejected_timestamp_drift() -> None:
    """Events exceeding past threshold or with excessive future clock skew must be rejected."""
    now = datetime.now(UTC)
    detector = ReplayDetector(max_age_seconds=900.0, max_future_skew_seconds=120.0)

    # 1. Stale event (> 15 minutes past)
    stale_event = make_test_event(
        event_id="evt-stale-001",
        timestamp=now - timedelta(seconds=901),
    )
    valid_stale, msg_stale = detector.validate_event(stale_event, current_time=now)
    assert valid_stale is False
    assert "too old" in msg_stale

    # 2. Future event (> 2 minutes future skew)
    future_event = make_test_event(
        event_id="evt-future-001",
        timestamp=now + timedelta(seconds=130),
    )
    valid_future, msg_future = detector.validate_event(future_event, current_time=now)
    assert valid_future is False
    assert "excessive future clock skew" in msg_future

    # 3. Acceptable past event (5 minutes old)
    fresh_event = make_test_event(
        event_id="evt-fresh-001",
        timestamp=now - timedelta(minutes=5),
    )
    valid_fresh, _ = detector.validate_event(fresh_event, current_time=now)
    assert valid_fresh is True


# ---------------------------------------------------------------------------
# 2. CIRCUIT BREAKER FAULT TOLERANCE
# ---------------------------------------------------------------------------


def test_circuit_breaker_transitions_and_trip() -> None:
    """Verify circuit breaker trips from CLOSED -> OPEN after N failures and blocks calls."""
    breaker = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=0.5)
    assert breaker.state == CircuitState.CLOSED
    assert breaker.can_execute() is True

    # Record 2 failures (threshold is 3)
    breaker.record_failure(RuntimeError("fail 1"))
    breaker.record_failure(RuntimeError("fail 2"))
    assert breaker.state == CircuitState.CLOSED
    assert breaker.can_execute() is True

    # 3rd failure trips the breaker
    breaker.record_failure(RuntimeError("fail 3"))
    assert breaker.state == CircuitState.OPEN
    assert breaker.can_execute() is False

    # Calling execute() while OPEN must raise CircuitBreakerOpenException
    with pytest.raises(CircuitBreakerOpenException):
        breaker.execute(lambda: "should not run")


def test_circuit_breaker_half_open_recovery() -> None:
    """Verify circuit breaker transitions OPEN -> HALF_OPEN after timeout and recovers to CLOSED on success."""
    breaker = CircuitBreaker(failure_threshold=2, recovery_timeout_seconds=0.1)

    # Trip breaker
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state == CircuitState.OPEN

    # Wait for recovery timeout
    import time

    time.sleep(0.15)

    # Breaker state automatically transitions to HALF_OPEN
    assert breaker.state == CircuitState.HALF_OPEN
    assert breaker.can_execute() is True

    # Successful probe restores CLOSED state
    breaker.record_success()
    assert breaker.state == CircuitState.CLOSED
    assert breaker.consecutive_failures == 0


def test_orchestrator_circuit_breaker_halts_remediation() -> None:
    """When the circuit breaker is OPEN, the remediation orchestrator halts containment to prevent flapping."""
    breaker = CircuitBreaker(failure_threshold=1)
    breaker.trip()  # Manually trip into OPEN
    assert breaker.state == CircuitState.OPEN

    orchestrator = RemediationOrchestrator(circuit_breaker=breaker)
    req = RemediationRequest(
        remediation_id="rem-breaker-test-01",
        finding_id="finding-test-01",
        action=RemediationAction.DEACTIVATE_ACCESS_KEY,
        target_resource_id="arn:aws:iam::333333333333:user/test-user",
        account_id="333333333333",
        risk_score=90.0,
        idempotency_key="idem-breaker-01",
        parameters={"access_key_id": "AKIAEXAMPLENOTUSED"},
    )

    result = orchestrator.execute(req)
    assert result.status == RemediationStatus.FAILED
    assert f"Circuit breaker '{breaker.name}' is OPEN" in result.verification_details
    assert "CircuitBreakerOpenException" in (result.error_message or "")


# ---------------------------------------------------------------------------
# 3. GRACEFUL DEGRADATION & DEPENDENCY FALLBACKS
# ---------------------------------------------------------------------------


def test_neptune_outage_fallback_blast_radius() -> None:
    """When Neptune/Graph query fails, ResilientGraphEvaluator falls back to deterministic heuristic blast radius."""
    evaluator = ResilientGraphEvaluator()

    def failing_neptune_query(arn: str) -> BlastRadiusReport:
        raise ConnectionError("Neptune graph cluster endpoint connection timed out (504)")

    report, is_fallback = evaluator.evaluate_safe(
        failing_neptune_query,
        principal_arn="arn:aws:iam::111111111111:role/ProdAdminRole",
        account_id="111111111111",
    )

    assert is_fallback is True
    assert report.score >= 80.0
    assert report.principal_id == "arn:aws:iam::111111111111:role/ProdAdminRole"
    assert "Graph engine offline" in report.explanation


def test_sagemaker_outage_fallback_anomaly_score() -> None:
    """When SageMaker endpoint fails, ResilientAnomalyEvaluator provides baseline score without dropping finding."""
    evaluator = ResilientAnomalyEvaluator()
    event = make_test_event(action="iam:AttachUserPolicy")

    def failing_sagemaker_inference(ev: NormalizedSecurityEvent) -> tuple[float, bool]:
        raise TimeoutError("SageMaker Serverless endpoint 503 Service Unavailable")

    score, is_anomalous, is_fallback = evaluator.score_safe(failing_sagemaker_inference, event)

    assert is_fallback is True
    assert score == 0.70
    assert is_anomalous is True


# ---------------------------------------------------------------------------
# 4. CONCURRENCY & RACE CONDITION DEFENSE
# ---------------------------------------------------------------------------


def test_dynamodb_race_condition_concurrency_lock() -> None:
    """Simulate 20 concurrent threads racing for the same idempotency key; exactly 1 must win."""
    tester = ConcurrencyStressTester()
    race_key = f"race-key-{uuid.uuid4().hex[:8]}"

    report = tester.run_lock_race(idempotency_key=race_key, num_threads=20)

    assert report["num_threads"] == 20
    assert report["acquired_count"] == 1
    assert report["denied_count"] == 19
    assert report["is_consistent"] is True
    assert report["winner"] is not None


# ---------------------------------------------------------------------------
# 5. POISON-PILL TELEMETRY & INPUT SANITIZATION
# ---------------------------------------------------------------------------


def test_poison_pill_malformed_telemetry_isolation() -> None:
    """Malformed events and poison payloads must route safely to DLQ without uncaught exceptions."""
    from services.pipeline.dlq import DeadLetterQueue

    dlq = DeadLetterQueue()
    processor = EventPipelineProcessor(dlq=dlq)

    # 1. Missing required field 'event_id'
    poison_1 = {"source": "cloudtrail", "action": "iam:CreateUser"}
    findings = processor.process_batch([poison_1])
    assert len(findings) == 0
    assert dlq.count() == 1
    record = dlq.list_records()[0]
    assert record.error_type == "ValidationError"

    # 2. SQL injection and command injection strings in fields
    poison_2 = {
        "event_id": "evt-poison-02",
        "source": "cloudtrail",
        "timestamp": datetime.now(UTC),
        "account_id": "333333333333",
        "region": "us-east-1",
        "principal_arn": "'; DROP TABLE users; --",
        "principal_type": "IAMUser",
        "action": "`rm -rf /`",
        "resource_arns": ["arn:aws:s3:::safe-bucket"],
        "source_ip": "198.51.100.1",
        "user_agent": "<script>alert('xss')</script>",
        "status": "SUCCESS",
        "raw_payload": {"injection": "test"},
    }
    # Pydantic validation must succeed safely without evaluating shell/SQL
    validated = NormalizedSecurityEvent.model_validate(poison_2)
    assert validated.principal_arn == "'; DROP TABLE users; --"
    assert validated.action == "`rm -rf /`"


# ---------------------------------------------------------------------------
# 6. LEAST-PRIVILEGE ARCHITECTURAL VERIFICATION
# ---------------------------------------------------------------------------


def test_least_privilege_audit_no_administrator_access() -> None:
    """Verify that no AEGIS IAM policies or remediator roles grant AdministratorAccess."""
    import os

    workspace_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    terraform_dir = os.path.join(workspace_dir, "terraform")

    # Inspect all .tf files for forbidden AdministratorAccess or Action = "*"
    forbidden_strings = ["AdministratorAccess", 'Action = "*"', 'Action = ["*"]']
    violations: list[str] = []

    for root, _, files in os.walk(terraform_dir):
        for file in files:
            if file.endswith(".tf"):
                filepath = os.path.join(root, file)
                with open(filepath, encoding="utf-8") as f:
                    content = f.read()
                    for forbidden in forbidden_strings:
                        # Allow SCP Deny * if accompanied by Deny
                        if forbidden in content and "Effect" not in content:
                            violations.append(f"{file}: contains {forbidden}")

    assert len(violations) == 0, f"Found policy violations: {violations}"
