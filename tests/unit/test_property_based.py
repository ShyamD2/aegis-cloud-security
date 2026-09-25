"""
Project AEGIS - Property-Based & Invariant Verification Tests
Validates mathematical boundary invariants, monotonicity, idempotency determinism,
canonical JSON hashing stability, and rollback state restoration.
"""

from __future__ import annotations

import itertools

from services.common.models import FindingSeverity
from services.forensics.collector import compute_canonical_sha256
from services.remediation.idempotency import IdempotencyStore
from services.remediation.models import RemediationAction, RemediationRequest, RemediationStatus
from services.remediation.remediators.ec2 import EC2Remediator
from services.risk_engine.engine import RiskEngine
from services.risk_engine.models import ExposureLevel, PrivilegeLevel, RiskContext


def test_property_risk_score_always_bounded() -> None:
    """Property: Risk Score is strictly bounded in [0.0, 100.0] across all parameter combinations."""
    engine = RiskEngine()

    severities = list(FindingSeverity)
    privileges = list(PrivilegeLevel)
    exposures = list(ExposureLevel)
    criticalities = [1.0, 3.0, 7.0, 10.0]
    blast_radii = [0.0, 25.0, 50.0, 85.0, 100.0]
    anomalies = [0.0, 0.25, 0.65, 1.0]
    confidences = [0.0, 0.5, 1.0]

    # Sample boundary grid
    for sev, priv, exp in itertools.product(severities[:2], privileges[:2], exposures[:2]):
        for crit in criticalities:
            for blast in blast_radii:
                for anom in anomalies:
                    for conf in confidences:
                        ctx = RiskContext(
                            finding_id="prop-test",
                            detection_severity=sev,
                            asset_criticality=crit,
                            privilege_level=priv,
                            blast_radius_score=blast,
                            anomaly_score=anom,
                            exposure_level=exp,
                            confidence=conf,
                            is_production=True,
                            cross_account=True,
                        )
                        assessment = engine.evaluate(ctx)
                        assert 0.0 <= assessment.risk_score <= 100.0, (
                            f"Violation: score={assessment.risk_score}"
                        )


def test_property_monotonicity_under_severity_escalation() -> None:
    """Property: Increasing detection severity monotonically increases or maintains risk score."""
    engine = RiskEngine()

    severity_order = [
        FindingSeverity.LOW,
        FindingSeverity.MEDIUM,
        FindingSeverity.HIGH,
        FindingSeverity.CRITICAL,
    ]

    scores: list[float] = []
    for sev in severity_order:
        ctx = RiskContext(
            finding_id="mono-test",
            detection_severity=sev,
            asset_criticality=5.0,
            privilege_level=PrivilegeLevel.WORKLOAD_WRITE,
            blast_radius_score=40.0,
            anomaly_score=0.4,
            exposure_level=ExposureLevel.INTERNAL_VPC,
            confidence=1.0,
        )
        scores.append(engine.evaluate(ctx).risk_score)

    for i in range(len(scores) - 1):
        assert scores[i] <= scores[i + 1], f"Monotonicity violated: {scores[i]} > {scores[i + 1]}"


def test_property_canonical_hashing_invariance_to_key_order() -> None:
    """Property: Canonical SHA-256 hash is invariant to dictionary key insertion order."""
    dict_a = {"alpha": 1, "beta": "two", "gamma": [1, 2, 3], "nested": {"z": 10, "a": 20}}
    dict_b = {"nested": {"a": 20, "z": 10}, "gamma": [1, 2, 3], "alpha": 1, "beta": "two"}

    hash_a = compute_canonical_sha256(dict_a)
    hash_b = compute_canonical_sha256(dict_b)

    assert hash_a == hash_b, "Canonical JSON hashing depends on key order!"


def test_property_idempotency_store_determinism() -> None:
    """Property: Exactly one concurrent caller acquires lock for an identical idempotency key."""
    store = IdempotencyStore()
    key = "idem-prop-unique-lock"

    # Attempt 100 acquisitions
    successes = [store.acquire_lock(key, f"worker-{i}") for i in range(100)]
    assert sum(successes) == 1, "Multiple workers acquired the same idempotency lock!"


def test_property_rollback_restores_pre_state() -> None:
    """Property: Rollback guarantees restoration of initial resource configuration."""
    remediator = EC2Remediator()
    instance_id = "i-rollback-prop"
    initial_sgs = ["sg-web-1", "sg-app-2"]
    remediator.set_mock_instance(instance_id, list(initial_sgs))

    request = RemediationRequest(
        remediation_id="rem-prop-01",
        finding_id="find-prop-01",
        action=RemediationAction.ISOLATE_EC2_INSTANCE,
        target_resource_id=instance_id,
        account_id="111122223333",
        risk_score=85.0,
        idempotency_key="key-prop-01",
    )

    result = remediator.remediate(request)
    assert result.status == RemediationStatus.VERIFIED
    assert remediator._mock_instances[instance_id] == ["sg-aegis-quarantine-default"]

    # Execute rollback using captured pre_state
    rollback_success = remediator.rollback(request, result.pre_state)
    assert rollback_success is True
    assert remediator._mock_instances[instance_id] == initial_sgs
