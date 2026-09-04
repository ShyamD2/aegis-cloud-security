"""
Project AEGIS - Security Risk Engine Unit Tests
Validates deterministic scoring, monotonicity, boundary conditions, factor breakdowns,
confidence scaling, and explainability narratives.
"""

from __future__ import annotations

from services.common.models import FindingSeverity
from services.risk_engine import (
    ExposureLevel,
    PrivilegeLevel,
    RiskContext,
    RiskEngine,
    RiskLevel,
)


def test_boundary_minimum_inputs() -> None:
    """Verify minimum inputs produce a calibrated LOW risk score (<= 25.0)."""
    engine = RiskEngine()
    context = RiskContext(
        finding_id="test-min-001",
        detection_severity=FindingSeverity.LOW,
        confidence=0.1,
        asset_criticality=1.0,
        privilege_level=PrivilegeLevel.UNPRIVILEGED,
        exposure_level=ExposureLevel.ISOLATED_PRIVATE,
        blast_radius_score=0.0,
        anomaly_score=0.0,
        is_production=False,
        cross_account=False,
    )
    assessment = engine.evaluate(context)

    assert assessment.risk_score <= 25.0
    assert assessment.risk_level == RiskLevel.LOW
    assert "LOW" in assessment.explanation


def test_boundary_maximum_inputs() -> None:
    """Verify maximal inputs saturate to 100.0 CRITICAL risk score."""
    engine = RiskEngine()
    context = RiskContext(
        finding_id="test-max-001",
        detection_severity=FindingSeverity.CRITICAL,
        confidence=1.0,
        asset_criticality=10.0,
        privilege_level=PrivilegeLevel.ADMINISTRATOR,
        exposure_level=ExposureLevel.INTERNET_FACING,
        blast_radius_score=100.0,
        anomaly_score=1.0,
        is_production=True,
        cross_account=True,
    )
    assessment = engine.evaluate(context)

    assert assessment.risk_score == 100.0
    assert assessment.risk_level == RiskLevel.CRITICAL
    assert "CRITICAL" in assessment.explanation


def test_monotonicity_across_dimensions() -> None:
    """Verify that increasing any single risk parameter monotonically increases the final score."""
    engine = RiskEngine()
    base = RiskContext(
        finding_id="test-mono-001",
        detection_severity=FindingSeverity.LOW,
        confidence=0.8,
        asset_criticality=3.0,
        privilege_level=PrivilegeLevel.READ_ONLY,
        exposure_level=ExposureLevel.INTERNAL_VPC,
        blast_radius_score=20.0,
        anomaly_score=0.1,
    )
    base_score = engine.evaluate(base).risk_score

    # Increase severity
    score_high_sev = engine.evaluate(
        base.model_copy(update={"detection_severity": FindingSeverity.HIGH})
    ).risk_score
    assert score_high_sev > base_score

    # Increase blast radius
    score_high_blast = engine.evaluate(
        base.model_copy(update={"blast_radius_score": 85.0})
    ).risk_score
    assert score_high_blast > base_score

    # Increase anomaly score
    score_high_anomaly = engine.evaluate(base.model_copy(update={"anomaly_score": 0.95})).risk_score
    assert score_high_anomaly > base_score

    # Increase privilege
    score_admin = engine.evaluate(
        base.model_copy(update={"privilege_level": PrivilegeLevel.ADMINISTRATOR})
    ).risk_score
    assert score_admin > base_score


def test_factor_breakdown_consistency() -> None:
    """Verify all 6 factors are present in breakdown and sum correctly to base score."""
    engine = RiskEngine()
    context = RiskContext(
        finding_id="test-factors-001",
        detection_severity=FindingSeverity.HIGH,
        confidence=1.0,
        asset_criticality=8.0,
        privilege_level=PrivilegeLevel.IAM_WRITE,
        exposure_level=ExposureLevel.RESTRICTED_INGRESS,
        blast_radius_score=50.0,
        anomaly_score=0.4,
    )
    assessment = engine.evaluate(context)

    assert len(assessment.factor_breakdown) == 6
    factor_names = {f.factor_name for f in assessment.factor_breakdown}
    assert factor_names == {
        "Detection Severity",
        "Asset Criticality",
        "Identity Privilege",
        "Graph Blast Radius",
        "Behavioral Anomaly",
        "Network Exposure",
    }
    calculated_sum = sum(f.weighted_contribution for f in assessment.factor_breakdown)
    assert abs(calculated_sum - assessment.risk_score) <= 1.0


def test_confidence_attenuation() -> None:
    """Verify lower confidence dampens the risk score."""
    engine = RiskEngine()
    high_conf = RiskContext(
        finding_id="test-conf-high",
        detection_severity=FindingSeverity.HIGH,
        confidence=1.0,
        asset_criticality=5.0,
        privilege_level=PrivilegeLevel.WORKLOAD_WRITE,
        exposure_level=ExposureLevel.INTERNAL_VPC,
        blast_radius_score=40.0,
        anomaly_score=0.5,
    )
    low_conf = high_conf.model_copy(update={"confidence": 0.0})

    score_high = engine.evaluate(high_conf).risk_score
    score_low = engine.evaluate(low_conf).risk_score

    assert score_low < score_high
    assert score_low == round(score_high * 0.8, 1)


def test_production_and_cross_account_modifiers() -> None:
    """Verify production and cross-account modifiers add expected point bonuses."""
    engine = RiskEngine()
    base = RiskContext(
        finding_id="test-modifiers",
        detection_severity=FindingSeverity.MEDIUM,
        confidence=1.0,
        asset_criticality=5.0,
        privilege_level=PrivilegeLevel.WORKLOAD_WRITE,
        exposure_level=ExposureLevel.INTERNAL_VPC,
        blast_radius_score=30.0,
        anomaly_score=0.2,
        is_production=False,
        cross_account=False,
    )
    base_score = engine.evaluate(base).risk_score

    prod_score = engine.evaluate(base.model_copy(update={"is_production": True})).risk_score
    assert prod_score == base_score + 5.0

    cross_score = engine.evaluate(base.model_copy(update={"cross_account": True})).risk_score
    assert cross_score == base_score + 5.0

    both_score = engine.evaluate(
        base.model_copy(update={"is_production": True, "cross_account": True})
    ).risk_score
    assert both_score == base_score + 10.0


def test_cvss_critical_floor_enforcement() -> None:
    """Verify a critical CVSS >= 9.0 vulnerability elevates score to at least 75.0."""
    engine = RiskEngine()
    benign_context = RiskContext(
        finding_id="test-cvss-floor",
        detection_severity=FindingSeverity.LOW,
        confidence=1.0,
        asset_criticality=2.0,
        privilege_level=PrivilegeLevel.UNPRIVILEGED,
        exposure_level=ExposureLevel.ISOLATED_PRIVATE,
        blast_radius_score=10.0,
        anomaly_score=0.05,
        vulnerability_cvss=9.8,
    )
    assessment = engine.evaluate(benign_context)

    assert assessment.risk_score >= 75.0
    assert assessment.risk_level == RiskLevel.CRITICAL
    assert "CVSS 9.8 Critical Vulnerability" in assessment.explanation
