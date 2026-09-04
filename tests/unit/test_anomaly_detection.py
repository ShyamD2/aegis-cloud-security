"""Unit tests for Phase 07 Behavioral Anomaly Detection, feature extraction, and ML evaluation."""

from datetime import UTC, datetime

import pytest

from services.anomaly.dataset import generate_synthetic_dataset
from services.anomaly.features import FeatureExtractor
from services.anomaly.inference import AnomalyInferenceEngine
from services.anomaly.model import AnomalyModel
from services.common.models import NormalizedSecurityEvent


def make_normal_event() -> NormalizedSecurityEvent:
    """Helper generating normal routine developer activity."""
    return NormalizedSecurityEvent(
        event_id="norm-evt-001",
        source="cloudtrail",
        timestamp=datetime(2026, 9, 4, 14, 0, 0, tzinfo=UTC),  # Business hours
        account_id="123456789012",
        region="us-east-1",
        principal_arn="arn:aws:iam::123456789012:user/developer-bob",
        principal_type="IAMUser",
        action="s3:GetObject",
        resource_arns=["arn:aws:s3:::standard-app-bucket/index.html"],
        source_ip="10.0.1.25",  # Internal private IP
        user_agent="aws-sdk-python/1.34.0",
        status="SUCCESS",
        raw_payload={},
    )


def make_anomalous_event() -> NormalizedSecurityEvent:
    """Helper generating anomalous off-hours external root burst activity."""
    return NormalizedSecurityEvent(
        event_id="anom-evt-999",
        source="cloudtrail",
        timestamp=datetime(2026, 9, 4, 3, 30, 0, tzinfo=UTC),  # 03:30 AM off-hours
        account_id="123456789012",
        region="me-central-1",  # Unapproved region
        principal_arn="arn:aws:iam::123456789012:root",  # Root principal
        principal_type="Root",
        action="secretsmanager:GetSecretValue",
        resource_arns=[
            "arn:aws:secretsmanager:me-central-1:123456789012:secret:master-prod-credential-vault"
        ],
        source_ip="203.0.113.199",  # External public IP
        user_agent="curl/7.88.1",
        status="SUCCESS",
        raw_payload={},
    )


@pytest.mark.unit
def test_feature_extraction() -> None:
    """Validate that 9 numerical features are computed within bounds [0.0, 1.0]."""
    norm_event = make_normal_event()
    fv_norm = FeatureExtractor.extract(norm_event, historical_frequency=5)

    assert fv_norm.source_ip_distance == 0.0
    assert fv_norm.region_deviation == 0.0
    assert fv_norm.time_of_day_deviation == 0.0
    assert fv_norm.privilege_score == 0.2
    assert len(fv_norm.to_list()) == 9

    anom_event = make_anomalous_event()
    fv_anom = FeatureExtractor.extract(anom_event, historical_frequency=450)

    assert fv_anom.source_ip_distance > 0.9
    assert fv_anom.region_deviation == 1.0
    assert fv_anom.privilege_score == 1.0
    assert fv_anom.resource_sensitivity == 1.0
    assert fv_anom.api_frequency_1h > 0.8


@pytest.mark.unit
def test_synthetic_dataset_generation() -> None:
    """Validate dataset generator produces balanced and properly labeled samples."""
    samples = generate_synthetic_dataset(normal_count=200, anomaly_count=30, seed=123)
    assert len(samples) == 230

    normals = [s for s in samples if not s.is_anomaly]
    anomalies = [s for s in samples if s.is_anomaly]

    assert len(normals) == 200
    assert len(anomalies) == 30
    assert (
        "burst" in anomalies[0].label_description
        or "Off-hours" in anomalies[0].label_description
        or "Root" in anomalies[0].label_description
        or "Cross-account" in anomalies[0].label_description
    )


@pytest.mark.unit
def test_model_training_and_evaluation() -> None:
    """Train AnomalyModel on synthetic normal baseline and verify real statistical metrics."""
    train_data = generate_synthetic_dataset(normal_count=800, anomaly_count=0, seed=42)
    test_data = generate_synthetic_dataset(normal_count=200, anomaly_count=50, seed=99)

    model = AnomalyModel(anomaly_threshold=0.60)
    model.train(train_data)

    metrics = model.evaluate(test_data)
    assert metrics.sample_count == 250
    assert metrics.true_positives > 0

    # Ensure model attains strong real metrics without fabrication
    assert metrics.precision >= 0.80, f"Expected precision >= 0.80, got {metrics.precision}"
    assert metrics.recall >= 0.80, f"Expected recall >= 0.80, got {metrics.recall}"
    assert metrics.false_positive_rate <= 0.15, (
        f"Expected FPR <= 0.15, got {metrics.false_positive_rate}"
    )
    assert metrics.f1_score >= 0.80


@pytest.mark.unit
def test_anomaly_inference_api() -> None:
    """Test operational AnomalyInferenceEngine scoring and latency measurement."""
    train_data = generate_synthetic_dataset(normal_count=500, anomaly_count=0, seed=42)
    model = AnomalyModel()
    model.train(train_data)

    engine = AnomalyInferenceEngine(model=model)

    # 1. Normal event should produce low anomaly score
    res_normal = engine.evaluate_event(make_normal_event())
    assert res_normal.anomaly_score < 0.50
    assert res_normal.is_anomaly is False
    assert res_normal.inference_latency_ms < 50.0
    assert len(res_normal.top_contributing_features) == 3

    # 2. Anomalous event should produce elevated anomaly score
    res_anom = engine.evaluate_event(make_anomalous_event())
    assert res_anom.anomaly_score >= 0.60
    assert res_anom.is_anomaly is True
    assert res_anom.inference_latency_ms < 50.0
