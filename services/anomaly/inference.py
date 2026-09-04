"""Inference engine providing an operational API for behavioral anomaly evaluation."""

import time
from typing import Any

from pydantic import BaseModel, Field

from services.anomaly.features import FeatureExtractor, FeatureVector
from services.anomaly.model import AnomalyModel
from services.common.models import NormalizedSecurityEvent


class AnomalyInferenceResult(BaseModel):
    """Result emitted by the behavioral anomaly inference engine."""

    anomaly_score: float = Field(ge=0.0, le=1.0, description="Normalized score 0.0 to 1.0")
    is_anomaly: bool
    inference_latency_ms: float
    feature_vector: FeatureVector
    top_contributing_features: list[dict[str, Any]] = Field(default_factory=list)


class AnomalyInferenceEngine:
    """Operational inference service interface simulating SageMaker Serverless Inference."""

    def __init__(self, model: AnomalyModel | None = None) -> None:
        self.model = model or AnomalyModel()
        self.feature_extractor = FeatureExtractor()

    def evaluate_event(self, event: NormalizedSecurityEvent) -> AnomalyInferenceResult:
        """Score an incoming event and return anomaly probability with latency measurement."""
        start_time = time.perf_counter()

        # Extract features
        fv = self.feature_extractor.extract(event)

        # Run inference
        score = self.model.predict_anomaly_score(fv)
        is_anom = score >= self.model.anomaly_threshold

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        # Compute top contributing features
        features_dict = fv.model_dump()
        sorted_features = sorted(
            [{"name": k, "value": v} for k, v in features_dict.items()],
            key=lambda x: x["value"],
            reverse=True,
        )

        return AnomalyInferenceResult(
            anomaly_score=score,
            is_anomaly=is_anom,
            inference_latency_ms=round(latency_ms, 3),
            feature_vector=fv,
            top_contributing_features=sorted_features[:3],
        )
