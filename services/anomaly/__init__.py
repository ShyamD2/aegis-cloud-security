"""AEGIS Behavioral Anomaly Detection Package."""

from services.anomaly.dataset import TelemetrySample, generate_synthetic_dataset
from services.anomaly.features import FeatureExtractor, FeatureVector
from services.anomaly.inference import AnomalyInferenceEngine, AnomalyInferenceResult
from services.anomaly.model import AnomalyModel, EvaluationMetrics

__all__ = [
    "FeatureExtractor",
    "FeatureVector",
    "generate_synthetic_dataset",
    "TelemetrySample",
    "AnomalyModel",
    "EvaluationMetrics",
    "AnomalyInferenceEngine",
    "AnomalyInferenceResult",
]
