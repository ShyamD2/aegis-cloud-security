"""Behavioral anomaly model and statistical evaluation metrics."""

import math
from dataclasses import dataclass

from services.anomaly.dataset import TelemetrySample
from services.anomaly.features import FeatureVector


@dataclass
class EvaluationMetrics:
    """Statistical evaluation metrics computed on labeled test splits."""

    sample_count: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    false_positive_rate: float
    f1_score: float


class AnomalyModel:
    """Unsupervised centroid and deviation-based behavioral anomaly scoring model."""

    def __init__(self, anomaly_threshold: float = 0.65) -> None:
        self.anomaly_threshold = anomaly_threshold
        self.baseline_mean: list[float] = [0.0] * 9
        self.baseline_std: list[float] = [1.0] * 9
        self.feature_weights: list[float] = [
            0.15,  # api_frequency
            0.10,  # sequence_entropy
            0.10,  # time_of_day
            0.15,  # source_ip
            0.10,  # region
            0.10,  # account
            0.10,  # privilege
            0.10,  # resource_sensitivity
            0.10,  # unusual_service
        ]
        self._is_trained = False

    def train(self, normal_samples: list[TelemetrySample]) -> None:
        """Fit the baseline distribution over known normal developer sessions."""
        if not normal_samples:
            raise ValueError("Training requires at least one normal sample.")

        vectors = [s.features.to_list() for s in normal_samples if not s.is_anomaly]
        if not vectors:
            raise ValueError("No normal samples found in training set.")

        dim = len(vectors[0])
        # Compute mean per feature
        means = [sum(v[d] for v in vectors) / len(vectors) for d in range(dim)]

        # Compute standard deviation per feature
        stds = []
        for d in range(dim):
            variance = sum((v[d] - means[d]) ** 2 for v in vectors) / len(vectors)
            std = math.sqrt(variance)
            stds.append(max(0.01, std))  # Avoid division by zero

        self.baseline_mean = means
        self.baseline_std = stds
        self._is_trained = True

    def predict_anomaly_score(self, feature_vector: FeatureVector) -> float:
        """Compute an anomaly score between 0.0 and 1.0.

        Calculates weighted normalized Euclidean distance from the learned baseline centroid.
        """
        features = feature_vector.to_list()
        weighted_dist_sq = 0.0

        for d in range(len(features)):
            z = (features[d] - self.baseline_mean[d]) / self.baseline_std[d]
            weighted_dist_sq += self.feature_weights[d] * (z**2)

        # Sigmoid compression to [0.0, 1.0]
        dist = math.sqrt(weighted_dist_sq)
        score = 1.0 / (1.0 + math.exp(-0.75 * (dist - 2.5)))
        return round(min(1.0, max(0.0, score)), 4)

    def is_anomaly(self, feature_vector: FeatureVector) -> bool:
        """Return True if anomaly score exceeds operational threshold."""
        return self.predict_anomaly_score(feature_vector) >= self.anomaly_threshold

    def evaluate(self, test_samples: list[TelemetrySample]) -> EvaluationMetrics:
        """Evaluate the model against a test split and compute precision, recall, and FPR."""
        tp = fp = tn = fn = 0

        for sample in test_samples:
            score = self.predict_anomaly_score(sample.features)
            predicted_anomaly = score >= self.anomaly_threshold
            actual_anomaly = sample.is_anomaly

            if predicted_anomaly and actual_anomaly:
                tp += 1
            elif predicted_anomaly and not actual_anomaly:
                fp += 1
            elif not predicted_anomaly and not actual_anomaly:
                tn += 1
            elif not predicted_anomaly and actual_anomaly:
                fn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        return EvaluationMetrics(
            sample_count=len(test_samples),
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            false_positive_rate=round(fpr, 4),
            f1_score=round(f1, 4),
        )
