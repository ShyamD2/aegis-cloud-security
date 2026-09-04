"""Synthetic cloud telemetry dataset generator for behavioral anomaly training and evaluation.

Transparency note:
This dataset is synthetic and modeled on cloud access distributions:
- Normal developer baselines (routine working hours, standard VPC subnets, s3/ec2 actions)
- Anomalous adversary samples (off-hours API bursts, external IP enumeration, root access, rare regions)
"""

import random
from dataclasses import dataclass

from services.anomaly.features import FeatureVector


@dataclass
class TelemetrySample:
    """A labeled feature vector sample."""

    features: FeatureVector
    is_anomaly: bool
    label_description: str


def generate_synthetic_dataset(
    normal_count: int = 1000,
    anomaly_count: int = 150,
    seed: int = 42,
) -> list[TelemetrySample]:
    """Generate a balanced labeled dataset of normal and anomalous cloud telemetry samples."""
    rng = random.Random(seed)  # noqa: S311
    samples: list[TelemetrySample] = []

    # 1. Normal Samples (low frequency, typical hours, internal IP, standard services)
    for _i in range(normal_count):
        fv = FeatureVector(
            api_frequency_1h=rng.uniform(0.01, 0.15),
            api_sequence_entropy=rng.uniform(0.1, 0.4),
            time_of_day_deviation=rng.choice([0.0, 0.0, 0.0, 0.1]),
            source_ip_distance=rng.choice([0.0, 0.0, 0.0, 0.1]),
            region_deviation=0.0,
            account_deviation=0.0,
            privilege_score=rng.choice([0.2, 0.4]),
            resource_sensitivity=rng.choice([0.2, 0.4, 0.6]),
            unusual_service_flag=0.0,
        )
        samples.append(
            TelemetrySample(
                features=fv,
                is_anomaly=False,
                label_description="Normal developer pipeline or routine console session",
            )
        )

    # 2. Anomalous Samples (high frequency bursts, off-hours, external IPs, privilege spikes)
    anomaly_types = [
        "Credential stuffing / high-frequency burst",
        "Off-hours reconnaissance from external IP",
        "Cross-account AssumeRole into sensitive vault",
        "Root account activity in unapproved region",
    ]

    for _i in range(anomaly_count):
        atype = rng.choice(anomaly_types)
        if "burst" in atype:
            fv = FeatureVector(
                api_frequency_1h=rng.uniform(0.7, 1.0),
                api_sequence_entropy=rng.uniform(0.7, 0.95),
                time_of_day_deviation=rng.uniform(0.5, 0.8),
                source_ip_distance=rng.uniform(0.8, 1.0),
                region_deviation=rng.choice([0.0, 1.0]),
                account_deviation=rng.choice([0.0, 1.0]),
                privilege_score=rng.uniform(0.6, 1.0),
                resource_sensitivity=rng.uniform(0.6, 1.0),
                unusual_service_flag=rng.choice([0.0, 1.0]),
            )
        else:
            fv = FeatureVector(
                api_frequency_1h=rng.uniform(0.2, 0.6),
                api_sequence_entropy=rng.uniform(0.6, 0.9),
                time_of_day_deviation=0.8,
                source_ip_distance=0.95,
                region_deviation=rng.choice([0.0, 1.0]),
                account_deviation=1.0,
                privilege_score=rng.uniform(0.8, 1.0),
                resource_sensitivity=1.0,
                unusual_service_flag=1.0,
            )
        samples.append(
            TelemetrySample(
                features=fv,
                is_anomaly=True,
                label_description=atype,
            )
        )

    rng.shuffle(samples)
    return samples
