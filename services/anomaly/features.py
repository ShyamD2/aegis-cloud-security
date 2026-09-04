"""Feature engineering translating security events into normalized numerical feature vectors."""

import math

from pydantic import BaseModel, Field

from services.common.models import NormalizedSecurityEvent


class FeatureVector(BaseModel):
    """Normalized 9-dimensional numerical feature vector for anomaly models."""

    api_frequency_1h: float = Field(ge=0.0, le=1.0)
    api_sequence_entropy: float = Field(ge=0.0, le=1.0)
    time_of_day_deviation: float = Field(ge=0.0, le=1.0)
    source_ip_distance: float = Field(ge=0.0, le=1.0)
    region_deviation: float = Field(ge=0.0, le=1.0)
    account_deviation: float = Field(ge=0.0, le=1.0)
    privilege_score: float = Field(ge=0.0, le=1.0)
    resource_sensitivity: float = Field(ge=0.0, le=1.0)
    unusual_service_flag: float = Field(ge=0.0, le=1.0)

    def to_list(self) -> list[float]:
        """Return features as a flat float array."""
        return [
            self.api_frequency_1h,
            self.api_sequence_entropy,
            self.time_of_day_deviation,
            self.source_ip_distance,
            self.region_deviation,
            self.account_deviation,
            self.privilege_score,
            self.resource_sensitivity,
            self.unusual_service_flag,
        ]


class FeatureExtractor:
    """Extracts normalized feature vectors from NormalizedSecurityEvent instances."""

    STANDARD_REGIONS = {"us-east-1", "us-west-2"}
    BUSINESS_HOURS = range(8, 19)  # 08:00 to 18:00 UTC

    @classmethod
    def calculate_entropy(cls, action_names: list[str]) -> float:
        """Calculate normalized Shannon entropy for recent API names."""
        if not action_names:
            return 0.0
        n = len(action_names)
        counts: dict[str, int] = {}
        for a in action_names:
            counts[a] = counts.get(a, 0) + 1

        entropy = 0.0
        for count in counts.values():
            p = count / n
            entropy -= p * math.log2(p)

        # Normalize against log2(max(2, unique_services))
        max_entropy = math.log2(max(2, len(counts)))
        return min(1.0, max(0.0, entropy / max_entropy)) if max_entropy > 0 else 0.0

    @classmethod
    def extract(
        cls,
        event: NormalizedSecurityEvent,
        historical_frequency: int = 1,
        recent_actions: list[str] | None = None,
        historical_services: set[str] | None = None,
    ) -> FeatureVector:
        """Extract and normalize all 9 features from an event."""
        # 1. API Frequency (clamped at 500/hr)
        freq_norm = min(1.0, max(0.0, historical_frequency / 500.0))

        # 2. Sequence Entropy
        actions = recent_actions or [event.action]
        entropy_norm = cls.calculate_entropy(actions)

        # 3. Time of Day Deviation (0.0 during business hours, 0.8 off-hours)
        hour = event.timestamp.hour
        time_dev = 0.0 if hour in cls.BUSINESS_HOURS else 0.8

        # 4. Source IP Distance: Internal=0.0, External=0.95
        ip = event.source_ip
        is_internal = (
            not ip
            or ip.startswith("10.")
            or ip.startswith("172.")
            or ip.startswith("192.168.")
            or ip.startswith("127.")
        )
        ip_dist = 0.0 if is_internal else 0.95

        # 5. Region Deviation: 0.0 for standard regions, 1.0 for unapproved
        region_dev = 0.0 if event.region in cls.STANDARD_REGIONS else 1.0

        # 6. Account Deviation: Cross-account=1.0, Internal=0.0
        account_dev = 0.0
        if "arn:aws:iam::" in event.principal_arn:
            parts = event.principal_arn.split(":")
            if len(parts) >= 5 and parts[4] and parts[4] != event.account_id:
                account_dev = 1.0

        # 7. Privilege Score
        p_lower = event.principal_arn.lower()
        if ":root" in p_lower:
            priv_score = 1.0
        elif "admin" in p_lower:
            priv_score = 0.8
        elif "role" in p_lower:
            priv_score = 0.4
        else:
            priv_score = 0.2

        # 8. Resource Sensitivity
        target_str = " ".join(event.resource_arns).lower()
        if any(k in target_str for k in ["secret", "vault", "kms", "credential"]):
            res_sens = 1.0
        elif any(k in target_str for k in ["s3", "db", "database"]):
            res_sens = 0.6
        else:
            res_sens = 0.2

        # 9. Unusual Service Flag
        service_prefix = event.action.split(":")[0]
        known = historical_services or {"s3", "ec2", "iam", "sts"}
        unusual_service = 0.0 if service_prefix in known else 1.0

        return FeatureVector(
            api_frequency_1h=freq_norm,
            api_sequence_entropy=entropy_norm,
            time_of_day_deviation=time_dev,
            source_ip_distance=ip_dist,
            region_deviation=region_dev,
            account_deviation=account_dev,
            privilege_score=priv_score,
            resource_sensitivity=res_sens,
            unusual_service_flag=unusual_service,
        )
