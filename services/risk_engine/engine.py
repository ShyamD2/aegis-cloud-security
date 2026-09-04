"""
Project AEGIS - Security Risk Engine Core
Evaluates contextual security risk across findings, asset criticality, identity privilege,
graph blast-radius, and behavioral anomalies with complete deterministic explainability.
"""

from __future__ import annotations

import uuid
from typing import Any

from services.common.models import FindingSeverity
from services.risk_engine.models import (
    ExposureLevel,
    PrivilegeLevel,
    RiskAssessment,
    RiskContext,
    RiskFactorContribution,
    RiskLevel,
)


class RiskEngineConfig:
    """Configurable weights and thresholds for the AEGIS Risk Engine."""

    def __init__(
        self,
        weight_severity: float = 0.25,
        weight_criticality: float = 0.15,
        weight_privilege: float = 0.15,
        weight_blast_radius: float = 0.20,
        weight_anomaly: float = 0.15,
        weight_exposure: float = 0.10,
        production_bonus: float = 5.0,
        cross_account_bonus: float = 5.0,
    ) -> None:
        total = (
            weight_severity
            + weight_criticality
            + weight_privilege
            + weight_blast_radius
            + weight_anomaly
            + weight_exposure
        )
        if abs(total - 1.0) > 1e-4:
            raise ValueError(f"Risk factor weights must sum to 1.0 (got {total})")

        self.w_severity = weight_severity
        self.w_criticality = weight_criticality
        self.w_privilege = weight_privilege
        self.w_blast_radius = weight_blast_radius
        self.w_anomaly = weight_anomaly
        self.w_exposure = weight_exposure
        self.production_bonus = production_bonus
        self.cross_account_bonus = cross_account_bonus


class RiskEngine:
    """
    AEGIS Contextual Risk Engine.
    Produces deterministic 0.0 - 100.0 scores with complete factor attribution.
    """

    SEVERITY_MAPPING: dict[FindingSeverity, float] = {
        FindingSeverity.LOW: 20.0,
        FindingSeverity.MEDIUM: 50.0,
        FindingSeverity.HIGH: 75.0,
        FindingSeverity.CRITICAL: 100.0,
    }

    PRIVILEGE_MAPPING: dict[PrivilegeLevel, float] = {
        PrivilegeLevel.UNPRIVILEGED: 20.0,
        PrivilegeLevel.READ_ONLY: 40.0,
        PrivilegeLevel.WORKLOAD_WRITE: 60.0,
        PrivilegeLevel.IAM_WRITE: 90.0,
        PrivilegeLevel.ADMINISTRATOR: 100.0,
    }

    EXPOSURE_MAPPING: dict[ExposureLevel, float] = {
        ExposureLevel.ISOLATED_PRIVATE: 20.0,
        ExposureLevel.INTERNAL_VPC: 40.0,
        ExposureLevel.RESTRICTED_INGRESS: 70.0,
        ExposureLevel.INTERNET_FACING: 100.0,
    }

    def __init__(self, config: RiskEngineConfig | None = None) -> None:
        self.config = config or RiskEngineConfig()

    def evaluate(self, context: RiskContext) -> RiskAssessment:
        """
        Evaluate context payload and generate a complete, explainable RiskAssessment.
        Guarantees strict monotonicity, boundary safety (0.0 to 100.0), and full factor breakdown.
        """
        breakdown: list[RiskFactorContribution] = []

        # 1. Detection Severity
        norm_severity = self.SEVERITY_MAPPING.get(context.detection_severity, 50.0)
        contrib_severity = norm_severity * self.config.w_severity
        breakdown.append(
            RiskFactorContribution(
                factor_name="Detection Severity",
                raw_value=norm_severity,
                normalized_value=norm_severity,
                weight=self.config.w_severity,
                weighted_contribution=round(contrib_severity, 2),
                narrative=f"Assigned {context.detection_severity.value} detection severity.",
            )
        )

        # 2. Asset Criticality (scale 1.0-10.0 -> 10.0-100.0)
        norm_criticality = max(10.0, min(100.0, context.asset_criticality * 10.0))
        contrib_criticality = norm_criticality * self.config.w_criticality
        breakdown.append(
            RiskFactorContribution(
                factor_name="Asset Criticality",
                raw_value=context.asset_criticality,
                normalized_value=norm_criticality,
                weight=self.config.w_criticality,
                weighted_contribution=round(contrib_criticality, 2),
                narrative=f"Target asset evaluated at criticality rating {context.asset_criticality}/10.",
            )
        )

        # 3. Identity Privilege
        norm_privilege = self.PRIVILEGE_MAPPING.get(context.privilege_level, 20.0)
        contrib_privilege = norm_privilege * self.config.w_privilege
        breakdown.append(
            RiskFactorContribution(
                factor_name="Identity Privilege",
                raw_value=norm_privilege,
                normalized_value=norm_privilege,
                weight=self.config.w_privilege,
                weighted_contribution=round(contrib_privilege, 2),
                narrative=f"Principal possesses {context.privilege_level.value} authority.",
            )
        )

        # 4. Attack Graph Blast Radius (0.0-100.0)
        norm_blast = max(0.0, min(100.0, context.blast_radius_score))
        contrib_blast = norm_blast * self.config.w_blast_radius
        breakdown.append(
            RiskFactorContribution(
                factor_name="Graph Blast Radius",
                raw_value=context.blast_radius_score,
                normalized_value=norm_blast,
                weight=self.config.w_blast_radius,
                weighted_contribution=round(contrib_blast, 2),
                narrative=f"Neptune reachability analysis yielded a {context.blast_radius_score}/100 blast radius.",
            )
        )

        # 5. SageMaker Behavioral Anomaly Score (0.0-1.0 -> 0.0-100.0)
        norm_anomaly = max(0.0, min(100.0, context.anomaly_score * 100.0))
        contrib_anomaly = norm_anomaly * self.config.w_anomaly
        breakdown.append(
            RiskFactorContribution(
                factor_name="Behavioral Anomaly",
                raw_value=context.anomaly_score,
                normalized_value=norm_anomaly,
                weight=self.config.w_anomaly,
                weighted_contribution=round(contrib_anomaly, 2),
                narrative=f"SageMaker inference registered a {round(context.anomaly_score, 3)} anomaly deviation.",
            )
        )

        # 6. Ingress / Network Exposure
        norm_exposure = self.EXPOSURE_MAPPING.get(context.exposure_level, 40.0)
        contrib_exposure = norm_exposure * self.config.w_exposure
        breakdown.append(
            RiskFactorContribution(
                factor_name="Network Exposure",
                raw_value=norm_exposure,
                normalized_value=norm_exposure,
                weight=self.config.w_exposure,
                weighted_contribution=round(contrib_exposure, 2),
                narrative=f"Asset configured with {context.exposure_level.value} network boundary.",
            )
        )

        # Calculate base weighted sum
        base_score = sum(f.weighted_contribution for f in breakdown)

        # Confidence scaling: attenuates unconfident detections slightly (0.8x to 1.0x)
        confidence_factor = 0.8 + (0.2 * context.confidence)
        scaled_score = base_score * confidence_factor

        # Environmental adjustments
        adjustments = 0.0
        applied_modifiers: list[str] = []

        if context.is_production and scaled_score >= 25.0:
            adjustments += self.config.production_bonus
            applied_modifiers.append(
                f"+{self.config.production_bonus} Production Environment Bonus"
            )

        if context.cross_account and scaled_score >= 25.0:
            adjustments += self.config.cross_account_bonus
            applied_modifiers.append(
                f"+{self.config.cross_account_bonus} Cross-Account Breach Penalty"
            )

        pre_cvss_score = scaled_score + adjustments

        # Vulnerability context floor
        if context.vulnerability_cvss is not None and context.vulnerability_cvss >= 9.0:
            if pre_cvss_score < 76.0:
                pre_cvss_score = 76.0
                applied_modifiers.append(
                    f"Floor applied: CVSS {context.vulnerability_cvss} Critical Vulnerability"
                )

        final_score = min(100.0, max(0.0, round(pre_cvss_score, 1)))

        # Categorize Risk Level
        if final_score <= 25.0:
            level = RiskLevel.LOW
            action = "Log telemetry, correlate in local finding registry, no active containment required."
        elif final_score <= 50.0:
            level = RiskLevel.MEDIUM
            action = "Publish War Room advisory, notify security team via Slack/SNS, monitor for lateral movement."
        elif final_score <= 75.0:
            level = RiskLevel.HIGH
            action = "Initiate approval workflow for targeted IAM or Security Group containment."
        else:
            level = RiskLevel.CRITICAL
            action = "Execute autonomous Step Functions containment (quarantine security group, attach deny-all boundary)."

        # Construct explanation
        top_factors = sorted(breakdown, key=lambda f: f.weighted_contribution, reverse=True)[:3]
        narratives = [f"{f.factor_name} ({f.weighted_contribution} pts)" for f in top_factors]
        explanation = (
            f"Risk Score: {final_score}/100 [{level.value}]. "
            f"Primary drivers: {', '.join(narratives)}. "
            f"Confidence: {round(context.confidence * 100)}%."
        )
        if applied_modifiers:
            explanation += f" Modifiers: {'; '.join(applied_modifiers)}."

        raw_factors_dump: dict[str, Any] = {
            "detection_severity": context.detection_severity.value,
            "asset_criticality": context.asset_criticality,
            "privilege_level": context.privilege_level.value,
            "blast_radius_score": context.blast_radius_score,
            "anomaly_score": context.anomaly_score,
            "exposure_level": context.exposure_level.value,
            "confidence": context.confidence,
            "is_production": context.is_production,
            "cross_account": context.cross_account,
            "vulnerability_cvss": context.vulnerability_cvss,
        }

        return RiskAssessment(
            assessment_id=f"risk-{uuid.uuid4().hex[:12]}",
            finding_id=context.finding_id,
            risk_score=final_score,
            risk_level=level,
            recommended_action=action,
            factor_breakdown=breakdown,
            explanation=explanation,
            raw_factors=raw_factors_dump,
        )
