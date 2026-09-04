"""
Project AEGIS - Fault-Tolerant Fallback Handlers
Provides resilient degradation for external distributed services:
- Amazon Neptune / Graph Engine unavailability fallback
- Amazon SageMaker Serverless Anomaly Inference unavailability fallback
Ensures the AEGIS pipeline never halts when external dependencies fail.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from services.attack_path.models import BlastRadiusReport
from services.common.models import NormalizedSecurityEvent

logger = logging.getLogger("aegis.resilience.fallbacks")


class ResilientGraphEvaluator:
    """
    Wraps attack-path graph traversals with heuristic fallback protection.
    If Neptune or in-memory graph traversals raise an unexpected error or timeout,
    calculates a safe localized blast-radius estimation without crashing.
    """

    @staticmethod
    def calculate_fallback_blast_radius(
        principal_arn: str,
        account_id: str,
        error_details: str,
    ) -> BlastRadiusReport:
        """Deterministic heuristic blast radius when graph engine is offline."""
        lower_arn = principal_arn.lower()

        # Heuristic scoring based on principal tier
        if ":root" in lower_arn:
            base_score = 95.0
            reasons = ["Fallback: Root identity estimated maximum blast radius"]
        elif "admin" in lower_arn or "administrator" in lower_arn:
            base_score = 80.0
            reasons = ["Fallback: Administrative identity high potential blast radius"]
        elif ":role/" in lower_arn:
            base_score = 50.0
            reasons = ["Fallback: Workload role moderate blast radius"]
        else:
            base_score = 30.0
            reasons = ["Fallback: Standard user limited blast radius"]

        # Production account modifier
        if account_id in ("777788889999", "111111111111"):
            base_score = min(100.0, base_score + 15.0)
            reasons.append("Fallback: Production account elevated blast weighting")

        return BlastRadiusReport(
            principal_id=principal_arn,
            score=base_score,
            assumable_roles=[],
            affected_accounts=[account_id],
            directly_accessible_resources=[principal_arn],
            indirectly_accessible_resources=[],
            sensitive_resources=[],
            attack_paths=[],
            total_reachable_nodes=1,
            cross_account_traversal=(account_id != "333333333333"),
            explanation=f"Graph engine offline ({error_details}). Localized heuristic fallback applied. {'; '.join(reasons)}",
        )

    def evaluate_safe(
        self,
        graph_callable: Callable[[str], BlastRadiusReport],
        principal_arn: str,
        account_id: str = "333333333333",
    ) -> tuple[BlastRadiusReport, bool]:
        """
        Execute graph traversal with automated fallback on error.

        Returns:
            tuple (report, is_fallback)
        """
        try:
            report = graph_callable(principal_arn)
            return report, False
        except Exception as exc:
            logger.warning(
                f"Graph query failed for '{principal_arn}' ({exc}). Applying resilient fallback."
            )
            report = self.calculate_fallback_blast_radius(
                principal_arn=principal_arn,
                account_id=account_id,
                error_details=str(exc),
            )
            return report, True


class ResilientAnomalyEvaluator:
    """
    Wraps Amazon SageMaker Serverless inference endpoint with heuristic fallback.
    If SageMaker returns 500, 503 Service Unavailable, or ClientTimeout,
    falls back to a rule-derived statistical baseline without discarding findings.
    """

    @staticmethod
    def calculate_fallback_anomaly_score(
        event: NormalizedSecurityEvent,
        error_details: str,
    ) -> tuple[float, bool]:
        """
        Compute baseline anomaly score when ML inference is unreachable.

        Returns:
            tuple (score, is_anomalous)
        """
        # Atypical administrative or key generation activities receive conservative anomaly baseline
        high_risk_actions = {
            "iam:CreateAccessKey",
            "iam:AttachUserPolicy",
            "iam:AttachRolePolicy",
            "sts:AssumeRole",
            "cloudtrail:StopLogging",
            "ec2:AuthorizeSecurityGroupIngress",
        }

        if event.action in high_risk_actions:
            score = 0.70
            is_anomalous = True
        else:
            score = 0.35
            is_anomalous = False

        logger.info(
            f"SageMaker fallback applied for action '{event.action}' (score={score}, err={error_details})"
        )
        return score, is_anomalous

    def score_safe(
        self,
        inference_callable: Callable[[NormalizedSecurityEvent], tuple[float, bool]],
        event: NormalizedSecurityEvent,
    ) -> tuple[float, bool, bool]:
        """
        Execute SageMaker inference with automated fallback on error.

        Returns:
            tuple (score, is_anomalous, is_fallback)
        """
        try:
            score, is_anomalous = inference_callable(event)
            return score, is_anomalous, False
        except Exception as exc:
            logger.warning(
                f"SageMaker inference failed for event '{event.event_id}' ({exc}). Applying fallback."
            )
            score, is_anomalous = self.calculate_fallback_anomaly_score(event, str(exc))
            return score, is_anomalous, True
