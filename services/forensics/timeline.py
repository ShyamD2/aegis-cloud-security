"""
Project AEGIS - Incident Timeline Reconstructor
Reconstructs end-to-end incident lifecycle from raw evidence:
ATTACK -> DETECTION -> CORRELATION -> RISK_EVALUATION -> CONTAINMENT_RESPONSE -> POST_VERIFICATION
"""

from __future__ import annotations

from typing import Any

from services.forensics.models import (
    EvidenceRecord,
    TimelineEvent,
    TimelineStage,
)


class TimelineReconstructor:
    """
    Synthesizes and measures the end-to-end incident progression.
    """

    @staticmethod
    def build_timeline_event(
        stage: TimelineStage,
        evidence: EvidenceRecord,
        summary: str,
        actor: str,
        target_resource: str,
        metadata: dict[str, Any] | None = None,
    ) -> TimelineEvent:
        """Helper to create a typed timeline event linked to forensic evidence."""
        return TimelineEvent(
            stage=stage,
            timestamp=evidence.timestamp,
            summary=summary,
            actor=actor,
            target_resource=target_resource,
            evidence_id=evidence.evidence_id,
            metadata=metadata or {},
        )

    @staticmethod
    def calculate_incident_metrics(timeline: list[TimelineEvent]) -> dict[str, float]:
        """
        Calculates empirical MTTD (Mean Time to Detect) and MTTC (Mean Time to Contain).
        """
        stage_map = {e.stage: e.timestamp for e in timeline}

        attack_time = stage_map.get(TimelineStage.ATTACK)
        detect_time = stage_map.get(TimelineStage.DETECTION)
        verify_time = stage_map.get(TimelineStage.POST_VERIFICATION) or stage_map.get(
            TimelineStage.CONTAINMENT_RESPONSE
        )

        mttd = 0.0
        mttc = 0.0
        total_duration = 0.0

        if attack_time and detect_time:
            mttd = max(0.0, (detect_time - attack_time).total_seconds())

        if detect_time and verify_time:
            mttc = max(0.0, (verify_time - detect_time).total_seconds())

        if attack_time and verify_time:
            total_duration = max(0.0, (verify_time - attack_time).total_seconds())

        return {
            "mttd_seconds": round(mttd, 2),
            "mttc_seconds": round(mttc, 2),
            "total_duration_seconds": round(total_duration, 2),
        }

    @staticmethod
    def generate_detective_investigation_url(
        account_id: str,
        finding_id: str,
        region: str = "us-east-1",
    ) -> str:
        """
        Generates standard AWS Detective investigation console deep-link for security analysts.
        """
        return (
            f"https://console.aws.amazon.com/detective/home?region={region}"
            f"#investigation/accounts/{account_id}/findings/{finding_id}"
        )
