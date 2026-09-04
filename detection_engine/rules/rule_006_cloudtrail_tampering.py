"""Rule AEGIS-DET-006: CloudTrail Configuration Modification."""

from detection_engine.models import EnrichedSecurityEvent
from detection_engine.rules.base import DetectionRule
from services.common.models import FindingSeverity, SecurityFinding


class Rule006CloudTrailTampering(DetectionRule):
    """Detects attempts to stop, delete, or reconfigure AWS CloudTrail auditing."""

    rule_id = "AEGIS-DET-006"
    name = "CloudTrail Disruption or Tampering Attempt"
    description = (
        "An identity attempted to stop logging, delete, or tamper with an AWS CloudTrail trail."
    )
    severity = FindingSeverity.CRITICAL
    confidence = 0.98
    mitre_attack_technique = "T1562.001"
    recommended_response = "Immediately verify CloudTrail status, re-enable trail if stopped, and isolate the acting principal."

    TAMPERING_ACTIONS = [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail",
    ]

    def evaluate(self, enriched: EnrichedSecurityEvent) -> SecurityFinding | None:
        ev = enriched.event
        if ev.action in self.TAMPERING_ACTIONS:
            return self.build_finding(
                enriched,
                custom_evidence={
                    "tampering_action": ev.action,
                    "reason": "Direct API call attempted to alter or disable CloudTrail auditing",
                },
                severity_override=FindingSeverity.CRITICAL,
                confidence_override=0.98,
            )
        return None
