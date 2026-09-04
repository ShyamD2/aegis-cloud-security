"""Rule AEGIS-DET-003: Unusual AssumeRole."""

from detection_engine.models import AccountTier, EnrichedSecurityEvent
from detection_engine.rules.base import DetectionRule
from services.common.models import FindingSeverity, SecurityFinding


class Rule003UnusualAssumeRole(DetectionRule):
    """Detects unusual or high-risk sts:AssumeRole calls."""

    rule_id = "AEGIS-DET-003"
    name = "Unusual AssumeRole Chaining"
    description = "An sts:AssumeRole request originated from an external IP or bridged into a Production account unexpectedly."
    severity = FindingSeverity.HIGH
    confidence = 0.82
    mitre_attack_technique = "T1548"
    recommended_response = "Audit assumed session context, check CloudTrail session tags, and terminate session if unauthorized."

    def evaluate(self, enriched: EnrichedSecurityEvent) -> SecurityFinding | None:
        ev = enriched.event
        if ev.action != "sts:AssumeRole":
            return None

        # Cross-account AssumeRole into Production from external IP
        if enriched.is_external_ip and enriched.account_tier == AccountTier.PRODUCTION:
            return self.build_finding(
                enriched,
                custom_evidence={
                    "reason": "Direct AssumeRole into Production environment from external IP",
                    "account_tier": enriched.account_tier.value,
                },
                severity_override=FindingSeverity.HIGH,
                confidence_override=0.90,
            )

        if enriched.is_cross_account and enriched.is_external_ip:
            return self.build_finding(
                enriched,
                custom_evidence={
                    "reason": "Cross-account AssumeRole invoked from public unverified IP",
                },
            )

        return None
