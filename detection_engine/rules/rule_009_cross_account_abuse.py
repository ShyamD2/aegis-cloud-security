"""Rule AEGIS-DET-009: Cross-Account Role Abuse."""

from detection_engine.models import AccountTier, EnrichedSecurityEvent
from detection_engine.rules.base import DetectionRule
from services.common.models import FindingSeverity, SecurityFinding


class Rule009CrossAccountAbuse(DetectionRule):
    """Detects suspicious cross-account role assumption without external ID or into production."""

    rule_id = "AEGIS-DET-009"
    name = "Suspicious Cross-Account Role Assumption"
    description = "An identity assumed a role across account boundaries without proper trust validation or into Production."
    severity = FindingSeverity.HIGH
    confidence = 0.87
    mitre_attack_technique = "T1078.004"
    recommended_response = (
        "Verify trust policy conditions on target role and require sts:ExternalId."
    )

    def evaluate(self, enriched: EnrichedSecurityEvent) -> SecurityFinding | None:
        ev = enriched.event
        if ev.action != "sts:AssumeRole":
            return None

        if enriched.is_cross_account:
            # Check if target account is production
            if enriched.account_tier == AccountTier.PRODUCTION:
                return self.build_finding(
                    enriched,
                    custom_evidence={
                        "reason": "Cross-account role assumption directly into Production account",
                        "account_tier": enriched.account_tier.value,
                    },
                    severity_override=FindingSeverity.HIGH,
                    confidence_override=0.91,
                )

            # Check if externalId was omitted in requestParameters
            req_params = ev.raw_payload.get("requestParameters", {})
            if isinstance(req_params, dict) and "externalId" not in req_params:
                return self.build_finding(
                    enriched,
                    custom_evidence={
                        "reason": "Cross-account assume-role executed without sts:ExternalId condition parameter",
                    },
                    severity_override=FindingSeverity.MEDIUM,
                    confidence_override=0.82,
                )

        return None
