"""Rule AEGIS-DET-008: Suspicious Sensitive-Resource Access."""

from detection_engine.models import EnrichedSecurityEvent
from detection_engine.rules.base import DetectionRule
from services.common.models import FindingSeverity, SecurityFinding


class Rule008SensitiveResourceAccess(DetectionRule):
    """Detects API access to secrets, credentials, or parameters from unexpected external sources."""

    rule_id = "AEGIS-DET-008"
    name = "Suspicious Access to Sensitive Credentials/Secrets"
    description = "Secrets Manager or SSM parameter credentials were read from an external IP address or unverified identity."
    severity = FindingSeverity.HIGH
    confidence = 0.85
    mitre_attack_technique = "T1552"
    recommended_response = (
        "Rotate the accessed secret immediately and isolate the requesting IAM session."
    )

    SECRET_ACTIONS = [
        "secretsmanager:GetSecretValue",
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
    ]

    def evaluate(self, enriched: EnrichedSecurityEvent) -> SecurityFinding | None:
        ev = enriched.event
        if ev.action not in self.SECRET_ACTIONS:
            return None

        # If accessed from external IP or target is classified sensitive
        if enriched.is_external_ip or enriched.is_sensitive_target:
            return self.build_finding(
                enriched,
                custom_evidence={
                    "secret_api": ev.action,
                    "is_external_ip": enriched.is_external_ip,
                    "is_sensitive_target": enriched.is_sensitive_target,
                    "reason": "Direct read of secret credentials from external IP address",
                },
                severity_override=FindingSeverity.HIGH,
                confidence_override=0.89,
            )

        return None
