"""Rule AEGIS-DET-004: Privilege-Escalation Indicators."""

from detection_engine.models import EnrichedSecurityEvent
from detection_engine.rules.base import DetectionRule
from services.common.models import FindingSeverity, SecurityFinding


class Rule004PrivilegeEscalation(DetectionRule):
    """Detects dangerous IAM policy attachments or modifications granting administrative escalation."""

    rule_id = "AEGIS-DET-004"
    name = "Privilege Escalation via IAM Policy Modification"
    description = "An identity attached AdministratorAccess or granted wildcard permissions via an inline or managed IAM policy."
    severity = FindingSeverity.CRITICAL
    confidence = 0.95
    mitre_attack_technique = "T1098"
    recommended_response = "Immediately detach escalated policy, invalidate principal sessions, and trigger IAM containment."

    ESCALATION_APIS = [
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
    ]

    def evaluate(self, enriched: EnrichedSecurityEvent) -> SecurityFinding | None:
        ev = enriched.event
        if ev.action not in self.ESCALATION_APIS:
            return None

        # Inspect raw payload for AdministratorAccess or wildcard
        raw_str = str(ev.raw_payload).lower()
        if "administratoraccess" in raw_str or (
            '"action": "*"' in raw_str and '"resource": "*"' in raw_str
        ):
            return self.build_finding(
                enriched,
                custom_evidence={
                    "reason": "Administrative policy attachment or full wildcard statement detected in IAM modification",
                    "escalation_api": ev.action,
                },
                severity_override=FindingSeverity.CRITICAL,
                confidence_override=0.96,
            )

        return None
