"""Rule AEGIS-DET-001: Suspicious IAM Access-Key Creation."""

from detection_engine.models import EnrichedSecurityEvent, PrincipalPrivilegeTier
from detection_engine.rules.base import DetectionRule
from services.common.models import FindingSeverity, SecurityFinding


class Rule001IAMKeyCreation(DetectionRule):
    """Detects creation of IAM access keys by or on privileged identities or from external IPs."""

    rule_id = "AEGIS-DET-001"
    name = "Suspicious IAM Access-Key Creation"
    description = "An IAM access key was created on a privileged identity or from an external non-corporate IP address."
    severity = FindingSeverity.HIGH
    confidence = 0.88
    mitre_attack_technique = "T1078.004"
    recommended_response = "Deactivate newly created access key and audit principal activity for signs of credential compromise."

    def evaluate(self, enriched: EnrichedSecurityEvent) -> SecurityFinding | None:
        ev = enriched.event
        if ev.action != "iam:CreateAccessKey":
            return None

        # Elevate to CRITICAL if created on root
        if enriched.principal_privilege == PrincipalPrivilegeTier.ROOT:
            return self.build_finding(
                enriched,
                custom_evidence={"reason": "Access key created for AWS Root account"},
                severity_override=FindingSeverity.CRITICAL,
                confidence_override=0.98,
            )

        # Trigger HIGH if created from external IP or for privileged identity
        if (
            enriched.is_external_ip
            or enriched.principal_privilege == PrincipalPrivilegeTier.IAM_ADMIN
        ):
            return self.build_finding(
                enriched,
                custom_evidence={
                    "reason": "Access key created from external IP or for admin principal",
                    "is_external_ip": enriched.is_external_ip,
                },
            )

        return None
