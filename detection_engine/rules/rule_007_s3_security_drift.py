"""Rule AEGIS-DET-007: S3 Security Configuration Modification."""

from detection_engine.models import EnrichedSecurityEvent
from detection_engine.rules.base import DetectionRule
from services.common.models import FindingSeverity, SecurityFinding


class Rule007S3SecurityDrift(DetectionRule):
    """Detects removal or modification of S3 security controls, public access blocks, or bucket policies."""

    rule_id = "AEGIS-DET-007"
    name = "S3 Security Configuration Modification"
    description = "An S3 bucket policy was deleted or S3 Public Access Block was removed, risking public exposure."
    severity = FindingSeverity.HIGH
    confidence = 0.90
    mitre_attack_technique = "T1530"
    recommended_response = (
        "Enforce S3 Block Public Access on the target bucket and audit bucket policy statements."
    )

    DRIFT_ACTIONS = [
        "s3:DeleteBucketPolicy",
        "s3:DeletePublicAccessBlock",
        "s3:DeleteAccountPublicAccessBlock",
    ]

    def evaluate(self, enriched: EnrichedSecurityEvent) -> SecurityFinding | None:
        ev = enriched.event
        if ev.action in self.DRIFT_ACTIONS:
            return self.build_finding(
                enriched,
                custom_evidence={
                    "drift_action": ev.action,
                    "reason": "Explicit removal of S3 security policy or public access block",
                },
                severity_override=FindingSeverity.HIGH,
                confidence_override=0.92,
            )

        # Also check PutBucketPolicy if granting Principal: *
        if ev.action == "s3:PutBucketPolicy":
            raw_str = str(ev.raw_payload).lower()
            if '"principal": "*"' in raw_str or '"principal":"*"' in raw_str:
                return self.build_finding(
                    enriched,
                    custom_evidence={
                        "drift_action": ev.action,
                        "reason": "S3 bucket policy attached with wildcard Principal (*)",
                    },
                    severity_override=FindingSeverity.CRITICAL,
                    confidence_override=0.95,
                )

        return None
