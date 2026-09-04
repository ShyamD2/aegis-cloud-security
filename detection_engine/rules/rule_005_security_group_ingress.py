"""Rule AEGIS-DET-005: Security-Group Dangerous Modification."""

from detection_engine.models import EnrichedSecurityEvent
from detection_engine.rules.base import DetectionRule
from services.common.models import FindingSeverity, SecurityFinding


class Rule005SecurityGroupIngress(DetectionRule):
    """Detects security group ingress rules permitting unrestricted access (0.0.0.0/0) to sensitive ports."""

    rule_id = "AEGIS-DET-005"
    name = "Dangerous Security Group Ingress Rule"
    description = "A security group rule was added allowing unrestricted inbound traffic (0.0.0.0/0) on sensitive management ports (SSH/RDP)."
    severity = FindingSeverity.CRITICAL
    confidence = 0.95
    mitre_attack_technique = "T1562.007"
    recommended_response = "Revoke permissive security group ingress rule immediately and inspect attached EC2 instances."

    DANGEROUS_PORTS = ["22", "3389", "0-65535", "-1"]

    def evaluate(self, enriched: EnrichedSecurityEvent) -> SecurityFinding | None:
        ev = enriched.event
        if ev.action != "ec2:AuthorizeSecurityGroupIngress":
            return None

        raw_str = str(ev.raw_payload)
        if "0.0.0.0/0" in raw_str:
            # Check if sensitive port opened
            is_sensitive_port = any(port in raw_str for port in self.DANGEROUS_PORTS)
            if is_sensitive_port:
                return self.build_finding(
                    enriched,
                    custom_evidence={
                        "cidr": "0.0.0.0/0",
                        "reason": "Unrestricted inbound access allowed to management ports (22/3389) from the internet",
                    },
                    severity_override=FindingSeverity.CRITICAL,
                    confidence_override=0.95,
                )

        return None
