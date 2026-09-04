"""Rule AEGIS-DET-002: Suspicious Access-Key Usage."""

from detection_engine.models import EnrichedSecurityEvent
from detection_engine.rules.base import DetectionRule
from services.common.models import FindingSeverity, SecurityFinding


class Rule002AccessKeyMisuse(DetectionRule):
    """Detects API calls using access keys from untrusted user agents or external IPs."""

    rule_id = "AEGIS-DET-002"
    name = "Suspicious Access-Key Usage"
    description = "An IAM access key was used from an untrusted external IP address or suspicious client user-agent."
    severity = FindingSeverity.HIGH
    confidence = 0.85
    mitre_attack_technique = "T1078"
    recommended_response = (
        "Temporarily inactivate access key and verify origin of API requests with principal owner."
    )

    SUSPICIOUS_AGENTS = ["curl", "python-requests", "postman", "go-http-client", "kali"]

    def evaluate(self, enriched: EnrichedSecurityEvent) -> SecurityFinding | None:
        ev = enriched.event
        # Only evaluate management API calls
        if ev.source != "cloudtrail" or not ev.action.startswith(("iam:", "ec2:", "s3:", "sts:")):
            return None

        # Check for suspicious user-agent or external IP usage on sensitive operations
        agent_lower = ev.user_agent.lower()
        is_suspicious_agent = any(agent in agent_lower for agent in self.SUSPICIOUS_AGENTS)

        if enriched.is_external_ip and is_suspicious_agent:
            return self.build_finding(
                enriched,
                custom_evidence={
                    "user_agent": ev.user_agent,
                    "source_ip": ev.source_ip,
                    "reason": "Suspicious scripting user-agent executing cloud API from external IP",
                },
                severity_override=FindingSeverity.HIGH,
                confidence_override=0.88,
            )

        return None
