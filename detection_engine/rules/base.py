"""Base class for all AEGIS deterministic detection rules."""

from abc import ABC, abstractmethod
from typing import Any

from detection_engine.models import EnrichedSecurityEvent
from services.common.models import FindingSeverity, FindingStatus, SecurityFinding


class DetectionRule(ABC):
    """Abstract base class defining the contract for AEGIS detection rules."""

    rule_id: str
    name: str
    description: str
    severity: FindingSeverity
    confidence: float
    mitre_attack_technique: str
    recommended_response: str

    @abstractmethod
    def evaluate(self, enriched: EnrichedSecurityEvent) -> SecurityFinding | None:
        """Evaluate an enriched security event and return a SecurityFinding if triggered."""
        pass

    def build_finding(
        self,
        enriched: EnrichedSecurityEvent,
        custom_evidence: dict[str, Any] | None = None,
        severity_override: FindingSeverity | None = None,
        confidence_override: float | None = None,
    ) -> SecurityFinding:
        """Helper to generate a populated SecurityFinding adhering to canonical standards."""
        ev = enriched.event
        finding_id = f"aegis-det-{self.rule_id.lower()}-{ev.event_id}"

        evidence = {
            "rule_id": self.rule_id,
            "rule_name": self.name,
            "principal_arn": ev.principal_arn,
            "source_ip": ev.source_ip,
            "action": ev.action,
            "account_tier": enriched.account_tier.value,
            "principal_privilege": enriched.principal_privilege.value,
        }
        if custom_evidence:
            evidence.update(custom_evidence)

        return SecurityFinding(
            finding_id=finding_id,
            rule_id=self.rule_id,
            title=f"{self.rule_id}: {self.name}",
            description=self.description,
            severity=severity_override or self.severity,
            confidence=confidence_override or self.confidence,
            status=FindingStatus.NEW,
            created_at=ev.timestamp,
            account_id=ev.account_id,
            region=ev.region,
            principal_arn=ev.principal_arn,
            target_resources=ev.resource_arns,
            mitre_attack_technique=self.mitre_attack_technique,
            evidence=evidence,
            recommended_response=self.recommended_response,
        )
