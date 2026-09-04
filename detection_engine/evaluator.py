"""Detection rule evaluation engine."""

from detection_engine.enrichment import EventEnricher
from detection_engine.models import EnrichedSecurityEvent
from detection_engine.registry import RuleRegistry
from services.common.models import NormalizedSecurityEvent, SecurityFinding


class DetectionEvaluator:
    """Evaluates telemetry events against registered detection rules."""

    def __init__(self, registry: RuleRegistry | None = None) -> None:
        self.registry = registry or RuleRegistry(load_defaults=True)
        self.enricher = EventEnricher()

    def evaluate_event(
        self, event: NormalizedSecurityEvent
    ) -> tuple[EnrichedSecurityEvent, list[SecurityFinding]]:
        """Enrich a normalized event and evaluate all registered detection rules.

        Returns:
            tuple (enriched_event, list_of_findings)
        """
        enriched = self.enricher.enrich(event)
        findings: list[SecurityFinding] = []

        for rule in self.registry.list_rules():
            finding = rule.evaluate(enriched)
            if finding is not None:
                findings.append(finding)

        return enriched, findings
