"""AEGIS Custom Detection Engine Package."""

from detection_engine.enrichment import EventEnricher
from detection_engine.evaluator import DetectionEvaluator
from detection_engine.models import EnrichedSecurityEvent
from detection_engine.registry import RuleRegistry

__all__ = [
    "DetectionEvaluator",
    "RuleRegistry",
    "EventEnricher",
    "EnrichedSecurityEvent",
]
