"""End-to-end event pipeline processor with latency metrics, retry backoff, and DLQ handling."""

import logging
import statistics
from datetime import UTC, datetime
from typing import Any

from detection_engine.evaluator import DetectionEvaluator
from services.common.models import SecurityFinding
from services.pipeline.dlq import DeadLetterQueue
from services.pipeline.idempotency import IdempotencyManager
from services.pipeline.models import PipelineEnvelope
from services.telemetry.parser import parse_cloudtrail_event

logger = logging.getLogger("aegis.pipeline")


class EventPipelineProcessor:
    """Core processor executing the Kinesis -> Lambda -> Normalizer -> Detection -> EventBridge pipeline."""

    def __init__(
        self,
        evaluator: DetectionEvaluator | None = None,
        idempotency: IdempotencyManager | None = None,
        dlq: DeadLetterQueue | None = None,
    ) -> None:
        self.evaluator = evaluator or DetectionEvaluator()
        self.idempotency = idempotency or IdempotencyManager()
        self.dlq = dlq or DeadLetterQueue()
        self.emitted_findings: list[SecurityFinding] = []
        self.latency_records: list[float] = []

    def process_envelope(self, envelope: PipelineEnvelope) -> list[SecurityFinding]:
        """Process a single event envelope through the pipeline."""
        metrics = envelope.metrics
        metrics.processing_started_at = datetime.now(UTC)

        raw = envelope.raw_payload

        # 1. Parse and validate telemetry
        try:
            norm_event = parse_cloudtrail_event(raw)
        except Exception as err:
            logger.warning("Event normalization failed: %s. Routing to DLQ.", err)
            self.dlq.send(envelope, err)
            metrics.processing_completed_at = datetime.now(UTC)
            return []

        # 2. Idempotency Check
        if self.idempotency.is_duplicate(norm_event.account_id, norm_event.event_id):
            logger.info(
                "Duplicate event dropped: %s/%s", norm_event.account_id, norm_event.event_id
            )
            metrics.processing_completed_at = datetime.now(UTC)
            return []

        # 3. Detection Engine Evaluation
        try:
            _, findings = self.evaluator.evaluate_event(norm_event)
            metrics.finding_created_at = datetime.now(UTC)
        except Exception as err:
            # Handle retry behavior
            if envelope.retry_count < envelope.max_retries:
                envelope.retry_count += 1
                logger.warning(
                    "Retry %d for event %s: %s", envelope.retry_count, norm_event.event_id, err
                )
                return self.process_envelope(envelope)
            else:
                logger.error(
                    "Max retries exceeded for event %s. Routing to DLQ.", norm_event.event_id
                )
                self.dlq.send(envelope, err)
                metrics.processing_completed_at = datetime.now(UTC)
                return []

        # 4. Dispatch findings (Simulating EventBridge PutEvents)
        for finding in findings:
            # Inject correlation ID into finding evidence
            finding.evidence["correlation_id"] = envelope.correlation_id
            self.emitted_findings.append(finding)

        # 5. Record Idempotency Lock and Final Latency
        self.idempotency.record_processed(norm_event.account_id, norm_event.event_id)
        metrics.processing_completed_at = datetime.now(UTC)
        self.latency_records.append(metrics.total_latency_ms)

        return findings

    def process_batch(self, raw_events: list[dict[str, Any]]) -> list[SecurityFinding]:
        """Process a batch of events arriving from a streaming buffer (e.g. Kinesis)."""
        batch_findings: list[SecurityFinding] = []
        for raw in raw_events:
            envelope = PipelineEnvelope(raw_payload=raw)
            findings = self.process_envelope(envelope)
            batch_findings.extend(findings)
        return batch_findings

    def calculate_latency_percentiles(self) -> dict[str, float]:
        """Calculate p50, p95, p99 latencies in milliseconds across recorded runs."""
        if not self.latency_records:
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "sample_count": 0.0}

        sorted_records = sorted(self.latency_records)
        n = len(sorted_records)

        def percentile(p: float) -> float:
            idx = int(round((p / 100.0) * (n - 1)))
            return sorted_records[min(idx, n - 1)]

        return {
            "p50": round(percentile(50), 3),
            "p95": round(percentile(95), 3),
            "p99": round(percentile(99), 3),
            "mean": round(statistics.mean(sorted_records), 3),
            "sample_count": float(n),
        }
