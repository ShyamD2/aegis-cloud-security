"""Unit and performance tests for Phase 06 Real-Time Event Pipeline."""

import copy
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from services.pipeline.dlq import DeadLetterQueue
from services.pipeline.models import PipelineEnvelope
from services.pipeline.processor import EventPipelineProcessor


@pytest.mark.unit
def test_duplicate_event_suppression(sample_cloudtrail_raw_event: dict) -> None:
    """IdempotencyManager must drop duplicate events arriving within the lock window."""
    processor = EventPipelineProcessor()

    # First event: processed
    findings_1 = processor.process_batch([sample_cloudtrail_raw_event])
    assert len(findings_1) >= 1

    # Second identical event: duplicate dropped
    findings_2 = processor.process_batch([sample_cloudtrail_raw_event])
    assert len(findings_2) == 0


@pytest.mark.unit
def test_malformed_event_routes_to_dlq() -> None:
    """Malformed events failing parsing must route to DeadLetterQueue without crashing."""
    dlq = DeadLetterQueue()
    processor = EventPipelineProcessor(dlq=dlq)

    malformed_event = {"corrupted": "payload_without_mandatory_fields"}
    findings = processor.process_batch([malformed_event])

    assert len(findings) == 0
    assert dlq.count() == 1
    record = dlq.list_records()[0]
    assert record.error_type == "ValidationError"
    assert (
        "eventID" in record.failure_reason
        or "eventId" in record.failure_reason
        or "eventTime" in record.failure_reason
    )


@pytest.mark.unit
def test_out_of_order_events(sample_cloudtrail_raw_event: dict) -> None:
    """Out of order events must be processed using their original eventTime."""
    processor = EventPipelineProcessor()

    ev1 = copy.deepcopy(sample_cloudtrail_raw_event)
    ev1["eventID"] = "evt-later-1"
    ev1["eventTime"] = "2026-09-04T12:10:00Z"

    ev2 = copy.deepcopy(sample_cloudtrail_raw_event)
    ev2["eventID"] = "evt-earlier-2"
    ev2["eventTime"] = "2026-09-04T12:05:00Z"

    # Delivered in reverse order (later first, earlier second)
    findings = processor.process_batch([ev1, ev2])
    assert len(findings) >= 2


@pytest.mark.unit
def test_processor_retry_and_dlq_on_failure(sample_cloudtrail_raw_event: dict) -> None:
    """Processor must attempt retries with backoff and route to DLQ upon exhaustion."""
    mock_evaluator = MagicMock()
    mock_evaluator.evaluate_event.side_effect = RuntimeError(
        "Simulated transient evaluation failure"
    )

    dlq = DeadLetterQueue()
    processor = EventPipelineProcessor(evaluator=mock_evaluator, dlq=dlq)

    envelope = PipelineEnvelope(raw_payload=sample_cloudtrail_raw_event, max_retries=3)
    findings = processor.process_envelope(envelope)

    assert len(findings) == 0
    assert envelope.retry_count == 3
    assert dlq.count() == 1
    assert dlq.list_records()[0].error_type == "RuntimeError"


@pytest.mark.unit
def test_correlation_id_propagation(sample_cloudtrail_raw_event: dict) -> None:
    """Correlation ID in envelope must propagate to finding evidence."""
    processor = EventPipelineProcessor()
    envelope = PipelineEnvelope(
        correlation_id="test-corr-id-12345",
        raw_payload=sample_cloudtrail_raw_event,
    )
    findings = processor.process_envelope(envelope)

    assert len(findings) >= 1
    for finding in findings:
        assert finding.evidence.get("correlation_id") == "test-corr-id-12345"


@pytest.mark.benchmark
def test_latency_percentile_benchmarking(sample_cloudtrail_raw_event: dict) -> None:
    """Benchmark real execution latency across 50 events and calculate p50/p95/p99."""
    processor = EventPipelineProcessor()

    # Generate 50 unique synthetic events
    events = []
    for i in range(50):
        ev = copy.deepcopy(sample_cloudtrail_raw_event)
        ev["eventID"] = f"benchmark-evt-{i}-{int(datetime.now(UTC).timestamp() * 1000)}"
        events.append(ev)

    processor.process_batch(events)

    percentiles = processor.calculate_latency_percentiles()
    assert percentiles["sample_count"] == 50.0
    assert percentiles["p50"] > 0.0
    assert percentiles["p95"] >= percentiles["p50"]
    assert percentiles["p99"] >= percentiles["p95"]
    assert percentiles["p50"] < 500.0  # Demonstrates sub-second processing capability empirically
