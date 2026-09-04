"""Data structures for real-time pipeline envelopes and latency metrics."""

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class PipelineMetrics(BaseModel):
    """Instrumentation metrics measuring processing latency milestones."""

    event_received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    processing_started_at: datetime | None = None
    finding_created_at: datetime | None = None
    processing_completed_at: datetime | None = None

    @property
    def total_latency_ms(self) -> float:
        """Calculate total pipeline latency in milliseconds from receipt to completion."""
        if not self.processing_completed_at:
            return 0.0
        diff = self.processing_completed_at - self.event_received_at
        return max(0.0, diff.total_seconds() * 1000.0)

    @property
    def evaluation_latency_ms(self) -> float:
        """Calculate detection evaluation latency in milliseconds."""
        if not self.processing_started_at or not self.finding_created_at:
            return 0.0
        diff = self.finding_created_at - self.processing_started_at
        return max(0.0, diff.total_seconds() * 1000.0)


class PipelineEnvelope(BaseModel):
    """Standard execution envelope propagating correlation IDs and retry metadata."""

    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    raw_payload: dict[str, Any]
    retry_count: int = 0
    max_retries: int = 3
    metrics: PipelineMetrics = Field(default_factory=PipelineMetrics)
