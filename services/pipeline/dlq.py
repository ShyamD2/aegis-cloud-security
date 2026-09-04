"""Dead Letter Queue (DLQ) abstraction for failure isolation and audit."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from services.pipeline.models import PipelineEnvelope


class DeadLetterRecord(BaseModel):
    """Encapsulates an unprocessable or repeatedly failing pipeline record."""

    dlq_id: str
    correlation_id: str
    failed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    failure_reason: str
    retry_count: int
    original_payload: dict[str, Any]
    error_type: str


class DeadLetterQueue:
    """Mock or runtime interface for Dead Letter Queue captures."""

    def __init__(self) -> None:
        self._dead_letters: list[DeadLetterRecord] = []

    def send(self, envelope: PipelineEnvelope, error: Exception) -> DeadLetterRecord:
        """Route failed envelope to DLQ storage."""
        dlq_id = f"dlq-{envelope.correlation_id}-{len(self._dead_letters) + 1}"
        record = DeadLetterRecord(
            dlq_id=dlq_id,
            correlation_id=envelope.correlation_id,
            failed_at=datetime.now(UTC),
            failure_reason=str(error),
            retry_count=envelope.retry_count,
            original_payload=envelope.raw_payload,
            error_type=error.__class__.__name__,
        )
        self._dead_letters.append(record)
        return record

    def list_records(self) -> list[DeadLetterRecord]:
        """List all captured dead letters."""
        return list(self._dead_letters)

    def count(self) -> int:
        """Return total dead letters captured."""
        return len(self._dead_letters)
