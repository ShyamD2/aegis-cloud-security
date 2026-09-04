"""
Project AEGIS - Purple-Team Attack Lab Models
Defines attack simulation specifications, lifecycle validation stages, and test runner results.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class LabValidationStage(StrEnum):
    """Seven-stage verification pipeline required for every attack lab scenario."""

    ATTACK = "ATTACK"
    TELEMETRY = "TELEMETRY"
    DETECTION = "DETECTION"
    CORRELATION = "CORRELATION"
    RISK = "RISK"
    RESPONSE = "RESPONSE"
    VERIFICATION = "VERIFICATION"
    CLEANUP = "CLEANUP"


class ScenarioExecutionResult(BaseModel):
    """Detailed execution and validation outcome for a purple-team attack scenario."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(description="Unique scenario identifier, e.g. SCENARIO-01")
    title: str = Field(description="Descriptive scenario name")
    passed: bool = Field(description="True if all pipeline verification stages succeeded")
    stages_completed: list[LabValidationStage] = Field(default_factory=list)
    stage_latencies_ms: dict[str, float] = Field(default_factory=dict)
    detection_rule_id: str | None = None
    calculated_risk_score: float | None = None
    containment_action: str | None = None
    cleanup_verified: bool = False
    execution_time_seconds: float = Field(ge=0.0)
    details: str = Field(description="Summary narrative of scenario execution")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
