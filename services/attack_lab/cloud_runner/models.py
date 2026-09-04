"""
Project AEGIS - AWS-Native Continuous Security Lab Cloud Runner
Provides cloud-native Lambda handlers for autonomous Phase-13 Purple-Team validation:
- Safety Gate & Kill-Switch Validation
- Tag-Enforced Lab Resource Boundary Checks
- 7-Stage Scenario Orchestration (Attack -> Detect -> Risk -> Response -> Verify -> Cleanup -> Evidence)
- Empirical Metrics & Latency Calculations (P50, P95, P99)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class LabExecutionStatus(StrEnum):
    """Execution status for continuous lab runs."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


@dataclass
class LabSafetyConfig:
    """Configurable execution and safety limits stored in DynamoDB."""

    aegis_lab_enabled: bool = True
    global_kill_switch: str = (
        "ENABLED"  # "ENABLED" means safety gate active; "TRIPPED" halts execution
    )
    scenario_interval_minutes: int = 15
    max_scenarios_per_hour: int = 4
    max_scenarios_per_day: int = 40
    max_concurrent_scenarios: int = 1
    max_remediations_per_hour: int = 6
    lab_timeout_seconds: int = 600
    hourly_executions_count: int = 0
    daily_executions_count: int = 0
    last_reset_hour: int = field(default_factory=lambda: datetime.now(UTC).hour)
    last_reset_day: int = field(default_factory=lambda: datetime.now(UTC).day)


@dataclass
class ScenarioRecord:
    """Detailed record for every autonomous Phase-13 lab execution."""

    execution_id: str
    scenario_id: str
    title: str
    start_time: str
    end_time: str | None = None
    status: LabExecutionStatus = LabExecutionStatus.PENDING
    target_resource: str = ""
    boundary_verified: bool = False
    expected_detection: str = ""
    actual_detection: str | None = None
    detection_latency_seconds: float = 0.0
    expected_risk: float = 0.0
    actual_risk: float = 0.0
    expected_response: str = ""
    actual_response: str | None = None
    response_latency_seconds: float = 0.0
    verification_result: bool = False
    cleanup_verified: bool = False
    evidence_location: str = ""
    evidence_sha256: str = ""
    error_message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
