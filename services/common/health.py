"""AEGIS System Health and Diagnostic Utility."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class HealthStatus(StrEnum):
    """Component health statuses."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"


class ComponentHealth(BaseModel):
    """Health status of an individual AEGIS subsystem."""

    name: str
    status: HealthStatus
    details: dict[str, Any] = Field(default_factory=dict)
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SystemHealthReport(BaseModel):
    """Comprehensive health summary across all AEGIS subsystems."""

    overall_status: HealthStatus
    components: list[ComponentHealth]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    version: str = "0.1.0"


class HealthChecker:
    """Evaluates the operational readiness of AEGIS components."""

    @staticmethod
    def check_schema_registry() -> ComponentHealth:
        """Verify that telemetry and finding schemas load correctly."""
        try:
            from services.common.models import NormalizedSecurityEvent, SecurityFinding

            assert NormalizedSecurityEvent is not None
            assert SecurityFinding is not None
            return ComponentHealth(
                name="schema_registry",
                status=HealthStatus.HEALTHY,
                details={"message": "All Pydantic v2 domain schemas registered successfully"},
            )
        except Exception as err:
            return ComponentHealth(
                name="schema_registry",
                status=HealthStatus.UNHEALTHY,
                details={"error": str(err)},
            )

    @classmethod
    def run_diagnostics(cls) -> SystemHealthReport:
        """Execute all subsystem diagnostic checks and compute aggregate status."""
        checks = [
            cls.check_schema_registry(),
        ]

        if any(c.status == HealthStatus.UNHEALTHY for c in checks):
            overall = HealthStatus.UNHEALTHY
        elif any(c.status == HealthStatus.DEGRADED for c in checks):
            overall = HealthStatus.DEGRADED
        else:
            overall = HealthStatus.HEALTHY

        return SystemHealthReport(
            overall_status=overall,
            components=checks,
        )
