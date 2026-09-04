"""Unit tests for AEGIS health diagnostic framework."""

import pytest

from services.common.health import HealthChecker, HealthStatus


@pytest.mark.unit
def test_schema_registry_health() -> None:
    """Ensure that the schema registry passes diagnostic self-check."""
    check = HealthChecker.check_schema_registry()
    assert check.status == HealthStatus.HEALTHY
    assert check.name == "schema_registry"
    assert "successfully" in check.details.get("message", "")


@pytest.mark.unit
def test_system_diagnostics_report() -> None:
    """Validate full aggregate system diagnostic report generation."""
    report = HealthChecker.run_diagnostics()
    assert report.overall_status == HealthStatus.HEALTHY
    assert len(report.components) >= 1
    assert report.version == "0.1.0"
