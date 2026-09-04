"""
Project AEGIS - Unit Tests for Continuous Security Lab Cloud Runner
Validates safety gate logic, kill-switch behavior, quota limit resets,
strict resource boundary validation, and latency percentile calculations.
"""

import pytest

from services.attack_lab.cloud_runner.controller import SecurityLabController
from services.attack_lab.cloud_runner.executor import ScenarioExecutor, SecurityBoundaryViolation
from services.attack_lab.cloud_runner.metrics import LatencyPercentileCalculator
from services.attack_lab.cloud_runner.models import LabSafetyConfig, ScenarioRecord


class TestSecurityLabSafetyGate:
    """Tests evaluating the autonomous execution safety gate and quota controls."""

    def test_safety_gate_passes_under_normal_limits(self) -> None:
        controller = SecurityLabController()
        config = LabSafetyConfig(
            aegis_lab_enabled=True,
            global_kill_switch="ENABLED",
            hourly_executions_count=2,
            max_scenarios_per_hour=4,
            daily_executions_count=10,
            max_scenarios_per_day=40,
        )
        passed, reason = controller.evaluate_safety_gate(config)
        assert passed is True
        assert reason == "SAFETY_GATE_PASSED"

    def test_safety_gate_aborts_when_kill_switch_tripped(self) -> None:
        controller = SecurityLabController()
        config = LabSafetyConfig(
            global_kill_switch="TRIPPED",
            aegis_lab_enabled=True,
        )
        passed, reason = controller.evaluate_safety_gate(config)
        assert passed is False
        assert "Global Kill Switch is TRIPPED" in reason

    def test_safety_gate_aborts_when_lab_disabled(self) -> None:
        controller = SecurityLabController()
        config = LabSafetyConfig(
            global_kill_switch="ENABLED",
            aegis_lab_enabled=False,
        )
        passed, reason = controller.evaluate_safety_gate(config)
        assert passed is False
        assert "globally DISABLED" in reason

    def test_safety_gate_aborts_when_hourly_quota_exceeded(self) -> None:
        controller = SecurityLabController()
        config = LabSafetyConfig(
            hourly_executions_count=4,
            max_scenarios_per_hour=4,
        )
        passed, reason = controller.evaluate_safety_gate(config)
        assert passed is False
        assert "Hourly quota exceeded" in reason

    def test_safety_gate_aborts_when_daily_quota_exceeded(self) -> None:
        controller = SecurityLabController()
        config = LabSafetyConfig(
            hourly_executions_count=1,
            max_scenarios_per_hour=4,
            daily_executions_count=40,
            max_scenarios_per_day=40,
        )
        passed, reason = controller.evaluate_safety_gate(config)
        assert passed is False
        assert "Daily quota exceeded" in reason


class TestResourceBoundaryEnforcement:
    """Tests ensuring simulation cannot target untagged, root, or production resources."""

    def test_boundary_passes_for_valid_lab_resource(self) -> None:
        target = "arn:aws:iam::111111111111:user/aegis-lab-test-user"
        tags = {
            "Environment": "aegis-security-lab",
            "Project": "aegis",
        }
        assert ScenarioExecutor.verify_resource_boundary(target, tags) is True

    def test_boundary_fails_for_missing_environment_tag(self) -> None:
        target = "arn:aws:iam::111111111111:user/aegis-lab-test-user"
        tags = {"Project": "aegis"}
        with pytest.raises(SecurityBoundaryViolation) as exc:
            ScenarioExecutor.verify_resource_boundary(target, tags)
        assert "BOUNDARY VIOLATION" in str(exc.value)

    def test_boundary_fails_for_wrong_environment_tag(self) -> None:
        target = "arn:aws:iam::111111111111:user/aegis-lab-test-user"
        tags = {
            "Environment": "production",
            "Project": "aegis",
        }
        with pytest.raises(SecurityBoundaryViolation) as exc:
            ScenarioExecutor.verify_resource_boundary(target, tags)
        assert "BOUNDARY VIOLATION" in str(exc.value)

    def test_boundary_fails_for_prohibited_production_substring(self) -> None:
        target = "arn:aws:iam::111111111111:role/production-data-reader"
        tags = {
            "Environment": "aegis-security-lab",
            "Project": "aegis",
        }
        with pytest.raises(SecurityBoundaryViolation) as exc:
            ScenarioExecutor.verify_resource_boundary(target, tags)
        assert "CRITICAL SAFETY VIOLATION" in str(exc.value)

    def test_boundary_fails_for_root_account_target(self) -> None:
        target = "arn:aws:iam::111111111111:root"
        tags = {
            "Environment": "aegis-security-lab",
            "Project": "aegis",
        }
        with pytest.raises(SecurityBoundaryViolation) as exc:
            ScenarioExecutor.verify_resource_boundary(target, tags)
        assert "CRITICAL SAFETY VIOLATION" in str(exc.value)


class TestMetricsAndPercentiles:
    """Tests validating statistical latency calculations and non-fabricated metrics."""

    def test_latency_percentile_calculation_accuracy(self) -> None:
        latencies = [1.0, 1.2, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 5.0, 10.0]
        percentiles = LatencyPercentileCalculator.calculate_percentiles(latencies)

        assert percentiles["p50"] >= 2.0
        assert percentiles["p95"] >= 5.0
        assert percentiles["p99"] >= 9.0

    def test_scenario_record_structure(self) -> None:
        record = ScenarioRecord(
            execution_id="exec-12345",
            scenario_id="SCENARIO-01",
            title="IAM Compromise",
            start_time="2026-09-04T12:00:00Z",
            detection_latency_seconds=1.12,
            response_latency_seconds=2.85,
        )
        assert record.execution_id == "exec-12345"
        assert record.detection_latency_seconds == 1.12
