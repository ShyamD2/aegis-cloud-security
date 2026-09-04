"""
Project AEGIS - Purple-Team Attack Lab Unit Tests
Executes the automated runner across all 8 purple-team attack scenarios,
verifying complete 7-stage validation (ATTACK -> TELEMETRY -> DETECTION ->
CORRELATION -> RISK -> RESPONSE -> VERIFICATION -> CLEANUP) and 100% pass rate.
"""

from __future__ import annotations

from services.attack_lab import (
    ALL_SCENARIOS,
    AttackLabRunner,
    LabValidationStage,
)


def test_purple_team_runner_all_scenarios_pass() -> None:
    """Execute all 8 purple-team attack scenarios and confirm 100% pass rate."""
    runner = AttackLabRunner()
    results = runner.run_all()

    assert len(results) == 8
    for r in results:
        assert r.passed is True, f"Scenario {r.scenario_id} failed: {r.details}"
        assert r.cleanup_verified is True
        assert r.calculated_risk_score is not None and r.calculated_risk_score >= 50.0
        assert r.containment_action is not None

        # Verify all 8 lifecycle stages were executed
        expected_stages = [
            LabValidationStage.ATTACK,
            LabValidationStage.TELEMETRY,
            LabValidationStage.DETECTION,
            LabValidationStage.CORRELATION,
            LabValidationStage.RISK,
            LabValidationStage.RESPONSE,
            LabValidationStage.VERIFICATION,
            LabValidationStage.CLEANUP,
        ]
        for stage in expected_stages:
            assert stage in r.stages_completed, f"Scenario {r.scenario_id} missed stage {stage}"


def test_purple_team_markdown_report_generation() -> None:
    """Verify markdown report generation contains all scenarios and expected summary headers."""
    runner = AttackLabRunner()
    results = runner.run_all()
    report = AttackLabRunner.generate_markdown_report(results)

    assert "# AEGIS Purple-Team Security Lab Execution Report" in report
    assert "**Pass Rate**: 100.0%" in report
    for r in results:
        assert f"`{r.scenario_id}`" in report
        assert "**PASS**" in report
        assert "✅" in report


def test_scenario_counts_match_specification() -> None:
    """Verify exactly 8 specialized scenarios are registered in the purple team catalog."""
    assert len(ALL_SCENARIOS) == 8
    expected_ids = {f"SCENARIO-0{i}" for i in range(1, 9)}
    registered_ids = {cls.scenario_id for cls in ALL_SCENARIOS}
    assert registered_ids == expected_ids
