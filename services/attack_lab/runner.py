"""
Project AEGIS - Purple-Team Attack Lab Runner
Orchestrates automated execution of all 8 attack scenarios, collects metrics,
and generates human-readable PASS/FAIL validation summaries.
"""

from __future__ import annotations

import logging

from services.attack_lab.models import ScenarioExecutionResult
from services.attack_lab.scenarios import ALL_SCENARIOS, BaseLabScenario

logger = logging.getLogger("aegis.attack_lab.runner")


class AttackLabRunner:
    """
    Automated test runner executing purple-team scenarios against AEGIS defense fabrics.
    """

    def __init__(self, scenarios: list[type[BaseLabScenario]] | None = None) -> None:
        self.scenario_classes = scenarios or ALL_SCENARIOS

    def run_all(self) -> list[ScenarioExecutionResult]:
        """Execute all configured lab scenarios sequentially and return results."""
        results: list[ScenarioExecutionResult] = []
        for cls in self.scenario_classes:
            instance = cls()
            logger.info(f"Executing Purple-Team Lab: {instance.scenario_id} - {instance.title}...")
            res = instance.execute()
            results.append(res)
            logger.info(f"Result for {res.scenario_id}: {'PASS' if res.passed else 'FAIL'}")
        return results

    @staticmethod
    def generate_markdown_report(results: list[ScenarioExecutionResult]) -> str:
        """Format test results as a markdown report for documentation and CI artifacts."""
        total = len(results)
        passed = sum(1 for r in results if r.passed)
        failed = total - passed
        pass_rate = round((passed / total) * 100, 1) if total > 0 else 0.0

        lines = [
            "# AEGIS Purple-Team Security Lab Execution Report",
            f"**Total Scenarios Executed**: {total} | **Passed**: {passed} | **Failed**: {failed} | **Pass Rate**: {pass_rate}%\n",
            "| Scenario ID | Title | Detection Rule | Risk Score | Containment Action | Cleanup | Status | Duration |",
            "| :--- | :--- | :--- | :--- | :--- | :---: | :---: | :--- |",
        ]

        for r in results:
            status_badge = "**PASS**" if r.passed else "**FAIL**"
            cleanup_badge = "✅" if r.cleanup_verified else "❌"
            risk_str = f"{r.calculated_risk_score}/100" if r.calculated_risk_score else "N/A"
            lines.append(
                f"| `{r.scenario_id}` | {r.title} | `{r.detection_rule_id}` | {risk_str} | `{r.containment_action}` | {cleanup_badge} | {status_badge} | {r.execution_time_seconds}s |"
            )

        return "\n".join(lines)
