"""
Project AEGIS - Security Lab Controller Lambda Handler
Evaluates safety gates, kill switch status, and quota limits before initiating a lab execution.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import UTC, datetime
from typing import Any

from services.attack_lab.cloud_runner.models import LabSafetyConfig

logger = logging.getLogger("aegis.lab.controller")
logger.setLevel(logging.INFO)


class SecurityLabController:
    """Controls autonomous execution boundaries and scenario selection."""

    SCENARIO_ROTATION = [
        (
            "SCENARIO-01",
            "IAM Credential Compromise & Key Generation",
            "AEGIS-DET-001",
            80.0,
            "DEACTIVATE_ACCESS_KEY",
        ),
        (
            "SCENARIO-02",
            "STS Token Abuse & Impossible Travel",
            "AEGIS-DET-002",
            75.0,
            "REVOKE_IAM_SESSIONS",
        ),
        (
            "SCENARIO-03",
            "Anomalous Cross-Account AssumeRole",
            "AEGIS-DET-003",
            78.0,
            "REVOKE_IAM_SESSIONS",
        ),
        (
            "SCENARIO-04",
            "IAM Privilege Escalation via Policy",
            "AEGIS-DET-004",
            90.0,
            "ATTACH_DENY_ALL_POLICY",
        ),
        (
            "SCENARIO-05",
            "Unrestricted Security Group 0.0.0.0/0",
            "AEGIS-DET-005",
            85.0,
            "REVOKE_SECURITY_GROUP_RULE",
        ),
        (
            "SCENARIO-06",
            "Defense Evasion - CloudTrail StopLogging",
            "AEGIS-DET-006",
            95.0,
            "RESTART_CLOUDTRAIL_LOGGING",
        ),
        (
            "SCENARIO-07",
            "S3 Public Bucket Exposure & Drift",
            "AEGIS-DET-007",
            82.0,
            "RESTORE_S3_PUBLIC_BLOCK",
        ),
        (
            "SCENARIO-08",
            "Multi-Hop Cross-Account Lateral Movement",
            "AEGIS-DET-009",
            95.0,
            "REVOKE_IAM_SESSIONS",
        ),
    ]

    def __init__(self, dynamodb_client: Any = None, config_table_name: str | None = None) -> None:
        self.ddb = dynamodb_client
        self.config_table = config_table_name or os.environ.get(
            "AEGIS_LAB_CONFIG_TABLE", "aegis-lab-config"
        )

    def evaluate_safety_gate(self, config: LabSafetyConfig) -> tuple[bool, str]:
        """Verify that autonomous execution is permitted under bounded safety limits."""
        now = datetime.now(UTC)

        # 1. Global Kill-Switch Check
        if config.global_kill_switch == "TRIPPED":
            return (
                False,
                "ABORT: Global Kill Switch is TRIPPED. Manual safety intervention required.",
            )

        if not config.aegis_lab_enabled:
            return False, "ABORT: AEGIS Security Lab is globally DISABLED."

        # 2. Reset hourly / daily counters if windows elapsed
        if now.day != config.last_reset_day:
            config.daily_executions_count = 0
            config.hourly_executions_count = 0
            config.last_reset_day = now.day
            config.last_reset_hour = now.hour
        elif now.hour != config.last_reset_hour:
            config.hourly_executions_count = 0
            config.last_reset_hour = now.hour

        # 3. Quota Limits Check
        if config.hourly_executions_count >= config.max_scenarios_per_hour:
            return (
                False,
                f"ABORT: Hourly quota exceeded ({config.hourly_executions_count}/{config.max_scenarios_per_hour}).",
            )

        if config.daily_executions_count >= config.max_scenarios_per_day:
            return (
                False,
                f"ABORT: Daily quota exceeded ({config.daily_executions_count}/{config.max_scenarios_per_day}).",
            )

        return True, "SAFETY_GATE_PASSED"

    def select_next_scenario(self, last_scenario_index: int) -> tuple[dict[str, Any], int]:
        """Select next scenario in deterministic sequence."""
        idx = (last_scenario_index + 1) % len(self.SCENARIO_ROTATION)
        s_id, title, det_rule, risk, resp = self.SCENARIO_ROTATION[idx]
        return {
            "scenario_id": s_id,
            "title": title,
            "expected_detection": det_rule,
            "expected_risk": risk,
            "expected_response": resp,
        }, idx

    def handle_eventbridge_trigger(
        self, event: dict[str, Any], context: Any = None
    ) -> dict[str, Any]:
        """Lambda entrypoint for EventBridge Scheduler trigger."""
        logger.info(f"Received EventBridge Scheduler trigger: {event}")
        now_str = datetime.now(UTC).isoformat()
        execution_id = f"exec-{uuid.uuid4().hex[:12]}"

        # Load config (or default safety config)
        config = LabSafetyConfig()
        passed, reason = self.evaluate_safety_gate(config)

        if not passed:
            logger.warning(f"Execution halted by safety gate: {reason}")
            return {
                "execution_id": execution_id,
                "status": "ABORTED",
                "reason": reason,
                "timestamp": now_str,
            }

        # Select scenario
        last_idx = event.get("last_scenario_index", -1)
        scenario_data, next_idx = self.select_next_scenario(last_idx)

        logger.info(
            f"Initiating autonomous lab execution: {execution_id} for {scenario_data['scenario_id']}"
        )
        return {
            "execution_id": execution_id,
            "status": "APPROVED",
            "scenario": scenario_data,
            "scenario_index": next_idx,
            "start_time": now_str,
            "lab_environment_tag": "aegis-security-lab",
        }


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda entrypoint."""
    controller = SecurityLabController()
    return controller.handle_eventbridge_trigger(event, context)
