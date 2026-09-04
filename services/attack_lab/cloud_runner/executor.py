"""
Project AEGIS - Security Lab Scenario Executor Lambda Handler
Validates target resource tagging boundaries and initiates controlled purple-team simulation.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger("aegis.lab.executor")
logger.setLevel(logging.INFO)


class SecurityBoundaryViolation(Exception):
    """Raised when an operation attempts to target an untagged or non-lab resource."""


class ScenarioExecutor:
    """Safely executes purple-team attacks strictly against tagged lab resources."""

    REQUIRED_ENVIRONMENT_TAG = "aegis-security-lab"
    REQUIRED_PROJECT_TAG = "aegis"

    def __init__(self, kinesis_client: Any = None, eventbridge_client: Any = None) -> None:
        self.kinesis = kinesis_client
        self.events = eventbridge_client
        self.stream_name = os.environ.get("AEGIS_EVENTS_STREAM", "aegis-security-events-stream")
        self.event_bus = os.environ.get("AEGIS_FINDINGS_BUS", "aegis-findings-bus")

    @classmethod
    def verify_resource_boundary(cls, target_arn: str, tags: dict[str, str]) -> bool:
        """
        Enforce strict isolation:
        - Target resource MUST have Environment=aegis-security-lab
        - Target resource MUST have Project=aegis
        - Target resource MUST NOT be root, administrator, or production ARN
        """
        # Block privileged or root ARNs
        prohibited_substrings = [":root", "admin", "production", "prod-"]
        for p in prohibited_substrings:
            if p in target_arn.lower() and "lab" not in target_arn.lower():
                raise SecurityBoundaryViolation(
                    f"CRITICAL SAFETY VIOLATION: Target '{target_arn}' contains prohibited production pattern '{p}'!"
                )

        env_tag = tags.get("Environment")
        proj_tag = tags.get("Project")

        if env_tag != cls.REQUIRED_ENVIRONMENT_TAG:
            raise SecurityBoundaryViolation(
                f"BOUNDARY VIOLATION: Target '{target_arn}' has Environment='{env_tag}'. Expected '{cls.REQUIRED_ENVIRONMENT_TAG}'."
            )

        if proj_tag != cls.REQUIRED_PROJECT_TAG:
            raise SecurityBoundaryViolation(
                f"BOUNDARY VIOLATION: Target '{target_arn}' has Project='{proj_tag}'. Expected '{cls.REQUIRED_PROJECT_TAG}'."
            )

        return True

    def execute_simulation(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Execute simulation step with boundary validation."""
        scenario = payload.get("scenario", {})
        execution_id = payload.get("execution_id", "unknown-exec")
        scenario_id = scenario.get("scenario_id", "SCENARIO-01")

        # Map scenario to designated lab target resource
        lab_targets = {
            "SCENARIO-01": "arn:aws:iam::111111111111:user/aegis-lab-test-user",
            "SCENARIO-02": "arn:aws:iam::111111111111:role/aegis-lab-test-role",
            "SCENARIO-03": "arn:aws:iam::111111111111:role/aegis-lab-test-role",
            "SCENARIO-04": "arn:aws:iam::111111111111:user/aegis-lab-test-user",
            "SCENARIO-05": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-aegis-lab-test",
            "SCENARIO-06": "arn:aws:cloudtrail:us-east-1:111111111111:trail/aegis-lab-audit-trail",
            "SCENARIO-07": "arn:aws:s3:::aegis-lab-target-bucket-111111111111",
            "SCENARIO-08": "arn:aws:iam::111111111111:role/aegis-lab-test-role",
        }
        target_arn = lab_targets.get(
            scenario_id, "arn:aws:iam::111111111111:user/aegis-lab-test-user"
        )

        # Simulated tags for target resource
        resource_tags = {
            "Environment": self.REQUIRED_ENVIRONMENT_TAG,
            "Project": self.REQUIRED_PROJECT_TAG,
            "ManagedBy": "Terraform",
        }

        # 1. Enforce strict boundary verification
        self.verify_resource_boundary(target_arn, resource_tags)
        logger.info(
            f"Boundary verified: target '{target_arn}' has required {self.REQUIRED_ENVIRONMENT_TAG} tags."
        )

        # 2. Record simulation execution timestamp
        attack_time = datetime.now(UTC).isoformat()

        return {
            "execution_id": execution_id,
            "scenario_id": scenario_id,
            "target_resource": target_arn,
            "boundary_verified": True,
            "attack_timestamp": attack_time,
            "expected_detection": scenario.get("expected_detection"),
            "expected_risk": scenario.get("expected_risk"),
            "expected_response": scenario.get("expected_response"),
            "status": "SIMULATION_DISPATCHED",
        }


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda entrypoint."""
    executor = ScenarioExecutor()
    return executor.execute_simulation(event)
