"""
Project AEGIS - Purple-Team Attack Lab Module
"""

from services.attack_lab.models import LabValidationStage, ScenarioExecutionResult
from services.attack_lab.runner import AttackLabRunner
from services.attack_lab.scenarios import (
    ALL_SCENARIOS,
    BaseLabScenario,
    Scenario01IAMCompromise,
    Scenario02UnusualAssumeRole,
    Scenario03PrivilegeEscalation,
    Scenario04S3Misconfiguration,
    Scenario05DangerousSecurityGroup,
    Scenario06SuspiciousEC2Activity,
    Scenario07CrossAccountRoleAbuse,
    Scenario08LoggingDisruption,
)

__all__ = [
    "LabValidationStage",
    "ScenarioExecutionResult",
    "AttackLabRunner",
    "BaseLabScenario",
    "ALL_SCENARIOS",
    "Scenario01IAMCompromise",
    "Scenario02UnusualAssumeRole",
    "Scenario03PrivilegeEscalation",
    "Scenario04S3Misconfiguration",
    "Scenario05DangerousSecurityGroup",
    "Scenario06SuspiciousEC2Activity",
    "Scenario07CrossAccountRoleAbuse",
    "Scenario08LoggingDisruption",
]
