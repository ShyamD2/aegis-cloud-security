"""
Project AEGIS - Attack Lab Module Interface
"""

from services.attack_lab import (
    ALL_SCENARIOS,
    AttackLabRunner,
    BaseLabScenario,
    LabValidationStage,
    Scenario01IAMCompromise,
    Scenario02UnusualAssumeRole,
    Scenario03PrivilegeEscalation,
    Scenario04S3Misconfiguration,
    Scenario05DangerousSecurityGroup,
    Scenario06SuspiciousEC2Activity,
    Scenario07CrossAccountRoleAbuse,
    Scenario08LoggingDisruption,
    ScenarioExecutionResult,
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
