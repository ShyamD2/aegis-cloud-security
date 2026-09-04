"""AEGIS Detection Rules Package."""

from detection_engine.rules.base import DetectionRule
from detection_engine.rules.rule_001_iam_key_creation import Rule001IAMKeyCreation
from detection_engine.rules.rule_002_access_key_misuse import Rule002AccessKeyMisuse
from detection_engine.rules.rule_003_unusual_assumerole import Rule003UnusualAssumeRole
from detection_engine.rules.rule_004_privilege_escalation import Rule004PrivilegeEscalation
from detection_engine.rules.rule_005_security_group_ingress import Rule005SecurityGroupIngress
from detection_engine.rules.rule_006_cloudtrail_tampering import Rule006CloudTrailTampering
from detection_engine.rules.rule_007_s3_security_drift import Rule007S3SecurityDrift
from detection_engine.rules.rule_008_sensitive_resource_access import Rule008SensitiveResourceAccess
from detection_engine.rules.rule_009_cross_account_abuse import Rule009CrossAccountAbuse
from detection_engine.rules.rule_010_api_sequence import Rule010APISequence

ALL_RULES: list[type[DetectionRule]] = [
    Rule001IAMKeyCreation,
    Rule002AccessKeyMisuse,
    Rule003UnusualAssumeRole,
    Rule004PrivilegeEscalation,
    Rule005SecurityGroupIngress,
    Rule006CloudTrailTampering,
    Rule007S3SecurityDrift,
    Rule008SensitiveResourceAccess,
    Rule009CrossAccountAbuse,
    Rule010APISequence,
]

__all__ = [
    "DetectionRule",
    "Rule001IAMKeyCreation",
    "Rule002AccessKeyMisuse",
    "Rule003UnusualAssumeRole",
    "Rule004PrivilegeEscalation",
    "Rule005SecurityGroupIngress",
    "Rule006CloudTrailTampering",
    "Rule007S3SecurityDrift",
    "Rule008SensitiveResourceAccess",
    "Rule009CrossAccountAbuse",
    "Rule010APISequence",
    "ALL_RULES",
]
