"""Unit tests for Phase 05 Custom Detection Engine, rules, enrichment, and sequence detection."""

from datetime import UTC, datetime, timedelta

import pytest

from detection_engine.enrichment import EventEnricher
from detection_engine.evaluator import DetectionEvaluator
from detection_engine.models import AccountTier, PrincipalPrivilegeTier
from detection_engine.registry import RuleRegistry
from services.common.models import FindingSeverity, NormalizedSecurityEvent


def make_test_event(
    action: str,
    principal_arn: str = "arn:aws:iam::123456789012:user/test-user",
    principal_type: str = "IAMUser",
    source_ip: str = "198.51.100.24",
    account_id: str = "123456789012",
    resource_arns: list[str] | None = None,
    raw_payload: dict | None = None,
    user_agent: str = "aws-cli/2.15.0",
    timestamp: datetime | None = None,
) -> NormalizedSecurityEvent:
    """Helper to generate synthetic NormalizedSecurityEvent."""
    return NormalizedSecurityEvent(
        event_id=f"evt-{int(datetime.now(UTC).timestamp() * 1000)}",
        source="cloudtrail",
        timestamp=timestamp or datetime.now(UTC),
        account_id=account_id,
        region="us-east-1",
        principal_arn=principal_arn,
        principal_type=principal_type,
        action=action,
        resource_arns=resource_arns or [principal_arn],
        source_ip=source_ip,
        user_agent=user_agent,
        status="SUCCESS",
        raw_payload=raw_payload or {},
    )


@pytest.mark.unit
def test_event_enrichment_classification() -> None:
    """Validate that EventEnricher properly classifies account tiers, principal privilege, and external IPs."""
    # 1. Root user test
    root_event = make_test_event(
        action="iam:ListUsers",
        principal_arn="arn:aws:iam::123456789012:root",
        principal_type="Root",
        source_ip="10.0.1.5",  # Private RFC 1918 IP
    )
    enriched_root = EventEnricher.enrich(root_event)
    assert enriched_root.principal_privilege == PrincipalPrivilegeTier.ROOT
    assert enriched_root.is_external_ip is False

    # 2. External IP & Admin test
    admin_event = make_test_event(
        action="iam:ListUsers",
        principal_arn="arn:aws:iam::777788889999:role/ProdAdminRole",
        source_ip="203.0.113.88",  # Public external IP
        account_id="777788889999",
    )
    enriched_admin = EventEnricher.enrich(admin_event)
    assert enriched_admin.principal_privilege == PrincipalPrivilegeTier.IAM_ADMIN
    assert enriched_admin.account_tier == AccountTier.PRODUCTION
    assert enriched_admin.is_external_ip is True


@pytest.mark.unit
def test_rule_001_iam_key_creation() -> None:
    """Rule 001 must trigger on key creation on root (CRITICAL) and external IP (HIGH)."""
    evaluator = DetectionEvaluator()

    # Root key creation -> CRITICAL
    root_event = make_test_event(
        action="iam:CreateAccessKey",
        principal_arn="arn:aws:iam::123456789012:root",
        principal_type="Root",
    )
    _, findings = evaluator.evaluate_event(root_event)
    r1_findings = [f for f in findings if f.rule_id == "AEGIS-DET-001"]
    assert len(r1_findings) == 1
    assert r1_findings[0].severity == FindingSeverity.CRITICAL

    # External IP key creation -> HIGH
    ext_event = make_test_event(
        action="iam:CreateAccessKey",
        principal_arn="arn:aws:iam::123456789012:user/dev-bob",
        source_ip="198.51.100.5",
    )
    _, findings2 = evaluator.evaluate_event(ext_event)
    r1_findings2 = [f for f in findings2 if f.rule_id == "AEGIS-DET-001"]
    assert len(r1_findings2) == 1
    assert r1_findings2[0].severity == FindingSeverity.HIGH


@pytest.mark.unit
def test_rule_002_access_key_misuse() -> None:
    """Rule 002 must trigger on curl / python-requests scripting agents from external IPs."""
    evaluator = DetectionEvaluator()

    script_event = make_test_event(
        action="iam:GetUser",
        source_ip="203.0.113.45",
        user_agent="python-requests/2.31.0",
    )
    _, findings = evaluator.evaluate_event(script_event)
    r2_findings = [f for f in findings if f.rule_id == "AEGIS-DET-002"]
    assert len(r2_findings) == 1
    assert r2_findings[0].severity == FindingSeverity.HIGH


@pytest.mark.unit
def test_rule_003_unusual_assumerole() -> None:
    """Rule 003 must trigger on cross-account AssumeRole from external IP."""
    evaluator = DetectionEvaluator()

    assume_event = make_test_event(
        action="sts:AssumeRole",
        principal_arn="arn:aws:iam::999988887777:user/attacker",
        account_id="777788889999",  # Target account != principal account (cross-account)
        source_ip="198.51.100.99",
    )
    _, findings = evaluator.evaluate_event(assume_event)
    r3_findings = [f for f in findings if f.rule_id == "AEGIS-DET-003"]
    assert len(r3_findings) == 1


@pytest.mark.unit
def test_rule_004_privilege_escalation() -> None:
    """Rule 004 must detect AdministratorAccess attachments."""
    evaluator = DetectionEvaluator()

    esc_event = make_test_event(
        action="iam:AttachUserPolicy",
        raw_payload={"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
    )
    _, findings = evaluator.evaluate_event(esc_event)
    r4_findings = [f for f in findings if f.rule_id == "AEGIS-DET-004"]
    assert len(r4_findings) == 1
    assert r4_findings[0].severity == FindingSeverity.CRITICAL


@pytest.mark.unit
def test_rule_005_security_group_ingress() -> None:
    """Rule 005 must detect 0.0.0.0/0 ingress on port 22/3389."""
    evaluator = DetectionEvaluator()

    sg_event = make_test_event(
        action="ec2:AuthorizeSecurityGroupIngress",
        raw_payload={"ipPermissions": [{"cidrIp": "0.0.0.0/0", "fromPort": 22, "toPort": 22}]},
    )
    _, findings = evaluator.evaluate_event(sg_event)
    r5_findings = [f for f in findings if f.rule_id == "AEGIS-DET-005"]
    assert len(r5_findings) == 1
    assert r5_findings[0].severity == FindingSeverity.CRITICAL


@pytest.mark.unit
def test_rule_006_cloudtrail_tampering() -> None:
    """Rule 006 must detect StopLogging and DeleteTrail."""
    evaluator = DetectionEvaluator()

    stop_event = make_test_event(action="cloudtrail:StopLogging")
    _, findings = evaluator.evaluate_event(stop_event)
    r6_findings = [f for f in findings if f.rule_id == "AEGIS-DET-006"]
    assert len(r6_findings) == 1
    assert r6_findings[0].severity == FindingSeverity.CRITICAL


@pytest.mark.unit
def test_rule_007_s3_security_drift() -> None:
    """Rule 007 must detect DeleteBucketPolicy and wildcard PutBucketPolicy."""
    evaluator = DetectionEvaluator()

    drift_event = make_test_event(action="s3:DeleteBucketPolicy")
    _, findings = evaluator.evaluate_event(drift_event)
    r7_findings = [f for f in findings if f.rule_id == "AEGIS-DET-007"]
    assert len(r7_findings) == 1


@pytest.mark.unit
def test_rule_008_sensitive_resource_access() -> None:
    """Rule 008 must detect GetSecretValue from external IP."""
    evaluator = DetectionEvaluator()

    secret_event = make_test_event(
        action="secretsmanager:GetSecretValue",
        source_ip="198.51.100.12",
        resource_arns=["arn:aws:secretsmanager:us-east-1:123456789012:secret:db-password-vault"],
    )
    _, findings = evaluator.evaluate_event(secret_event)
    r8_findings = [f for f in findings if f.rule_id == "AEGIS-DET-008"]
    assert len(r8_findings) == 1


@pytest.mark.unit
def test_rule_009_cross_account_abuse() -> None:
    """Rule 009 must detect cross-account assume-role into Production."""
    evaluator = DetectionEvaluator()

    abuse_event = make_test_event(
        action="sts:AssumeRole",
        principal_arn="arn:aws:iam::888877776666:role/StagingWorker",
        account_id="777788889999",  # Production account
    )
    _, findings = evaluator.evaluate_event(abuse_event)
    r9_findings = [f for f in findings if f.rule_id == "AEGIS-DET-009"]
    assert len(r9_findings) == 1


@pytest.mark.unit
def test_rule_010_api_sequence_detection() -> None:
    """Rule 010 must trigger only after complete multi-step attack sequence within 5 minutes."""
    evaluator = DetectionEvaluator()
    principal = "arn:aws:iam::123456789012:user/attacker-dave"
    now = datetime.now(UTC)

    # Step 1: CreateAccessKey (isolated)
    ev1 = make_test_event("iam:CreateAccessKey", principal_arn=principal, timestamp=now)
    _, f1 = evaluator.evaluate_event(ev1)
    assert not any(f.rule_id == "AEGIS-DET-010" for f in f1)

    # Step 2: Privilege escalation (AttachUserPolicy)
    ev2 = make_test_event(
        "iam:AttachUserPolicy", principal_arn=principal, timestamp=now + timedelta(seconds=30)
    )
    _, f2 = evaluator.evaluate_event(ev2)
    assert not any(f.rule_id == "AEGIS-DET-010" for f in f2)

    # Step 3: Sensitive Secret Access (GetSecretValue)
    ev3 = make_test_event(
        "secretsmanager:GetSecretValue",
        principal_arn=principal,
        timestamp=now + timedelta(seconds=60),
    )
    _, f3 = evaluator.evaluate_event(ev3)
    # Now sequence is complete -> AEGIS-DET-010 MUST trigger!
    r10_findings = [f for f in f3 if f.rule_id == "AEGIS-DET-010"]
    assert len(r10_findings) == 1
    assert r10_findings[0].severity == FindingSeverity.CRITICAL


@pytest.mark.unit
def test_benign_event_triggers_no_findings() -> None:
    """Benign standard developer activity must produce zero findings."""
    evaluator = DetectionEvaluator()

    benign_event = make_test_event(
        action="s3:GetObject",
        principal_arn="arn:aws:iam::123456789012:role/StandardAppRole",
        source_ip="10.0.2.15",  # Internal private IP
        user_agent="aws-sdk-python/1.34.0",
        resource_arns=["arn:aws:s3:::app-static-assets/index.html"],
    )
    _, findings = evaluator.evaluate_event(benign_event)
    assert len(findings) == 0


@pytest.mark.unit
def test_rule_registry_management() -> None:
    """Verify registry counts and registration/unregistration behavior."""
    registry = RuleRegistry(load_defaults=True)
    assert registry.count() == 10
    assert registry.get_rule("AEGIS-DET-001") is not None

    registry.unregister("AEGIS-DET-001")
    assert registry.count() == 9
    assert registry.get_rule("AEGIS-DET-001") is None
