"""Unit tests for Phase 04 AWS Native Security Detection adapters and deduplicator."""

from datetime import UTC, datetime

import pytest

from services.common.models import FindingSeverity, FindingStatus, SecurityFinding
from services.findings.adapters.config import normalize_config_finding
from services.findings.adapters.detective import normalize_detective_finding
from services.findings.adapters.guardduty import normalize_guardduty_finding
from services.findings.adapters.inspector import normalize_inspector_finding
from services.findings.adapters.securityhub import normalize_securityhub_finding
from services.findings.deduplicator import FindingDeduplicator, FindingLifecycleManager


@pytest.mark.unit
def test_guardduty_adapter_normalization() -> None:
    """Validate GuardDuty raw finding normalization into canonical SecurityFinding."""
    gd_raw = {
        "id": "gd-12345-abcde",
        "detail": {
            "id": "gd-12345-abcde",
            "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
            "title": "Credentials exfiltrated to external IP",
            "description": "IAM credentials were used from an external IP address.",
            "severity": 8.0,
            "accountId": "123456789012",
            "region": "us-east-1",
            "createdAt": "2026-09-04T12:00:00Z",
            "resource": {
                "resourceType": "Instance",
                "instanceDetails": {"instanceId": "i-0123456789abcdef0"},
                "accessKeyDetails": {
                    "principalId": "AIDAEXAMPLE1234",
                    "userName": "compromised-user",
                },
            },
            "service": {"action": {"actionType": "AWS_API_CALL"}},
        },
    }
    finding = normalize_guardduty_finding(gd_raw)

    assert finding.finding_id == "aegis-gd-gd-12345-abcde"
    assert finding.severity == FindingSeverity.HIGH
    assert finding.account_id == "123456789012"
    assert finding.region == "us-east-1"
    assert "i-0123456789abcdef0" in finding.target_resources[0]
    assert finding.status == FindingStatus.NEW
    assert finding.confidence >= 0.8


@pytest.mark.unit
def test_securityhub_adapter_normalization() -> None:
    """Validate Security Hub ASFF normalization."""
    sh_raw = {
        "id": "arn:aws:securityhub:us-east-1:123456789012:subscription/pci-dss/v/3.2.1/PCI.S3.1/finding/sh-987",
        "detail": {
            "findings": [
                {
                    "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/sh-987",
                    "GeneratorId": "pci-dss/v/3.2.1/PCI.S3.1",
                    "AwsAccountId": "123456789012",
                    "Region": "us-east-1",
                    "Title": "S3 buckets should prohibit public write access",
                    "Description": "Bucket data-vault allows public write access.",
                    "Severity": {"Label": "CRITICAL"},
                    "Resources": [{"Id": "arn:aws:s3:::data-vault"}],
                    "Compliance": {"Status": "FAILED", "SecurityControlId": "PCI.S3.1"},
                    "CreatedAt": "2026-09-04T12:00:00Z",
                }
            ]
        },
    }
    finding = normalize_securityhub_finding(sh_raw)

    assert finding.finding_id == "aegis-sh-sh-987"
    assert finding.severity == FindingSeverity.CRITICAL
    assert finding.target_resources == ["arn:aws:s3:::data-vault"]
    assert finding.mitre_attack_technique == "PCI.S3.1"


@pytest.mark.unit
def test_config_adapter_normalization() -> None:
    """Validate AWS Config compliance event normalization."""
    config_raw = {
        "detail": {
            "configRuleName": "s3-bucket-public-read-prohibited",
            "awsAccountId": "123456789012",
            "awsRegion": "us-east-1",
            "newEvaluationResult": {
                "complianceType": "NON_COMPLIANT",
                "evaluationResultIdentifier": {
                    "evaluationResultQualifier": {
                        "resourceType": "AWS::S3::Bucket",
                        "resourceId": "open-customer-data",
                    }
                },
            },
        }
    }
    finding = normalize_config_finding(config_raw)

    assert "s3-bucket-public-read-prohibited" in finding.rule_id
    assert finding.severity == FindingSeverity.HIGH
    assert "open-customer-data" in finding.target_resources[0]


@pytest.mark.unit
def test_inspector_adapter_normalization() -> None:
    """Validate Amazon Inspector v2 CVE normalization."""
    inspector_raw = {
        "detail": {
            "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/cve-2026-9999",
            "awsAccountId": "123456789012",
            "region": "us-east-1",
            "title": "CVE-2026-9999 in urllib3",
            "severity": "CRITICAL",
            "packageVulnerabilityDetails": {
                "vulnerabilityId": "CVE-2026-9999",
                "cvss": [{"baseScore": 9.8}],
                "vulnerablePackages": [{"name": "urllib3", "version": "1.26.4"}],
            },
            "resources": [
                {"id": "arn:aws:ec2:us-east-1:123456789012:instance/i-11112222333344445"}
            ],
        }
    }
    finding = normalize_inspector_finding(inspector_raw)

    assert finding.finding_id == "aegis-insp-cve-2026-9999"
    assert finding.severity == FindingSeverity.CRITICAL
    assert finding.mitre_attack_technique == "T1190"


@pytest.mark.unit
def test_detective_adapter_normalization() -> None:
    """Validate Amazon Detective investigation summary normalization."""
    detective_raw = {
        "detail": {
            "investigationId": "inv-55555",
            "accountId": "123456789012",
            "region": "us-east-1",
            "title": "Anomalous API calls from new location",
            "entityArn": "arn:aws:iam::123456789012:role/AdminWorker",
            "indicators": ["New Geo Location", "Impossible Travel"],
        }
    }
    finding = normalize_detective_finding(detective_raw)

    assert finding.finding_id == "aegis-det-inv-55555"
    assert finding.status == FindingStatus.ANALYZING
    assert finding.principal_arn == "arn:aws:iam::123456789012:role/AdminWorker"


@pytest.mark.unit
def test_deduplicator_suppresses_duplicate() -> None:
    """Deduplicator must suppress exact duplicate findings."""
    deduper = FindingDeduplicator()

    finding = SecurityFinding(
        finding_id="aegis-test-01",
        rule_id="RULE-1",
        title="Test Finding",
        description="Testing deduplication",
        severity=FindingSeverity.HIGH,
        confidence=0.8,
        status=FindingStatus.NEW,
        created_at=datetime.now(UTC),
        account_id="123456789012",
        region="us-east-1",
        principal_arn="arn:aws:iam::123456789012:root",
        target_resources=["arn:aws:s3:::test-bucket"],
    )

    # First event: new finding
    is_new, result = deduper.process(finding)
    assert is_new is True

    # Second identical event: suppressed duplicate
    is_new2, result2 = deduper.process(finding)
    assert is_new2 is False
    assert result2.finding_id == "aegis-test-01"


@pytest.mark.unit
def test_deduplicator_updates_severity_change() -> None:
    """Deduplicator must yield an update if severity increases."""
    deduper = FindingDeduplicator()

    finding_v1 = SecurityFinding(
        finding_id="aegis-test-02",
        rule_id="RULE-2",
        title="Test Severity Escalation",
        description="Testing update detection",
        severity=FindingSeverity.MEDIUM,
        confidence=0.7,
        status=FindingStatus.NEW,
        created_at=datetime.now(UTC),
        account_id="123456789012",
        region="us-east-1",
        principal_arn="arn:aws:iam::123456789012:root",
        target_resources=["arn:aws:s3:::test-bucket-2"],
    )
    deduper.process(finding_v1)

    # Escalated version of the same finding
    finding_v2 = SecurityFinding(
        finding_id="aegis-test-02-esc",
        rule_id="RULE-2",
        title="Test Severity Escalation",
        description="Testing update detection",
        severity=FindingSeverity.CRITICAL,  # Changed
        confidence=0.9,
        status=FindingStatus.NEW,
        created_at=datetime.now(UTC),
        account_id="123456789012",
        region="us-east-1",
        principal_arn="arn:aws:iam::123456789012:root",
        target_resources=["arn:aws:s3:::test-bucket-2"],
    )
    is_new, updated = deduper.process(finding_v2)
    assert is_new is True
    assert updated.severity == FindingSeverity.CRITICAL


@pytest.mark.unit
def test_lifecycle_manager_valid_and_illegal_transitions() -> None:
    """Verify lifecycle manager allows valid transitions and blocks illegal shortcuts."""
    finding = SecurityFinding(
        finding_id="aegis-test-03",
        rule_id="RULE-3",
        title="Test Lifecycle",
        description="Testing state transitions",
        severity=FindingSeverity.LOW,
        confidence=0.5,
        status=FindingStatus.NEW,
        created_at=datetime.now(UTC),
        account_id="123456789012",
        region="us-east-1",
        principal_arn="arn:aws:iam::123456789012:root",
        target_resources=["arn:aws:s3:::test-bucket-3"],
    )

    # Valid: NEW -> ANALYZING
    FindingLifecycleManager.transition(finding, FindingStatus.ANALYZING)
    assert finding.status == FindingStatus.ANALYZING

    # Valid: ANALYZING -> CONTAINING
    FindingLifecycleManager.transition(finding, FindingStatus.CONTAINING)
    assert finding.status == FindingStatus.CONTAINING

    # Invalid: CONTAINING -> RESOLVED directly without VERIFIED
    with pytest.raises(ValueError, match="Illegal state transition"):
        FindingLifecycleManager.transition(finding, FindingStatus.RESOLVED)


@pytest.mark.unit
def test_malformed_event_handling() -> None:
    """Ensure adapters reject malformed payloads without crash."""
    with pytest.raises(ValueError, match="missing mandatory identifier"):
        normalize_guardduty_finding({"invalid": "payload"})

    with pytest.raises(ValueError, match="missing mandatory identifier"):
        normalize_securityhub_finding({"detail": {}})

    with pytest.raises(ValueError, match="missing mandatory identifier"):
        normalize_inspector_finding({"detail": {}})
