"""Unit tests for Phase 03 Centralized Security Telemetry parsers and validators."""

from pathlib import Path

import pytest

from services.common.models import NormalizedSecurityEvent
from services.telemetry.parser import (
    parse_cloudtrail_event,
    parse_dns_query_log,
    parse_vpc_flow_log_line,
)
from services.telemetry.validator import TelemetryValidationError, validate_telemetry_event

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.mark.unit
def test_parse_cloudtrail_event(sample_cloudtrail_raw_event: dict) -> None:
    """Ensure CloudTrail events parse into NormalizedSecurityEvent retaining mandatory fields."""
    norm = parse_cloudtrail_event(sample_cloudtrail_raw_event)
    assert norm.source == "cloudtrail"
    assert norm.account_id == "123456789012"
    assert norm.region == "us-east-1"
    assert norm.action == "iam:CreateAccessKey"
    assert norm.principal_arn == "arn:aws:iam::123456789012:user/developer-dave"
    assert norm.source_ip == "198.51.100.24"
    assert len(norm.resource_arns) >= 1
    assert validate_telemetry_event(norm) is True


@pytest.mark.unit
def test_parse_vpc_flow_log_accepted() -> None:
    """Ensure accepted VPC Flow Logs parse into NormalizedSecurityEvent."""
    # Standard format: version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
    flow_line = "2 123456789012 eni-0123456789abcdef0 10.0.1.50 198.51.100.10 44322 443 6 12 1840 1725451200 1725451260 ACCEPT OK"
    norm = parse_vpc_flow_log_line(flow_line, region="us-east-1")

    assert norm.source == "vpcflow"
    assert norm.account_id == "123456789012"
    assert norm.region == "us-east-1"
    assert norm.action == "network:accept"
    assert norm.source_ip == "10.0.1.50"
    assert norm.status == "SUCCESS"
    assert validate_telemetry_event(norm) is True


@pytest.mark.unit
def test_parse_vpc_flow_log_rejected() -> None:
    """Ensure rejected VPC Flow Logs parse with REJECTED status."""
    flow_line = "2 123456789012 eni-0123456789abcdef0 203.0.113.5 10.0.1.50 51234 22 6 1 40 1725451200 1725451260 REJECT OK"
    norm = parse_vpc_flow_log_line(flow_line, region="us-east-1")

    assert norm.source == "vpcflow"
    assert norm.action == "network:reject"
    assert norm.status == "REJECTED"
    assert norm.source_ip == "203.0.113.5"


@pytest.mark.unit
def test_parse_dns_query_log() -> None:
    """Ensure Route 53 Resolver query logs parse into NormalizedSecurityEvent."""
    dns_raw = {
        "account_id": "123456789012",
        "query_timestamp": "2026-09-04T12:00:00Z",
        "query_name": "c2-bad-domain.attacker.com.",
        "query_type": "A",
        "rcode": "NOERROR",
        "srcaddr": "10.0.2.14",
        "srcids": {"instance": "i-0987654321fedcba0"},
    }
    norm = parse_dns_query_log(dns_raw, region="us-east-1")

    assert norm.source == "route53"
    assert norm.account_id == "123456789012"
    assert norm.action == "dns:query"
    assert norm.resource_arns == ["domain/c2-bad-domain.attacker.com."]
    assert norm.source_ip == "i-0987654321fedcba0"
    assert validate_telemetry_event(norm) is True


@pytest.mark.unit
def test_validator_rejects_invalid_account_id(
    sample_normalized_event: NormalizedSecurityEvent,
) -> None:
    """Validator must reject non-12-digit account IDs."""
    sample_normalized_event.account_id = "bad_account"
    with pytest.raises(TelemetryValidationError, match="Invalid AWS account ID"):
        validate_telemetry_event(sample_normalized_event)


@pytest.mark.unit
def test_validator_rejects_empty_resources(
    sample_normalized_event: NormalizedSecurityEvent,
) -> None:
    """Validator must reject events with empty resource_arns."""
    sample_normalized_event.resource_arns = []
    with pytest.raises(TelemetryValidationError, match="Missing mandatory field: resource_arns"):
        validate_telemetry_event(sample_normalized_event)


@pytest.mark.security
def test_telemetry_terraform_security_invariants() -> None:
    """Verify that the Terraform telemetry module enforces Object Lock, KMS encryption, and TLS."""
    telemetry_main = REPO_ROOT / "terraform" / "modules" / "telemetry" / "main.tf"
    assert telemetry_main.exists()

    content = telemetry_main.read_text(encoding="utf-8")
    assert "object_lock_enabled = true" in content
    assert 'sse_algorithm     = "aws:kms"' in content
    assert "aws:SecureTransport" in content
    assert "enable_log_file_validation    = true" in content
    assert "INTELLIGENT_TIERING" in content
    assert "GLACIER" in content
