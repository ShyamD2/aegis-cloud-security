"""Tests verifying IAM policies, SCP guardrails, and trust model invariants for Phase 02."""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.mark.security
def test_scp_policy_syntax_and_denies() -> None:
    """Validate that SCPs in terraform/modules/scps/main.tf enforce Deny rules and protected controls."""
    scps_main_file = REPO_ROOT / "terraform" / "modules" / "scps" / "main.tf"
    assert scps_main_file.exists(), f"File {scps_main_file} not found"

    content = scps_main_file.read_text(encoding="utf-8")

    # Verify all 5 SCP policies exist
    expected_policies = [
        "aegis-deny-leaving-org",
        "aegis-protect-security-controls",
        "aegis-protect-log-archive",
        "aegis-restrict-regions",
        "aegis-emergency-quarantine",
    ]
    for policy_name in expected_policies:
        assert policy_name in content, f"Missing SCP: {policy_name}"

    # Verify that all SCP statements specify Effect = "Deny"
    effects = re.findall(r'Effect\s*=\s*"(\w+)"', content)
    assert len(effects) >= 5, "Expected multiple statements in SCP definitions"
    assert all(e == "Deny" for e in effects), f"Non-Deny statements detected in SCP: {effects}"

    # Verify critical protected API actions
    assert "organizations:LeaveOrganization" in content
    assert "cloudtrail:DeleteTrail" in content
    assert "cloudtrail:StopLogging" in content
    assert "guardduty:DeleteDetector" in content
    assert "securityhub:DisableSecurityHub" in content
    assert "config:StopConfigurationRecorder" in content
    assert "s3:DeleteBucket" in content


@pytest.mark.security
def test_iam_trust_and_containment_boundary() -> None:
    """Verify that IAM containment roles require sts:ExternalId and enforce boundaries."""
    iam_main_file = REPO_ROOT / "terraform" / "modules" / "iam_trust" / "main.tf"
    assert iam_main_file.exists()

    content = iam_main_file.read_text(encoding="utf-8")

    # Ensure external_id is required in assume_role policies
    assert "sts:ExternalId" in content
    assert "permissions_boundary" in content

    # Ensure dangerous admin actions are denied in the boundary policy
    assert "organizations:*" in content
    assert "cloudtrail:*" in content
    assert "DenyHighPrivilegeEscalation" in content


@pytest.mark.security
def test_kms_foundation_policies() -> None:
    """Ensure KMS keys have explicit root administration and key rotation enabled."""
    kms_main_file = REPO_ROOT / "terraform" / "modules" / "kms_foundation" / "main.tf"
    assert kms_main_file.exists()

    content = kms_main_file.read_text(encoding="utf-8")
    assert "enable_key_rotation     = true" in content
    assert "alias/${var.project_name}-central-logs" in content
    assert "alias/${var.project_name}-pipeline" in content
    assert "alias/${var.project_name}-forensic-evidence" in content
