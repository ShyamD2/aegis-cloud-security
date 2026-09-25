"""
Project AEGIS - Attack Replay Engine Unit Tests
Validates the replay runner across scenarios, execution modes, and KMS digital signing.
"""

from __future__ import annotations

from scripts.aegis_replay import run_attack_replay
from services.remediation.models import RemediationExecutionMode


def test_attack_replay_scenario_01_enforce() -> None:
    """Verify Scenario 01 runs through complete pipeline, contains threat, and seals manifest."""
    report = run_attack_replay(1, execution_mode=RemediationExecutionMode.ENFORCE)

    assert report["scenario_id"] == "SCENARIO-01"
    assert report["status"] == "VERIFIED"
    assert report["stages_passed"] == 8
    assert report["expected_remediation"] == "DEACTIVATE_ACCESS_KEY"
    assert report["authenticity_verified"] is True
    assert report["signing_algorithm"] == "RSASSA_PSS_SHA_256"
    assert report["object_lock_mode"] == "COMPLIANCE"
    assert report["manifest_sha256"] != ""
    assert report["detection_latency_ms"] > 0


def test_attack_replay_scenario_04_dry_run() -> None:
    """Verify Scenario 04 executes in DRY_RUN mode with verified simulation."""
    report = run_attack_replay(4, execution_mode=RemediationExecutionMode.DRY_RUN)

    assert report["scenario_id"] == "SCENARIO-04"
    assert report["status"] == "VERIFIED"
    assert report["expected_remediation"] == "ENFORCE_S3_BLOCK_PUBLIC"
    assert report["authenticity_verified"] is True


def test_attack_replay_scenario_08_logging_tamper() -> None:
    """Verify Scenario 08 CloudTrail tampering triggers emergency session revocation and seal."""
    report = run_attack_replay(8, execution_mode=RemediationExecutionMode.ENFORCE)

    assert report["scenario_id"] == "SCENARIO-08"
    assert report["status"] == "VERIFIED"
    assert report["expected_remediation"] == "REVOKE_IAM_SESSIONS"
    assert report["risk_score"] >= 90.0  # Sev-1
