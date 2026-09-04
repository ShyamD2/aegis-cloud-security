"""
Project AEGIS - Digital Forensics & Immutable Evidence Unit Tests
Validates cryptographic canonical hashing, manifest integrity, tamper detection,
chronological timeline reconstruction, incident metrics, and Athena query generation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from services.forensics import (
    EvidenceCollector,
    EvidenceType,
    TimelineReconstructor,
    TimelineStage,
    compute_canonical_sha256,
    get_athena_evidence_ddl,
    query_incident_chronology,
    query_principal_forensic_history,
)


def test_evidence_canonical_hashing_invariance() -> None:
    """Verify dictionary key insertion order does not affect computed SHA-256 hash."""
    data_order_a = {"account": "111122223333", "action": "AssumeRole", "severity": "HIGH"}
    data_order_b = {"severity": "HIGH", "action": "AssumeRole", "account": "111122223333"}

    hash_a = compute_canonical_sha256(data_order_a)
    hash_b = compute_canonical_sha256(data_order_b)

    assert hash_a == hash_b
    assert len(hash_a) == 64


def test_evidence_capture_and_manifest_assembly() -> None:
    """Verify evidence collection and cumulative manifest generation."""
    collector = EvidenceCollector(vault_bucket="test-forensics-bucket")
    incident_id = "inc-2026-0904-001"
    now = datetime.now(UTC)

    # 1. Capture CloudTrail record
    ev1 = collector.capture_record(
        incident_id=incident_id,
        evidence_type=EvidenceType.CLOUDTRAIL_RECORD,
        source_service="cloudtrail",
        account_id="111122223333",
        raw_data={"eventName": "CreateAccessKey", "userName": "contractor-alice"},
        timestamp=now,
    )
    assert ev1.evidence_id.startswith("ev-")
    assert ev1.sha256_checksum is not None

    # 2. Capture Security Finding
    ev2 = collector.capture_record(
        incident_id=incident_id,
        evidence_type=EvidenceType.FINDING_PAYLOAD,
        source_service="detection-engine",
        account_id="111122223333",
        raw_data={"rule_id": "AEGIS-001", "severity": "HIGH", "score": 85.0},
        timestamp=now + timedelta(seconds=5),
    )

    # 3. Capture Remediation Action
    ev3 = collector.capture_record(
        incident_id=incident_id,
        evidence_type=EvidenceType.REMEDIATION_ACTION_RECORD,
        source_service="stepfunctions",
        account_id="111122223333",
        raw_data={"action": "DEACTIVATE_ACCESS_KEY", "status": "VERIFIED"},
        timestamp=now + timedelta(seconds=12),
    )

    # 4. Assemble timeline
    timeline = [
        TimelineReconstructor.build_timeline_event(
            stage=TimelineStage.ATTACK,
            evidence=ev1,
            summary="Compromised user contractor-alice generated unauthorized access key",
            actor="arn:aws:iam::111122223333:user/contractor-alice",
            target_resource="arn:aws:iam::111122223333:user/contractor-alice",
        ),
        TimelineReconstructor.build_timeline_event(
            stage=TimelineStage.DETECTION,
            evidence=ev2,
            summary="AEGIS Rule AEGIS-001 triggered high severity finding",
            actor="aegis-detection-engine",
            target_resource="arn:aws:iam::111122223333:user/contractor-alice",
        ),
        TimelineReconstructor.build_timeline_event(
            stage=TimelineStage.POST_VERIFICATION,
            evidence=ev3,
            summary="Access key confirmed Inactive post-containment",
            actor="aegis-iam-remediator",
            target_resource="arn:aws:iam::111122223333:user/contractor-alice",
        ),
    ]

    manifest = collector.assemble_manifest(
        incident_id=incident_id,
        account_id="111122223333",
        evidence_items=[ev1, ev2, ev3],
        timeline=timeline,
    )

    assert manifest.total_evidence_items == 3
    assert len(manifest.manifest_sha256) == 64
    assert len(manifest.timeline) == 3

    # Verify integrity passes
    is_valid, msg = EvidenceCollector.verify_manifest_integrity(manifest)
    assert is_valid is True
    assert "passed" in msg.lower()


def test_evidence_tamper_detection() -> None:
    """Verify modifying any piece of evidence invalidates cryptographic verification."""
    collector = EvidenceCollector()
    incident_id = "inc-tamper-001"
    ev = collector.capture_record(
        incident_id=incident_id,
        evidence_type=EvidenceType.CLOUDTRAIL_RECORD,
        source_service="cloudtrail",
        account_id="111122223333",
        raw_data={"action": "OriginalData"},
    )
    manifest = collector.assemble_manifest(
        incident_id=incident_id,
        account_id="111122223333",
        evidence_items=[ev],
        timeline=[],
    )

    # Attacker alters the raw_data payload
    manifest.evidence_items[0].raw_data["action"] = "AlteredMaliciousData"

    is_valid, err_msg = EvidenceCollector.verify_manifest_integrity(manifest)
    assert is_valid is False
    assert "Tampering detected" in err_msg


def test_timeline_reconstruction_and_incident_metrics() -> None:
    """Verify MTTD and MTTC metrics across full 6-stage lifecycle."""
    collector = EvidenceCollector()
    incident_id = "inc-metrics-001"
    t0 = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

    e_attack = collector.capture_record(
        incident_id=incident_id,
        evidence_type=EvidenceType.CLOUDTRAIL_RECORD,
        source_service="cloudtrail",
        account_id="111",
        raw_data={"event": "Attack"},
        timestamp=t0,
    )
    e_detect = collector.capture_record(
        incident_id=incident_id,
        evidence_type=EvidenceType.FINDING_PAYLOAD,
        source_service="engine",
        account_id="111",
        raw_data={"event": "Detect"},
        timestamp=t0 + timedelta(seconds=14.5),
    )
    e_verify = collector.capture_record(
        incident_id=incident_id,
        evidence_type=EvidenceType.REMEDIATION_ACTION_RECORD,
        source_service="remediator",
        account_id="111",
        raw_data={"event": "Verify"},
        timestamp=t0 + timedelta(seconds=26.0),
    )

    timeline = [
        TimelineReconstructor.build_timeline_event(
            TimelineStage.ATTACK, e_attack, "Attack initiated", "actor", "resource"
        ),
        TimelineReconstructor.build_timeline_event(
            TimelineStage.DETECTION, e_detect, "Detected", "engine", "resource"
        ),
        TimelineReconstructor.build_timeline_event(
            TimelineStage.POST_VERIFICATION, e_verify, "Verified", "remediator", "resource"
        ),
    ]

    metrics = TimelineReconstructor.calculate_incident_metrics(timeline)
    assert metrics["mttd_seconds"] == 14.5
    assert metrics["mttc_seconds"] == 11.5
    assert metrics["total_duration_seconds"] == 26.0


def test_athena_queries_and_detective_links() -> None:
    """Verify Athena query generation and Detective deep-links."""
    ddl = get_athena_evidence_ddl("aegis_forensics", "evidence", "aegis-forensic-vault")
    assert "CREATE EXTERNAL TABLE IF NOT EXISTS aegis_forensics.evidence" in ddl
    assert "s3://aegis-forensic-vault/incidents/" in ddl

    chrono_query = query_incident_chronology("aegis_forensics", "evidence", "inc-999")
    assert "incident_id = 'inc-999'" in chrono_query
    assert "ORDER BY timestamp ASC" in chrono_query

    principal_query = query_principal_forensic_history(
        "aegis_forensics", "evidence", "contractor-alice"
    )
    assert "contractor-alice" in principal_query

    detective_url = TimelineReconstructor.generate_detective_investigation_url(
        account_id="111122223333", finding_id="finding-abc"
    )
    assert "https://console.aws.amazon.com/detective/home" in detective_url
    assert "finding-abc" in detective_url
