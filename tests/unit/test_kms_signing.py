"""
Project AEGIS - Forensic Cryptographic Signing & Authenticity Tests
Validates RSA-PSS asymmetric digital signatures, signature verification, and tamper detection.
"""

from __future__ import annotations

from services.forensics.collector import (
    EvidenceCollector,
    generate_ephemeral_keypair,
)
from services.forensics.models import (
    EvidenceType,
    TimelineEvent,
    TimelineStage,
)


def test_asymmetric_kms_signature_verification() -> None:
    """Verify authentic manifest generates valid RSASSA-PSS signature that passes verification."""
    collector = EvidenceCollector(vault_bucket="aegis-test-vault", object_lock_mode="COMPLIANCE")

    ev1 = collector.capture_record(
        incident_id="inc-sig-01",
        evidence_type=EvidenceType.FINDING_PAYLOAD,
        source_service="aegis.detection",
        account_id="197550036081",
        raw_data={"alert": "UnauthorizedRootLogin", "ip": "198.51.100.1"},
    )

    ev2 = collector.capture_record(
        incident_id="inc-sig-01",
        evidence_type=EvidenceType.REMEDIATION_ACTION_RECORD,
        source_service="aegis.soar",
        account_id="197550036081",
        raw_data={"action": "REVOKE_IAM_SESSIONS", "status": "VERIFIED"},
    )

    timeline = [
        TimelineEvent(
            stage=TimelineStage.DETECTION,
            timestamp=ev1.timestamp,
            summary="Threat detected",
            actor="root",
            target_resource="arn:aws:iam::197550036081:root",
            evidence_id=ev1.evidence_id,
        )
    ]

    manifest = collector.assemble_manifest(
        incident_id="inc-sig-01",
        account_id="197550036081",
        evidence_items=[ev1, ev2],
        timeline=timeline,
    )

    # Generate keypair and sign
    priv_pem, pub_pem = generate_ephemeral_keypair()
    signed_manifest = collector.sign_manifest(manifest, private_key_pem=priv_pem)

    assert signed_manifest.signature is not None
    assert signed_manifest.signing_algorithm == "RSASSA_PSS_SHA_256"

    # Verify authenticity with public key
    valid, msg = EvidenceCollector.verify_manifest_authenticity(
        signed_manifest, public_key_pem=pub_pem
    )
    assert valid is True
    assert "RSASSA_PSS_SHA_256" in msg
    assert "COMPLIANCE" in msg


def test_tampered_manifest_fails_authenticity_verification() -> None:
    """Verify signature verification fails if the manifest digest or record is altered."""
    collector = EvidenceCollector(vault_bucket="aegis-test-vault")

    ev1 = collector.capture_record(
        incident_id="inc-sig-02",
        evidence_type=EvidenceType.FINDING_PAYLOAD,
        source_service="aegis.detection",
        account_id="197550036081",
        raw_data={"target": "bucket-public"},
    )

    manifest = collector.assemble_manifest(
        incident_id="inc-sig-02",
        account_id="197550036081",
        evidence_items=[ev1],
        timeline=[],
    )

    priv_pem, pub_pem = generate_ephemeral_keypair()
    signed_manifest = collector.sign_manifest(manifest, private_key_pem=priv_pem)

    # Case 1: Tamper with raw evidence data
    tampered_items = [ev1.model_copy(update={"raw_data": {"target": "bucket-tampered"}})]
    tampered_manifest = signed_manifest.model_copy(update={"evidence_items": tampered_items})

    valid, msg = EvidenceCollector.verify_manifest_authenticity(
        tampered_manifest, public_key_pem=pub_pem
    )
    assert valid is False
    assert "Tampering detected" in msg

    # Case 2: Tamper with signature bytes
    corrupted_sig_manifest = signed_manifest.model_copy(
        update={"signature": "QUFBQUFBQUFBQUFBQUFBQQ=="}
    )
    valid2, msg2 = EvidenceCollector.verify_manifest_authenticity(
        corrupted_sig_manifest, public_key_pem=pub_pem
    )
    assert valid2 is False
    assert "Authenticity failed" in msg2
