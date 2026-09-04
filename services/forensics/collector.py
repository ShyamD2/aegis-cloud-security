"""
Project AEGIS - Evidence Collector & Cryptographic Sealer
Captures forensic telemetry, generates immutable SHA-256 digests, and packages
evidence manifests with cryptographic verification.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from services.forensics.models import (
    EvidenceManifest,
    EvidenceRecord,
    EvidenceType,
    TimelineEvent,
)

logger = logging.getLogger("aegis.forensics.collector")


def compute_canonical_sha256(data: dict[str, Any]) -> str:
    """
    Serializes a dictionary using canonical JSON (sorted keys, no extraneous whitespace)
    and returns the lowercase SHA-256 hexadecimal digest.
    """
    canonical_json = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class EvidenceCollector:
    """
    Acquires, cryptographically seals, and archives incident evidence.
    """

    def __init__(self, vault_bucket: str = "aegis-forensic-vault-lab") -> None:
        self.vault_bucket = vault_bucket

    def capture_record(
        self,
        incident_id: str,
        evidence_type: EvidenceType,
        source_service: str,
        account_id: str,
        raw_data: dict[str, Any],
        region: str = "us-east-1",
        timestamp: datetime | None = None,
    ) -> EvidenceRecord:
        """Capture and cryptographically hash an individual forensic record."""
        ts = timestamp or datetime.now(UTC)
        ev_id = f"ev-{uuid.uuid4().hex[:12]}"
        checksum = compute_canonical_sha256(raw_data)
        s3_uri = f"s3://{self.vault_bucket}/incidents/{incident_id}/{ev_id}.json"

        return EvidenceRecord(
            evidence_id=ev_id,
            incident_id=incident_id,
            timestamp=ts,
            evidence_type=evidence_type,
            source_service=source_service,
            account_id=account_id,
            region=region,
            raw_data=raw_data,
            sha256_checksum=checksum,
            s3_uri=s3_uri,
        )

    def assemble_manifest(
        self,
        incident_id: str,
        account_id: str,
        evidence_items: list[EvidenceRecord],
        timeline: list[TimelineEvent],
    ) -> EvidenceManifest:
        """
        Assembles all captured evidence and timeline events into a cryptographically sealed manifest.
        The manifest SHA-256 is the digest of the sorted individual evidence checksums.
        """
        sorted_digests = sorted(item.sha256_checksum for item in evidence_items)
        combined_payload = "".join(sorted_digests)
        manifest_digest = hashlib.sha256(combined_payload.encode("utf-8")).hexdigest()

        return EvidenceManifest(
            manifest_id=f"manifest-{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            account_id=account_id,
            total_evidence_items=len(evidence_items),
            manifest_sha256=manifest_digest,
            evidence_items=evidence_items,
            timeline=timeline,
            storage_vault_bucket=self.vault_bucket,
        )

    @staticmethod
    def verify_manifest_integrity(manifest: EvidenceManifest) -> tuple[bool, str]:
        """
        Validates the cryptographic integrity of an evidence manifest:
        1. Confirms each record's raw_data recomputes to its sha256_checksum.
        2. Confirms cumulative manifest_sha256 matches the recomputed combined digest.
        """
        for item in manifest.evidence_items:
            expected = compute_canonical_sha256(item.raw_data)
            if expected != item.sha256_checksum:
                return (
                    False,
                    f"Tampering detected: Evidence {item.evidence_id} checksum mismatch (expected {expected}, got {item.sha256_checksum})",
                )

        sorted_digests = sorted(item.sha256_checksum for item in manifest.evidence_items)
        expected_manifest_digest = hashlib.sha256(
            "".join(sorted_digests).encode("utf-8")
        ).hexdigest()
        if expected_manifest_digest != manifest.manifest_sha256:
            return (
                False,
                f"Manifest seal broken: Cumulative digest mismatch (expected {expected_manifest_digest}, got {manifest.manifest_sha256})",
            )

        return (
            True,
            "Cryptographic verification passed: All evidence records and manifest seal intact.",
        )
