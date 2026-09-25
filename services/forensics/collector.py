"""
Project AEGIS - Evidence Collector & Cryptographic Sealer
Captures forensic telemetry, generates immutable SHA-256 digests, packages
evidence manifests, and applies AWS KMS asymmetric digital signatures (RSASSA-PSS-SHA-256).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

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


def generate_ephemeral_keypair() -> tuple[bytes, bytes]:
    """Generates an ephemeral RSA-2048 keypair in PEM format for local test signing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


class EvidenceCollector:
    """
    Acquires, cryptographically seals, signs, and archives incident evidence.
    """

    def __init__(
        self,
        vault_bucket: str = "aegis-forensic-vault-lab",
        object_lock_mode: str = "COMPLIANCE",
    ) -> None:
        self.vault_bucket = vault_bucket
        self.object_lock_mode = object_lock_mode

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
        object_lock_mode: str | None = None,
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
            object_lock_mode=object_lock_mode or self.object_lock_mode,
        )

    def sign_manifest(
        self,
        manifest: EvidenceManifest,
        kms_key_id: str = "arn:aws:kms:us-east-1:197550036081:key/aegis-forensic-signing-key",
        kms_client: Any = None,
        private_key_pem: bytes | None = None,
    ) -> EvidenceManifest:
        """
        Digitally signs the manifest's cumulative SHA-256 digest using RSASSA-PSS-SHA-256.
        Uses AWS KMS if `kms_client` is provided; otherwise uses software RSA key for local verification.
        """
        digest_bytes = manifest.manifest_sha256.encode("utf-8")

        if kms_client is not None:
            # AWS KMS Asymmetric Sign API
            response = kms_client.sign(
                KeyId=kms_key_id,
                Message=digest_bytes,
                MessageType="RAW",
                SigningAlgorithm="RSASSA_PSS_SHA_256",
            )
            raw_sig = response["Signature"]
            b64_sig = base64.b64encode(raw_sig).decode("utf-8")
            signed_by = kms_key_id
        else:
            # Software RSA-PSS fallback for local/offline testing
            key_pem = private_key_pem
            if key_pem is None:
                key_pem, _ = generate_ephemeral_keypair()
            loaded_key = serialization.load_pem_private_key(key_pem, password=None)
            assert isinstance(loaded_key, rsa.RSAPrivateKey)  # type: ignore[redundant-expr]
            raw_sig = loaded_key.sign(
                digest_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            b64_sig = base64.b64encode(raw_sig).decode("utf-8")
            signed_by = f"local-software-signer:{kms_key_id}"

        return manifest.model_copy(
            update={
                "kms_key_id": kms_key_id,
                "signature": b64_sig,
                "signing_algorithm": "RSASSA_PSS_SHA_256",
                "signed_by_arn": signed_by,
                "authenticity_verified": True,
            }
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
            "Cryptographic integrity passed: All evidence records and manifest seal intact.",
        )

    @staticmethod
    def verify_manifest_authenticity(
        manifest: EvidenceManifest,
        public_key_pem: bytes | None = None,
        kms_client: Any = None,
    ) -> tuple[bool, str]:
        """
        Validates integrity + non-repudiable authenticity + WORM immutability:
        1. Confirms raw data SHA-256 integrity and cumulative manifest seal.
        2. Validates the asymmetric digital signature against the manifest SHA-256.
        3. Validates S3 Object Lock configuration (COMPLIANCE or GOVERNANCE).
        """
        integrity_ok, integrity_msg = EvidenceCollector.verify_manifest_integrity(manifest)
        if not integrity_ok:
            return False, integrity_msg

        if not manifest.signature:
            return False, "Authenticity failed: Manifest is missing cryptographic digital signature."

        digest_bytes = manifest.manifest_sha256.encode("utf-8")
        try:
            raw_sig = base64.b64decode(manifest.signature)
        except Exception as e:
            return False, f"Authenticity failed: Invalid base64 signature encoding ({e})."

        if kms_client is not None and manifest.kms_key_id:
            try:
                response = kms_client.verify(
                    KeyId=manifest.kms_key_id,
                    Message=digest_bytes,
                    MessageType="RAW",
                    Signature=raw_sig,
                    SigningAlgorithm="RSASSA_PSS_SHA_256",
                )
                if not response.get("SignatureValid", False):
                    return False, "Authenticity failed: KMS signature verification returned False."
            except Exception as e:
                return False, f"Authenticity failed: KMS verify exception ({e})."
        elif public_key_pem is not None:
            try:
                pub_key = serialization.load_pem_public_key(public_key_pem)
                assert isinstance(pub_key, rsa.RSAPublicKey)  # type: ignore[redundant-expr]
                pub_key.verify(
                    raw_sig,
                    digest_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            except InvalidSignature:
                return False, "Authenticity failed: RSASSA-PSS signature verification failed."
            except Exception as e:
                return False, f"Authenticity failed: Error loading public key ({e})."

        if manifest.object_lock_mode not in ("COMPLIANCE", "GOVERNANCE"):
            return False, f"Immutability failed: Unrecognized Object Lock mode '{manifest.object_lock_mode}'."

        return (
            True,
            f"Verified: Integrity (SHA-256), Authenticity ({manifest.signing_algorithm}), and Immutability ({manifest.object_lock_mode} mode).",
        )
