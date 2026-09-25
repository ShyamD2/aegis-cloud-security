"""
Project AEGIS - Digital Forensics & Immutable Evidence Models
Defines evidence record schemas, cryptographic checksums, timeline stages,
asymmetric KMS digital signature envelopes, and evidence manifests.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EvidenceType(StrEnum):
    """Categorization of captured forensic artifacts."""

    CLOUDTRAIL_RECORD = "CLOUDTRAIL_RECORD"
    FINDING_PAYLOAD = "FINDING_PAYLOAD"
    IAM_STATE_SNAPSHOT = "IAM_STATE_SNAPSHOT"
    EC2_METADATA_SNAPSHOT = "EC2_METADATA_SNAPSHOT"
    SECURITY_GROUP_SNAPSHOT = "SECURITY_GROUP_SNAPSHOT"
    S3_CONFIG_SNAPSHOT = "S3_CONFIG_SNAPSHOT"
    NETWORK_FLOW_TELEMETRY = "NETWORK_FLOW_TELEMETRY"
    REMEDIATION_ACTION_RECORD = "REMEDIATION_ACTION_RECORD"


class TimelineStage(StrEnum):
    """Standardized stages of cloud incident progression."""

    ATTACK = "ATTACK"
    DETECTION = "DETECTION"
    CORRELATION = "CORRELATION"
    RISK_EVALUATION = "RISK_EVALUATION"
    CONTAINMENT_RESPONSE = "CONTAINMENT_RESPONSE"
    POST_VERIFICATION = "POST_VERIFICATION"


class EvidenceRecord(BaseModel):
    """Single forensically captured and cryptographically hashed artifact."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(description="Unique evidence identifier")
    incident_id: str = Field(description="Correlated incident ID")
    timestamp: datetime = Field(description="ISO timestamp of evidence capture")
    evidence_type: EvidenceType = Field(description="Type of forensic artifact")
    source_service: str = Field(description="Originating AWS service or AEGIS sub-engine")
    account_id: str = Field(description="AWS account where artifact originated")
    region: str = Field(default="us-east-1", description="AWS region")
    raw_data: dict[str, Any] = Field(
        description="Original telemetry, finding, or configuration payload"
    )
    sha256_checksum: str = Field(description="SHA-256 cryptographic digest of canonical raw_data")
    s3_uri: str | None = Field(default=None, description="S3 Object Lock vault URI if persisted")
    retention_days: int = Field(
        default=90, description="Object Lock legal hold/retention period in days"
    )


class TimelineEvent(BaseModel):
    """Reconstructed event in the incident timeline."""

    model_config = ConfigDict(extra="forbid")

    stage: TimelineStage = Field(description="Lifecycle stage of the event")
    timestamp: datetime = Field(description="Timestamp of event occurrence")
    summary: str = Field(description="Human-readable event description")
    actor: str = Field(description="Principal, IP, or service responsible")
    target_resource: str = Field(description="Impacted ARN, resource ID, or account")
    evidence_id: str = Field(description="ID of associated EvidenceRecord")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional context")


class EvidenceManifest(BaseModel):
    """Immutable forensic evidence package sealing an entire incident investigation."""

    model_config = ConfigDict(extra="forbid")

    manifest_id: str = Field(description="Unique manifest identifier")
    incident_id: str = Field(description="Correlated incident ID")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Manifest creation timestamp",
    )
    account_id: str = Field(description="Primary account under investigation")
    total_evidence_items: int = Field(ge=0, description="Count of archived evidence items")
    manifest_sha256: str = Field(
        description="Cumulative cryptographic digest over all constituent evidence digests",
    )
    evidence_items: list[EvidenceRecord] = Field(description="List of captured evidence records")
    timeline: list[TimelineEvent] = Field(description="Synthesized chronological incident timeline")
    storage_vault_bucket: str = Field(description="S3 bucket housing the Object Lock evidence")
    kms_key_id: str | None = Field(
        default=None,
        description="AWS KMS asymmetric key ARN or ID used for digital signature",
    )
    signature: str | None = Field(
        default=None,
        description="Base64-encoded asymmetric digital signature proving authenticity",
    )
    signing_algorithm: str = Field(
        default="RSASSA_PSS_SHA_256",
        description="Asymmetric signing algorithm",
    )
    signed_by_arn: str | None = Field(
        default=None,
        description="IAM identity or KMS alias that executed the signature",
    )
    object_lock_mode: str = Field(
        default="COMPLIANCE",
        description="S3 Object Lock retention mode (COMPLIANCE or GOVERNANCE)",
    )
    retention_until_date: datetime | None = Field(
        default=None,
        description="Explicit WORM retention expiration timestamp",
    )
    authenticity_verified: bool = Field(
        default=False,
        description="True if cryptographic signature and integrity were verified",
    )
