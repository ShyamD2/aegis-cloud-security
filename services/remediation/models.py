"""
Project AEGIS - Automated Incident Response Models
Defines remediation actions, execution statuses, request payloads, and verification results.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RemediationAction(StrEnum):
    """Supported containment and self-healing actions."""

    REVOKE_IAM_SESSIONS = "REVOKE_IAM_SESSIONS"
    DEACTIVATE_ACCESS_KEY = "DEACTIVATE_ACCESS_KEY"
    ATTACH_QUARANTINE_BOUNDARY = "ATTACH_QUARANTINE_BOUNDARY"
    ISOLATE_EC2_INSTANCE = "ISOLATE_EC2_INSTANCE"
    ENFORCE_S3_BLOCK_PUBLIC = "ENFORCE_S3_BLOCK_PUBLIC"
    REVOKE_SECURITY_GROUP_INGRESS = "REVOKE_SECURITY_GROUP_INGRESS"
    QUARANTINE_ACCOUNT = "QUARANTINE_ACCOUNT"


class RemediationStatus(StrEnum):
    """Lifecycle status of a containment task."""

    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


class RemediationRequest(BaseModel):
    """Standardized invocation request for the AEGIS Remediation Engine."""

    model_config = ConfigDict(extra="forbid")

    remediation_id: str = Field(description="Unique remediation identifier")
    finding_id: str = Field(description="Originating security finding ID")
    action: RemediationAction = Field(description="Specific containment action to execute")
    target_resource_id: str = Field(
        description="Target ARN, instance ID, bucket name, or account ID"
    )
    account_id: str = Field(description="AWS account containing target resource")
    region: str = Field(default="us-east-1", description="Target AWS region")
    risk_score: float = Field(
        ge=0.0,
        le=100.0,
        description="Calculated risk score from Phase 09 Risk Engine",
    )
    requires_human_approval: bool = Field(
        default=False,
        description="If True, action must provide a valid approval_token",
    )
    approval_token: str | None = Field(
        default=None,
        description="Cryptographic or SOC operator approval token",
    )
    idempotency_key: str = Field(
        description="Unique deduplication key preventing repeated containment executions",
    )
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Action-specific parameters (e.g. access_key_id, quarantine_sg_id)",
    )


class RemediationResult(BaseModel):
    """Detailed outcome of a remediation and post-execution verification."""

    model_config = ConfigDict(extra="forbid")

    remediation_id: str = Field(description="Remediation request identifier")
    action: RemediationAction = Field(description="Action executed")
    target_resource_id: str = Field(description="Target resource identifier")
    status: RemediationStatus = Field(description="Terminal or execution status")
    pre_state: dict[str, Any] = Field(
        default_factory=dict,
        description="Snapshot of configuration prior to containment (used for rollback)",
    )
    post_state: dict[str, Any] = Field(
        default_factory=dict,
        description="Snapshot of configuration immediately following containment",
    )
    verified: bool = Field(
        default=False,
        description="True if post-execution inspection confirms security state achieved",
    )
    verification_details: str = Field(
        description="Technical evidence verifying containment success or failure",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Completion timestamp",
    )
    error_message: str | None = Field(
        default=None,
        description="Error description if containment failed",
    )
    rollback_supported: bool = Field(
        default=True,
        description="Indicates whether this remediator supports automated rollback",
    )
