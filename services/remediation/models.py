"""
Project AEGIS - Automated Incident Response Models
Defines remediation actions, execution statuses, safety policies, request payloads, and verification results.
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


class RemediationExecutionMode(StrEnum):
    """Operational mode governing autonomous remediation execution safety."""

    RECOMMENDATION = (
        "RECOMMENDATION"  # Safe default: generate advisory proposal without mutating AWS
    )
    DRY_RUN = "DRY_RUN"  # Simulate validation & snapshot without mutating AWS
    ENFORCE = "ENFORCE"  # Active execution with automated post-verification & rollback


class ContainmentSafetyPolicy(BaseModel):
    """Formal governance policy defining execution thresholds and constraints for a containment action."""

    model_config = ConfigDict(extra="forbid")

    action: RemediationAction
    minimum_risk_score: float = Field(
        ge=0.0, le=100.0, description="Minimum risk score required to trigger action"
    )
    minimum_confidence: float = Field(
        default=0.75, ge=0.0, le=1.0, description="Minimum detection confidence required"
    )
    blast_radius_scope: str = Field(
        description="Operational scope (e.g. single_credential, single_instance, account_wide)"
    )
    is_reversible: bool = Field(
        default=True, description="Whether this containment action supports automated rollback"
    )
    requires_human_approval: bool = Field(
        default=False, description="Whether action requires explicit SOC operator approval"
    )
    requires_post_verification: bool = Field(
        default=True, description="Whether immediate post-condition check is enforced"
    )


DEFAULT_SAFETY_POLICIES: dict[RemediationAction, ContainmentSafetyPolicy] = {
    RemediationAction.REVOKE_IAM_SESSIONS: ContainmentSafetyPolicy(
        action=RemediationAction.REVOKE_IAM_SESSIONS,
        minimum_risk_score=50.0,
        minimum_confidence=0.75,
        blast_radius_scope="single_identity",
        is_reversible=True,
        requires_human_approval=False,
    ),
    RemediationAction.DEACTIVATE_ACCESS_KEY: ContainmentSafetyPolicy(
        action=RemediationAction.DEACTIVATE_ACCESS_KEY,
        minimum_risk_score=50.0,
        minimum_confidence=0.80,
        blast_radius_scope="single_credential",
        is_reversible=True,
        requires_human_approval=False,
    ),
    RemediationAction.ATTACH_QUARANTINE_BOUNDARY: ContainmentSafetyPolicy(
        action=RemediationAction.ATTACH_QUARANTINE_BOUNDARY,
        minimum_risk_score=60.0,
        minimum_confidence=0.85,
        blast_radius_scope="single_identity",
        is_reversible=True,
        requires_human_approval=False,
    ),
    RemediationAction.ISOLATE_EC2_INSTANCE: ContainmentSafetyPolicy(
        action=RemediationAction.ISOLATE_EC2_INSTANCE,
        minimum_risk_score=50.0,
        minimum_confidence=0.75,
        blast_radius_scope="single_instance",
        is_reversible=True,
        requires_human_approval=False,
    ),
    RemediationAction.ENFORCE_S3_BLOCK_PUBLIC: ContainmentSafetyPolicy(
        action=RemediationAction.ENFORCE_S3_BLOCK_PUBLIC,
        minimum_risk_score=50.0,
        minimum_confidence=0.75,
        blast_radius_scope="single_bucket",
        is_reversible=True,
        requires_human_approval=False,
    ),
    RemediationAction.REVOKE_SECURITY_GROUP_INGRESS: ContainmentSafetyPolicy(
        action=RemediationAction.REVOKE_SECURITY_GROUP_INGRESS,
        minimum_risk_score=55.0,
        minimum_confidence=0.80,
        blast_radius_scope="single_security_group",
        is_reversible=True,
        requires_human_approval=False,
    ),
    RemediationAction.QUARANTINE_ACCOUNT: ContainmentSafetyPolicy(
        action=RemediationAction.QUARANTINE_ACCOUNT,
        minimum_risk_score=80.0,
        minimum_confidence=0.90,
        blast_radius_scope="account_wide",
        is_reversible=True,
        requires_human_approval=True,
    ),
}


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
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Detection confidence score (0.0 to 1.0)",
    )
    execution_mode: RemediationExecutionMode | None = Field(
        default=None,
        description="Execution mode override (RECOMMENDATION, DRY_RUN, ENFORCE). Defaults to orchestrator configuration.",
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
    execution_mode: RemediationExecutionMode = Field(
        default=RemediationExecutionMode.ENFORCE,
        description="Mode under which this remediation was evaluated",
    )
    is_dry_run: bool = Field(
        default=False,
        description="True if evaluation was performed without mutating live cloud resources",
    )
    recommendation_text: str | None = Field(
        default=None,
        description="Human-readable remediation recommendation when in RECOMMENDATION mode",
    )
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
