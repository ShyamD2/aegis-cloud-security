"""Pydantic v2 domain models for Project AEGIS telemetry and security findings."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class FindingSeverity(StrEnum):
    """Normalized finding severity levels."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(StrEnum):
    """Lifecycle status of an AEGIS security finding."""

    NEW = "NEW"
    ANALYZING = "ANALYZING"
    CONTAINING = "CONTAINING"
    VERIFIED = "VERIFIED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class CloudTrailIdentity(BaseModel):
    """CloudTrail userIdentity structure."""

    model_config = ConfigDict(extra="ignore")

    type: str = Field(description="Principal type (e.g. IAMUser, AssumedRole, Root)")
    principal_id: str = Field(
        validation_alias=AliasChoices("principalId", "principal_id"), default=""
    )
    arn: str = Field(default="")
    account_id: str = Field(validation_alias=AliasChoices("accountId", "account_id"), default="")
    user_name: str | None = Field(
        validation_alias=AliasChoices("userName", "user_name"), default=None
    )
    session_context: dict[str, Any] | None = Field(
        validation_alias=AliasChoices("sessionContext", "session_context"), default=None
    )


class CloudTrailRecord(BaseModel):
    """Standardized representation of an AWS CloudTrail management or data event."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    event_version: str = Field(
        validation_alias=AliasChoices("eventVersion", "event_version"), default="1.08"
    )
    event_id: str = Field(validation_alias=AliasChoices("eventID", "eventId", "event_id"))
    event_time: datetime = Field(validation_alias=AliasChoices("eventTime", "event_time"))
    event_source: str = Field(validation_alias=AliasChoices("eventSource", "event_source"))
    event_name: str = Field(validation_alias=AliasChoices("eventName", "event_name"))
    aws_region: str = Field(validation_alias=AliasChoices("awsRegion", "aws_region"))
    source_ip_address: str = Field(
        validation_alias=AliasChoices("sourceIPAddress", "source_ip_address"), default=""
    )
    user_agent: str = Field(validation_alias=AliasChoices("userAgent", "user_agent"), default="")
    recipient_account_id: str = Field(
        validation_alias=AliasChoices("recipientAccountId", "recipient_account_id")
    )
    user_identity: CloudTrailIdentity = Field(
        validation_alias=AliasChoices("userIdentity", "user_identity")
    )
    request_parameters: dict[str, Any] | None = Field(
        validation_alias=AliasChoices("requestParameters", "request_parameters"), default=None
    )
    response_elements: dict[str, Any] | None = Field(
        validation_alias=AliasChoices("responseElements", "response_elements"), default=None
    )
    error_code: str | None = Field(
        validation_alias=AliasChoices("errorCode", "error_code"), default=None
    )
    error_message: str | None = Field(
        validation_alias=AliasChoices("errorMessage", "error_message"), default=None
    )


class NormalizedSecurityEvent(BaseModel):
    """Canonical normalized event structure ingested across all telemetry sources."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(description="Unique telemetry event identifier")
    source: str = Field(description="Telemetry source: cloudtrail, vpcflow, route53, guardduty")
    timestamp: datetime = Field(description="UTC timestamp of the security event")
    account_id: str = Field(description="AWS 12-digit account identifier")
    region: str = Field(description="AWS region where the event occurred")
    principal_arn: str = Field(description="Full ARN of the acting entity")
    principal_type: str = Field(description="IAMUser, AssumedRole, FederatedUser, Root")
    action: str = Field(description="API action or event name (e.g. iam:CreateAccessKey)")
    resource_arns: list[str] = Field(default_factory=list, description="Target AWS resource ARNs")
    source_ip: str = Field(default="", description="IPv4 or IPv6 address of the caller")
    user_agent: str = Field(default="", description="Client user agent string")
    status: str = Field(default="SUCCESS", description="SUCCESS or FAILURE/AccessDenied")
    raw_payload: dict[str, Any] = Field(default_factory=dict, description="Original raw event")


class SecurityFinding(BaseModel):
    """Canonical normalized AEGIS security finding emitted by detection engines."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(description="Unique AEGIS finding identifier (e.g. aegis-f-uuid)")
    rule_id: str = Field(description="Identifier of the detection rule (e.g. AEGIS-DET-001)")
    title: str = Field(description="Short human-readable finding title")
    description: str = Field(description="Detailed explanation of the observed threat")
    severity: FindingSeverity = Field(description="Severity classification")
    confidence: float = Field(
        ge=0.0, le=1.0, description="Detection confidence score from 0.0 to 1.0"
    )
    status: FindingStatus = Field(
        default=FindingStatus.NEW, description="Current finding lifecycle status"
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    account_id: str = Field(description="Affected AWS account ID")
    region: str = Field(description="Affected AWS region")
    principal_arn: str = Field(description="Compromised or acting principal ARN")
    target_resources: list[str] = Field(default_factory=list, description="Affected resource ARNs")
    mitre_attack_technique: str | None = Field(
        default=None, description="MITRE ATT&CK technique ID (e.g. T1078.004)"
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Structured supporting evidence"
    )
    recommended_response: str = Field(
        default="", description="Recommended containment or triage action"
    )
