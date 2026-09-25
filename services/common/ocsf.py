"""
Project AEGIS - Open Cybersecurity Schema Framework (OCSF v1.1.0) Normalization Engine
Provides standardized schemas, category/class mappings, and bidirectional adapters
for AWS CloudTrail, VPC Flow, DNS, GuardDuty, and Security Hub telemetry.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import IntEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from services.common.models import FindingSeverity, NormalizedSecurityEvent


class OCSFCategory(IntEnum):
    """OCSF Top-Level Event Categories."""

    SYSTEM_ACTIVITY = 1
    FINDINGS = 2
    IDENTITY_ACCESS_MANAGEMENT = 3
    NETWORK_ACTIVITY = 4
    DISCOVERY = 5
    APPLICATION_ACTIVITY = 6


class OCSFClass(IntEnum):
    """OCSF Standard Event Classes."""

    SECURITY_FINDING = 2001
    ACCOUNT_CHANGE = 3001
    AUTHENTICATION = 3002
    AUTHORIZE_SESSION = 3003
    NETWORK_ACTIVITY = 4001
    DNS_ACTIVITY = 4003
    API_ACTIVITY = 6003


class OCSFSeverity(IntEnum):
    """OCSF Standardized Severity Identifiers."""

    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6


class OCSFCloudContext(BaseModel):
    """Cloud provider metadata context in OCSF."""

    model_config = ConfigDict(extra="allow")

    provider: str = Field(default="AWS", description="Cloud provider identifier")
    account_uid: str = Field(description="Cloud account identifier")
    region: str = Field(default="us-east-1", description="Cloud deployment region")


class OCSFActorUser(BaseModel):
    """Identity representation of the principal actor."""

    model_config = ConfigDict(extra="allow")

    name: str = Field(default="", description="Principal user name or role name")
    uid: str = Field(default="", description="Unique principal identifier / ARN")
    type: str = Field(default="IAMUser", description="IAMUser, AssumedRole, Root, FederatedUser")


class OCSFApiContext(BaseModel):
    """API operation context for cloud control plane activities."""

    model_config = ConfigDict(extra="allow")

    operation: str = Field(description="API action name (e.g. PutBucketPolicy)")
    service: str = Field(description="Target service namespace (e.g. s3.amazonaws.com)")
    request_data: dict[str, Any] = Field(default_factory=dict)
    response_data: dict[str, Any] = Field(default_factory=dict)


class OCSFEndpoint(BaseModel):
    """Network connection endpoint."""

    model_config = ConfigDict(extra="allow")

    ip: str = Field(default="", description="IPv4 or IPv6 address")
    port: int | None = Field(default=None, description="Transport port")


class OCSFResource(BaseModel):
    """Target resource affected by the event."""

    model_config = ConfigDict(extra="allow")

    uid: str = Field(description="Unique resource identifier / ARN")
    type: str = Field(default="CloudResource", description="Resource type classification")
    name: str = Field(default="", description="Human-readable resource name")


class OCSFMetadata(BaseModel):
    """Metadata enclosing event schema and versioning info."""

    model_config = ConfigDict(extra="allow")

    version: str = Field(default="1.1.0", description="OCSF schema version")
    product_name: str = Field(default="Project AEGIS", description="Originating product name")
    product_vendor: str = Field(default="AEGIS Security Fabric", description="Vendor / platform")


class OCSFEvent(BaseModel):
    """
    Canonical Open Cybersecurity Schema Framework (OCSF v1.1.0) Security Event.
    Standardizes disparate cloud telemetry into an interoperable format.
    """

    model_config = ConfigDict(extra="allow")

    metadata: OCSFMetadata = Field(default_factory=OCSFMetadata)
    category_uid: OCSFCategory = Field(description="OCSF category code")
    class_uid: OCSFClass = Field(description="OCSF class code")
    type_uid: int = Field(description="Computed type UID: class_uid * 100 + activity_id")
    activity_id: int = Field(default=1, description="Specific activity code within class")
    activity_name: str = Field(description="Normalized name of the activity")
    severity_id: OCSFSeverity = Field(description="Normalized OCSF severity rating")
    time: datetime = Field(description="UTC event occurrence timestamp")
    cloud: OCSFCloudContext = Field(description="AWS account and regional context")
    actor: OCSFActorUser = Field(description="Principal executing the activity")
    api: OCSFApiContext | None = Field(default=None, description="API metadata if cloud activity")
    resources: list[OCSFResource] = Field(default_factory=list, description="Impacted resources")
    src_endpoint: OCSFEndpoint | None = Field(default=None, description="Source IP context")
    dst_endpoint: OCSFEndpoint | None = Field(default=None, description="Destination context")
    raw_payload: dict[str, Any] = Field(default_factory=dict, description="Raw source telemetry")

    def to_normalized_event(self) -> NormalizedSecurityEvent:
        """Converts an OCSF event back to an AEGIS internal NormalizedSecurityEvent."""
        return OCSFAdapter.to_normalized_event(self)


class OCSFAdapter:
    """Bi-directional translation adapter between native AWS telemetry and OCSF schemas."""

    @staticmethod
    def _map_severity(severity_str: str | FindingSeverity) -> OCSFSeverity:
        s = str(severity_str).upper()
        if "CRITICAL" in s:
            return OCSFSeverity.CRITICAL
        elif "HIGH" in s:
            return OCSFSeverity.HIGH
        elif "MEDIUM" in s:
            return OCSFSeverity.MEDIUM
        elif "LOW" in s:
            return OCSFSeverity.LOW
        elif "INFO" in s:
            return OCSFSeverity.INFORMATIONAL
        return OCSFSeverity.UNKNOWN

    @classmethod
    def from_normalized_event(cls, event: NormalizedSecurityEvent) -> OCSFEvent:
        """Translates an AEGIS NormalizedSecurityEvent into a canonical OCSF event."""
        action_lower = event.action.lower()

        # Class determination based on action
        if any(term in action_lower for term in ["login", "assumerole", "federat"]):
            class_uid = OCSFClass.AUTHENTICATION
            category_uid = OCSFCategory.IDENTITY_ACCESS_MANAGEMENT
            activity_id = 1
            activity_name = "Logon / AssumeRole"
        elif any(
            term in action_lower
            for term in ["create", "delete", "attach", "detach", "put", "update"]
        ):
            if "iam" in event.source.lower() or "iam" in action_lower:
                class_uid = OCSFClass.ACCOUNT_CHANGE
                category_uid = OCSFCategory.IDENTITY_ACCESS_MANAGEMENT
            else:
                class_uid = OCSFClass.API_ACTIVITY
                category_uid = OCSFCategory.APPLICATION_ACTIVITY
            activity_id = 1
            activity_name = f"Mutate Resource ({event.action})"
        elif "vpc" in event.source.lower() or "dns" in event.source.lower():
            class_uid = OCSFClass.NETWORK_ACTIVITY
            category_uid = OCSFCategory.NETWORK_ACTIVITY
            activity_id = 1
            activity_name = "Network Flow"
        else:
            class_uid = OCSFClass.API_ACTIVITY
            category_uid = OCSFCategory.APPLICATION_ACTIVITY
            activity_id = 1
            activity_name = event.action

        type_uid = int(class_uid) * 100 + activity_id

        resources = [
            OCSFResource(uid=arn, type="AWSResource", name=arn.split("/")[-1])
            for arn in event.resource_arns
        ]

        src_ip = event.source_ip or event.raw_payload.get("sourceIPAddress", "")

        return OCSFEvent(
            category_uid=category_uid,
            class_uid=class_uid,
            type_uid=type_uid,
            activity_id=activity_id,
            activity_name=activity_name,
            severity_id=OCSFSeverity.INFORMATIONAL,
            time=event.timestamp,
            cloud=OCSFCloudContext(
                account_uid=event.account_id,
                region=event.region,
            ),
            actor=OCSFActorUser(
                name=event.principal_arn.split("/")[-1]
                if "/" in event.principal_arn
                else event.principal_arn,
                uid=event.principal_arn,
                type=event.principal_type,
            ),
            api=OCSFApiContext(
                operation=event.action,
                service=event.source,
                request_data=event.raw_payload,
            ),
            resources=resources,
            src_endpoint=OCSFEndpoint(ip=str(src_ip)) if src_ip else None,
            raw_payload={
                "event_id": event.event_id,
                "status": event.status,
                "user_agent": event.user_agent,
            },
        )

    @classmethod
    def from_cloudtrail(cls, record: dict[str, Any]) -> OCSFEvent:
        """Converts raw CloudTrail JSON payload into an OCSF v1.1.0 Event."""
        event_time_str = record.get("eventTime", "")
        try:
            event_time = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
        except Exception:
            event_time = datetime.now(UTC)

        user_ident = record.get("userIdentity", {})
        principal_arn = user_ident.get("arn", user_ident.get("principalId", "unknown-principal"))
        principal_type = user_ident.get("type", "IAMUser")
        user_name = user_ident.get("userName", principal_arn.split("/")[-1])

        event_name = record.get("eventName", "UnknownAPI")
        event_source = record.get("eventSource", "aws.general")
        account_id = record.get("recipientAccountId", user_ident.get("accountId", "000000000000"))
        region = record.get("awsRegion", "us-east-1")
        source_ip = record.get("sourceIPAddress", "")

        resources: list[OCSFResource] = []
        for res in record.get("resources", []):
            arn = res.get("ARN") or res.get("arn", "")
            if arn:
                resources.append(OCSFResource(uid=arn, type=res.get("type", "AWSResource")))

        if "AssumeRole" in event_name or "Login" in event_name:
            class_uid = OCSFClass.AUTHENTICATION
            category_uid = OCSFCategory.IDENTITY_ACCESS_MANAGEMENT
        elif (
            any(kw in event_name for kw in ["Create", "Delete", "Attach", "Put"])
            and "iam" in event_source
        ):
            class_uid = OCSFClass.ACCOUNT_CHANGE
            category_uid = OCSFCategory.IDENTITY_ACCESS_MANAGEMENT
        else:
            class_uid = OCSFClass.API_ACTIVITY
            category_uid = OCSFCategory.APPLICATION_ACTIVITY

        type_uid = int(class_uid) * 100 + 1

        return OCSFEvent(
            category_uid=category_uid,
            class_uid=class_uid,
            type_uid=type_uid,
            activity_id=1,
            activity_name=f"AWS API: {event_name}",
            severity_id=OCSFSeverity.INFORMATIONAL,
            time=event_time,
            cloud=OCSFCloudContext(
                account_uid=account_id,
                region=region,
            ),
            actor=OCSFActorUser(
                name=user_name,
                uid=principal_arn,
                type=principal_type,
            ),
            api=OCSFApiContext(
                operation=event_name,
                service=event_source,
                request_data=record.get("requestParameters") or {},
                response_data=record.get("responseElements") or {},
            ),
            resources=resources,
            src_endpoint=OCSFEndpoint(ip=source_ip) if source_ip else None,
            raw_payload=record,
        )

    @classmethod
    def from_security_finding(
        cls,
        finding_id: str,
        title: str,
        severity: FindingSeverity | str,
        account_id: str,
        region: str,
        resource_arns: list[str],
        timestamp: datetime | None = None,
        description: str = "",
    ) -> OCSFEvent:
        """Converts an internal or AWS Security Hub/GuardDuty finding into OCSF Security Finding class (2001)."""
        ocsf_sev = cls._map_severity(severity)
        ts = timestamp or datetime.now(UTC)
        resources = [OCSFResource(uid=arn, type="VulnerableResource") for arn in resource_arns]

        return OCSFEvent(
            category_uid=OCSFCategory.FINDINGS,
            class_uid=OCSFClass.SECURITY_FINDING,
            type_uid=int(OCSFClass.SECURITY_FINDING) * 100 + 1,
            activity_id=1,
            activity_name=f"Security Finding: {title}",
            severity_id=ocsf_sev,
            time=ts,
            cloud=OCSFCloudContext(
                account_uid=account_id,
                region=region,
            ),
            actor=OCSFActorUser(
                name="AEGIS Detection Engine",
                uid="arn:aws:iam::197550036081:role/aegis-detection-worker",
                type="SecurityService",
            ),
            resources=resources,
            raw_payload={
                "finding_id": finding_id,
                "title": title,
                "description": description,
                "severity": str(severity),
            },
        )

    @classmethod
    def to_normalized_event(cls, ocsf_event: OCSFEvent) -> NormalizedSecurityEvent:
        """Converts an OCSFEvent into an AEGIS NormalizedSecurityEvent."""
        action = ocsf_event.api.operation if ocsf_event.api else ocsf_event.activity_name
        source = ocsf_event.api.service if ocsf_event.api else "ocsf.standard"
        event_id = (
            ocsf_event.raw_payload.get("event_id") or f"ocsf-{int(ocsf_event.time.timestamp())}"
        )

        return NormalizedSecurityEvent(
            event_id=event_id,
            source=source,
            timestamp=ocsf_event.time,
            account_id=ocsf_event.cloud.account_uid,
            region=ocsf_event.cloud.region,
            principal_arn=ocsf_event.actor.uid or ocsf_event.actor.name,
            principal_type=ocsf_event.actor.type,
            action=action,
            resource_arns=[r.uid for r in ocsf_event.resources],
            source_ip=ocsf_event.src_endpoint.ip if ocsf_event.src_endpoint else "",
            user_agent=str(ocsf_event.raw_payload.get("user_agent", "")),
            status=str(ocsf_event.raw_payload.get("status", "SUCCESS")),
            raw_payload=ocsf_event.api.request_data if ocsf_event.api else {},
        )
