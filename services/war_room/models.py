"""
Project AEGIS - Security Operations War Room Models
Defines posture summary metrics, incident detail schemas, attack chain visual nodes,
and role-based approval requests for the SOC dashboard.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from services.common.models import FindingSeverity
from services.forensics.models import TimelineEvent
from services.risk_engine.models import RiskLevel


class IncidentState(StrEnum):
    """Real-time operational containment status."""

    DETECTED = "DETECTED"
    ANALYZING = "ANALYZING"
    CONTAINING = "CONTAINING"
    VERIFIED = "VERIFIED"
    CLOSED = "CLOSED"


class UserRole(StrEnum):
    """Role-based access control tiers for War Room operators."""

    SOC_VIEWER = "SOC_VIEWER"
    SOC_ANALYST = "SOC_ANALYST"
    SOC_LEAD = "SOC_LEAD"
    SECURITY_ADMIN = "SECURITY_ADMIN"


class SecurityPostureSummary(BaseModel):
    """Aggregate posture and SLA metrics displayed on the War Room header."""

    model_config = ConfigDict(extra="forbid")

    posture_score: float = Field(ge=0.0, le=100.0, description="Overall health score (0-100)")
    critical_findings_count: int = Field(ge=0)
    high_findings_count: int = Field(ge=0)
    active_incidents_count: int = Field(ge=0)
    contained_incidents_count: int = Field(ge=0)
    mean_time_to_detect_seconds: float = Field(ge=0.0)
    mean_time_to_contain_seconds: float = Field(ge=0.0)
    total_protected_accounts: int = Field(ge=1)
    total_protected_resources: int = Field(ge=0)
    last_updated: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AttackChainNode(BaseModel):
    """Visual node for the interactive attack-chain graph."""

    model_config = ConfigDict(extra="forbid")

    id: str
    label: str
    node_type: str
    account_id: str
    is_compromised: bool = False
    is_sensitive: bool = False
    criticality: float = 1.0


class AttackChainEdge(BaseModel):
    """Visual edge connecting nodes in the attack chain."""

    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    relationship: str
    action: str | None = None


class IncidentDetail(BaseModel):
    """Comprehensive incident dossier presented to SOC responders."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str
    title: str
    severity: FindingSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=100.0)
    risk_level: RiskLevel
    principal_arn: str
    account_id: str
    region: str
    current_state: IncidentState
    blast_radius_score: float
    affected_accounts: list[str] = Field(default_factory=list)
    affected_resources: list[str] = Field(default_factory=list)
    attack_chain_nodes: list[AttackChainNode] = Field(default_factory=list)
    attack_chain_edges: list[AttackChainEdge] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    evidence_manifest_id: str | None = None
    response_action: str | None = None
    verification_status: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ApprovalActionRequest(BaseModel):
    """SOC operator containment authorization request."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str
    action: str
    operator_role: UserRole
    operator_id: str
    decision: str = Field(pattern="^(APPROVE|REJECT)$")
    rationale: str
    mfa_code: str | None = None


class ApprovalActionResponse(BaseModel):
    """Result of approval authorization."""

    model_config = ConfigDict(extra="forbid")

    approval_id: str
    incident_id: str
    approved: bool
    status: str
    approval_token: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
