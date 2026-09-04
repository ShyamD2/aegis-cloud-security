"""
Project AEGIS - Attack-Path & Blast-Radius Models
Defines graph entity schemas, edge types, attack path traversals, and blast radius reports.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class NodeType(StrEnum):
    """Supported graph node entities in AWS cloud environments."""

    USER = "USER"
    ROLE = "ROLE"
    POLICY = "POLICY"
    S3_BUCKET = "S3_BUCKET"
    EC2_INSTANCE = "EC2_INSTANCE"
    RDS_DATABASE = "RDS_DATABASE"
    LAMBDA_FUNCTION = "LAMBDA_FUNCTION"
    SECRETS_MANAGER_SECRET = "SECRETS_MANAGER_SECRET"  # noqa: S105
    SECURITY_GROUP = "SECURITY_GROUP"
    ACCOUNT = "ACCOUNT"


class EdgeType(StrEnum):
    """Directed relationships between graph entities."""

    ASSUME_ROLE = "ASSUME_ROLE"
    HAS_POLICY = "HAS_POLICY"
    CAN_ACCESS = "CAN_ACCESS"
    IN_ACCOUNT = "IN_ACCOUNT"
    MEMBER_OF_SG = "MEMBER_OF_SG"
    ALLOWS_TRAFFIC = "ALLOWS_TRAFFIC"
    TRUSTS_ACCOUNT = "TRUSTS_ACCOUNT"
    PASS_ROLE = "PASS_ROLE"  # noqa: S105


class GraphNode(BaseModel):
    """Represents a single node in the AEGIS security graph."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(description="Unique node identifier, e.g. ARN or ID")
    node_type: NodeType = Field(description="Cloud entity type")
    name: str = Field(description="Human-readable resource or entity name")
    account_id: str = Field(description="AWS account ID containing or owning the entity")
    region: str = Field(default="global", description="AWS region or 'global'")
    is_sensitive: bool = Field(
        default=False,
        description="True if resource holds sensitive data (e.g. PII, credentials, prod DB)",
    )
    sensitivity_reason: str | None = Field(
        default=None,
        description="Explanation for sensitivity classification",
    )
    criticality: float = Field(
        default=1.0,
        ge=1.0,
        le=10.0,
        description="Asset criticality multiplier from 1.0 (dev/testing) to 10.0 (mission-critical prod)",
    )
    properties: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional key-value metadata (e.g. tags, encryption status, public exposure)",
    )


class GraphEdge(BaseModel):
    """Represents a directed permission, trust, or network relationship."""

    model_config = ConfigDict(extra="forbid")

    source: str = Field(description="Source node ID (e.g. principal ARN)")
    target: str = Field(description="Target node ID (e.g. role ARN, resource ARN)")
    edge_type: EdgeType = Field(description="Type of connection")
    action: str | None = Field(
        default=None,
        description="AWS action permitting the connection, e.g. sts:AssumeRole, s3:GetObject",
    )
    properties: dict[str, Any] = Field(
        default_factory=dict,
        description="Contextual metadata (e.g. conditions, port, protocol)",
    )


class AttackPath(BaseModel):
    """A reconstructed traversable path from a compromised entity to a target resource."""

    model_config = ConfigDict(extra="forbid")

    source_node: str = Field(description="Compromised initial node ID")
    target_node: str = Field(description="Reachable target resource or role ID")
    path: list[str] = Field(description="Ordered sequence of node IDs along the path")
    hops: int = Field(ge=1, description="Number of edges traversed to reach target")
    actions: list[str] = Field(description="Sequence of actions taken along the edges")
    is_cross_account: bool = Field(
        default=False,
        description="True if the path traverses across different AWS account boundaries",
    )
    target_is_sensitive: bool = Field(
        default=False,
        description="True if destination node is marked as sensitive",
    )


class BlastRadiusReport(BaseModel):
    """Detailed blast-radius impact analysis for a compromised identity."""

    model_config = ConfigDict(extra="forbid")

    principal_id: str = Field(description="Compromised principal ARN or ID")
    score: float = Field(
        ge=0.0,
        le=100.0,
        description="Deterministic blast-radius impact score from 0.0 to 100.0",
    )
    assumable_roles: list[str] = Field(
        default_factory=list,
        description="List of IAM roles directly or indirectly assumable",
    )
    affected_accounts: list[str] = Field(
        default_factory=list,
        description="Unique AWS accounts exposed to reachability",
    )
    directly_accessible_resources: list[str] = Field(
        default_factory=list,
        description="Resources directly accessible (1 hop away)",
    )
    indirectly_accessible_resources: list[str] = Field(
        default_factory=list,
        description="Resources accessible via role-chaining or privilege escalation",
    )
    sensitive_resources: list[str] = Field(
        default_factory=list,
        description="Sensitive resources reachable via any valid attack path",
    )
    attack_paths: list[AttackPath] = Field(
        default_factory=list,
        description="All valid traversable attack paths discovered",
    )
    total_reachable_nodes: int = Field(
        default=0,
        description="Total distinct reachable nodes across the graph",
    )
    cross_account_traversal: bool = Field(
        default=False,
        description="Indicates whether reachability spans outside the source account",
    )
    explanation: str = Field(
        description="Human-readable breakdown of factors driving the blast-radius score",
    )
