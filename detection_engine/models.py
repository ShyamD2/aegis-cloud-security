"""Domain models for event enrichment and detection rules."""

from enum import StrEnum

from pydantic import BaseModel, Field

from services.common.models import NormalizedSecurityEvent


class AccountTier(StrEnum):
    """Account operational classification."""

    MANAGEMENT = "MANAGEMENT"
    SECURITY = "SECURITY"
    LOG_ARCHIVE = "LOG_ARCHIVE"
    PRODUCTION = "PRODUCTION"
    DEVELOPMENT = "DEVELOPMENT"
    SECURITY_LAB = "SECURITY_LAB"
    UNKNOWN = "UNKNOWN"


class PrincipalPrivilegeTier(StrEnum):
    """Privilege level of the acting principal."""

    ROOT = "ROOT"
    IAM_ADMIN = "IAM_ADMIN"
    WORKLOAD_ROLE = "WORKLOAD_ROLE"
    STANDARD_USER = "STANDARD_USER"
    SERVICE_PRINCIPAL = "SERVICE_PRINCIPAL"


class EnrichedSecurityEvent(BaseModel):
    """Normalized security event augmented with contextual metadata."""

    event: NormalizedSecurityEvent
    account_tier: AccountTier = AccountTier.UNKNOWN
    principal_privilege: PrincipalPrivilegeTier = PrincipalPrivilegeTier.STANDARD_USER
    is_cross_account: bool = False
    is_external_ip: bool = False
    is_sensitive_target: bool = False
    context_tags: dict[str, str] = Field(default_factory=dict)
