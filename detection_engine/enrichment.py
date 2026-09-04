"""Contextual event enrichment adding account, identity, and network awareness."""

import ipaddress

from detection_engine.models import AccountTier, EnrichedSecurityEvent, PrincipalPrivilegeTier
from services.common.models import NormalizedSecurityEvent


class EventEnricher:
    """Enriches NormalizedSecurityEvent with contextual metadata."""

    KNOWN_ACCOUNTS: dict[str, AccountTier] = {
        "111122223333": AccountTier.SECURITY,
        "444455556666": AccountTier.LOG_ARCHIVE,
        "777788889999": AccountTier.PRODUCTION,
        "123456789012": AccountTier.SECURITY_LAB,
    }

    SENSITIVE_KEYWORDS: list[str] = [
        "secret",
        "vault",
        "credential",
        "database",
        "prod-data",
        "customer",
        "kms-root",
    ]

    RFC_PRIVATE_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
    ]

    @classmethod
    def is_private_or_internal_ip(cls, ip_str: str) -> bool:
        """Return True if IP is RFC 1918 private, link-local, loopback, or empty."""
        if not ip_str or ip_str.endswith(".amazonaws.com"):
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return any(ip_obj in net for net in cls.RFC_PRIVATE_NETWORKS)
        except ValueError:
            return False

    @classmethod
    def classify_principal(cls, principal_arn: str, principal_type: str) -> PrincipalPrivilegeTier:
        """Classify principal privilege level."""
        lower_arn = principal_arn.lower()
        if ":root" in lower_arn or principal_type.lower() == "root":
            return PrincipalPrivilegeTier.ROOT
        if "admin" in lower_arn or "administrator" in lower_arn:
            return PrincipalPrivilegeTier.IAM_ADMIN
        if "role" in lower_arn:
            return PrincipalPrivilegeTier.WORKLOAD_ROLE
        if "amazonaws.com" in lower_arn:
            return PrincipalPrivilegeTier.SERVICE_PRINCIPAL
        return PrincipalPrivilegeTier.STANDARD_USER

    @classmethod
    def enrich(cls, event: NormalizedSecurityEvent) -> EnrichedSecurityEvent:
        """Produce an EnrichedSecurityEvent from a raw NormalizedSecurityEvent."""
        account_tier = cls.KNOWN_ACCOUNTS.get(event.account_id, AccountTier.UNKNOWN)
        principal_privilege = cls.classify_principal(event.principal_arn, event.principal_type)
        is_external = not cls.is_private_or_internal_ip(event.source_ip)

        # Check cross-account: principal account != recipient account
        is_cross = False
        if "arn:aws:iam::" in event.principal_arn:
            parts = event.principal_arn.split(":")
            if len(parts) >= 5:
                principal_account = parts[4]
                if principal_account and principal_account != event.account_id:
                    is_cross = True

        # Check sensitive target
        is_sensitive = False
        target_str = " ".join(event.resource_arns).lower()
        if any(keyword in target_str for keyword in cls.SENSITIVE_KEYWORDS):
            is_sensitive = True

        return EnrichedSecurityEvent(
            event=event,
            account_tier=account_tier,
            principal_privilege=principal_privilege,
            is_cross_account=is_cross,
            is_external_ip=is_external,
            is_sensitive_target=is_sensitive,
            context_tags={
                "enriched": "true",
                "tier": account_tier.value,
            },
        )
