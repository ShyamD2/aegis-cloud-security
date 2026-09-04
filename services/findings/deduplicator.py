"""Finding deduplication cache and lifecycle state management."""

import hashlib
from datetime import UTC, datetime

from services.common.models import FindingStatus, SecurityFinding


class FindingDeduplicator:
    """Manages finding de-duplication, state updates, and duplicate suppression."""

    def __init__(self) -> None:
        # Maps finding_fingerprint -> cached SecurityFinding
        self._cache: dict[str, SecurityFinding] = {}

    @staticmethod
    def compute_fingerprint(finding: SecurityFinding) -> str:
        """Generate a deterministic signature based on account, rule, and targets."""
        sorted_targets = sorted(finding.target_resources)
        raw_sig = f"{finding.account_id}:{finding.rule_id}:{':'.join(sorted_targets)}"
        return hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()

    def process(self, finding: SecurityFinding) -> tuple[bool, SecurityFinding]:
        """Ingest finding, check for duplicates, and update state if needed.

        Returns:
            tuple (is_new_or_updated: bool, effective_finding: SecurityFinding)
        """
        fingerprint = self.compute_fingerprint(finding)
        cached = self._cache.get(fingerprint)

        if cached is None:
            self._cache[fingerprint] = finding
            return True, finding

        # Check if severity or status changed (update)
        if cached.severity != finding.severity or cached.status != finding.status:
            cached.severity = finding.severity
            cached.status = finding.status
            cached.evidence.update(finding.evidence)
            return True, cached

        # Exactly identical finding received -> duplicate suppressed
        return False, cached

    def close_finding(self, finding_id: str, reason: str = "RESOLVED") -> bool:
        """Mark an existing finding as RESOLVED or FALSE_POSITIVE."""
        for finding in self._cache.values():
            if finding.finding_id == finding_id:
                if reason == "FALSE_POSITIVE":
                    finding.status = FindingStatus.FALSE_POSITIVE
                else:
                    finding.status = FindingStatus.RESOLVED
                finding.evidence["closed_at"] = datetime.now(UTC).isoformat()
                finding.evidence["close_reason"] = reason
                return True
        return False


class FindingLifecycleManager:
    """Enforces valid state progressions across finding lifecycles."""

    VALID_TRANSITIONS: dict[FindingStatus, list[FindingStatus]] = {
        FindingStatus.NEW: [FindingStatus.ANALYZING, FindingStatus.FALSE_POSITIVE],
        FindingStatus.ANALYZING: [
            FindingStatus.CONTAINING,
            FindingStatus.RESOLVED,
            FindingStatus.FALSE_POSITIVE,
        ],
        FindingStatus.CONTAINING: [FindingStatus.VERIFIED, FindingStatus.ANALYZING],
        FindingStatus.VERIFIED: [FindingStatus.RESOLVED],
        FindingStatus.RESOLVED: [FindingStatus.ANALYZING],  # Re-opening
        FindingStatus.FALSE_POSITIVE: [FindingStatus.ANALYZING],  # Re-opening
    }

    @classmethod
    def transition(cls, finding: SecurityFinding, new_status: FindingStatus) -> SecurityFinding:
        """Transition finding status verifying transition validity."""
        allowed = cls.VALID_TRANSITIONS.get(finding.status, [])
        if new_status not in allowed:
            raise ValueError(
                f"Illegal state transition from {finding.status.value} to {new_status.value}."
            )
        finding.status = new_status
        return finding
