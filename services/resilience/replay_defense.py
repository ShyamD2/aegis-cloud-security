"""
Project AEGIS - Replay Attack Defense & Telemetry Freshness Engine
Protects telemetry ingestion and remediation dispatch against duplicate, replayed,
or timestamp-manipulated events.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime, timedelta

from services.common.models import NormalizedSecurityEvent

logger = logging.getLogger("aegis.resilience.replay_defense")


class ReplayDefenseError(Exception):
    """Raised when an event fails replay detection or freshness validation."""

    pass


class ReplayDetector:
    """
    Sliding-window nonce and timestamp freshness validator.
    Prevents replay attacks by enforcing:
    1. Maximum past time window (e.g. events older than 15 minutes rejected)
    2. Future timestamp skew tolerance (e.g. clock drift > 2 minutes rejected)
    3. Nonce / Event ID deduplication within active sliding window
    4. Cryptographic payload fingerprint tracking
    """

    def __init__(
        self,
        max_age_seconds: float = 900.0,  # 15 minutes
        max_future_skew_seconds: float = 120.0,  # 2 minutes
    ) -> None:
        self.max_age_seconds = max_age_seconds
        self.max_future_skew_seconds = max_future_skew_seconds

        # Map of event_id -> seen_timestamp
        self._seen_events: dict[str, datetime] = {}
        # Map of payload_hash -> seen_timestamp
        self._seen_hashes: dict[str, datetime] = {}

    def _purge_expired(self, now: datetime) -> None:
        """Purge entries older than max_age_seconds to prevent memory bloat."""
        cutoff = now - timedelta(seconds=self.max_age_seconds)
        self._seen_events = {eid: ts for eid, ts in self._seen_events.items() if ts >= cutoff}
        self._seen_hashes = {ph: ts for ph, ts in self._seen_hashes.items() if ts >= cutoff}

    @staticmethod
    def compute_fingerprint(event: NormalizedSecurityEvent) -> str:
        """Compute deterministic SHA-256 fingerprint of event canonical fields."""
        canonical_str = (
            f"{event.event_id}:{event.source}:{event.account_id}:{event.action}:"
            f"{event.principal_arn}:{event.timestamp.isoformat()}"
        )
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def validate_event(
        self, event: NormalizedSecurityEvent, current_time: datetime | None = None
    ) -> tuple[bool, str]:
        """
        Validate security event freshness and verify it is not a replay.

        Returns:
            tuple (is_valid, reason)
        """
        now = current_time or datetime.now(UTC)
        self._purge_expired(now)

        event_time = event.timestamp
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=UTC)

        # 1. Past Age Check
        age_seconds = (now - event_time).total_seconds()
        if age_seconds > self.max_age_seconds:
            msg = (
                f"Event timestamp {event_time.isoformat()} is too old "
                f"({round(age_seconds, 1)}s > max {self.max_age_seconds}s). Replay rejected."
            )
            logger.warning(msg)
            return False, msg

        # 2. Future Clock Skew Check
        if age_seconds < -self.max_future_skew_seconds:
            msg = (
                f"Event timestamp {event_time.isoformat()} has excessive future clock skew "
                f"({round(abs(age_seconds), 1)}s > tolerance {self.max_future_skew_seconds}s). Rejected."
            )
            logger.warning(msg)
            return False, msg

        # 3. Nonce / Event ID Replay Check
        if event.event_id in self._seen_events:
            first_seen = self._seen_events[event.event_id]
            msg = (
                f"Duplicate event_id '{event.event_id}' detected. "
                f"First seen at {first_seen.isoformat()}. Replay rejected."
            )
            logger.warning(msg)
            return False, msg

        # 4. Cryptographic Hash Deduplication Check
        fingerprint = self.compute_fingerprint(event)
        if fingerprint in self._seen_hashes:
            first_seen = self._seen_hashes[fingerprint]
            msg = (
                f"Identical event payload fingerprint '{fingerprint[:16]}...' detected. "
                f"First seen at {first_seen.isoformat()}. Replay rejected."
            )
            logger.warning(msg)
            return False, msg

        # Register event in active window
        self._seen_events[event.event_id] = now
        self._seen_hashes[fingerprint] = now

        return True, "Event freshness and anti-replay validation passed."

    def assert_valid(
        self, event: NormalizedSecurityEvent, current_time: datetime | None = None
    ) -> None:
        """Helper that raises ReplayDefenseError if validation fails."""
        valid, reason = self.validate_event(event, current_time)
        if not valid:
            raise ReplayDefenseError(reason)
