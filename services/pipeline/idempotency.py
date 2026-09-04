"""Idempotency management preventing duplicate event processing."""

import hashlib
from datetime import UTC, datetime, timedelta


class IdempotencyManager:
    """Tracks processed event signatures with TTL to guarantee exactly-once processing semantics."""

    def __init__(self, ttl_seconds: int = 900) -> None:
        self.ttl_seconds = ttl_seconds
        # Maps event_hash -> expiration_datetime
        self._cache: dict[str, datetime] = {}

    @staticmethod
    def hash_event(account_id: str, event_id: str) -> str:
        """Create a SHA-256 fingerprint from account ID and event ID."""
        key = f"{account_id}:{event_id}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def _purge_expired(self) -> None:
        """Remove expired lock entries."""
        now = datetime.now(UTC)
        expired_keys = [k for k, exp in self._cache.items() if exp <= now]
        for k in expired_keys:
            self._cache.pop(k, None)

    def is_duplicate(self, account_id: str, event_id: str) -> bool:
        """Check if an event was already processed within the TTL window."""
        self._purge_expired()
        sig = self.hash_event(account_id, event_id)
        return sig in self._cache

    def record_processed(self, account_id: str, event_id: str) -> None:
        """Mark an event as successfully processed."""
        self._purge_expired()
        sig = self.hash_event(account_id, event_id)
        self._cache[sig] = datetime.now(UTC) + timedelta(seconds=self.ttl_seconds)

    def size(self) -> int:
        """Return active cache size."""
        self._purge_expired()
        return len(self._cache)
