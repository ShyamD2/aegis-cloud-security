"""
Project AEGIS - Remediation Circuit Breaker
Prevents cascading failures, remediation flapping, and denial-of-service against infrastructure
by tracking consecutive execution failures and temporarily tripping into OPEN state.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, TypeVar

logger = logging.getLogger("aegis.resilience.circuit_breaker")

T = TypeVar("T")


class CircuitState(StrEnum):
    """Lifecycle states of the remediation circuit breaker."""

    CLOSED = "CLOSED"  # Normal operation: all remediations executed
    OPEN = "OPEN"  # Tripped: all automated containment paused to prevent flapping
    HALF_OPEN = "HALF_OPEN"  # Testing recovery: single probe allowed to check system health


class CircuitBreakerOpenException(Exception):
    """Raised when an action is attempted while the circuit breaker is in OPEN state."""

    def __init__(self, message: str = "Remediation circuit breaker is OPEN.") -> None:
        super().__init__(message)


class CircuitBreaker:
    """
    Thread-safe circuit breaker with configurable failure thresholds,
    timeout windows, and probe recovery.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout_seconds: float = 30.0,
        name: str = "default-remediation-breaker",
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be at least 1")
        if recovery_timeout_seconds <= 0.0:
            raise ValueError("recovery_timeout_seconds must be positive")

        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = recovery_timeout_seconds

        self._state: CircuitState = CircuitState.CLOSED
        self._consecutive_failures: int = 0
        self._last_state_change: datetime = datetime.now(UTC)
        self._last_failure_time: datetime | None = None
        self._total_trips: int = 0

    @property
    def state(self) -> CircuitState:
        """Current state of the circuit breaker, evaluating timeout expiration if OPEN."""
        if self._state == CircuitState.OPEN:
            elapsed = (datetime.now(UTC) - self._last_state_change).total_seconds()
            if elapsed >= self.recovery_timeout_seconds:
                logger.info(
                    f"Circuit breaker '{self.name}' recovery timeout ({self.recovery_timeout_seconds}s) elapsed. Transitioning OPEN -> HALF_OPEN."
                )
                self._state = CircuitState.HALF_OPEN
                self._last_state_change = datetime.now(UTC)
        return self._state

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    @property
    def total_trips(self) -> int:
        return self._total_trips

    def can_execute(self) -> bool:
        """Determine whether an operation is permitted to execute under current circuit state."""
        current = self.state
        return current in (CircuitState.CLOSED, CircuitState.HALF_OPEN)

    def record_success(self) -> None:
        """Record a successful operation, resetting failure counters and closing circuit."""
        if self._state == CircuitState.HALF_OPEN:
            logger.info(
                f"Circuit breaker '{self.name}' probe succeeded. Transitioning HALF_OPEN -> CLOSED."
            )
            self._state = CircuitState.CLOSED
            self._last_state_change = datetime.now(UTC)
        self._consecutive_failures = 0

    def record_failure(self, error: Exception | None = None) -> None:
        """Record an operation failure, incrementing counter and tripping if threshold met."""
        self._consecutive_failures += 1
        self._last_failure_time = datetime.now(UTC)

        if self._state == CircuitState.HALF_OPEN:
            logger.warning(
                f"Circuit breaker '{self.name}' probe failed ({error}). Transitioning HALF_OPEN -> OPEN."
            )
            self._state = CircuitState.OPEN
            self._last_state_change = datetime.now(UTC)
            self._total_trips += 1
        elif self._state == CircuitState.CLOSED:
            if self._consecutive_failures >= self.failure_threshold:
                logger.error(
                    f"Circuit breaker '{self.name}' reached threshold ({self._consecutive_failures} failures). Tripping CLOSED -> OPEN."
                )
                self._state = CircuitState.OPEN
                self._last_state_change = datetime.now(UTC)
                self._total_trips += 1

    def trip(self) -> None:
        """Manually trip the circuit breaker into OPEN state."""
        self._state = CircuitState.OPEN
        self._last_state_change = datetime.now(UTC)
        self._total_trips += 1

    def reset(self) -> None:
        """Manually reset the circuit breaker into CLOSED state."""
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._last_state_change = datetime.now(UTC)

    def execute(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Wrap callable with circuit breaker execution guard."""
        if not self.can_execute():
            raise CircuitBreakerOpenException(
                f"Circuit breaker '{self.name}' is OPEN. Execution halted to protect system."
            )

        try:
            result = func(*args, **kwargs)
            self.record_success()
            return result
        except Exception as exc:
            self.record_failure(exc)
            raise
