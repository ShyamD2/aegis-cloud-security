"""
Project AEGIS - Base Remediator Interface
Defines the required lifecycle methods for all specialized remediation sub-engines.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from services.remediation.models import RemediationRequest, RemediationResult


class BaseRemediator(ABC):
    """Abstract base class ensuring least privilege, verification, and rollback support."""

    @abstractmethod
    def remediate(self, request: RemediationRequest) -> RemediationResult:
        """Execute the containment action and return result with pre- and post-state snapshots."""
        pass

    @abstractmethod
    def verify(self, request: RemediationRequest) -> tuple[bool, str]:
        """Inspect the resource post-execution to confirm intended security state is active."""
        pass

    @abstractmethod
    def rollback(self, request: RemediationRequest, pre_state: dict[str, Any]) -> bool:
        """Revert the resource to its pre-remediation configuration if execution was erroneous."""
        pass
