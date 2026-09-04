"""
Project AEGIS - Remediation Orchestrator
Coordinates multi-service incident response, idempotency locks, risk gating,
automated post-verification, and automatic rollback on failure.
"""

from __future__ import annotations

import logging
from typing import Any

from services.remediation.idempotency import IdempotencyStore
from services.remediation.models import (
    RemediationAction,
    RemediationRequest,
    RemediationResult,
    RemediationStatus,
)
from services.remediation.remediators.account import AccountQuarantineRemediator
from services.remediation.remediators.base import BaseRemediator
from services.remediation.remediators.ec2 import EC2Remediator
from services.remediation.remediators.iam import IAMRemediator
from services.remediation.remediators.s3 import S3Remediator

logger = logging.getLogger("aegis.remediation.orchestrator")


class RemediationOrchestrator:
    """
    Central coordinator orchestrating specialized remediators with idempotency,
    verification, and rollback controls.
    """

    def __init__(
        self,
        idempotency_store: IdempotencyStore | None = None,
        iam_remediator: IAMRemediator | None = None,
        ec2_remediator: EC2Remediator | None = None,
        s3_remediator: S3Remediator | None = None,
        account_remediator: AccountQuarantineRemediator | None = None,
    ) -> None:
        self.store = idempotency_store or IdempotencyStore()
        self.iam = iam_remediator or IAMRemediator()
        self.ec2 = ec2_remediator or EC2Remediator()
        self.s3 = s3_remediator or S3Remediator()
        self.account = account_remediator or AccountQuarantineRemediator()

    def _get_remediator(self, action: RemediationAction) -> BaseRemediator:
        if action in (
            RemediationAction.DEACTIVATE_ACCESS_KEY,
            RemediationAction.REVOKE_IAM_SESSIONS,
        ):
            return self.iam
        elif action == RemediationAction.ISOLATE_EC2_INSTANCE:
            return self.ec2
        elif action == RemediationAction.ENFORCE_S3_BLOCK_PUBLIC:
            return self.s3
        elif action == RemediationAction.QUARANTINE_ACCOUNT:
            return self.account
        else:
            raise ValueError(f"No specialized remediator registered for action: {action}")

    def execute(self, request: RemediationRequest) -> RemediationResult:
        """
        Main execution pipeline:
        1. Idempotency Lock
        2. Risk Score Gate
        3. Dispatch to Specialized Remediator
        4. Post-Execution Verification
        5. Rollback on Verification Failure
        6. Record Audit State
        """
        # Step 1: Idempotency Lock
        lock_acquired = self.store.acquire_lock(request.idempotency_key, request.remediation_id)
        if not lock_acquired:
            return RemediationResult(
                remediation_id=request.remediation_id,
                action=request.action,
                target_resource_id=request.target_resource_id,
                status=RemediationStatus.FAILED,
                verified=False,
                verification_details="Idempotency lock denied: duplicate or concurrent containment request.",
                error_message="Duplicate containment prevented by IdempotencyStore.",
            )

        # Step 2: Risk Gating
        # Scores below 50.0 (LOW/MEDIUM) must not trigger active automated containment
        if request.risk_score < 50.0:
            result = RemediationResult(
                remediation_id=request.remediation_id,
                action=request.action,
                target_resource_id=request.target_resource_id,
                status=RemediationStatus.COMPLETED,
                verified=True,
                verification_details=f"Risk score ({request.risk_score}) below containment threshold (50.0). Log only.",
            )
            self.store.record_completion(request.idempotency_key, result)
            return result

        # Step 3: Dispatch to Specialized Remediator
        try:
            remediator = self._get_remediator(request.action)
            result = remediator.remediate(request)
        except Exception as e:
            logger.error(f"Remediator exception during {request.action}: {e}")
            result = RemediationResult(
                remediation_id=request.remediation_id,
                action=request.action,
                target_resource_id=request.target_resource_id,
                status=RemediationStatus.FAILED,
                verified=False,
                verification_details=f"Execution exception: {e}",
                error_message=str(e),
            )
            self.store.record_completion(request.idempotency_key, result)
            return result

        # Step 4 & 5: Verification and Rollback if needed
        if not result.verified and result.pre_state:
            logger.warning(
                f"Remediation {request.remediation_id} failed verification; initiating rollback."
            )
            rolled_back = remediator.rollback(request, result.pre_state)
            result.status = (
                RemediationStatus.ROLLED_BACK if rolled_back else RemediationStatus.FAILED
            )
            result.verification_details += (
                f" [Automatic Rollback {'SUCCESSFUL' if rolled_back else 'FAILED'}]"
            )

        # Step 6: Record in Idempotency Store
        self.store.record_completion(request.idempotency_key, result)
        return result

    def rollback_remediation(
        self,
        request: RemediationRequest,
        pre_state: dict[str, Any],
    ) -> bool:
        """Manual or operator-initiated rollback."""
        remediator = self._get_remediator(request.action)
        return remediator.rollback(request, pre_state)
