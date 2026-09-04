"""
Project AEGIS - Account Quarantine Remediator
Attaches organizational quarantine Service Control Policies (SCPs) to isolate compromised accounts.
Enforces explicit human approval gates for any non-lab account containment.
"""

from __future__ import annotations

import logging
from typing import Any

from services.remediation.models import (
    RemediationAction,
    RemediationRequest,
    RemediationResult,
    RemediationStatus,
)
from services.remediation.remediators.base import BaseRemediator

logger = logging.getLogger("aegis.remediators.account")

# Defined Security Lab account constant
SECURITY_LAB_ACCOUNT_ID = "555555555555"
QUARANTINE_POLICY_ID = "p-aegis-quarantine-scp"


class AccountQuarantineRemediator(BaseRemediator):
    """
    Scoped remediator for account-level boundary quarantine.
    Requires organizations:AttachPolicy, organizations:DetachPolicy,
    and organizations:ListPoliciesForTarget.
    """

    def __init__(self, org_client: Any = None) -> None:
        self.client = org_client
        self._mock_attached_policies: dict[str, list[str]] = {}

    def remediate(self, request: RemediationRequest) -> RemediationResult:
        if request.action != RemediationAction.QUARANTINE_ACCOUNT:
            return RemediationResult(
                remediation_id=request.remediation_id,
                action=request.action,
                target_resource_id=request.target_resource_id,
                status=RemediationStatus.FAILED,
                verified=False,
                verification_details=f"Unsupported action: {request.action}",
                error_message=f"Action {request.action} not handled by AccountQuarantineRemediator",
            )

        account_id = request.target_resource_id

        # Human Approval Gate: Non-lab accounts require approval token
        if account_id != SECURITY_LAB_ACCOUNT_ID:
            if not request.approval_token or len(request.approval_token.strip()) < 8:
                return RemediationResult(
                    remediation_id=request.remediation_id,
                    action=request.action,
                    target_resource_id=account_id,
                    status=RemediationStatus.FAILED,
                    verified=False,
                    verification_details="Account quarantine blocked: non-lab account requires valid human approval token.",
                    error_message="Missing or invalid human approval_token for non-lab account quarantine.",
                )

        if not self.client:
            original_policies = list(
                self._mock_attached_policies.get(account_id, ["p-FullAWSAccess"])
            )
            if QUARANTINE_POLICY_ID not in self._mock_attached_policies.get(account_id, []):
                self._mock_attached_policies[account_id] = original_policies + [
                    QUARANTINE_POLICY_ID
                ]
        else:
            try:
                # Capture pre-state policies
                resp = self.client.list_policies_for_target(
                    TargetId=account_id,
                    Filter="SERVICE_CONTROL_POLICY",
                )
                original_policies = [p["Id"] for p in resp.get("Policies", [])]

                # Attach quarantine SCP
                self.client.attach_policy(
                    PolicyId=QUARANTINE_POLICY_ID,
                    TargetId=account_id,
                )
            except Exception as e:
                return RemediationResult(
                    remediation_id=request.remediation_id,
                    action=request.action,
                    target_resource_id=account_id,
                    status=RemediationStatus.FAILED,
                    verified=False,
                    verification_details=f"AWS Organizations attach_policy call failed: {e}",
                    error_message=str(e),
                )

        pre_state = {"account_id": account_id, "attached_policies": original_policies}
        post_state = {
            "account_id": account_id,
            "attached_policies": original_policies + [QUARANTINE_POLICY_ID],
        }

        verified, details = self.verify(request)

        return RemediationResult(
            remediation_id=request.remediation_id,
            action=request.action,
            target_resource_id=account_id,
            status=RemediationStatus.VERIFIED if verified else RemediationStatus.FAILED,
            pre_state=pre_state,
            post_state=post_state,
            verified=verified,
            verification_details=details,
        )

    def verify(self, request: RemediationRequest) -> tuple[bool, str]:
        account_id = request.target_resource_id
        if not self.client:
            policies = self._mock_attached_policies.get(account_id, [])
            if QUARANTINE_POLICY_ID in policies:
                return (
                    True,
                    f"Verified: Quarantine SCP {QUARANTINE_POLICY_ID} is active on account {account_id}.",
                )
            return False, f"Verification failed: Quarantine SCP missing on account {account_id}."

        try:
            resp = self.client.list_policies_for_target(
                TargetId=account_id,
                Filter="SERVICE_CONTROL_POLICY",
            )
            attached = [p["Id"] for p in resp.get("Policies", [])]
            if QUARANTINE_POLICY_ID in attached:
                return (
                    True,
                    f"Verified: Live Organizations target {account_id} has active {QUARANTINE_POLICY_ID}.",
                )
            return (
                False,
                f"Verification failed: {QUARANTINE_POLICY_ID} not in target policies: {attached}",
            )
        except Exception as e:
            return False, f"Verification error querying Organizations: {e}"

    def rollback(self, request: RemediationRequest, pre_state: dict[str, Any]) -> bool:
        account_id = request.target_resource_id
        if not self.client:
            if account_id in self._mock_attached_policies:
                self._mock_attached_policies[account_id] = [
                    p for p in self._mock_attached_policies[account_id] if p != QUARANTINE_POLICY_ID
                ]
            return True

        try:
            self.client.detach_policy(PolicyId=QUARANTINE_POLICY_ID, TargetId=account_id)
            return True
        except Exception as e:
            logger.error(f"Failed to detach quarantine policy during rollback: {e}")
            return False
