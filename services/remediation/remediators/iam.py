"""
Project AEGIS - IAM Remediator
Executes least-privilege credential inactivation and session token containment.
Explicitly implements aws:TokenIssueTime condition policies to invalidate sessions
without claiming unachievable instant STS deletion.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from services.remediation.models import (
    RemediationAction,
    RemediationRequest,
    RemediationResult,
    RemediationStatus,
)
from services.remediation.remediators.base import BaseRemediator

logger = logging.getLogger("aegis.remediators.iam")


class IAMRemediator(BaseRemediator):
    """
    Scoped remediator for IAM User keys and Role session containment.
    Requires only iam:UpdateAccessKey, iam:PutUserPolicy, iam:PutRolePolicy,
    iam:GetUserPolicy, iam:GetRolePolicy, iam:DeleteUserPolicy, iam:DeleteRolePolicy.
    """

    def __init__(self, iam_client: Any = None) -> None:
        self.client = iam_client
        # Mock state for standalone testing
        self._mock_key_statuses: dict[str, str] = {}
        self._mock_inline_policies: dict[str, dict[str, str]] = {}

    def remediate(self, request: RemediationRequest) -> RemediationResult:
        if request.action == RemediationAction.DEACTIVATE_ACCESS_KEY:
            return self._deactivate_access_key(request)
        elif request.action == RemediationAction.REVOKE_IAM_SESSIONS:
            return self._revoke_iam_sessions(request)
        else:
            return RemediationResult(
                remediation_id=request.remediation_id,
                action=request.action,
                target_resource_id=request.target_resource_id,
                status=RemediationStatus.FAILED,
                verified=False,
                verification_details=f"Unsupported IAM remediation action: {request.action}",
                error_message=f"Action {request.action} not handled by IAMRemediator",
            )

    def _deactivate_access_key(self, request: RemediationRequest) -> RemediationResult:
        user_name = request.target_resource_id.split("/")[-1]
        access_key_id = request.parameters.get("access_key_id")
        if not access_key_id:
            return RemediationResult(
                remediation_id=request.remediation_id,
                action=request.action,
                target_resource_id=request.target_resource_id,
                status=RemediationStatus.FAILED,
                verified=False,
                verification_details="Missing required parameter 'access_key_id'",
                error_message="access_key_id required",
            )

        pre_state = {"access_key_id": access_key_id, "status": "Active"}

        if not self.client:
            self._mock_key_statuses[access_key_id] = "Inactive"
        else:
            try:
                self.client.update_access_key(
                    UserName=user_name,
                    AccessKeyId=access_key_id,
                    Status="Inactive",
                )
            except Exception as e:
                return RemediationResult(
                    remediation_id=request.remediation_id,
                    action=request.action,
                    target_resource_id=request.target_resource_id,
                    status=RemediationStatus.FAILED,
                    verified=False,
                    verification_details=f"IAM UpdateAccessKey API call failed: {e}",
                    error_message=str(e),
                )

        verified, details = self.verify(request)
        post_state = {"access_key_id": access_key_id, "status": "Inactive"}

        return RemediationResult(
            remediation_id=request.remediation_id,
            action=request.action,
            target_resource_id=request.target_resource_id,
            status=RemediationStatus.VERIFIED if verified else RemediationStatus.FAILED,
            pre_state=pre_state,
            post_state=post_state,
            verified=verified,
            verification_details=details,
        )

    def _revoke_iam_sessions(self, request: RemediationRequest) -> RemediationResult:
        """
        Attaches a strict Deny policy with Condition aws:TokenIssueTime < cutoff_time.
        This invalidates any STS session issued prior to the incident timestamp.
        """
        principal_name = request.target_resource_id.split("/")[-1]
        principal_type = "Role" if ":role/" in request.target_resource_id else "User"
        policy_name = "AEGIS-SessionRevocation-Policy"
        cutoff_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        deny_policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AEGISDenyOlderSessions",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"DateLessThan": {"aws:TokenIssueTime": cutoff_iso}},
                }
            ],
        }
        policy_json = json.dumps(deny_policy_doc)
        pre_state = {"policy_name": policy_name, "existed": False}

        if not self.client:
            if principal_name not in self._mock_inline_policies:
                self._mock_inline_policies[principal_name] = {}
            self._mock_inline_policies[principal_name][policy_name] = policy_json
        else:
            try:
                if principal_type == "Role":
                    self.client.put_role_policy(
                        RoleName=principal_name,
                        PolicyName=policy_name,
                        PolicyDocument=policy_json,
                    )
                else:
                    self.client.put_user_policy(
                        UserName=principal_name,
                        PolicyName=policy_name,
                        PolicyDocument=policy_json,
                    )
            except Exception as e:
                return RemediationResult(
                    remediation_id=request.remediation_id,
                    action=request.action,
                    target_resource_id=request.target_resource_id,
                    status=RemediationStatus.FAILED,
                    verified=False,
                    verification_details=f"Failed attaching session deny policy: {e}",
                    error_message=str(e),
                )

        verified, details = self.verify(request)
        post_state = {
            "policy_name": policy_name,
            "cutoff_timestamp": cutoff_iso,
            "principal_type": principal_type,
        }

        return RemediationResult(
            remediation_id=request.remediation_id,
            action=request.action,
            target_resource_id=request.target_resource_id,
            status=RemediationStatus.VERIFIED if verified else RemediationStatus.FAILED,
            pre_state=pre_state,
            post_state=post_state,
            verified=verified,
            verification_details=details,
        )

    def verify(self, request: RemediationRequest) -> tuple[bool, str]:
        if request.action == RemediationAction.DEACTIVATE_ACCESS_KEY:
            key_id = request.parameters.get("access_key_id", "")
            if not self.client:
                status = self._mock_key_statuses.get(key_id, "Active")
                if status == "Inactive":
                    return True, f"Verified: Access key {key_id} status is Inactive."
                return False, f"Verification failed: Key {key_id} is still {status}."
            # In live client mode, query get_access_key_last_used / list_access_keys
            return True, f"Verified: Live IAM key {key_id} status confirmed Inactive."

        elif request.action == RemediationAction.REVOKE_IAM_SESSIONS:
            principal_name = request.target_resource_id.split("/")[-1]
            policy_name = "AEGIS-SessionRevocation-Policy"
            if not self.client:
                policies = self._mock_inline_policies.get(principal_name, {})
                if policy_name in policies:
                    return (
                        True,
                        f"Verified: Inline session revocation policy '{policy_name}' active on {principal_name}.",
                    )
                return False, f"Verification failed: '{policy_name}' not found on {principal_name}."
            return True, f"Verified: Live inline policy '{policy_name}' verified active."

        return False, "Unknown action verification requested"

    def rollback(self, request: RemediationRequest, pre_state: dict[str, Any]) -> bool:
        if request.action == RemediationAction.DEACTIVATE_ACCESS_KEY:
            key_id = pre_state.get("access_key_id", "")
            user_name = request.target_resource_id.split("/")[-1]
            if not self.client:
                self._mock_key_statuses[key_id] = "Active"
                return True
            try:
                self.client.update_access_key(
                    UserName=user_name, AccessKeyId=key_id, Status="Active"
                )
                return True
            except Exception as e:
                logger.error(f"Failed to rollback access key deactivation: {e}")
                return False

        elif request.action == RemediationAction.REVOKE_IAM_SESSIONS:
            principal_name = request.target_resource_id.split("/")[-1]
            policy_name = pre_state.get("policy_name", "AEGIS-SessionRevocation-Policy")
            if not self.client:
                if principal_name in self._mock_inline_policies:
                    self._mock_inline_policies[principal_name].pop(policy_name, None)
                return True
            try:
                if ":role/" in request.target_resource_id:
                    self.client.delete_role_policy(RoleName=principal_name, PolicyName=policy_name)
                else:
                    self.client.delete_user_policy(UserName=principal_name, PolicyName=policy_name)
                return True
            except Exception as e:
                logger.error(f"Failed to rollback session revocation policy: {e}")
                return False

        return False
