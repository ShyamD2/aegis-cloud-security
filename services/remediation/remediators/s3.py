"""
Project AEGIS - S3 Remediator
Enforces S3 Block Public Access across all 4 protection flags with zero data destruction.
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

logger = logging.getLogger("aegis.remediators.s3")


class S3Remediator(BaseRemediator):
    """
    Scoped remediator for Amazon S3 public exposure mitigation.
    Requires only s3:GetBucketPolicy, s3:PutBucketPolicy,
    s3:GetBucketPublicAccessBlock, and s3:PutBucketPublicAccessBlock.
    """

    def __init__(self, s3_client: Any = None) -> None:
        self.client = s3_client
        self._mock_pab: dict[str, dict[str, bool]] = {}

    def set_mock_bucket(self, bucket_name: str, config: dict[str, bool]) -> None:
        """Register bucket in mock store for testing."""
        self._mock_pab[bucket_name] = config

    def remediate(self, request: RemediationRequest) -> RemediationResult:
        if request.action != RemediationAction.ENFORCE_S3_BLOCK_PUBLIC:
            return RemediationResult(
                remediation_id=request.remediation_id,
                action=request.action,
                target_resource_id=request.target_resource_id,
                status=RemediationStatus.FAILED,
                verified=False,
                verification_details=f"Unsupported S3 action: {request.action}",
                error_message=f"Action {request.action} not supported by S3Remediator",
            )

        bucket_name = request.target_resource_id.replace("arn:aws:s3:::", "")
        enforce_config = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }

        if not self.client:
            pre_state = self._mock_pab.get(
                bucket_name,
                {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
            )
            self._mock_pab[bucket_name] = dict(enforce_config)
        else:
            try:
                try:
                    pab_resp = self.client.get_public_access_block(Bucket=bucket_name)
                    pre_state = pab_resp.get("PublicAccessBlockConfiguration", {})
                except Exception:
                    pre_state = {"BlockPublicAcls": False, "BlockPublicPolicy": False}

                self.client.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration=enforce_config,
                )
            except Exception as e:
                return RemediationResult(
                    remediation_id=request.remediation_id,
                    action=request.action,
                    target_resource_id=bucket_name,
                    status=RemediationStatus.FAILED,
                    verified=False,
                    verification_details=f"S3 PutPublicAccessBlock failed: {e}",
                    error_message=str(e),
                )

        verified, details = self.verify(request)

        return RemediationResult(
            remediation_id=request.remediation_id,
            action=request.action,
            target_resource_id=bucket_name,
            status=RemediationStatus.VERIFIED if verified else RemediationStatus.FAILED,
            pre_state=pre_state,
            post_state=enforce_config,
            verified=verified,
            verification_details=details,
        )

    def verify(self, request: RemediationRequest) -> tuple[bool, str]:
        bucket_name = request.target_resource_id.replace("arn:aws:s3:::", "")
        if not self.client:
            cfg = self._mock_pab.get(bucket_name, {})
            all_blocked = all(
                cfg.get(k) is True
                for k in [
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                ]
            )
            if all_blocked:
                return (
                    True,
                    f"Verified: Bucket {bucket_name} has all 4 Block Public Access flags enabled.",
                )
            return (
                False,
                f"Verification failed: Bucket {bucket_name} PAB settings incomplete: {cfg}",
            )

        try:
            resp = self.client.get_public_access_block(Bucket=bucket_name)
            cfg = resp.get("PublicAccessBlockConfiguration", {})
            all_blocked = all(
                cfg.get(k) is True
                for k in [
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                ]
            )
            if all_blocked:
                return (
                    True,
                    f"Verified: Live S3 bucket {bucket_name} Block Public Access verified enabled.",
                )
            return (
                False,
                f"Verification failed: Live S3 bucket {bucket_name} has incomplete protection: {cfg}",
            )
        except Exception as e:
            return False, f"Verification error querying S3: {e}"

    def rollback(self, request: RemediationRequest, pre_state: dict[str, Any]) -> bool:
        bucket_name = request.target_resource_id.replace("arn:aws:s3:::", "")
        if not self.client:
            self._mock_pab[bucket_name] = pre_state
            return True

        try:
            self.client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration=pre_state,
            )
            return True
        except Exception as e:
            logger.error(f"Failed to rollback S3 PAB configuration: {e}")
            return False
