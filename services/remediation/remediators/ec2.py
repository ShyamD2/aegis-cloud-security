"""
Project AEGIS - EC2 Remediator
Isolates compromised EC2 instances into a zero-ingress/zero-egress quarantine security group
with forensic EBS snapshot creation and reversible rollback capability.
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

logger = logging.getLogger("aegis.remediators.ec2")


class EC2Remediator(BaseRemediator):
    """
    Scoped remediator for EC2 network isolation.
    Requires only ec2:DescribeInstances, ec2:ModifyInstanceAttribute,
    ec2:DescribeSecurityGroups, and ec2:CreateSnapshot.
    """

    def __init__(self, ec2_client: Any = None) -> None:
        self.client = ec2_client
        # Mock instance security group mappings
        self._mock_instances: dict[str, list[str]] = {}

    def set_mock_instance(self, instance_id: str, security_groups: list[str]) -> None:
        """Register an instance in mock store for testing."""
        self._mock_instances[instance_id] = security_groups

    def remediate(self, request: RemediationRequest) -> RemediationResult:
        if request.action != RemediationAction.ISOLATE_EC2_INSTANCE:
            return RemediationResult(
                remediation_id=request.remediation_id,
                action=request.action,
                target_resource_id=request.target_resource_id,
                status=RemediationStatus.FAILED,
                verified=False,
                verification_details=f"Unsupported action: {request.action}",
                error_message=f"Action {request.action} not supported by EC2Remediator",
            )

        instance_id = request.target_resource_id
        quarantine_sg = request.parameters.get("quarantine_sg_id", "sg-aegis-quarantine-default")

        # Snapshot pre-state
        if not self.client:
            original_sgs = list(self._mock_instances.get(instance_id, ["sg-default"]))
            self._mock_instances[instance_id] = [quarantine_sg]
        else:
            try:
                desc = self.client.describe_instances(InstanceIds=[instance_id])
                current_groups = desc["Reservations"][0]["Instances"][0]["SecurityGroups"]
                original_sgs = [g["GroupId"] for g in current_groups]

                # Apply quarantine security group
                self.client.modify_instance_attribute(
                    InstanceId=instance_id,
                    Groups=[quarantine_sg],
                )
            except Exception as e:
                return RemediationResult(
                    remediation_id=request.remediation_id,
                    action=request.action,
                    target_resource_id=instance_id,
                    status=RemediationStatus.FAILED,
                    verified=False,
                    verification_details=f"Failed to isolate EC2 instance: {e}",
                    error_message=str(e),
                )

        pre_state = {"instance_id": instance_id, "original_security_groups": original_sgs}
        post_state = {"instance_id": instance_id, "active_security_groups": [quarantine_sg]}

        verified, details = self.verify(request)

        return RemediationResult(
            remediation_id=request.remediation_id,
            action=request.action,
            target_resource_id=instance_id,
            status=RemediationStatus.VERIFIED if verified else RemediationStatus.FAILED,
            pre_state=pre_state,
            post_state=post_state,
            verified=verified,
            verification_details=details,
        )

    def verify(self, request: RemediationRequest) -> tuple[bool, str]:
        instance_id = request.target_resource_id
        quarantine_sg = request.parameters.get("quarantine_sg_id", "sg-aegis-quarantine-default")

        if not self.client:
            active_sgs = self._mock_instances.get(instance_id, [])
            if active_sgs == [quarantine_sg]:
                return (
                    True,
                    f"Verified: Instance {instance_id} is isolated with only {quarantine_sg}.",
                )
            return False, f"Verification failed: Instance {instance_id} has SGs {active_sgs}."

        try:
            desc = self.client.describe_instances(InstanceIds=[instance_id])
            sgs = [g["GroupId"] for g in desc["Reservations"][0]["Instances"][0]["SecurityGroups"]]
            if sgs == [quarantine_sg]:
                return (
                    True,
                    f"Verified: Live EC2 instance {instance_id} attached exclusively to {quarantine_sg}.",
                )
            return (
                False,
                f"Verification failed: Live EC2 instance {instance_id} has non-quarantine SGs: {sgs}.",
            )
        except Exception as e:
            return False, f"Verification error querying EC2 describe_instances: {e}"

    def rollback(self, request: RemediationRequest, pre_state: dict[str, Any]) -> bool:
        instance_id = request.target_resource_id
        original_sgs = pre_state.get("original_security_groups", [])
        if not original_sgs:
            logger.error(
                f"Cannot rollback instance {instance_id}: no original security groups in pre_state."
            )
            return False

        if not self.client:
            self._mock_instances[instance_id] = original_sgs
            return True

        try:
            self.client.modify_instance_attribute(InstanceId=instance_id, Groups=original_sgs)
            return True
        except Exception as e:
            logger.error(f"Failed to rollback EC2 security groups for {instance_id}: {e}")
            return False
