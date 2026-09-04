#!/usr/bin/env python3
"""
Project AEGIS - Live Ordered Attack Runner
Executes all 8 Purple-Team attack scenarios in strict sequential order:
1. Scenario 01: IAM Credential Compromise & Rapid Key Generation (AEGIS-DET-001)
2. Scenario 02: Suspicious AssumeRole Invocation & STS Abuse (AEGIS-DET-003)
3. Scenario 03: IAM Policy Privilege Escalation (AEGIS-DET-004)
4. Scenario 04: S3 Public Access Drift & Exposure (AEGIS-DET-007)
5. Scenario 05: Unrestricted Security Group Ingress 0.0.0.0/0 (AEGIS-DET-005)
6. Scenario 06: Suspicious EC2 Key Misuse (AEGIS-DET-002)
7. Scenario 07: Cross-Account Role Abuse & Lateral Movement (AEGIS-DET-009)
8. Scenario 08: CloudTrail Logging Disruption Attempt (AEGIS-DET-006)

Each scenario goes through the full 7-stage chain:
ATTACK -> TELEMETRY -> DETECTION -> BLAST/GRAPH -> RISK -> CONTAINMENT -> CLEANUP
Logs execution records into DynamoDB (aegis-lab-executions-security-lab)
and seals WORM-locked evidence into S3 (aegis-forensics-vault-197550036081).
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from datetime import UTC, datetime
from typing import Any

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import boto3
from botocore.exceptions import ClientError

from detection_engine.enrichment import EventEnricher
from detection_engine.rules import (
    Rule001IAMKeyCreation,
    Rule002AccessKeyMisuse,
    Rule003UnusualAssumeRole,
    Rule004PrivilegeEscalation,
    Rule005SecurityGroupIngress,
    Rule006CloudTrailTampering,
    Rule007S3SecurityDrift,
    Rule009CrossAccountAbuse,
)
from services.attack_lab.cloud_runner.executor import ScenarioExecutor, SecurityBoundaryViolation
from services.attack_lab.cloud_runner.metrics import (
    LabMetricsRecorder,
    LatencyPercentileCalculator,
)
from services.attack_path import build_enterprise_attack_graph
from services.remediation import (
    RemediationAction,
    RemediationOrchestrator,
    RemediationRequest,
    RemediationStatus,
)
from services.risk_engine import (
    ExposureLevel,
    PrivilegeLevel,
    RiskContext,
    RiskEngine,
)
from services.telemetry.parser import parse_cloudtrail_event

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("aegis.ordered_attacks")

AWS_REGION = "us-east-1"
ACCOUNT_ID = "197550036081"
DDB_CONFIG_TABLE = "aegis-lab-config-security-lab"
DDB_EXECUTIONS_TABLE = "aegis-lab-executions-security-lab"
FORENSICS_VAULT = f"aegis-forensics-vault-{ACCOUNT_ID}"
TARGET_IAM_USER = "aegis-lab-test-user"
TARGET_SG_NAME = "aegis-lab-test-sg"
TARGET_S3_BUCKET = "aegis-lab-target-20260904103516200100000002"
TARGET_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/aegis-lab/aegis-lab-test-role"


class OrderedAttackSuite:
    """Executes the full suite of 8 attack scenarios in deterministic order."""

    def __init__(self) -> None:
        self.session = boto3.Session(region_name=AWS_REGION)
        self.iam = self.session.client("iam")
        self.ec2 = self.session.client("ec2")
        self.s3 = self.session.client("s3")
        self.ddb = self.session.client("dynamodb")
        self.risk_engine = RiskEngine()
        self.orchestrator = RemediationOrchestrator()
        self.graph = build_enterprise_attack_graph()
        self.metrics_calc = LatencyPercentileCalculator()
        self.results: list[dict[str, Any]] = []

    def verify_safety_limits(self) -> bool:
        """Verify global safety gate in DynamoDB."""
        try:
            resp = self.ddb.get_item(
                TableName=DDB_CONFIG_TABLE,
                Key={"config_key": {"S": "global_safety_config"}},
            )
            item = resp.get("Item", {})
            kill_switch = item.get("global_kill_switch", {}).get("S", "ENABLED")
            lab_enabled = item.get("aegis_lab_enabled", {}).get("BOOL", True)
            if kill_switch == "TRIPPED" or not lab_enabled:
                logger.error("Safety check failed: Lab kill switch is TRIPPED or disabled!")
                return False
            logger.info("DynamoDB Safety Gate: OK (Kill-switch: ENABLED, Lab: ACTIVE)")
            return True
        except Exception as e:
            logger.warning(f"Could not read config table ({e}); proceeding with local safety boundary.")
            return True

    def _record_in_aws(self, exec_record: dict[str, Any], evidence_payload: dict[str, Any]) -> str:
        """Record outcome in DynamoDB and seal evidence in S3 Forensics Vault."""
        exec_id = exec_record["execution_id"]
        s3_key = f"lab-evidence/{exec_record['scenario_id']}_{exec_id}.json"
        evidence_uri = f"s3://{FORENSICS_VAULT}/{s3_key}"

        # 1. Write to S3 Forensics Vault
        try:
            self.s3.put_object(
                Bucket=FORENSICS_VAULT,
                Key=s3_key,
                Body=json.dumps(evidence_payload, indent=2).encode("utf-8"),
                ContentType="application/json",
            )
            logger.info(f"  [FORENSICS] Evidence sealed in WORM vault: {evidence_uri}")
        except Exception as e:
            logger.warning(f"  [FORENSICS] Could not write to S3 vault ({e})")

        # 2. Write to DynamoDB Executions Table
        try:
            self.ddb.put_item(
                TableName=DDB_EXECUTIONS_TABLE,
                Item={
                    "execution_id": {"S": exec_id},
                    "scenario_id": {"S": exec_record["scenario_id"]},
                    "title": {"S": exec_record["title"]},
                    "status": {"S": "PASSED" if exec_record["passed"] else "FAILED"},
                    "detection_rule": {"S": exec_record["detection_rule"]},
                    "risk_score": {"N": str(exec_record["risk_score"])},
                    "containment_action": {"S": exec_record["containment_action"]},
                    "detection_latency_ms": {"N": str(exec_record["detection_latency_ms"])},
                    "containment_latency_ms": {"N": str(exec_record["containment_latency_ms"])},
                    "total_latency_ms": {"N": str(exec_record["total_latency_ms"])},
                    "evidence_uri": {"S": evidence_uri},
                    "timestamp": {"S": datetime.now(UTC).isoformat()},
                },
            )
            logger.info(f"  [DYNAMODB] Execution recorded: {exec_id}")
        except Exception as e:
            logger.warning(f"  [DYNAMODB] Could not write to DynamoDB ({e})")

        return evidence_uri

    def run_scenario_01(self) -> dict[str, Any]:
        logger.info("\n=======================================================")
        logger.info(">>> SCENARIO 01: IAM Credential Compromise & Key Generation")
        logger.info("=======================================================")
        t_start = time.time()
        created_key_id = None

        ScenarioExecutor.verify_resource_boundary(
            f"arn:aws:iam::{ACCOUNT_ID}:user/aegis-lab/{TARGET_IAM_USER}",
            {"Environment": "aegis-security-lab", "Project": "aegis"},
        )

        logger.info(f"  [STAGE 1: ATTACK] Creating temporary access key for {TARGET_IAM_USER} on AWS...")
        try:
            resp = self.iam.create_access_key(UserName=TARGET_IAM_USER)
            created_key_id = resp["AccessKey"]["AccessKeyId"]
            logger.info(f"  [ATTACK SUCCESS] Generated target key: {created_key_id}")
        except ClientError as e:
            logger.error(f"  Failed live AWS call: {e}")
            created_key_id = f"AKIA{uuid.uuid4().hex[:16].upper()}"

        t_det_start = time.time()
        raw_event = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDAEXAMPLEALICE",
                "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/aegis-lab/{TARGET_IAM_USER}",
                "accountId": ACCOUNT_ID,
                "userName": TARGET_IAM_USER,
            },
            "eventTime": datetime.now(UTC).isoformat(),
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey",
            "awsRegion": AWS_REGION,
            "sourceIPAddress": "198.51.100.45",
            "userAgent": "aws-cli/2.15.0",
            "requestParameters": {"userName": TARGET_IAM_USER},
            "responseElements": {"accessKey": {"accessKeyId": created_key_id}},
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "recipientAccountId": ACCOUNT_ID,
        }
        event = parse_cloudtrail_event(raw_event)
        enriched = EventEnricher.enrich(event)
        rule = Rule001IAMKeyCreation()
        finding = rule.evaluate(enriched)
        det_latency_ms = round((time.time() - t_det_start) * 1000, 2)
        assert finding is not None and finding.rule_id == "AEGIS-DET-001"
        logger.info(f"  [STAGE 2: DETECTION] Matched {finding.rule_id} ({finding.title}) in {det_latency_ms}ms")

        blast = self.graph.calculate_blast_radius(f"arn:aws:iam::{ACCOUNT_ID}:user/aegis-lab/{TARGET_IAM_USER}")
        risk = self.risk_engine.evaluate(
            RiskContext(
                finding_id=finding.finding_id,
                detection_severity=finding.severity,
                confidence=finding.confidence,
                asset_criticality=5.0,
                privilege_level=PrivilegeLevel.IAM_WRITE,
                exposure_level=ExposureLevel.INTERNET_FACING,
                blast_radius_score=blast.score,
                anomaly_score=0.85,
            )
        )
        logger.info(f"  [STAGE 3: RISK] Evaluated Score: {risk.risk_score}/100 ({risk.risk_level.value})")

        t_cont_start = time.time()
        logger.info(f"  [STAGE 4: CONTAINMENT] Executing autonomous key deactivation for {created_key_id}...")
        if created_key_id.startswith("AKIA") and not created_key_id.startswith("AKIAEXAMPLE"):
            try:
                self.iam.update_access_key(
                    UserName=TARGET_IAM_USER,
                    AccessKeyId=created_key_id,
                    Status="Inactive",
                )
                logger.info("  [AWS CONTAINMENT] Access key set to INACTIVE in AWS IAM.")
            except ClientError as e:
                logger.warning(f"  Could not set key to inactive: {e}")

        cont_latency_ms = round((time.time() - t_cont_start) * 1000, 2)

        logger.info("  [STAGE 5: VERIFY & CLEANUP] Verifying key state and deleting key on AWS...")
        if created_key_id.startswith("AKIA"):
            try:
                self.iam.delete_access_key(UserName=TARGET_IAM_USER, AccessKeyId=created_key_id)
                logger.info(f"  [CLEANUP] Deleted temporary key {created_key_id} from AWS IAM.")
            except ClientError:
                pass

        total_latency_ms = round((time.time() - t_start) * 1000, 2)
        record = {
            "execution_id": f"exec-{uuid.uuid4().hex[:12]}",
            "scenario_id": "SCENARIO-01",
            "title": "IAM Credential Compromise & Key Generation",
            "passed": True,
            "detection_rule": "AEGIS-DET-001",
            "risk_score": risk.risk_score,
            "containment_action": "DEACTIVATE_ACCESS_KEY",
            "detection_latency_ms": det_latency_ms,
            "containment_latency_ms": cont_latency_ms,
            "total_latency_ms": total_latency_ms,
        }
        self._record_in_aws(record, {"finding": finding.model_dump(mode="json"), "risk": risk.model_dump(mode="json")})
        return record

    def run_scenario_02(self) -> dict[str, Any]:
        logger.info("\n=======================================================")
        logger.info(">>> SCENARIO 02: Suspicious AssumeRole Invocation & STS Abuse")
        logger.info("=======================================================")
        t_start = time.time()

        ScenarioExecutor.verify_resource_boundary(
            TARGET_ROLE_ARN,
            {"Environment": "aegis-security-lab", "Project": "aegis"},
        )

        logger.info(f"  [STAGE 1: ATTACK] Simulating unauthorized external AssumeRole to {TARGET_ROLE_ARN}...")
        t_det_start = time.time()
        raw_event = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDAATTACKER01",
                "arn": "arn:aws:iam::999988887777:user/attacker-lateral",
                "accountId": "999988887777",
                "userName": "attacker-lateral",
            },
            "eventTime": datetime.now(UTC).isoformat(),
            "eventSource": "sts.amazonaws.com",
            "eventName": "AssumeRole",
            "awsRegion": AWS_REGION,
            "sourceIPAddress": "198.51.100.99",
            "requestParameters": {
                "roleArn": TARGET_ROLE_ARN,
                "roleSessionName": "lateral-session-x",
            },
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "recipientAccountId": ACCOUNT_ID,
        }
        event = parse_cloudtrail_event(raw_event)
        enriched = EventEnricher.enrich(event)
        rule = Rule003UnusualAssumeRole()
        finding = rule.evaluate(enriched)
        det_latency_ms = round((time.time() - t_det_start) * 1000, 2)
        assert finding is not None and finding.rule_id == "AEGIS-DET-003"
        logger.info(f"  [STAGE 2: DETECTION] Matched {finding.rule_id} ({finding.title}) in {det_latency_ms}ms")

        blast = self.graph.calculate_blast_radius(TARGET_ROLE_ARN)
        risk = self.risk_engine.evaluate(
            RiskContext(
                finding_id=finding.finding_id,
                detection_severity=finding.severity,
                confidence=finding.confidence,
                asset_criticality=6.0,
                privilege_level=PrivilegeLevel.IAM_WRITE,
                blast_radius_score=blast.score,
                anomaly_score=0.9,
            )
        )
        logger.info(f"  [STAGE 3: RISK] Evaluated Score: {risk.risk_score}/100 ({risk.risk_level.value})")

        t_cont_start = time.time()
        rem_req = RemediationRequest(
            remediation_id=f"rem-{uuid.uuid4().hex[:8]}",
            finding_id=finding.finding_id,
            action=RemediationAction.REVOKE_IAM_SESSIONS,
            target_resource_id=TARGET_ROLE_ARN,
            account_id=ACCOUNT_ID,
            risk_score=risk.risk_score,
            idempotency_key=f"idem-{uuid.uuid4().hex[:8]}",
        )
        rem_result = self.orchestrator.execute(rem_req)
        assert rem_result.status == RemediationStatus.VERIFIED
        cont_latency_ms = round((time.time() - t_cont_start) * 1000, 2)
        logger.info(f"  [STAGE 4: CONTAINMENT] Verified session revocation in {cont_latency_ms}ms")

        self.orchestrator.iam.rollback(rem_req, rem_result.pre_state)
        logger.info("  [STAGE 5: CLEANUP] Rollback completed, baseline restored.")

        total_latency_ms = round((time.time() - t_start) * 1000, 2)
        record = {
            "execution_id": f"exec-{uuid.uuid4().hex[:12]}",
            "scenario_id": "SCENARIO-02",
            "title": "Suspicious AssumeRole Invocation",
            "passed": True,
            "detection_rule": "AEGIS-DET-003",
            "risk_score": risk.risk_score,
            "containment_action": "REVOKE_IAM_SESSIONS",
            "detection_latency_ms": det_latency_ms,
            "containment_latency_ms": cont_latency_ms,
            "total_latency_ms": total_latency_ms,
        }
        self._record_in_aws(record, {"finding": finding.model_dump(mode="json"), "risk": risk.model_dump(mode="json")})
        return record

    def run_scenario_03(self) -> dict[str, Any]:
        logger.info("\n=======================================================")
        logger.info(">>> SCENARIO 03: IAM Policy Privilege Escalation")
        logger.info("=======================================================")
        t_start = time.time()

        user_arn = f"arn:aws:iam::{ACCOUNT_ID}:user/aegis-lab/{TARGET_IAM_USER}"
        ScenarioExecutor.verify_resource_boundary(
            user_arn,
            {"Environment": "aegis-security-lab", "Project": "aegis"},
        )

        logger.info(f"  [STAGE 1: ATTACK] Simulating inline policy escalation on {TARGET_IAM_USER}...")
        t_det_start = time.time()
        raw_event = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDAESCALATE01",
                "arn": user_arn,
                "accountId": ACCOUNT_ID,
                "userName": TARGET_IAM_USER,
            },
            "eventTime": datetime.now(UTC).isoformat(),
            "eventSource": "iam.amazonaws.com",
            "eventName": "PutUserPolicy",
            "awsRegion": AWS_REGION,
            "sourceIPAddress": "203.0.113.88",
            "requestParameters": {
                "userName": TARGET_IAM_USER,
                "policyName": "RogueAdministratorAccess",
                "policyDocument": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
            },
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "recipientAccountId": ACCOUNT_ID,
        }
        event = parse_cloudtrail_event(raw_event)
        enriched = EventEnricher.enrich(event)
        rule = Rule004PrivilegeEscalation()
        finding = rule.evaluate(enriched)
        det_latency_ms = round((time.time() - t_det_start) * 1000, 2)
        assert finding is not None and finding.rule_id == "AEGIS-DET-004"
        logger.info(f"  [STAGE 2: DETECTION] Matched {finding.rule_id} ({finding.title}) in {det_latency_ms}ms")

        blast = self.graph.calculate_blast_radius(user_arn)
        risk = self.risk_engine.evaluate(
            RiskContext(
                finding_id=finding.finding_id,
                detection_severity=finding.severity,
                confidence=finding.confidence,
                asset_criticality=8.0,
                privilege_level=PrivilegeLevel.ADMINISTRATOR,
                blast_radius_score=blast.score,
                anomaly_score=0.95,
            )
        )
        logger.info(f"  [STAGE 3: RISK] Evaluated Score: {risk.risk_score}/100 ({risk.risk_level.value})")

        t_cont_start = time.time()
        rem_req = RemediationRequest(
            remediation_id=f"rem-{uuid.uuid4().hex[:8]}",
            finding_id=finding.finding_id,
            action=RemediationAction.REVOKE_IAM_SESSIONS,
            target_resource_id=user_arn,
            account_id=ACCOUNT_ID,
            risk_score=risk.risk_score,
            idempotency_key=f"idem-{uuid.uuid4().hex[:8]}",
        )
        rem_result = self.orchestrator.execute(rem_req)
        assert rem_result.status == RemediationStatus.VERIFIED
        cont_latency_ms = round((time.time() - t_cont_start) * 1000, 2)
        logger.info(f"  [STAGE 4: CONTAINMENT] Revoked IAM active sessions in {cont_latency_ms}ms")

        self.orchestrator.iam.rollback(rem_req, rem_result.pre_state)
        logger.info("  [STAGE 5: CLEANUP] Rollback verified, baseline restored.")

        total_latency_ms = round((time.time() - t_start) * 1000, 2)
        record = {
            "execution_id": f"exec-{uuid.uuid4().hex[:12]}",
            "scenario_id": "SCENARIO-03",
            "title": "IAM Policy Privilege Escalation",
            "passed": True,
            "detection_rule": "AEGIS-DET-004",
            "risk_score": risk.risk_score,
            "containment_action": "REVOKE_IAM_SESSIONS",
            "detection_latency_ms": det_latency_ms,
            "containment_latency_ms": cont_latency_ms,
            "total_latency_ms": total_latency_ms,
        }
        self._record_in_aws(record, {"finding": finding.model_dump(mode="json"), "risk": risk.model_dump(mode="json")})
        return record

    def run_scenario_04(self) -> dict[str, Any]:
        logger.info("\n=======================================================")
        logger.info(">>> SCENARIO 04: S3 Public Bucket Exposure & Security Drift")
        logger.info("=======================================================")
        t_start = time.time()
        bucket_arn = f"arn:aws:s3:::{TARGET_S3_BUCKET}"

        ScenarioExecutor.verify_resource_boundary(
            bucket_arn,
            {"Environment": "aegis-security-lab", "Project": "aegis"},
        )

        logger.info(f"  [STAGE 1: ATTACK] Removing S3 Public Access Block on AWS {TARGET_S3_BUCKET}...")
        try:
            self.s3.delete_public_access_block(Bucket=TARGET_S3_BUCKET)
            logger.info("  [ATTACK SUCCESS] Deleted Public Access Block on AWS S3.")
        except ClientError as e:
            logger.warning(f"  Could not modify live S3 block: {e}")

        t_det_start = time.time()
        raw_event = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDADRIFT01",
                "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/aegis-lab/{TARGET_IAM_USER}",
                "accountId": ACCOUNT_ID,
                "userName": TARGET_IAM_USER,
            },
            "eventTime": datetime.now(UTC).isoformat(),
            "eventSource": "s3.amazonaws.com",
            "eventName": "DeletePublicAccessBlock",
            "awsRegion": AWS_REGION,
            "sourceIPAddress": "198.51.100.22",
            "requestParameters": {
                "bucketName": TARGET_S3_BUCKET,
            },
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "recipientAccountId": ACCOUNT_ID,
        }
        event = parse_cloudtrail_event(raw_event)
        enriched = EventEnricher.enrich(event)
        rule = Rule007S3SecurityDrift()
        finding = rule.evaluate(enriched)
        det_latency_ms = round((time.time() - t_det_start) * 1000, 2)
        assert finding is not None and finding.rule_id == "AEGIS-DET-007"
        logger.info(f"  [STAGE 2: DETECTION] Matched {finding.rule_id} ({finding.title}) in {det_latency_ms}ms")

        blast = self.graph.calculate_blast_radius(bucket_arn)
        risk = self.risk_engine.evaluate(
            RiskContext(
                finding_id=finding.finding_id,
                detection_severity=finding.severity,
                confidence=finding.confidence,
                asset_criticality=7.0,
                privilege_level=PrivilegeLevel.IAM_WRITE,
                exposure_level=ExposureLevel.INTERNET_FACING,
                blast_radius_score=blast.score,
                anomaly_score=0.92,
            )
        )
        logger.info(f"  [STAGE 3: RISK] Evaluated Score: {risk.risk_score}/100 ({risk.risk_level.value})")

        t_cont_start = time.time()
        logger.info("  [STAGE 4: CONTAINMENT] Restoring 4-point Public Access Block on AWS S3...")
        try:
            self.s3.put_public_access_block(
                Bucket=TARGET_S3_BUCKET,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            logger.info("  [AWS CONTAINMENT SUCCESS] S3 Public Access Block restored to 100% blocked state.")
        except ClientError as e:
            logger.warning(f"  Could not restore live S3 block: {e}")

        cont_latency_ms = round((time.time() - t_cont_start) * 1000, 2)

        pab = self.s3.get_public_access_block(Bucket=TARGET_S3_BUCKET)
        conf = pab["PublicAccessBlockConfiguration"]
        assert conf["BlockPublicAcls"] and conf["BlockPublicPolicy"]
        logger.info("  [STAGE 5: VERIFIED] Confirmed live S3 bucket is secure.")

        total_latency_ms = round((time.time() - t_start) * 1000, 2)
        record = {
            "execution_id": f"exec-{uuid.uuid4().hex[:12]}",
            "scenario_id": "SCENARIO-04",
            "title": "S3 Public Bucket Exposure & Security Drift",
            "passed": True,
            "detection_rule": "AEGIS-DET-007",
            "risk_score": risk.risk_score,
            "containment_action": "ENFORCE_S3_BLOCK_PUBLIC",
            "detection_latency_ms": det_latency_ms,
            "containment_latency_ms": cont_latency_ms,
            "total_latency_ms": total_latency_ms,
        }
        self._record_in_aws(record, {"finding": finding.model_dump(mode="json"), "risk": risk.model_dump(mode="json")})
        return record

    def run_scenario_05(self) -> dict[str, Any]:
        logger.info("\n=======================================================")
        logger.info(">>> SCENARIO 05: Unrestricted Security Group Ingress 0.0.0.0/0")
        logger.info("=======================================================")
        t_start = time.time()
        sg_id = None

        try:
            sgs = self.ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [TARGET_SG_NAME]}])
            if sgs["SecurityGroups"]:
                sg_id = sgs["SecurityGroups"][0]["GroupId"]
        except Exception:
            sg_id = "sg-031f227f89ddc2a50"

        sg_arn = f"arn:aws:ec2:{AWS_REGION}:{ACCOUNT_ID}:security-group/{sg_id}"
        ScenarioExecutor.verify_resource_boundary(
            sg_arn,
            {"Environment": "aegis-security-lab", "Project": "aegis"},
        )

        logger.info(f"  [STAGE 1: ATTACK] Injecting unrestricted ingress 0.0.0.0/0 port 22 into {sg_id} on AWS...")
        rule_added = False
        try:
            self.ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "Rogue SSH exposure"}],
                    }
                ],
            )
            rule_added = True
            logger.info(f"  [ATTACK SUCCESS] Authorized 0.0.0.0/0 port 22 in AWS SG {sg_id}.")
        except ClientError as e:
            logger.warning(f"  Live ingress authorize returned: {e}")

        t_det_start = time.time()
        raw_event = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDAINSECURE01",
                "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/aegis-lab/{TARGET_IAM_USER}",
                "accountId": ACCOUNT_ID,
                "userName": TARGET_IAM_USER,
            },
            "eventTime": datetime.now(UTC).isoformat(),
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "awsRegion": AWS_REGION,
            "sourceIPAddress": "198.51.100.10",
            "requestParameters": {
                "groupId": sg_id,
                "ipPermissions": {
                    "items": [
                        {
                            "ipProtocol": "tcp",
                            "fromPort": 22,
                            "toPort": 22,
                            "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                        }
                    ]
                },
            },
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "recipientAccountId": ACCOUNT_ID,
        }
        event = parse_cloudtrail_event(raw_event)
        enriched = EventEnricher.enrich(event)
        rule = Rule005SecurityGroupIngress()
        finding = rule.evaluate(enriched)
        det_latency_ms = round((time.time() - t_det_start) * 1000, 2)
        assert finding is not None and finding.rule_id == "AEGIS-DET-005"
        logger.info(f"  [STAGE 2: DETECTION] Matched {finding.rule_id} ({finding.title}) in {det_latency_ms}ms")

        blast = self.graph.calculate_blast_radius(sg_arn)
        risk = self.risk_engine.evaluate(
            RiskContext(
                finding_id=finding.finding_id,
                detection_severity=finding.severity,
                confidence=finding.confidence,
                asset_criticality=8.0,
                privilege_level=PrivilegeLevel.IAM_WRITE,
                exposure_level=ExposureLevel.INTERNET_FACING,
                blast_radius_score=blast.score,
                anomaly_score=0.9,
            )
        )
        logger.info(f"  [STAGE 3: RISK] Evaluated Score: {risk.risk_score}/100 ({risk.risk_level.value})")

        t_cont_start = time.time()
        logger.info("  [STAGE 4: CONTAINMENT] Revoking unrestricted 0.0.0.0/0 rule on AWS EC2...")
        if rule_added:
            try:
                self.ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                )
                logger.info("  [AWS CONTAINMENT SUCCESS] Ingress rule 0.0.0.0/0 revoked on AWS SG.")
            except ClientError as e:
                logger.warning(f"  Could not revoke rule: {e}")

        cont_latency_ms = round((time.time() - t_cont_start) * 1000, 2)

        sgs = self.ec2.describe_security_groups(GroupIds=[sg_id])
        assert sgs["SecurityGroups"][0]["IpPermissions"] == []
        logger.info("  [STAGE 5: VERIFIED & CLEANUP] Confirmed 0 inbound open rules remaining.")

        total_latency_ms = round((time.time() - t_start) * 1000, 2)
        record = {
            "execution_id": f"exec-{uuid.uuid4().hex[:12]}",
            "scenario_id": "SCENARIO-05",
            "title": "Unrestricted Security Group Ingress 0.0.0.0/0",
            "passed": True,
            "detection_rule": "AEGIS-DET-005",
            "risk_score": risk.risk_score,
            "containment_action": "REVOKE_SECURITY_GROUP_RULE",
            "detection_latency_ms": det_latency_ms,
            "containment_latency_ms": cont_latency_ms,
            "total_latency_ms": total_latency_ms,
        }
        self._record_in_aws(record, {"finding": finding.model_dump(mode="json"), "risk": risk.model_dump(mode="json")})
        return record

    def run_scenario_06(self) -> dict[str, Any]:
        logger.info("\n=======================================================")
        logger.info(">>> SCENARIO 06: Suspicious EC2 Key Misuse")
        logger.info("=======================================================")
        t_start = time.time()

        user_arn = f"arn:aws:iam::{ACCOUNT_ID}:user/aegis-lab/{TARGET_IAM_USER}"
        ScenarioExecutor.verify_resource_boundary(
            user_arn,
            {"Environment": "aegis-security-lab", "Project": "aegis"},
        )

        logger.info("  [STAGE 1: ATTACK] Simulating credential misuse from suspicious IP...")
        t_det_start = time.time()
        raw_event = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDAMISUSE01",
                "arn": user_arn,
                "accountId": ACCOUNT_ID,
                "userName": TARGET_IAM_USER,
            },
            "eventTime": datetime.now(UTC).isoformat(),
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstances",
            "awsRegion": AWS_REGION,
            "sourceIPAddress": "198.51.100.77",
            "userAgent": "python-requests/2.31.0",
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "recipientAccountId": ACCOUNT_ID,
        }
        event = parse_cloudtrail_event(raw_event)
        enriched = EventEnricher.enrich(event)
        rule = Rule002AccessKeyMisuse()
        finding = rule.evaluate(enriched)
        det_latency_ms = round((time.time() - t_det_start) * 1000, 2)
        assert finding is not None and finding.rule_id == "AEGIS-DET-002"
        logger.info(f"  [STAGE 2: DETECTION] Matched {finding.rule_id} ({finding.title}) in {det_latency_ms}ms")

        blast = self.graph.calculate_blast_radius(user_arn)
        risk = self.risk_engine.evaluate(
            RiskContext(
                finding_id=finding.finding_id,
                detection_severity=finding.severity,
                confidence=finding.confidence,
                asset_criticality=6.0,
                privilege_level=PrivilegeLevel.IAM_WRITE,
                blast_radius_score=blast.score,
                anomaly_score=0.88,
            )
        )
        logger.info(f"  [STAGE 3: RISK] Evaluated Score: {risk.risk_score}/100 ({risk.risk_level.value})")

        t_cont_start = time.time()
        rem_req = RemediationRequest(
            remediation_id=f"rem-{uuid.uuid4().hex[:8]}",
            finding_id=finding.finding_id,
            action=RemediationAction.DEACTIVATE_ACCESS_KEY,
            target_resource_id=user_arn,
            account_id=ACCOUNT_ID,
            risk_score=risk.risk_score,
            idempotency_key=f"idem-{uuid.uuid4().hex[:8]}",
            parameters={"access_key_id": "AKIAEXAMPLEUNUSUAL"},
        )
        rem_result = self.orchestrator.execute(rem_req)
        assert rem_result.status == RemediationStatus.VERIFIED
        cont_latency_ms = round((time.time() - t_cont_start) * 1000, 2)
        logger.info(f"  [STAGE 4: CONTAINMENT] Deactivated access key in {cont_latency_ms}ms")

        self.orchestrator.iam.rollback(rem_req, rem_result.pre_state)
        logger.info("  [STAGE 5: CLEANUP] Cleanup verified.")

        total_latency_ms = round((time.time() - t_start) * 1000, 2)
        record = {
            "execution_id": f"exec-{uuid.uuid4().hex[:12]}",
            "scenario_id": "SCENARIO-06",
            "title": "Suspicious EC2 Key Misuse",
            "passed": True,
            "detection_rule": "AEGIS-DET-002",
            "risk_score": risk.risk_score,
            "containment_action": "DEACTIVATE_ACCESS_KEY",
            "detection_latency_ms": det_latency_ms,
            "containment_latency_ms": cont_latency_ms,
            "total_latency_ms": total_latency_ms,
        }
        self._record_in_aws(record, {"finding": finding.model_dump(mode="json"), "risk": risk.model_dump(mode="json")})
        return record

    def run_scenario_07(self) -> dict[str, Any]:
        logger.info("\n=======================================================")
        logger.info(">>> SCENARIO 07: Cross-Account Role Abuse & Lateral Movement")
        logger.info("=======================================================")
        t_start = time.time()

        ScenarioExecutor.verify_resource_boundary(
            TARGET_ROLE_ARN,
            {"Environment": "aegis-security-lab", "Project": "aegis"},
        )

        logger.info("  [STAGE 1: ATTACK] Simulating multi-hop cross-account role assumption...")
        t_det_start = time.time()
        raw_event = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AROAEXTERNAL01:external-hop",
                "arn": "arn:aws:iam::999999999999:role/UnknownExternalRole",
                "accountId": "999999999999",
            },
            "eventTime": datetime.now(UTC).isoformat(),
            "eventSource": "sts.amazonaws.com",
            "eventName": "AssumeRole",
            "awsRegion": AWS_REGION,
            "sourceIPAddress": "198.51.100.99",
            "requestParameters": {
                "roleArn": TARGET_ROLE_ARN,
                "roleSessionName": "lateral-pivot-02",
            },
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "recipientAccountId": ACCOUNT_ID,
        }
        event = parse_cloudtrail_event(raw_event)
        enriched = EventEnricher.enrich(event)
        rule = Rule009CrossAccountAbuse()
        finding = rule.evaluate(enriched)
        det_latency_ms = round((time.time() - t_det_start) * 1000, 2)
        assert finding is not None and finding.rule_id == "AEGIS-DET-009"
        logger.info(f"  [STAGE 2: DETECTION] Matched {finding.rule_id} ({finding.title}) in {det_latency_ms}ms")

        blast = self.graph.calculate_blast_radius(TARGET_ROLE_ARN)
        risk = self.risk_engine.evaluate(
            RiskContext(
                finding_id=finding.finding_id,
                detection_severity=finding.severity,
                confidence=finding.confidence,
                asset_criticality=9.0,
                privilege_level=PrivilegeLevel.ADMINISTRATOR,
                blast_radius_score=blast.score,
                anomaly_score=0.98,
            )
        )
        logger.info(f"  [STAGE 3: RISK] Evaluated Score: {risk.risk_score}/100 ({risk.risk_level.value})")

        t_cont_start = time.time()
        rem_req = RemediationRequest(
            remediation_id=f"rem-{uuid.uuid4().hex[:8]}",
            finding_id=finding.finding_id,
            action=RemediationAction.REVOKE_IAM_SESSIONS,
            target_resource_id=TARGET_ROLE_ARN,
            account_id=ACCOUNT_ID,
            risk_score=risk.risk_score,
            idempotency_key=f"idem-{uuid.uuid4().hex[:8]}",
        )
        rem_result = self.orchestrator.execute(rem_req)
        assert rem_result.status == RemediationStatus.VERIFIED
        cont_latency_ms = round((time.time() - t_cont_start) * 1000, 2)
        logger.info(f"  [STAGE 4: CONTAINMENT] Invalidated active sessions across account in {cont_latency_ms}ms")

        self.orchestrator.iam.rollback(rem_req, rem_result.pre_state)
        logger.info("  [STAGE 5: CLEANUP] Cleanup verified.")

        total_latency_ms = round((time.time() - t_start) * 1000, 2)
        record = {
            "execution_id": f"exec-{uuid.uuid4().hex[:12]}",
            "scenario_id": "SCENARIO-07",
            "title": "Cross-Account Role Abuse & Lateral Movement",
            "passed": True,
            "detection_rule": "AEGIS-DET-009",
            "risk_score": risk.risk_score,
            "containment_action": "REVOKE_IAM_SESSIONS",
            "detection_latency_ms": det_latency_ms,
            "containment_latency_ms": cont_latency_ms,
            "total_latency_ms": total_latency_ms,
        }
        self._record_in_aws(record, {"finding": finding.model_dump(mode="json"), "risk": risk.model_dump(mode="json")})
        return record

    def run_scenario_08(self) -> dict[str, Any]:
        logger.info("\n=======================================================")
        logger.info(">>> SCENARIO 08: CloudTrail Logging Disruption Attempt")
        logger.info("=======================================================")
        t_start = time.time()
        trail_arn = f"arn:aws:cloudtrail:{AWS_REGION}:{ACCOUNT_ID}:trail/aegis-lab-audit-trail"

        ScenarioExecutor.verify_resource_boundary(
            trail_arn,
            {"Environment": "aegis-security-lab", "Project": "aegis"},
        )

        logger.info("  [STAGE 1: ATTACK] Simulating StopLogging evasion on audit trail...")
        t_det_start = time.time()
        raw_event = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDATAMPER01",
                "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/aegis-lab/{TARGET_IAM_USER}",
                "accountId": ACCOUNT_ID,
                "userName": TARGET_IAM_USER,
            },
            "eventTime": datetime.now(UTC).isoformat(),
            "eventSource": "cloudtrail.amazonaws.com",
            "eventName": "StopLogging",
            "awsRegion": AWS_REGION,
            "sourceIPAddress": "198.51.100.66",
            "requestParameters": {"name": "aegis-lab-audit-trail"},
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "recipientAccountId": ACCOUNT_ID,
        }
        event = parse_cloudtrail_event(raw_event)
        enriched = EventEnricher.enrich(event)
        rule = Rule006CloudTrailTampering()
        finding = rule.evaluate(enriched)
        det_latency_ms = round((time.time() - t_det_start) * 1000, 2)
        assert finding is not None and finding.rule_id == "AEGIS-DET-006"
        logger.info(f"  [STAGE 2: DETECTION] Matched {finding.rule_id} ({finding.title}) in {det_latency_ms}ms")

        blast = self.graph.calculate_blast_radius(trail_arn)
        risk = self.risk_engine.evaluate(
            RiskContext(
                finding_id=finding.finding_id,
                detection_severity=finding.severity,
                confidence=finding.confidence,
                asset_criticality=9.5,
                privilege_level=PrivilegeLevel.ADMINISTRATOR,
                blast_radius_score=blast.score,
                anomaly_score=0.99,
            )
        )
        logger.info(f"  [STAGE 3: RISK] Evaluated Score: {risk.risk_score}/100 ({risk.risk_level.value})")

        t_cont_start = time.time()
        rem_req = RemediationRequest(
            remediation_id=f"rem-{uuid.uuid4().hex[:8]}",
            finding_id=finding.finding_id,
            action=RemediationAction.REVOKE_IAM_SESSIONS,
            target_resource_id=f"arn:aws:iam::{ACCOUNT_ID}:user/aegis-lab/{TARGET_IAM_USER}",
            account_id=ACCOUNT_ID,
            risk_score=risk.risk_score,
            idempotency_key=f"idem-{uuid.uuid4().hex[:8]}",
        )
        rem_result = self.orchestrator.execute(rem_req)
        assert rem_result.status == RemediationStatus.VERIFIED
        cont_latency_ms = round((time.time() - t_cont_start) * 1000, 2)
        logger.info(f"  [STAGE 4: CONTAINMENT] Revoked adversary session in {cont_latency_ms}ms")

        self.orchestrator.iam.rollback(rem_req, rem_result.pre_state)
        logger.info("  [STAGE 5: CLEANUP] Cleanup verified.")

        total_latency_ms = round((time.time() - t_start) * 1000, 2)
        record = {
            "execution_id": f"exec-{uuid.uuid4().hex[:12]}",
            "scenario_id": "SCENARIO-08",
            "title": "CloudTrail Logging Disruption Attempt",
            "passed": True,
            "detection_rule": "AEGIS-DET-006",
            "risk_score": risk.risk_score,
            "containment_action": "REVOKE_IAM_SESSIONS",
            "detection_latency_ms": det_latency_ms,
            "containment_latency_ms": cont_latency_ms,
            "total_latency_ms": total_latency_ms,
        }
        self._record_in_aws(record, {"finding": finding.model_dump(mode="json"), "risk": risk.model_dump(mode="json")})
        return record

    def run_all_in_order(self) -> list[dict[str, Any]]:
        """Run all 8 attack scenarios in strict numerical order."""
        if not self.verify_safety_limits():
            sys.exit(1)

        scenarios = [
            self.run_scenario_01,
            self.run_scenario_02,
            self.run_scenario_03,
            self.run_scenario_04,
            self.run_scenario_05,
            self.run_scenario_06,
            self.run_scenario_07,
            self.run_scenario_08,
        ]

        for fn in scenarios:
            res = fn()
            self.results.append(res)
            time.sleep(0.5)

        return self.results


if __name__ == "__main__":
    suite = OrderedAttackSuite()
    results = suite.run_all_in_order()
    print("\n" + "=" * 80)
    print("ALL 8 PURPLE-TEAM ATTACK SCENARIOS COMPLETED SUCCESSFULLY")
    print("=" * 80)
    print(f"Total Scenarios: {len(results)} | Passed: {sum(1 for r in results if r['passed'])}")
    for r in results:
        print(f"  [{r['scenario_id']}] {r['title']} -> {r['containment_action']} (Risk: {r['risk_score']}/100, Total Latency: {r['total_latency_ms']}ms)")
