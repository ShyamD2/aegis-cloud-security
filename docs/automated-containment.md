# Automated Incident Response & Self-Healing Containment
## Project AEGIS - Phase 10 Architecture & Technical Specification

```
                   ┌─────────────────────────────────────────┐
                   │       Verified Finding & Risk Score     │
                   └────────────────────┬────────────────────┘
                                        │
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │     Amazon EventBridge Rule Bus         │
                   └────────────────────┬────────────────────┘
                                        │
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │       AWS Step Functions Orchestrator   │
                   │    (DynamoDB Idempotency Gated)         │
                   └────────────────────┬────────────────────┘
                                        │
             ┌──────────────────────────┼──────────────────────────┐
             ▼                          ▼                          ▼
     [Score < 50.0]             [50.0 <= S < 75.0]           [Score >= 75.0]
     ┌─────────────┐            ┌─────────────────┐        ┌─────────────────┐
     │  Log Only   │            │ Security Team   │        │ Autonomous      │
     │  No Action  │            │ Approval Gate   │        │ Containment     │
     └─────────────┘            └─────────────────┘        └────────┬────────┘
                                                                    │
                     ┌──────────────────────┬───────────────────────┼──────────────────────┐
                     ▼                      ▼                       ▼                      ▼
             ┌──────────────┐       ┌──────────────┐        ┌──────────────┐       ┌──────────────┐
             │ IAMRemediator│       │ EC2Remediator│        │ S3Remediator │       │AccountQuaran.│
             └──────┬───────┘       └──────┬───────┘        └──────┬───────┘       └──────┬───────┘
                    │                      │                       │                      │
                    └──────────────────────┼───────────────────────┴──────────────────────┘
                                           │
                                           ▼
                            ┌─────────────────────────────┐
                            │  Post-Action Verification   │
                            └──────────────┬──────────────┘
                                           │
                        ┌──────────────────┴──────────────────┐
                        ▼                                     ▼
                 [Verification PASS]                  [Verification FAIL]
             ┌─────────────────────────┐         ┌─────────────────────────┐
             │ Evidence Recorded to S3 │         │ Immediate Auto-Rollback │
             │   & Incident Closed     │         │   & Security PagerDuty  │
             └─────────────────────────┘         └─────────────────────────┘
```

---

### 1. Specialized Remediators & Least Privilege

AEGIS strictly rejects the anti-pattern of deploying a monolithic "Administrator Lambda" with broad cloud write privileges. Every remediation component executes under its own dedicated, minimal IAM policy:

| Remediator | Target Resource | Permitted IAM Actions | Prohibited Actions |
| :--- | :--- | :--- | :--- |
| **IAMRemediator** | IAM Users & Roles | `iam:UpdateAccessKey`, `iam:Put*Policy`, `iam:Delete*Policy`, `iam:Get*Policy` | `iam:Create*`, `iam:AttachUserPolicy`, `iam:*` |
| **EC2Remediator** | EC2 Instances | `ec2:DescribeInstances`, `ec2:ModifyInstanceAttribute`, `ec2:DescribeSecurityGroups`, `ec2:CreateSnapshot` | `ec2:TerminateInstances`, `ec2:DeleteVolume`, `ec2:StopInstances` |
| **S3Remediator** | S3 Buckets | `s3:GetBucketPolicy`, `s3:PutBucketPolicy`, `s3:GetBucketPublicAccessBlock`, `s3:PutBucketPublicAccessBlock` | `s3:DeleteBucket`, `s3:DeleteObject*` |
| **AccountQuarantine**| AWS Accounts | `organizations:AttachPolicy`, `organizations:DetachPolicy`, `organizations:ListPoliciesForTarget` | `organizations:Delete*`, `organizations:Leave*` |

---

### 2. STS Session Revocation: Realities & Limitations

> [!IMPORTANT]
> **AWS STS does NOT support instantaneous cryptographic deletion of already-issued session tokens.**
>
> 1. AWS SigV4 temporary credentials (such as those minted via `sts:AssumeRole` or `sts:GetSessionToken`) are cryptographically self-contained. The AWS authentication infrastructure validates them statelessly against the HMAC signature without maintaining a central revocation list of issued tokens.
> 2. **AEGIS Implementation**: To reliably contain compromised sessions, `IAMRemediator` applies an inline policy with an explicit `Deny` conditioned on `aws:TokenIssueTime`:
>    ```json
>    {
>      "Version": "2012-10-17",
>      "Statement": [
>        {
>          "Sid": "AEGISDenyOlderSessions",
>          "Effect": "Deny",
>          "Action": "*",
>          "Resource": "*",
>          "Condition": {
>            "DateLessThan": {
>              "aws:TokenIssueTime": "2026-09-04T12:00:00Z"
>            }
>          }
>        }
>      ]
>    }
>    ```
> 3. Any API request signed with a temporary token minted *before* the cutoff timestamp is rejected by the AWS authorization engine during policy evaluation, achieving complete containment.

---

### 3. Idempotency & Distributed Race Condition Prevention

All remediation requests must contain an `idempotency_key` (derived as `sha256(finding_id + action + target_arn)`).

1. Before invoking containment, `IdempotencyStore` attempts an atomic write to DynamoDB:
   ```python
   dynamodb.put_item(
       TableName="aegis-remediation-idempotency",
       Item={
           "idempotency_key": {"S": idempotency_key},
           "status": {"S": "IN_PROGRESS"},
           "ttl": {"N": str(now + 3600)},
       },
       ConditionExpression="attribute_not_exists(idempotency_key)",
   )
   ```
2. If another worker or Step Functions branch is processing the same finding, the conditional write fails, preventing duplicate containment actions, conflicting rollbacks, and race conditions.

---

### 4. Non-Destructive Containment & Reversibility

AEGIS enforces non-destructive self-healing:
- **Zero Resource Deletion**: Instances are isolated to a quarantine security group, not terminated; S3 buckets have Block Public Access applied, not emptied or deleted.
- **State Capture**: Every remediator records the exact pre-remediation resource configuration in `pre_state`.
- **Post-Action Verification**: Immediately following containment, the remediator queries the AWS API to independently verify that the quarantine state is active.
- **Automated Rollback**: If post-verification fails or encounters unexpected errors, the orchestrator triggers `rollback()`, restoring `pre_state` and alerting the SOC.
