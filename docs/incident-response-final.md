# Project AEGIS - Incident Response & Autonomous Self-Healing Runbook
## End-to-End Playbooks, Containment Workflows & Cryptographic Verification Framework

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                    AEGIS Incident Response Lifecycle                    │
  │                                                                         │
  │  [DETECTION] ──► [BLAST RADIUS] ──► [RISK GATING] ──► [CONTAINMENT]     │
  │                                                              │          │
  │  [EVIDENCE SEAL] ◄── [TIMELINE] ◄── [ROLLBACK] ◄── [VERIFY] ◄┘          │
  └─────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Executive Summary

Project AEGIS replaces manual, high-latency security runbooks with deterministic, verified autonomous self-healing. When a security finding breaches the defined risk threshold ($\text{Score} \ge 50.0$), the incident response state machine dispatches targeted, least-privilege remediators to neutralize the threat in under 1.5 seconds.

Every containment action is:
1. **Idempotent**: Protected by distributed DynamoDB locks to prevent duplicate mutations.
2. **Verified**: The system queries the target resource post-mutation to confirm the remediation succeeded.
3. **Reversible**: Pre-remediation state is captured, enabling automated rollback if post-verification fails or if an operator initiates an authorized rollback.
4. **Sealed**: Telemetry, state snapshots, and timelines are packaged into an immutable SHA-256 evidence manifest.

---

## 2. Specialized Playbook Matrix (Scenarios 01 – 08)

| Playbook | Attack Category | Detection Rule | Target Resource | Automated Containment Action | Rollback Mechanism |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **PB-01** | IAM Key Compromise | `AEGIS-DET-001` | Compromised IAM User | `DEACTIVATE_ACCESS_KEY` via `iam:UpdateAccessKey` | Re-enables access key if confirmed benign. |
| **PB-02** | Suspicious AssumeRole | `AEGIS-DET-003` | Workload IAM Role | `REVOKE_IAM_SESSIONS` via inline `aws:TokenIssueTime` condition policy | Deletes inline revocation policy to restore sessions. |
| **PB-03** | Privilege Escalation | `AEGIS-DET-004` | Escalated Identity | Detaches `AdministratorAccess` policy & revokes active sessions | Re-attaches approved baseline policy. |
| **PB-04** | S3 Public Exposure | `AEGIS-DET-007` | Production S3 Bucket | `ENFORCE_S3_BLOCK_PUBLIC` across all 4 protection flags | Restores pre-state PAB configuration if authorized. |
| **PB-05** | Dangerous SG Ingress | `AEGIS-DET-005` | Exposed EC2 Security Group | Swaps attached SGs to zero-ingress `aegis-quarantine-sg` | Restores original security group IDs. |
| **PB-06** | Atypical Key Misuse | `AEGIS-DET-002` | Unverified Scripting Identity | Inactivates access key & alerts SOC for origin verification | Re-activates access key post-investigation. |
| **PB-07** | Cross-Account Abuse | `AEGIS-DET-009` | Target Production Role | Invalidates cross-account session tokens & updates trust policy | Restores verified trust relationship. |
| **PB-08** | Audit Trail Disruption | `AEGIS-DET-006` | Organization Trail | Calls `cloudtrail:StartLogging` & revokes acting principal's sessions | Maintains logging continuously; sessions restored post-triage. |

---

## 3. High-Impact Approval Gates (Account Quarantine)

While low-blast-radius containment actions (deactivating access keys, restoring S3 block public access, network isolating instances) execute autonomously, destructive actions such as **Account Quarantine** require explicit Human-in-the-Loop (HITL) authorization:

1. **State Machine Hold**: Step Functions enters `WaitForApproval` task state.
2. **War Room Notification**: A high-priority incident card is rendered in the SOC dashboard with the attack chain visualizer.
3. **Cognito RBAC Gate**: Only operators with the `SecurityLead` or `CISO` Cognito role can approve account quarantine.
4. **Execution**: Upon signed approval, the account remediator attaches the `AEGIS-AccountQuarantine-SCP` to isolate all outbound and cross-account traffic.

---

## 4. Post-Remediation Verification & Rollback Flow

```python
# Conceptual Execution Flow in RemediationOrchestrator
result = remediator.remediate(request)

if not result.verified and result.pre_state:
    logger.warning("Verification failed. Initiating automatic rollback.")
    remediator.rollback(request, result.pre_state)
    result.status = RemediationStatus.ROLLED_BACK
```

1. **Snapshot Pre-State**: Remediator captures exact resource attributes before applying mutations (e.g. current attached SG IDs, bucket PAB settings, access key status).
2. **Apply Mutation**: Executes scoped AWS API mutation.
3. **Post-Query Verification**: Queries AWS API directly to verify state transitioned to the desired security invariant.
4. **Automatic Rollback**: If verification times out or returns unexpected state, the remediator automatically applies the pre-state snapshot to prevent half-baked or broken configurations.
