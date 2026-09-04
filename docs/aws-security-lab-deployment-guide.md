# Project AEGIS — AWS Continuous Security Lab Deployment Guide & Operations Manual

## 1. Overview & Objective

This guide details how to deploy the completed Project AEGIS ecosystem into an isolated **AWS Security Lab** environment.

Once deployed, the system operates **100% autonomously inside AWS**:
- You can **completely shut down your laptop** for hours or days.
- Amazon EventBridge Scheduler and AWS Step Functions continuously execute controlled Phase-13 Purple-Team attack scenarios every 15 minutes.
- Real-time telemetry is ingested, evaluated by deterministic detection rules, analyzed for reachability in the attack-path graph, and scored by the explainable risk engine.
- Automated, idempotent containment playbooks execute via Step Functions with post-execution verification.
- Every run seals an immutable, cryptographically hashed SHA-256 evidence manifest into the S3 Forensics Vault (WORM Compliance Mode).
- All empirical metrics (P50, P95, P99 latencies, detection rates, containment success rates) are streamed to Amazon CloudWatch and DynamoDB.

---

## 2. Architecture & Control Flow

```
[Amazon EventBridge Scheduler: rate(15 minutes)]
                   │
                   ▼
       [Check Kill Switch & Quotas] ──(Tripped / Exceeded)──► [Halt & Publish SNS Alert]
                   │ (Passed)
                   ▼
      [Select Next Scenario (01-08)]
                   │
                   ▼
    [Validate Target Resource Tags] ──(Missing Lab Tag)──► [ABORT: Boundary Violation]
                   │ (Tag: Environment=aegis-security-lab)
                   ▼
     [Execute Lab Threat Simulation] (e.g. Generate Key, Alter SG Rule, Test S3 Bucket)
                   │
                   ▼
       [Await Telemetry Ingestion] (CloudTrail / GuardDuty -> Kinesis / EventBridge)
                   │
                   ▼
       [Verify Detection Engine Rule] (Poll DynamoDB Incident Table, Timeout: 30s)
                   │
                   ▼
       [Verify Risk & Blast Radius] (Calculate 6-Factor Score & Graph Reachability)
                   │
                   ▼
      [Verify Automated Containment] (Step Functions SOAR Action Confirmed)
                   │
                   ▼
      [Rollback & Cleanup Lab Target] (Delete Test Key, Restore SG, Enforce S3 Public Block)
                   │
                   ▼
       [Seal Forensic Evidence WORM] (Upload Signed Manifest to S3 Object Lock Vault)
                   │
                   ▼
        [Publish CloudWatch Metrics] (P50/P95/P99, Latency, PASS/FAIL Records)
```

---

## 3. Strict Security Lab Boundary Guardrails

The Security Lab operates under **three zero-trust isolation boundaries**:

1. **Tag-Enforced Execution Boundary**:
   Every Lambda that interacts with target resources enforces:
   - Target resource MUST possess tag: `Environment = "aegis-security-lab"`.
   - Target resource MUST possess tag: `Project = "aegis"`.
   - Target resource MUST NOT contain substrings: `:root`, `admin`, `prod-`, or `production`.
   - If any condition is violated, the executor immediately raises `SecurityBoundaryViolation` and aborts.

2. **Dedicated Isolated Lab Target Resources**:
   The module provisions dedicated, disposable test assets:
   - `aws_iam_user.lab_test_user`: Path `/aegis-lab/` strictly for key compromise simulations.
   - `aws_iam_role.lab_test_role`: Path `/aegis-lab/` for assume-role simulations.
   - `aws_s3_bucket.lab_test_bucket`: Prefix `aegis-lab-target-` with public access block for drift testing.
   - `aws_security_group.lab_test_sg`: Isolated security group for ingress opening testing.

3. **Least-Privilege Execution IAM Policy**:
   The orchestrator IAM role includes an explicit IAM condition:
   ```json
   "Condition": {
     "StringEquals": {
       "aws:ResourceTag/Environment": "aegis-security-lab"
     }
   }
   ```
   Even if misconfigured, AWS IAM will physically deny any API call targeting resources outside the lab boundary.

---

## 4. Cost Management: DEMO vs. FULL Mode

| Resource | DEMO Mode *(Default)* | FULL Mode |
|---|---|---|
| **Architecture** | Pure Serverless (Lambda, DynamoDB On-Demand, S3, EventBridge, Step Functions) | Adds Amazon Neptune Serverless + SageMaker Serverless Inference |
| **Neptune Graph** | In-memory graph reachability evaluated in Lambda memory ($0.00) | 1.0 min NCU Serverless cluster (~$2.40/day) |
| **SageMaker Anomaly** | Statistical Gaussian centroid evaluated in Lambda memory ($0.00) | Serverless Inference endpoint (~$0.50–$1.20/day) |
| **Kinesis Data Streams** | On-Demand mode (~$0.20/day baseline) | On-Demand mode (~$0.20/day baseline) |
| **Step Functions & Lambda** | ~$0.15/day (4 runs/hour = 96 runs/day) | ~$0.20/day |
| **Total Daily Cost** | **~$0.40 / day (~$12.00 / month)** | **~$3.40 / day (~$102.00 / month)** |

> **Recommendation**: Deploy in `DEMO` mode for initial continuous testing. It proves the complete 7-stage detection, containment, forensics, and latency reporting at negligible cost.

---

## 5. Deployment Guide (Step-by-Step)

### Step 1: Pre-Deployment Validation
Run local verification commands to confirm syntax and test integrity:
```powershell
# 1. Run full unit test suite (110/110 passing)
.\.venv\Scripts\pytest.exe -q

# 2. Check code formatting and linter
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\ruff.exe format --check .

# 3. Validate Terraform syntax across all modules
terraform fmt -check -recursive terraform/
cd terraform/environments/security_lab
terraform init -backend=false
terraform validate
cd ../../..
```

### Step 2: Configure Deployment Variables
Navigate to the security lab environment directory and configure variables:
```powershell
cd terraform/environments/security_lab
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:
```hcl
aws_region                 = "us-east-1"
project_name               = "aegis"
environment                = "security-lab"
deployment_mode            = "DEMO"
scheduler_interval_minutes = 15
```

### Step 3: Terraform Plan Review
Generate an execution plan to verify planned cloud changes:
```powershell
terraform plan -out=security-lab.tfplan
```
Review the output to ensure all target resources, IAM roles, Step Functions state machines, and DynamoDB tables match the expected definitions.

### Step 4: Terraform Apply Execution
Execute the deployment when ready:
```powershell
terraform apply security-lab.tfplan
```

---

## 6. Remote Control & Operations Manual (Laptop OFF)

Once deployed, you can manage the lab remotely via AWS CLI or AWS Console:

### 1. View Continuous Execution History & Latencies
```bash
aws dynamodb scan \
  --table-name aegis-lab-executions-security-lab \
  --query "Items[*].[scenario_id.S, status.S, detection_latency_seconds.N, containment_latency_seconds.N]" \
  --output table
```

### 2. Check the Kill Switch Status
```bash
aws dynamodb get-item \
  --table-name aegis-lab-config-security-lab \
  --key '{"config_key": {"S": "SAFETY_GATE"}}'
```

### 3. Emergency Kill Switch Activation (Trip the Switch)
To immediately halt all autonomous simulations:
```bash
aws dynamodb update-item \
  --table-name aegis-lab-config-security-lab \
  --key '{"config_key": {"S": "SAFETY_GATE"}}' \
  --update-expression "SET global_kill_switch = :status" \
  --expression-attribute-values '{":status": {"S": "TRIPPED"}}'
```

### 4. Resume Autonomous Simulations (Reset the Switch)
```bash
aws dynamodb update-item \
  --table-name aegis-lab-config-security-lab \
  --key '{"config_key": {"S": "SAFETY_GATE"}}' \
  --update-expression "SET global_kill_switch = :status, aegis_lab_enabled = :enabled" \
  --expression-attribute-values '{":status": {"S": "ENABLED"}, ":enabled": {"BOOL": true}}'
```

### 5. Inspect Forensics Evidence Manifests in S3 Object Lock Vault
```bash
aws s3 ls s3://aegis-forensics-vault-<account-id>/lab-evidence/
```
Download and view any sealed cryptographic manifest:
```bash
aws s3 cp s3://aegis-forensics-vault-<account-id>/lab-evidence/<execution-id>.json - | jq .
```

---

## 7. Teardown / Destruction Procedure

When your testing or portfolio demonstration is complete, destroy the resources to eliminate ongoing costs:

```powershell
cd terraform/environments/security_lab
terraform destroy -auto-approve
```

> [!NOTE]
> The S3 Forensics Vault bucket has S3 Object Lock enabled. Any evidence objects under legal hold or compliance retention must have their retention period expire before the bucket itself can be deleted.
