# AEGIS Cost Model & Financial Guardrails
## Infrastructure Cost Estimation, Lab Optimization & Teardown Guidelines

### 1. Cost Management Philosophy

Security engineering must not ignore financial reality. Running high-end AWS services permanently (e.g., Neptune multi-AZ clusters, SageMaker multi-model endpoints, OpenSearch clusters, AWS Network Firewall) can cost thousands of dollars per month.

AEGIS implements a **tier-based cost architecture**:
- **Lab / Portfolio Mode**: Uses single-AZ, serverless, scale-to-zero, and on-demand configurations where possible. Synthetic data tests run on ephemeral resources that are torn down after validation.
- **Enterprise Production Mode**: Scaled-out, multi-AZ, provisioned capacity with strict reserved instances.

---

### 2. Estimated Service Cost Breakdown

| Component / Service | Lab / Portfolio Tier (Monthly Est.) | Production Enterprise Tier (Monthly Est.) | Cost Optimization Tactic |
|---|---|---|---|
| **AWS CloudTrail** | Free (first copy of management events) | ~$20 - $100 (multi-account data events) | Ingest only security-relevant management & data events |
| **Amazon S3** | < $2.00 | $15 - $50 | S3 Intelligent-Tiering, lifecycle rules to Glacier after 90 days |
| **Amazon Kinesis Data Streams** | ~$1.50 (On-Demand mode) | $30 - $150 (Provisioned shards) | Use On-Demand capacity mode during development |
| **AWS Lambda** | < $1.00 (within free tier) | $10 - $40 | Fine-tune memory allocation, optimize cold start times |
| **Amazon DynamoDB** | < $1.00 (On-Demand pay-per-request) | $15 - $50 | On-Demand capacity, aggressive TTL expiration on lock table |
| **AWS KMS** | $3.00 (3 CMKs @ $1/mo) | $20 - $50 | Reuse CMKs per domain, KMS data key caching in SDK |
| **Amazon Neptune** | ~$0 (Tear down after tests) or $80/mo (db.t3.medium) | $350+ (Multi-AZ db.r5.large) | Provision on-demand for attack-path testing; destroy via script |
| **Amazon SageMaker** | ~$0 (Serverless Inference) | $200+ (Real-time GPU endpoint) | Deploy Serverless Inference endpoints with 0 min instances |
| **Amazon GuardDuty** | Free tier (30 days) then ~$5/mo (lab volume) | $100 - $500 | Filter VPC flow log analysis to active security subnets |
| **AWS Security Hub** | Free tier (30 days) then ~$3/mo | $50 - $200 | Centralized finding aggregation |
| **Total Estimated Cost** | **$10 - $20/month** (with Neptune destroyed) | **$800 - $1,500/month** | **Automated lab shutdown scripts enforce low cost** |

---

### 3. Lab Teardown & Cost Guardrails

1. **AWS Budgets Alert**: Every environment provisions an AWS Budget with alarms at \$20, \$50, and \$100 thresholds sending SMS/email notifications.
2. **Ephemeral Attack Lab**: The attack simulation lab is managed by Terraform workspace `lab`. After purple-team test execution (Phase 13), resources are destroyed via `terraform destroy -target=module.attack_lab`.
3. **Neptune & SageMaker Auto-Pause**: In non-production environments, Lambda functions triggered by CloudWatch event rules stop or delete expensive Neptune instances during off-hours (00:00 to 07:00 UTC).
