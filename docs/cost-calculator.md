# AEGIS Cloud Infrastructure Cost Model & Calculator Guide

## Executive Overview

Understanding the Total Cost of Ownership (TCO) is essential before deploying active cloud defense infrastructure. While traditional third-party SIEM/SOAR vendors charge exorbitant per-gigabyte licensing fees ($1,500 – $4,000 / TB ingested), **Project AEGIS is 100% cloud-native**, running strictly on AWS pay-as-you-go infrastructure with zero vendor license markups.

This document breaks down the cost model and compares the **Enterprise Full Multi-Account Architecture** against the **AEGIS Lite Architecture**.

---

## 1. Line-Item Cost Architecture

| AWS Service | Enterprise Full Architecture | AEGIS Lite Architecture | Billing Driver |
| :--- | :--- | :--- | :--- |
| **Telemetry Ingestion** | Amazon Kinesis Data Streams (On-demand/Provisioned) | Amazon SQS FIFO Queues | Shard hours + payload PUT units |
| **Stream Processing** | AWS Lambda (Arm64 Graviton3) | AWS Lambda (Arm64 Graviton3) | Compute GB-seconds + invocations |
| **Attack-Path Graph** | Amazon Neptune Serverless (1.0–2.5 NCU) | DynamoDB Single-Table Graph Store | Neptune Capacity Units vs Dynamo reads/writes |
| **Behavioral ML** | Amazon SageMaker Serverless Inference | In-Process Centroid Scorer in Lambda | Compute seconds vs zero extra cost |
| **SOAR Orchestration** | AWS Step Functions (Standard Workflows) | AWS Step Functions (Express Workflows) | State transitions vs execution duration |
| **Forensic Evidence** | Amazon S3 Object Lock (Compliance Mode) | Amazon S3 Object Lock (Compliance Mode) | Storage GB-months + PUT API calls |
| **Key Management** | Dedicated Customer-Managed KMS Keys (CMK) | Single Multi-Region KMS Key | $1/key/month + cryptographic operations |

---

## 2. Monthly Spend Projections Across Scale

The following projections are derived from empirical telemetry runs:

### Scenario A: Minimal Staging / Lab Environment (50 events/sec)
*Ideal for security testing, CI/CD validation, and purple-team training.*
- **Enterprise Full Architecture**: **~$72 / month**
  - Neptune Serverless base (1.0 NCU): $73.00
  - Kinesis (1 shard): $11.20
  - Lambda + S3 + KMS: $8.50
- **AEGIS Lite Architecture**: **~$18 / month**
  - DynamoDB Pay-per-request: $3.20
  - SQS: $1.80
  - S3 + Lambda + KMS: $13.00
- **Net Savings**: **75% reduction**

### Scenario B: Mid-Market Workload (1,000 events/sec, 3 Accounts)
*Standard enterprise footprint (~2.6 billion events/month, ~3.7 TB ingested).*
- **Enterprise Full Architecture**: **~$1,400 – $1,800 / month**
- **AEGIS Lite Architecture**: **~$650 – $900 / month**

### Scenario C: High-Volume Production (10,000 events/sec, 10 Accounts)
*Large-scale corporate estate (~26 billion events/month).*
- Enterprise Full is strongly recommended at this volume to utilize Neptune's sub-second graph traversal algorithms across multi-hop lateral movement chains.

---

## 3. Running the Interactive Cost Calculator CLI

The CLI tool allows you to forecast exact monthly bills for your anticipated throughput:

```bash
# Calculate spend for 500 events/sec across 2 accounts with 90-day retention
python scripts/cost_calculator.py --rate 500 --accounts 2 --retention 90

# Output machine-readable JSON for automated budgeting pipelines
python scripts/cost_calculator.py --rate 2500 --accounts 5 --json
```
