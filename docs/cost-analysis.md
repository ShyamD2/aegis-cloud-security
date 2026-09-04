# Project AEGIS - Cloud Financial Engineering & Cost Analysis
## Phase 16 Specification: FinOps Architecture, AWS Service Breakdown & Multi-Tier Modeling

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                   AEGIS Monthly Cloud Expenditure Model                 │
  │                                                                         │
  │  [Startup Tier]       1M Events/Mo   ──► $68.42/mo   ($68.42 / M)       │
  │  [Enterprise Tier]    50M Events/Mo  ──► $482.15/mo  ($9.64 / M)        │
  │  [Hyperscale Tier]   500M Events/Mo  ──► $2,845.60/mo ($5.69 / M)       │
  │                                                                         │
  │  Economies of Scale: Cost per million drops by 91.7% at high volumes    │
  └─────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Executive Summary

Autonomous cloud security must be economically sustainable. Project AEGIS is designed using a serverless-first, consumption-based architecture that scales down to near-zero idle cost for small organizations while demonstrating substantial economies of scale at enterprise volumes.

All cost models are calculated using standard AWS US East (N. Virginia, `us-east-1`) published pricing dimensions and verified via `services/benchmarks/cost_calculator.py`.

---

## 2. Granular Multi-Tier Expenditure Comparison

| Component / AWS Service | Startup (1M Events/mo) | Enterprise (50M Events/mo) | Hyperscale (500M Events/mo) | Primary Cost Driver |
| :--- | :--- | :--- | :--- | :--- |
| **Amazon Kinesis Data Streams** | $10.96 (1 shard) | $44.50 (4 shards) | $226.00 (20 shards) | Shard hours + 25KB PUT payload units |
| **AWS Lambda (Compute)** | $0.58 | $20.83 | $300.00 | Invocations + GB-seconds execution |
| **Amazon DynamoDB (State & Locks)** | $1.50 | $75.00 | $750.00 | On-Demand write and read request units |
| **Amazon S3 (Evidence Vault & Logs)** | $5.02 | $28.50 | $265.00 | Compressed JSON storage + PUT requests |
| **Amazon Neptune Serverless** | $36.50 (0.5 NCU) | $182.50 (2.5 NCU) | $584.00 (8.0 NCU) | Neptune Capacity Unit (NCU) hours |
| **Amazon SageMaker Serverless** | $0.02 (10k scores) | $0.50 (250k scores) | $5.00 (2.5M scores) | Provisioned memory + inference duration |
| **Amazon EventBridge & SQS DLQ** | $1.00 | $50.00 | $500.00 | Custom event delivery requests |
| **AWS KMS (Customer Managed Keys)**| $12.84 | $80.32 | $215.60 | CMK monthly fee + cryptographic decrypts |
| **TOTAL MONTHLY EXPENDITURE** | **$68.42** | **$482.15** | **$2,845.60** | **Total infrastructure operating cost** |
| **COST PER MILLION EVENTS** | **$68.42 / M** | **$9.64 / M** | **$5.69 / M** | **Decreases 91.7% with scale** |

---

## 3. Cost Architecture & Component Analysis

### 3.1. Neptune Serverless Optimization
- Traditional Neptune graph instances cost hundreds of dollars per month even when idle.
- AEGIS utilizes **Amazon Neptune Serverless**, configured with a minimum capacity of 0.5 NCU ($0.05/hour).
- The cluster scales automatically up to 8.0 NCUs only during burst investigation or high-concurrency attack path calculations, reducing idle expenditure by $> 75\%$.

### 3.2. Telemetry Gzip Compression & Storage Lifecycle
- Raw CloudTrail management events average ~2.0 KB - 2.5 KB each.
- The AEGIS Kinesis consumer writes gzipped JSON batches to Amazon S3, achieving an **85% compression ratio** (~0.37 KB per event).
- S3 Lifecycle configurations automatically transition raw telemetry to **S3 Glacier Instant Retrieval** after 30 days and **S3 Glacier Deep Archive** after 90 days, reducing long-term storage costs by over 90%.

### 3.3. VPC Endpoints (AWS PrivateLink) vs. NAT Gateways
- Standard AWS architectures route internal AWS API calls through NAT Gateways, incurring $0.045/GB data processing fees.
- AEGIS enforces **AWS VPC Interface and Gateway Endpoints** for S3, DynamoDB, Kinesis, KMS, and CloudWatch.
- S3 and DynamoDB Gateway Endpoints are **$0.00/hour with zero data transfer fees**, completely eliminating NAT Gateway data egress charges.

### 3.4. KMS Key Caching
- High-frequency cryptographic operations on telemetry batches utilize AWS Encryption SDK data key caching.
- By caching data keys across 100-record batch boundaries, KMS `GenerateDataKey` API calls are reduced by $99\%$, protecting against API throttling and saving hundreds of dollars monthly at high volume.
