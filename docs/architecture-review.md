# Project AEGIS - Architecture Review & Systems Specification
## Multi-Account Security Fabric, Streaming Pipeline & Graph Blast-Radius Architecture

```
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                         AEGIS Architectural Overview                        │
  │                                                                             │
  │  [Workload Accounts]                                                        │
  │    ├── Prod (111111111111)    ──(Kinesis/EventBridge)──┐                    │
  │    ├── Dev  (333333333333)                             │                    │
  │    └── Lab  (555555555555)                             ▼                    │
  │                                                  [Telemetry Ingest]         │
  │  [Security Account (222222222222)]                     │                    │
  │    ├── Normalization & Enrichment (Pydantic v2)  ◄─────┘                    │
  │    ├── Detection Engine (10 Deterministic Rules)                            │
  │    ├── Behavioral Anomaly Inference (SageMaker)                             │
  │    ├── Attack-Path Graph Engine (Amazon Neptune)                            │
  │    ├── Contextual Risk Engine (6-Factor Model)                              │
  │    └── Automated Remediation Orchestrator (Step Functions)                  │
  │                                                                             │
  │  [Log Archive Account (444444444444)]                                       │
  │    └── S3 Forensic Vault (Object Lock Compliance Mode + KMS CMK)            │
  └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. System Architecture Overview

Project AEGIS is designed as a multi-account, event-driven security fabric operating within an AWS Organizations hierarchy. It separates security monitoring, telemetry archival, and workload execution across distinct, isolated AWS accounts to guarantee defense-in-depth.

### 1.1. Account Topology
1. **Management Account**: Houses AWS Organizations, root Service Control Policies (SCPs), and AWS Single Sign-On (IAM Identity Center).
2. **Security Tooling Account (Delegated Admin)**: Operates the core AEGIS engine, including Kinesis streams, Lambda workers, SageMaker serverless endpoints, Neptune graph clusters, Step Functions state machines, and the Security War Room API.
3. **Log Archive Account**: Serves as the centralized, immutable telemetry repository. Houses S3 buckets with Object Lock (`COMPLIANCE` mode) and customer-managed KMS encryption.
4. **Workload Accounts (Prod, Dev, Lab)**: Run application infrastructure under continuous monitoring and automated containment.

---

## 2. Core Subsystems

### 2.1. Centralized Telemetry & Event Ingestion (Phases 03 & 06)
- **Organization CloudTrail**: Multi-region trail capturing management and data events across all accounts.
- **Amazon Kinesis Data Streams**: Scalable real-time ingestion buffer with 24-hour replay retention.
- **Pydantic v2 Canonical Models**: Strict schemas (`NormalizedSecurityEvent`, `CloudTrailRecord`) ensuring type safety, strict validation, and zero extra field injection.
- **Dead-Letter Queue (DLQ)**: Poison-pill or malformed events are automatically routed to SQS DLQ with exponential backoff and 14-day retention.

### 2.2. Multi-Engine Threat Detection (Phases 04, 05 & 07)
- **AWS-Native Findings Adapter**: Ingests, normalizes, and deduplicates findings from Amazon GuardDuty, AWS Security Hub, AWS Config, and Amazon Inspector.
- **Custom Deterministic Rule Engine**: 10 compiled rules covering IAM credential compromise, privilege escalation, S3 drift, security group ingress exposure, CloudTrail disruption, and multi-step attack sequences.
- **Behavioral Anomaly Scoring**: SageMaker Serverless endpoint running an Isolation Forest / autoencoder model scoring deviation from synthetic baseline profiles.

### 2.3. Attack-Path Graph & Blast-Radius Engine (Phase 08)
- **Graph Schema**: Directed multigraph modeling identities (users, roles), permissions (managed policies, inline policies), resources (S3, EC2, RDS, SecretsManager), and trust boundaries.
- **Traversal & Cycle Avoidance**: BFS traversal with visited-set tracking calculating reachable nodes, role-chaining depth, and cross-account pivots.
- **Neptune Compatibility**: In-memory graph synchronizes with Amazon Neptune via openCypher / Gremlin statements.

### 2.4. Explainable Contextual Risk Engine (Phase 09)
- Computes deterministic scores from 0.0 to 100.0 utilizing a 6-factor weighting model:
  $$\text{Score} = w_s S + w_c C + w_p P + w_b B + w_a A + w_e E + \Delta_{\text{env}}$$
- Includes CVSS Critical Floor enforcement and explicit factor attribution for complete SOC explainability.

### 2.5. Autonomous Incident Response & Self-Healing (Phase 10)
- **Step Functions State Machine**: Executes automated containment workflows with idempotency locking, risk score gating ($\ge 50.0$), post-remediation verification, and automatic rollback on failure.
- **Scoped Remediators**: Fine-grained IAM, EC2 network isolation, S3 Block Public Access enforcement, and account quarantine handlers.

### 2.6. Digital Forensics & Security War Room (Phases 11 & 12)
- **Immutable Evidence Vault**: Stores evidence records sealed by SHA-256 manifests under S3 Object Lock.
- **Athena Forensic Chronology**: Pre-built SQL queries for incident reconstruction and timeline correlation.
- **Operations War Room**: Real-time SOC dashboard with Cognito MFA authorization and zero long-lived credentials.
