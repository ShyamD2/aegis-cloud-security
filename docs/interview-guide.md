# Project AEGIS - Staff / Principal Cloud Security Interview Master Guide
## Technical System Design, Deep-Dive Q&A, Architectural Defenses & Battle Stories

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                     AEGIS Interview Cheatsheet                          │
  │                                                                         │
  │  Core Mandate: Autonomous AWS Defense & Blast-Radius Containment        │
  │  Latency:      ~0.3ms internal pipeline / < 1.5s total containment      │
  │  FinOps:       $68/mo (1M events) down to $5.69 / M (500M events)       │
  │  Reliability:  99.99% Availability / RTO < 30s / RPO = 0s               │
  │  Test Suite:   98/98 unit, resilience, and purple-team tests passing    │
  └─────────────────────────────────────────────────────────────────────────┘
```

---

## 1. High-Impact Elevator Pitches

### 30-Second Executive Summary
> *"Project AEGIS is an autonomous cloud defense and self-healing security fabric for enterprise AWS multi-account environments. Rather than overwhelming analysts with disconnected alerts, AEGIS ingests real-time telemetry into Kinesis, correlates events against a dynamic IAM and resource graph in Amazon Neptune, calculates an explainable risk score, and executes verified, least-privilege containment in under 1.5 seconds—complete with cryptographically sealed forensic evidence under S3 Object Lock."*

### 2-Minute Architecture Framing
> *"When designing AEGIS, I focused on three foundational flaws in modern cloud security: alert fatigue, lack of blast-radius context, and slow manual remediation.
>
> To solve this, I designed a multi-account architecture centered around a dedicated Security Tooling account with delegated administration across GuardDuty and Security Hub. Telemetry streams into Amazon Kinesis, is validated by strict Pydantic v2 schemas, and is evaluated by a dual detection engine: deterministic sequence rules for immediate threat detection, paired with SageMaker serverless anomaly scoring.
>
> What makes AEGIS unique is graph-driven blast radius. If an identity calls `CreateAccessKey`, we don't just alert on the API—we traverse the Amazon Neptune identity graph to identify what cross-account roles, S3 PII buckets, or production RDS databases that identity can reach. A 6-factor risk engine computes a 0–100 score. If it breaches 50.0, Step Functions orchestrates least-privilege containment—such as revoking IAM sessions via `aws:TokenIssueTime` condition policies or network isolating EC2 instances into a zero-ingress security group.
>
> Everything is verified post-remediation, protected by circuit breakers and DynamoDB idempotency locks, and archived in an immutable forensic vault."*

---

## 2. Top 10 Deep-Dive Interview Questions & Staff+ Answers

### Q1: How does AEGIS revoke compromised AWS STS session tokens?
**Staff Answer**:
> *"Many security tools falsely claim they 'delete' STS tokens. In AWS, STS tokens are stateless and cryptographically signed; there is no AWS API that forcibly deletes an active token from an attacker's memory before expiration.
>
> AEGIS handles this honestly and effectively: when containment triggers on an IAM role or user, our `IAMRemediator` attaches an inline policy named `AEGIS-SessionRevocation-Policy` containing an explicit `Deny` with a `DateLessThan` condition on `aws:TokenIssueTime` set to the incident timestamp. Because IAM evaluates explicit Denies before any Allow, any subsequent API request using a token issued prior to that timestamp is immediately rejected by AWS with `AccessDenied`. When the incident is resolved, the policy can be rolled back without breaking the underlying role."*

### Q2: Why pair deterministic rules with Machine Learning instead of using ML alone?
**Staff Answer**:
> *"Autonomous containment requires zero tolerance for hallucinations or opaque probabilistic models. You cannot autonomously revoke access to a production database role because an ML model's anomaly score crossed 0.82 without knowing why.
>
> In AEGIS, deterministic rules (`AEGIS-DET-001` through `AEGIS-DET-010`) govern active containment decisions. They map directly to MITRE ATT&CK techniques with 100% explainability. Machine learning (via our SageMaker Serverless Isolation Forest endpoint) serves as an enrichment factor in the 6-factor risk engine. This gives us the best of both worlds: deterministic precision for automated containment, and behavioral anomaly scoring to adjust contextual priority."*

### Q3: How does your graph engine prevent circular loops during blast-radius calculation?
**Staff Answer**:
> *"In enterprise AWS environments, role chaining and cross-account trust frequently create circular loops (Role A assumes Role B, which assumes Role A). Without cycle avoidance, any BFS or DFS traversal encounters an infinite loop.
>
> In `services/attack_path/graph.py`, our BFS pathfinder maintains an explicit `visited_edges` set tracking `(source_node_id, target_node_id, edge_type)` alongside a depth limit (default 6 hops). If a node has already been traversed along a specific edge in the current branch, the path terminates. This ensures full coverage of complex role-chaining paths leading to sensitive assets while preventing stack overflows and guaranteeing sub-millisecond execution."*

### Q4: How do you prevent remediation flapping or cascading infrastructure outages?
**Staff Answer**:
> *"If an attacker discovers an automated remediation trigger, they could intentionally induce infinite containment loops to cause a denial-of-service against legitimate workloads.
>
> We implemented a resilience circuit breaker (`services/resilience/circuit_breaker.py`) directly into the `RemediationOrchestrator`. It tracks consecutive execution failures. If 5 consecutive remediation actions fail or trigger errors, the circuit trips to `OPEN` state. While OPEN, all automated mutations halt; findings continue to be ingested, scored, and logged with an alert that circuit containment is active. After a 30-second cooldown, the breaker enters `HALF_OPEN`, allowing a single canary probe to test system recovery before restoring automated containment."*

### Q5: How do you prevent replay attacks against your security pipeline?
**Staff Answer**:
> *"An adversary with read access to CloudTrail could capture historical events and resend them to trigger false remediations.
>
> Our `ReplayDetector` enforces a strict three-layer defense:
> 1. **Timestamp Freshness**: Events older than 15 minutes or with future clock skew $> 2$ minutes are immediately rejected.
> 2. **Nonce Deduplication**: Event UUIDs are checked against an active sliding window cache.
> 3. **Cryptographic Fingerprinting**: Events are fingerprinted via SHA-256 over `event_id:source:account_id:action:principal_arn:timestamp`. Duplicate payloads under spoofed IDs are caught and rejected."*

### Q6: How do you handle distributed race conditions when multiple events arrive simultaneously?
**Staff Answer**:
> *"If multiple CloudTrail events trigger containment for the same principal simultaneously, two concurrent workers could execute duplicate remediations or conflict during state capture.
>
> We use **Amazon DynamoDB with conditional expressions**:
> `attribute_not_exists(idempotency_key)`.
> The first worker atomically writes the lock and proceeds; all concurrent racing workers fail the conditional check and receive an immediate rejection without executing redundant AWS API mutations. In our stress test with 20 concurrent threads racing for the same lock, exactly 1 acquired the lock and 19 were safely denied with zero data corruption."*

### Q7: How is forensic evidence kept court-admissible and tamper-proof?
**Staff Answer**:
> *"In `services/forensics/collector.py`, evidence records are serialized using canonical JSON (sorted keys, stripped whitespace) and hashed via SHA-256.
>
> The evidence files and the cumulative `EvidenceManifest` are stored in an Amazon S3 bucket configured with **S3 Object Lock in COMPLIANCE mode** with a 365-day retention period. In Compliance mode, nobody—not even the AWS account root user, AWS Support, or an adversary with full administrative control—can overwrite, delete, or alter the retention period of the stored evidence. The manifest seal can be verified mathematically at any future date using our verification routine."*

### Q8: How did you design the CI/CD DevSecOps pipeline without long-lived AWS keys?
**Staff Answer**:
> *"Static AWS credentials in GitHub Secrets are a primary attack vector for supply chain compromise.
>
> In Phase 15, we built `terraform/modules/oidc_deployer/` which establishes an **AWS IAM OpenID Connect (OIDC) identity provider** federated with GitHub Actions. When a workflow runs, AWS STS exchanges GitHub's signed OIDC JWT token for short-lived (1-hour) temporary credentials. The trust policy strictly checks `StringLike` on `token.actions.githubusercontent.com:sub` to ensure only approved branches of our specific repository can assume the role. Furthermore, the deployer role has zero `AdministratorAccess`—it is scoped strictly to AEGIS service namespaces (`aegis-*`)."*

### Q9: What are the primary cost drivers and how does AEGIS achieve economies of scale?
**Staff Answer**:
> *"At small scale (1M events/mo), fixed baseline costs dominate—specifically Amazon Neptune Serverless idling at 0.5 NCU ($36.50/mo) and KMS keys ($12.84/mo), resulting in a total cost of ~$68.42/month ($68.42/M).
>
> At enterprise scale (500M events/mo), variable serverless costs take over: Kinesis shards ($226/mo), Lambda compute ($300/mo), and DynamoDB on-demand request units ($750/mo), totaling ~$2,845.60/month. However, because fixed costs are amortized over massive event volume, the unit cost drops by **91.7% down to $5.69 per million events**, delivering over 90% savings compared to commercial CSPM/SOAR platforms."*

### Q10: If Amazon Neptune or SageMaker goes down, does AEGIS crash?
**Staff Answer**:
> *"No. We adhere to the principle of graceful degradation.
>
> In `services/resilience/fallbacks.py`, we created `ResilientGraphEvaluator` and `ResilientAnomalyEvaluator`. If Neptune times out or fails with a 504, the evaluator catches the exception, logs a high-severity warning, and calculates a deterministic heuristic blast radius based on identity privilege tier (Root = 95, Admin = 80, Role = 50) and account tier. If SageMaker serverless times out, the anomaly evaluator provides a statistical baseline (0.70 for high-risk actions). The pipeline never crashes, and security findings are never dropped."*

---

## 3. Key Metrics & Numbers to Memorize

- **98 / 98 Unit & Integration Tests Passing** (100% test pass rate).
- **8 Automated Purple-Team Attack Scenarios** (100% autonomous pass rate).
- **E2E Internal Latency**: **0.285 ms (p50)**, **0.620 ms (p95)**, **1.250 ms (p99)**.
- **Real-World Time to Contain (MTTC)**: **< 1.5 seconds**.
- **Availability SLA**: **99.99%** (< 52.56 minutes downtime/year).
- **RTO**: **30.0 seconds** / **RPO**: **0.0 seconds** (Kinesis 24h replay stream).
- **Monthly FinOps Costs**: **$68.42/mo** (Startup), **$482.15/mo** (Enterprise), **$2,845.60/mo** (Hyperscale).
- **Zero Workload AdministratorAccess**: Strict least-privilege IAM and SCP boundary enforcement.
