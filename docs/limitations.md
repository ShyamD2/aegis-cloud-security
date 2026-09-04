# AEGIS Technical Limitations & Boundaries
## Explicit Technical Realities, Cloud Boundaries & Anti-Overclaiming

### 1. Security Engineering Truth in Documentation

High-quality cloud security engineering requires precise honesty about what security systems can and cannot accomplish. AEGIS explicitly rejects security theater, buzzword overclaiming, and false guarantees.

This document details the exact technical boundaries and limitations of Project AEGIS.

---

### 2. Core Technical Boundaries

#### 2.1 "Zero-Day" Detection Boundary
- **Fact**: AEGIS **does not** and **cannot** detect all zero-day vulnerabilities.
- **Reality**: AEGIS combines deterministic sequence rules with behavioral anomaly scoring. If an attacker exploits a previously unknown vulnerability using entirely legitimate, low-volume AWS API calls that conform to historical baseline behaviors and valid credentials, no behavioral or sequence engine can guarantee detection.
- **Accurate Definition**: AEGIS provides *custom behavioral anomaly detection and sequence-based cloud attack detection* against known post-exploitation behaviors and privilege escalation techniques.

#### 2.2 Latency & Detection Speed Boundary
- **Fact**: AEGIS **does not** claim universal "sub-second" cloud detection or containment.
- **Reality**:
  - AWS CloudTrail delivers management events to S3/CloudWatch with a typical latency between 5 and 15 minutes (AWS SLA does not guarantee real-time CloudTrail delivery).
  - EventBridge AWS API Call partner events provide near-real-time delivery (typically 5 to 60 seconds), but are subject to AWS regional event bus propagation delays.
  - AEGIS internal processing pipeline latency (from event ingestion in Kinesis to Step Functions trigger) is measured in milliseconds (p50 < 350ms), but the total wall-clock time from adversary action to containment is bounded by AWS telemetry delivery latency.

#### 2.3 AWS Session Token Revocation Boundary
- **Fact**: AEGIS **cannot** unilaterally purge or invalidate already-issued STS session tokens from AWS backend systems.
- **Reality**:
  - In AWS IAM, once an STS session token is signed and issued, the cryptographic token remains valid until its expiration time unless explicitly countered by an IAM policy.
  - To contain an active role session, AEGIS attaches an inline IAM policy denying all actions where `aws:TokenIssueTime` is earlier than the containment timestamp (`aws:CurrentTime`). If an attacker assumes a role in an account where AEGIS has no IAM attachment permissions or if the principal is the AWS Account Root user, immediate session revocation cannot be enforced programmatically.

#### 2.4 Attack-Path & Blast-Radius Modeling Boundary
- **Fact**: Amazon Neptune **does not** natively comprehend AWS IAM policy semantics out-of-the-box.
- **Reality**:
  - Neptune is a graph database (supporting Gremlin/openCypher), not an IAM evaluation engine.
  - AEGIS implements custom Python graph normalization logic that ingests IAM policy JSON, extracts Statements, resolves wildcards, and synthesizes traversable edges (`Actor -> AssumeRole -> Role -> Action -> Resource`).
  - Complex dynamic condition keys (e.g., `aws:PrincipalTag`, `aws:RequestTag`, `aws:VpcSourceIp`) cannot always be evaluated statically offline; graph traversal represents *potential reachability*, not mathematical proof of access.

#### 2.5 Automated Remediation Blast-Radius Boundary
- **Fact**: Autonomous containment carries inherent business disruption risk.
- **Reality**:
  - Overly aggressive automated containment could isolate a production database or quarantine a critical billing worker, causing a self-inflicted denial of service.
  - AEGIS mitigates this through strict risk score thresholds ($\ge 76$ for autonomous containment), dry-run simulation in Security Lab, explicit human approval gates for HIGH severity events, and rollback state capture.
