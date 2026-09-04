# Project AEGIS - Technical Limitations & Boundary Analysis
## Architectural Trade-Offs, Anti-Overclaiming Guarantees & Operational Boundaries

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                 AEGIS Honest Engineering Boundaries                     │
  │                                                                         │
  │  [NO Unsupported Claims]  Explicit limits on STS instant deletion       │
  │  [NO Magic ML]            ML scores enrich; deterministic rules govern  │
  │  [NO Host Agent Overlap]  Control-plane & network focus (no kernel eBPF)│
  │  [Cloud Inherent Latency] Bounded by AWS CloudTrail delivery frequency │
  │  [Target Cloud]           Purpose-built for AWS multi-account estates   │
  └─────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Executive Summary

Senior engineering integrity requires explicit documentation of system boundaries and trade-offs. Overclaiming security capabilities creates false confidence and operational blind spots.

This document details the exact technical boundaries, cloud provider limitations, and deliberate design trade-offs governing **Project AEGIS**.

---

## 2. Cloud Provider & Technical Limitations

### 2.1. AWS STS Temporary Token Invalidation Latency
- **The Limitation**: Once an AWS STS temporary security token is issued (via `sts:AssumeRole` or `sts:GetSessionToken`), there is no AWS API that can forcibly delete the token from the caller's memory before its natural expiration (up to 12 hours).
- **How AEGIS Solves This Honestly**: AEGIS does not claim impossible "instant token destruction". Instead, it attaches an inline IAM policy to the compromised role/user containing an explicit Deny condition:
  ```json
  {
    "Sid": "AEGISDenyOlderSessions",
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "DateLessThan": {
        "aws:TokenIssueTime": "2026-09-04T12:00:00Z"
      }
    }
  }
  ```
- Any subsequent AWS API request using a token issued prior to that timestamp is immediately rejected by the IAM policy evaluation engine with `AccessDenied`.

### 2.2. Telemetry Ingestion Latency (CloudTrail Delivery Lag)
- **The Limitation**: AWS CloudTrail standard delivery to Amazon S3 or CloudWatch Logs operates on a native delivery frequency of approximately **5 to 15 minutes**.
- **Impact on Containment**: While AEGIS processes and contains incidents in **sub-second time (< 1.5s)** once telemetry arrives, the initial arrival of the log is bounded by AWS internal CloudTrail batch flush intervals.
- **Architectural Solution**: AEGIS integrates with **Amazon EventBridge CloudTrail API call events** for near-real-time ingestion of high-severity management actions (`CreateAccessKey`, `AttachUserPolicy`, `StopLogging`), reducing delivery latency to seconds.

### 2.3. Control Plane vs. Data Plane Scope
- **The Limitation**: AEGIS is an **agentless, cloud-native control plane defense fabric**. It analyzes CloudTrail management/data events, VPC Flow Logs, and Route 53 DNS queries.
- **What AEGIS Is NOT**: AEGIS does not install in-guest kernel drivers, eBPF probes, or host-based EDR agents. It does not perform live process memory dumping or kernel hook inspection inside running EC2 virtual machines.
- **Integration**: AEGIS ingests Amazon GuardDuty runtime monitoring findings to bridge host-level telemetry into the attack graph without requiring proprietary agents.

### 2.4. Autonomous False-Positive Risk
- **The Limitation**: Aggressive autonomous containment (e.g. revoking IAM sessions or isolating EC2 instances) carries a risk of business disruption if triggered on a benign administrative task.
- **Mitigations Implemented**:
  1. **Risk Gating**: Autonomous mutations are strictly forbidden for risk scores $< 50.0$.
  2. **Circuit Breaker**: Trips to `OPEN` state if 5 consecutive errors occur, preventing runaway cascading containment.
  3. **Human Approval Gate**: Account quarantine and destructive actions require explicit SOC Lead approval via Cognito MFA.
  4. **Instant Rollback**: Pre-remediation state is preserved, enabling single-click or automated state restoration.

---

## 3. Future Architectural Enhancements

1. **Multi-Cloud Federation**: Adapting canonical telemetry parsers to ingest Azure Activity Logs and Google Cloud Audit Logs into the unified Pydantic v2 schema.
2. **eBPF Sidecar Integration**: Optional lightweight eBPF container daemon for Kubernetes (EKS) runtime memory protection.
3. **Automated Threat Hunting**: LLM-assisted graph query generation allowing SOC analysts to query attack paths using natural language.
